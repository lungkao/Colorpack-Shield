<?php
/**
 * WAF replay — "what would the header rules have done to my real traffic?"
 *
 * Reads web-server access logs (Apache/nginx "combined" format; .gz ok), runs
 * the same rules the plugin uses and prints ONLY A SUMMARY: counts per rule and
 * a few shortened, masked examples. It never prints a raw log line or an IP
 * address, never writes anything, and never touches the network.
 *
 *   headers  User-Agent and Referer of each line, through the header rules;
 *   paths    the request path of each line (query string ignored) through the
 *            path rules, split by the HTTP status the server really answered:
 *            a blocking rule that hit 2xx/3xx requests would have broken real
 *            visits (false positive); the same rule hitting only 404s is a scanner.
 *
 *   php waf_replay.php [--scope=both|headers|paths] [--mode=default|log|block]
 *        [--probe=off|log|block] [--allow=/prefix|re:REGEX]... [--samples=3]
 *        [--min-count=5] [--top404=N] [--max-lines=N] LOGFILE [LOGFILE…]
 *
 * Typical log locations (verify on your server):
 *   DirectAdmin  /var/log/httpd/domains/<domain>.log
 *   HestiaCP     /var/log/apache2/domains/<domain>.log  or  /var/log/nginx/domains/<domain>.log
 *
 * Only User-Agent and Referer are in a combined log; the other inspected
 * headers (X-Forwarded-For, Host, Accept*) can only be judged live, in log mode.
 * Path shapes (numbers → {n}, long hex → {hex}, non-ASCII → {th}) are shown only
 * when they occurred at least --min-count times (default 5), so a single odd URL
 * of one visitor is never printed. Use --min-count=1 to see everything on your
 * own screen; do not share that output.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

\define('_JEXEC', 1);

$src = \dirname(__DIR__) . '/src';

foreach ([
    'Geo/CidrMatcher', 'Net/ClientIp', 'Net/ClientIpResolver',
    'Waf/WafResult', 'Waf/Normalizer', 'Waf/PathNormalizer', 'Waf/RequestData', 'Waf/Rules/HeaderRules', 'Waf/Rules/PathRules',
    'Waf/Shield/ShieldInterface', 'Waf/Shield/MultiResultShield', 'Waf/Shield/HeaderShield', 'Waf/Shield/PathShield',
] as $file) {
    require_once $src . '/' . $file . '.php';
}

use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

function cps_usage(int $code): never
{
    fwrite($code === 0 ? STDOUT : STDERR, "Usage: php waf_replay.php [--scope=both|headers|paths] [--mode=default|log|block] [--probe=off|log|block] [--allow=/prefix|re:REGEX]... [--samples=3] [--min-count=5] [--top404=N] [--max-lines=N] LOGFILE [LOGFILE...]\n");
    exit($code);
}

/** Undo the escaping Apache (\" \\ \xHH) and nginx (\xHH) apply inside quoted log fields. */
function cps_unescape(string $s): string
{
    if (!str_contains($s, '\\')) {
        return $s;
    }

    $s = preg_replace_callback('/\\\\x([0-9A-Fa-f]{2})/', static fn (array $m): string => \chr((int) hexdec($m[1])), $s) ?? $s;

    return str_replace(['\\"', '\\\\'], ['"', '\\'], $s);
}

/** Shorten and mask a value so an example can be shared without leaking addresses or tokens. */
function cps_mask(string $s): string
{
    $s = preg_replace('~(?<=://)[^/?#\s]+~', '<host>', $s) ?? $s;                                  // host names
    $s = preg_replace('~\?[^\s#]*~', '?<q>', $s) ?? $s;                                            // query strings
    $s = preg_replace('~\b\d{1,3}(?:\.\d{1,3}){3}\b~', '<ip>', $s) ?? $s;                          // IPv4
    $s = preg_replace('~\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b~', '<ip>', $s) ?? $s;      // IPv6
    $s = preg_replace('~[\w.+-]+@[\w-]+(?:\.[\w-]+)+~', '<email>', $s) ?? $s;                      // e-mail
    $s = preg_replace('/[^\x20-\x7e]/', '?', $s) ?? $s;                                            // control / non-ASCII
    $s = trim($s);

    return \strlen($s) > 80 ? substr($s, 0, 80) . '…' : $s;
}

/** Request target of an access-log request field ("GET /a/b?x=1 HTTP/1.1"), or null when it is not HTTP-like. */
function cps_target(string $request): ?string
{
    return preg_match('~^[A-Za-z]{3,10} (\S+)(?: HTTP/\d(?:\.\d)?)?$~', $request, $m) === 1 ? $m[1] : null;
}

/** Masked "shape" of a request path: no numbers, long hex, non-ASCII words, query string, hosts or addresses. */
function cps_shape(string $target): string
{
    $path = substr($target, 0, strcspn($target, '?#'));
    $path = preg_replace('~^[A-Za-z][A-Za-z0-9+.\-]*://[^/]*~', '', $path) ?? $path;
    $segs = explode('/', $path);

    foreach ($segs as $i => $seg) {
        if (preg_match('/%[89A-Fa-f][0-9A-Fa-f]|[\x80-\xff]/', $seg) === 1) {
            $segs[$i] = '{th}';
        } elseif (preg_match('/^[0-9A-Fa-f]{8,}$/', $seg) === 1) {
            $segs[$i] = '{hex}';
        } else {
            $segs[$i] = preg_replace('/\d+/', '{n}', preg_replace('/[0-9A-Fa-f]{8,}/', '{hex}', $seg) ?? $seg) ?? $seg;
        }
    }

    return cps_mask(implode('/', $segs));
}

/** @return string 2xx|3xx|4xx|5xx|other */
function cps_status_class(int $status): string
{
    return match (intdiv($status, 100)) {
        2 => '2xx', 3 => '3xx', 4 => '4xx', 5 => '5xx',
        default => 'other',
    };
}

$opt  = getopt('', ['mode:', 'samples:', 'max-lines:', 'scope:', 'probe:', 'allow:', 'min-count:', 'top404:', 'help'], $rest);
$args = \array_slice($argv, (int) $rest);

if (isset($opt['help'])) {
    cps_usage(0);
}

$mode = (string) ($opt['mode'] ?? 'default');

if (!\in_array($mode, ['default', 'log', 'block'], true)) {
    fwrite(STDERR, "ERROR: --mode must be default, log or block\n");
    exit(1);
}

$scope = (string) ($opt['scope'] ?? 'both');

if (!\in_array($scope, ['both', 'headers', 'paths'], true)) {
    fwrite(STDERR, "ERROR: --scope must be both, headers or paths\n");
    exit(1);
}

$probe = (string) ($opt['probe'] ?? 'log');

if (!\in_array($probe, ['off', 'log', 'block'], true)) {
    fwrite(STDERR, "ERROR: --probe must be off, log or block\n");
    exit(1);
}

$samples  = max(0, (int) ($opt['samples'] ?? 3));
$maxLines = max(0, (int) ($opt['max-lines'] ?? 0));
$minCount = max(1, (int) ($opt['min-count'] ?? 5));
$top404   = max(0, (int) ($opt['top404'] ?? 0));
$allow    = isset($opt['allow']) ? (array) $opt['allow'] : [];
$doHeader = $scope !== 'paths';
$doPath   = $scope !== 'headers';

$files = [];

foreach ($args as $arg) {
    $matches = glob($arg) ?: [$arg];

    foreach ($matches as $f) {
        if (is_file($f) && is_readable($f)) {
            $files[$f] = true;
        } else {
            fwrite(STDERR, 'WARNING: cannot read a file you listed; skipped' . "\n");
        }
    }
}

if ($files === []) {
    cps_usage(1);
}

$shield     = new HeaderShield($mode);
$pathShield = new PathShield($mode === 'default' ? 'recommended' : $mode, $probe, $allow);
$cache      = [];     // md5(ua|ref) => list of [rule, mode, header, maskedExample]
$stats      = [];     // rule => ['mode'=>, 'lines'=>int, 'distinct'=>array<md5,true>, 'examples'=>[masked,…]]
$pcache     = [];     // path => list of [rule, mode]
$pstats     = [];     // rule => ['mode'=>, 'c'=>[class=>int], 'total'=>int, 'shapes'=>[shape=>['n'=>int,'ok'=>int]]]
$p404       = [];     // shape => count of 404s no rule explains
$read       = 0;
$parsed     = 0;
$bad        = 0;
$notHttp    = 0;
$pathLines  = 0;
$flagBlock  = 0;
$flagLog    = 0;
$pBlock     = 0;      // path findings whose rule would block
$pLog       = 0;

foreach (array_keys($files) as $file) {
    $fh = str_ends_with($file, '.gz') ? @gzopen($file, 'rb') : @fopen($file, 'rb');

    if ($fh === false) {
        fwrite(STDERR, "WARNING: could not open a file; skipped\n");
        continue;
    }

    $isGz = str_ends_with($file, '.gz');

    while (($line = $isGz ? gzgets($fh, 65536) : fgets($fh, 65536)) !== false) {
        if ($maxLines > 0 && $read >= $maxLines) {
            break 2;
        }

        $read++;

        // combined: host ident user [time] "request" status bytes "referer" "agent"
        if (!preg_match('/^\S+ \S+ \S+ \[[^\]]*\] "((?:[^"\\\\]|\\\\.)*)" (\d{3}) \S+ "((?:[^"\\\\]|\\\\.)*)" "((?:[^"\\\\]|\\\\.)*)"/', $line, $m)) {
            $bad++;
            continue;
        }

        $parsed++;

        if ($doPath) {
            $target = cps_target(cps_unescape($m[1]));

            if ($target === null) {
                $notHttp++;
            } else {
                $pathLines++;
                $rawPath = substr($target, 0, strcspn($target, '?#'));
                $class   = cps_status_class((int) $m[2]);

                if (!isset($pcache[$rawPath])) {
                    $hits = [];

                    foreach ($pathShield->inspectAll(new RequestData(['PATH' => ['path' => $rawPath]])) as $r) {
                        $hits[] = [$r->rule, $r->mode];
                    }

                    if (\count($pcache) < 200000) {
                        $pcache[$rawPath] = $hits;
                    }
                } else {
                    $hits = $pcache[$rawPath];
                }

                $shape = null;

                foreach ($hits as [$rule, $ruleMode]) {
                    $shape ??= cps_shape($target);
                    $pstats[$rule] ??= ['mode' => $ruleMode, 'c' => ['2xx' => 0, '3xx' => 0, '4xx' => 0, '5xx' => 0, 'other' => 0], 'total' => 0, 'shapes' => []];
                    $pstats[$rule]['c'][$class]++;
                    $pstats[$rule]['total']++;

                    if (isset($pstats[$rule]['shapes'][$shape]) || \count($pstats[$rule]['shapes']) < 5000) {
                        $pstats[$rule]['shapes'][$shape] ??= ['n' => 0, 'ok' => 0];
                        $pstats[$rule]['shapes'][$shape]['n']++;
                        $pstats[$rule]['shapes'][$shape]['ok'] += ($class === '2xx' || $class === '3xx') ? 1 : 0;
                    }

                    $ruleMode === WafResult::MODE_BLOCK ? $pBlock++ : $pLog++;
                }

                if ($hits === [] && $top404 > 0 && $m[2] === '404') {
                    $shape = cps_shape($target);

                    if (isset($p404[$shape]) || \count($p404) < 50000) {
                        $p404[$shape] = ($p404[$shape] ?? 0) + 1;
                    }
                }
            }
        }

        if (!$doHeader) {
            continue;
        }

        $referer = cps_unescape($m[3]);
        $agent   = cps_unescape($m[4]);
        $headers = [];

        if ($agent !== '' && $agent !== '-') {
            $headers['User-Agent'] = $agent;
        }

        if ($referer !== '' && $referer !== '-') {
            $headers['Referer'] = $referer;
        }

        if ($headers === []) {
            continue;
        }

        $key = md5($agent . "\0" . $referer);

        if (!isset($cache[$key])) {
            $hits = [];

            foreach ($shield->inspectAll(new RequestData(['HEADER' => $headers])) as $r) {
                $hits[] = [$r->rule, $r->mode, $r->key, cps_mask($r->key . ': ' . ($headers[$r->key] ?? ''))];
            }

            if (\count($cache) < 200000) {
                $cache[$key] = $hits;
            }
        } else {
            $hits = $cache[$key];
        }

        foreach ($hits as [$rule, $ruleMode, $hdr, $example]) {
            $stats[$rule] ??= ['mode' => $ruleMode, 'lines' => 0, 'distinct' => [], 'examples' => []];
            $stats[$rule]['lines']++;

            if (\count($stats[$rule]['distinct']) < 100000) {
                $stats[$rule]['distinct'][$key] = true;
            }

            if (\count($stats[$rule]['examples']) < $samples && !\in_array($example, $stats[$rule]['examples'], true)) {
                $stats[$rule]['examples'][] = $example;
            }

            $ruleMode === WafResult::MODE_BLOCK ? $flagBlock++ : $flagLog++;
        }
    }

    $isGz ? gzclose($fh) : fclose($fh);
}

$pct = static fn (int $n, int $d): string => $d > 0 ? sprintf('%.3f%%', 100 * $n / $d) : '-';

echo "Colorpack Shield — WAF replay (summary only)\n";
echo "============================================\n";
echo 'Files: ' . \count($files) . "   Lines read: $read   Parsed: $parsed   Not in combined format: $bad\n";

if ($doHeader) {
    echo "Checked: User-Agent and Referer of each line, mode=$mode\n";
}

if ($doPath) {
    echo "Checked: the request path of each line (query string ignored), mode=$mode, probes=$probe\n";
}

echo "Nothing below is a raw log line; hosts, query strings, IPs and e-mails in examples are masked.\n\n";

if ($doHeader) {
    echo "HEADERS\n-------\n";

    if ($stats === []) {
        echo "No findings.\n";
    } else {
        uasort($stats, static fn (array $a, array $b): int => $b['lines'] <=> $a['lines']);
        printf("%-26s %-6s %9s %9s %9s\n", 'RULE', 'MODE', 'LINES', '% LINES', 'DISTINCT');

        foreach ($stats as $rule => $st) {
            printf("%-26s %-6s %9d %9s %9d\n", $rule, $st['mode'], $st['lines'], $pct($st['lines'], $parsed), \count($st['distinct']));

            foreach ($st['examples'] as $ex) {
                echo "    e.g. $ex\n";
            }
        }

        echo "\nFindings that would BLOCK a request: $flagBlock (" . $pct($flagBlock, $parsed) . " of parsed lines)\n";
        echo "Findings that would only be LOGGED:  $flagLog (" . $pct($flagLog, $parsed) . ")\n";
        echo "A blocking rule firing on real visitors is a false positive to fix BEFORE enabling blocking.\n";
    }

    echo "\n";
}

if ($doPath) {
    echo "URL PATHS\n---------\n";
    echo "Request lines: $pathLines   Not HTTP-like (TLS probes, garbage): $notHttp\n";

    // Rules a request should never legitimately answer 2xx for: the file or page really exists.
    $attention = ['php_in_data_dir', 'joomla_internal', 'scanner_probe', 'path_extra_deny'];
    $fp        = [];
    $served    = [];

    if ($pstats === []) {
        echo "No path findings.\n";
    } else {
        uasort($pstats, static fn (array $a, array $b): int => $b['total'] <=> $a['total']);
        printf("%-22s %-6s %7s %7s %7s %7s %7s %8s\n", 'RULE', 'MODE', '2xx', '3xx', '4xx', '5xx', 'OTHER', 'TOTAL');

        foreach ($pstats as $rule => $st) {
            $note = ($st['c']['2xx'] + $st['c']['3xx']) > 0 && $st['mode'] === WafResult::MODE_BLOCK ? '   <- would have broken real visits' : '';
            printf("%-22s %-6s %7d %7d %7d %7d %7d %8d%s\n", $rule, $st['mode'], $st['c']['2xx'], $st['c']['3xx'], $st['c']['4xx'], $st['c']['5xx'], $st['c']['other'], $st['total'], $note);

            $shown = 0;
            $rare  = 0;
            uasort($st['shapes'], static fn (array $a, array $b): int => $b['n'] <=> $a['n']);

            foreach ($st['shapes'] as $shape => $sh) {
                if ($sh['n'] < $minCount) {
                    $rare++;
                    continue;
                }

                if ($shown < $samples) {
                    echo "    e.g. $shape  (x{$sh['n']})\n";
                    $shown++;
                }
            }

            if ($rare > 0) {
                echo "    + $rare more path shape(s) seen fewer than $minCount times (withheld)\n";
            }

            if ($st['mode'] === WafResult::MODE_BLOCK && ($st['c']['2xx'] + $st['c']['3xx']) > 0) {
                $fp[$rule] = $st;
            }

            if (\in_array($rule, $attention, true) && $st['c']['2xx'] > 0) {
                $served[$rule] = $st;
            }
        }

        echo "\nPath findings that would BLOCK a request: $pBlock (" . $pct($pBlock, $pathLines) . " of request lines)\n";
        echo "Path findings that would only be LOGGED:  $pLog (" . $pct($pLog, $pathLines) . ")\n";
    }

    echo "\nPROBABLE FALSE POSITIVES (a blocking rule on requests the server answered 2xx/3xx): ";

    if ($fp === []) {
        echo "none\n";
    } else {
        echo \count($fp) . " rule(s)\n";

        foreach ($fp as $rule => $st) {
            $n = $st['c']['2xx'] + $st['c']['3xx'];
            echo "  $rule: $n request(s) of {$st['total']} succeeded; fix or allow-list before blocking\n";

            $shown = 0;

            foreach ($st['shapes'] as $shape => $sh) {
                if ($sh['ok'] > 0 && $sh['n'] >= $minCount && $shown < max(1, $samples)) {
                    echo "    e.g. $shape  ({$sh['ok']} succeeded of {$sh['n']})\n";
                    $shown++;
                }
            }
        }
    }

    echo "\nFILES THAT PROBABLY EXIST (rules for leftovers/probes answered 2xx): ";

    if ($served === []) {
        echo "none\n";
    } else {
        echo \count($served) . " rule(s)\n";

        foreach ($served as $rule => $st) {
            echo "  $rule: {$st['c']['2xx']} request(s) answered 2xx — check whether a file or page really exists at such an address\n";

            $shown = 0;

            foreach ($st['shapes'] as $shape => $sh) {
                if ($sh['ok'] > 0 && $sh['n'] >= $minCount && $shown < max(1, $samples)) {
                    echo "    e.g. $shape  ({$sh['ok']} succeeded of {$sh['n']})\n";
                    $shown++;
                }
            }
        }
    }

    if ($top404 > 0) {
        echo "\nMOST COMMON 404 PATHS NO RULE EXPLAINS (seen at least $minCount times; may include broken links of your own site):\n";
        arsort($p404);
        $n = 0;

        foreach ($p404 as $shape => $count) {
            if ($count < $minCount || $n >= $top404) {
                break;
            }

            echo "  $shape  (x$count)\n";
            $n++;
        }

        if ($n === 0) {
            echo "  none\n";
        }
    }

    echo "\nA blocking rule that hit requests answered 2xx/3xx is a false positive to fix BEFORE enabling blocking; a rule that only hits 404s is a scanner.\n";
}

exit(0);
