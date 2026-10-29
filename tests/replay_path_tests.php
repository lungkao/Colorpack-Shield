<?php
/**
 * waf_replay.php, path mode: status split, false-positive and "file exists"
 * sections, k-anonymity, masking, options. Runs the real CLI script against
 * synthetic logs. Included by run.php after replay_tests.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "== Replay tool: URL paths ==\n";

$rscript = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/waf_replay.php');
$pdir    = sys_get_temp_dir() . '/cps-replay-path-' . bin2hex(random_bytes(4));
mkdir($pdir);

$pline = static fn (string $ip, string $req, int $status, string $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0'): string =>
    sprintf("%s - - [28/Oct/2026:10:00:00 +0700] \"%s\" %d 512 \"-\" \"%s\"\n", $ip, $req, $status, $ua);

$ipn = 0;
$ip  = static function () use (&$ipn): string {
    $ipn++;

    return '198.51.100.' . (($ipn % 250) + 1);
};

// Benign-only log.
$benign = '';

for ($i = 1; $i <= 40; $i++) {
    $benign .= $pline($ip(), "GET /index.php/component/content/article/$i-news HTTP/1.1", 200);
    $benign .= $pline($ip(), 'GET /templates/yootheme/cache/ab/theme-9f8e7d6c.css HTTP/1.1', 200);
    $benign .= $pline($ip(), 'GET /%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7 HTTP/1.1', 200);
}

file_put_contents("$pdir/benign.log", $benign);

// A log with a known answer.
$log = $benign;

for ($i = 0; $i < 6; $i++) {
    $log .= $pline($ip(), 'GET /wp-login.php HTTP/1.1', 404);
    $log .= $pline($ip(), 'GET /xmlrpc.php HTTP/1.1', 404);
}

for ($i = 0; $i < 7; $i++) {
    $log .= $pline($ip(), 'GET /.env HTTP/1.1', 404);
}

$log .= $pline($ip(), 'GET /.env?token=SECRET77 HTTP/1.1', 404);                    // query string must never be shown
$log .= $pline($ip(), 'GET /.git/config HTTP/1.1', 200);                              // exists!  (2 times: rare shape)
$log .= $pline($ip(), 'GET /.git/config HTTP/1.1', 200);

for ($i = 0; $i < 6; $i++) {
    $log .= $pline($ip(), 'GET /a/../x HTTP/1.1', 200);                               // blocking rule on successful requests
}

for ($i = 0; $i < 5; $i++) {
    $log .= $pline($ip(), 'GET /images/%E0%B8%82.php HTTP/1.1', 404);                // php in a data dir, Thai name
}

for ($i = 0; $i < 7; $i++) {
    $log .= $pline($ip(), "GET /old-page-$i.html HTTP/1.1", 404);                    // broken links, no rule
}

$log .= $pline($ip(), 'GET /mail/boss@client.example/203.0.113.9/profile HTTP/1.1', 404);
$log .= $pline($ip(), 'GET /backup.zip HTTP/1.1', 404);
$log .= "198.51.100.200 - - [28/Oct/2026:10:00:00 +0700] \"\\x16\\x03\\x01\" 400 150 \"-\" \"-\"\n";   // TLS probe on the HTTP port
$log .= "this is not a log line at all 198.51.100.222\n";
file_put_contents("$pdir/known.log", $log);
file_put_contents("$pdir/known2.log.gz", gzencode($pline($ip(), 'GET /wp-login.php HTTP/1.1', 404)));

$prun = static function (array $args) use ($rscript): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($rscript);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    $o = [];
    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o)];
};

[$code, $t] = $prun(['--scope=paths', "$pdir/benign.log"]);
ipCheck('benign log: exit 0, "No path findings."', $code === 0 && str_contains($t, 'No path findings.'));
ipCheck('benign log: 120 request lines, none HTTP-garbage', str_contains($t, 'Request lines: 120') && str_contains($t, 'Not HTTP-like (TLS probes, garbage): 0'));
ipCheck('benign log: no false-positive / existing-file alarms', str_contains($t, 'PROBABLE FALSE POSITIVES (a blocking rule on requests the server answered 2xx/3xx): none') && preg_match('/FILES THAT PROBABLY EXIST[^\n]*: none/', $t) === 1);

[$code, $t] = $prun(['--scope=paths', "$pdir/known.log", "$pdir/known2.log.gz"]);
ipCheck('known log: exit 0', $code === 0);
ipCheck('scanner_probe row: 2 x 2xx, 22 x 4xx (+1 from the .gz), total 24', (bool) preg_match('/^scanner_probe\s+log\s+2\s+0\s+22\s+0\s+0\s+24\b/m', $t));
ipCheck('php_in_data_dir row: 5 x 404', (bool) preg_match('/^php_in_data_dir\s+log\s+0\s+0\s+5\s+0\s+0\s+5\b/m', $t));
ipCheck('joomla_internal row: the backup.zip 404', (bool) preg_match('/^joomla_internal\s+log\s+0\s+0\s+1\s+0\s+0\s+1\b/m', $t));
ipCheck('path_traversal row: block mode, 6 x 2xx, flagged as would-have-broken-visits', (bool) preg_match('/^path_traversal\s+block\s+6\s+0\s+0\s+0\s+0\s+6\s+<- would have broken real visits/m', $t));
ipCheck('wp-login .gz line counted too (files option accepts .gz)', str_contains($t, 'Files: 2'));
ipCheck('totals: 6 would block, rest logged', str_contains($t, 'would BLOCK a request: 6') && preg_match('/would only be LOGGED:\s+(\d+)/', $t, $mm) === 1 && (int) $mm[1] >= 30);
ipCheck('PROBABLE FALSE POSITIVES names path_traversal with its 6 successes and the shape', str_contains($t, "path_traversal: 6 request(s) of 6 succeeded") && str_contains($t, 'e.g. /a/../x  (6 succeeded of 6)'));
ipCheck('FILES THAT PROBABLY EXIST names scanner_probe (the 2 answered .git/config)', preg_match('/scanner_probe: 2 request\(s\) answered 2xx/', $t) === 1);
ipCheck('…but that rare shape is withheld (fewer than 5)', !str_contains($t, '/.git/config'));
ipCheck('…and the withheld notice says so', str_contains($t, 'seen fewer than 5 times (withheld)'));
ipCheck('shapes: Thai file name is {th}, repeated shape is counted', str_contains($t, '/images/{th}  (x5)'));
ipCheck('shapes: wp-login.php seen 7 times is printed', str_contains($t, '/wp-login.php  (x7)'));
ipCheck('the TLS probe is counted as not HTTP-like', str_contains($t, 'Not HTTP-like (TLS probes, garbage): 1'));
ipCheck('the non-log line is counted as not in combined format', str_contains($t, 'Not in combined format: 1'));
ipCheck('404 list is off by default', !str_contains($t, 'MOST COMMON 404'));

[$code, $t1] = $prun(['--scope=paths', '--min-count=1', '--samples=20', "$pdir/known.log"]);
ipCheck('--min-count=1 shows the rare shape', str_contains($t1, '/.git/config') && !str_contains($t1, 'withheld'));

[$code, $t404] = $prun(['--scope=paths', '--top404=5', "$pdir/known.log"]);
ipCheck('--top404 lists broken-link shapes no rule explains, masked', str_contains($t404, 'MOST COMMON 404 PATHS') && str_contains($t404, '/old-page-{n}.html  (x7)'));
ipCheck('--top404 does not list paths a rule already explains', !preg_match('/MOST COMMON 404.*\/wp-login\.php/s', $t404));
ipCheck('--top404 respects the minimum count', !str_contains($t404, 'profile'));

// Privacy.
[$code, $tAll] = $prun(['--scope=paths', '--samples=50', '--top404=50', "$pdir/known.log", "$pdir/known2.log.gz"]);
$leaks = [];

foreach (['SECRET77', '198.51.100.', '203.0.113.9', 'boss@client.example', 'client.example', '[28/Oct/2026', 'GET /', 'HTTP/1.1', 'not a log line at all', 'x16', 'token='] as $needle) {
    if (str_contains($t, $needle) || str_contains($tAll, $needle) || str_contains($t1, $needle) || str_contains($t404, $needle)) {
        $leaks[] = $needle;
    }
}

ipCheck('output never contains client IPs, query strings, e-mails, raw lines or request lines' . ($leaks ? ' — LEAKED: ' . implode(', ', $leaks) : ''), $leaks === []);
[$code, $tMin1] = $prun(['--scope=paths', '--min-count=1', '--samples=50', '--top404=50', "$pdir/known.log"]);
ipCheck('even with --min-count=1 the e-mail/IP in a path shape is masked', !str_contains($tMin1, 'boss@') && !str_contains($tMin1, '203.0.113.9') && !str_contains($tMin1, 'SECRET77') && str_contains($tMin1, '<email>'));

// Options.
[$code, $tProbeOff] = $prun(['--scope=paths', '--probe=off', "$pdir/known.log"]);
ipCheck('--probe=off: no scanner_probe row', !preg_match('/^scanner_probe/m', $tProbeOff) && preg_match('/^php_in_data_dir/m', $tProbeOff) === 1);
[$code, $tProbeBlock] = $prun(['--scope=paths', '--probe=block', "$pdir/known.log"]);
ipCheck('--probe=block: scanner_probe would block and is called out (2 successes)', (bool) preg_match('/^scanner_probe\s+block\s+2\s/m', $tProbeBlock) && str_contains($tProbeBlock, 'scanner_probe: 2 request(s) of 23 succeeded'));
[$code, $tLog] = $prun(['--scope=paths', '--mode=log', "$pdir/known.log"]);
ipCheck('--mode=log: traversal is log-only and nothing is a false positive', (bool) preg_match('/^path_traversal\s+log\s/m', $tLog) && str_contains($tLog, 'would BLOCK a request: 0') && preg_match('/PROBABLE FALSE POSITIVES[^\n]*: none/', $tLog) === 1);
[$code, $tBlock] = $prun(['--scope=paths', '--mode=block', "$pdir/known.log"]);
ipCheck('--mode=block: every row blocks', !preg_match('/^(?:scanner_probe|php_in_data_dir|joomla_internal)\s+log\s/m', $tBlock));
[$code, $tAllow] = $prun(['--scope=paths', '--allow=/.git/', '--allow=re:^/a/\.\./x$', "$pdir/known.log"]);
ipCheck('--allow (prefix and regex) leaves exempted paths out of the location rules', preg_match('/^scanner_probe\s+log\s+0\s/m', $tAllow) === 1 && preg_match('/FILES THAT PROBABLY EXIST[^\n]*: none/', $tAllow) === 1);
ipCheck('--allow never exempts traversal (integrity rules always apply)', (bool) preg_match('/^path_traversal\s+block\s+6\s/m', $tAllow));
[$code, $tHead] = $prun(['--scope=headers', "$pdir/known.log"]);
ipCheck('--scope=headers: no URL PATHS section', str_contains($tHead, 'HEADERS') && !str_contains($tHead, 'URL PATHS'));
[$code, $tPaths] = $prun(['--scope=paths', "$pdir/known.log"]);
ipCheck('--scope=paths: no HEADERS section', str_contains($tPaths, 'URL PATHS') && !str_contains($tPaths, "HEADERS\n"));
[$code, $tBoth] = $prun(["$pdir/known.log"]);
ipCheck('default scope shows both sections', str_contains($tBoth, "HEADERS\n-------") && str_contains($tBoth, 'URL PATHS'));
[$code, $tBadScope] = $prun(['--scope=nonsense', "$pdir/known.log"]);
ipCheck('invalid --scope: exit 1', $code === 1 && str_contains($tBadScope, '--scope'));
[$code, $tBadProbe] = $prun(['--probe=nonsense', "$pdir/known.log"]);
ipCheck('invalid --probe: exit 1', $code === 1 && str_contains($tBadProbe, '--probe'));
[$code, $tMax] = $prun(['--scope=paths', '--max-lines=10', "$pdir/known.log"]);
ipCheck('--max-lines applies to path mode', str_contains($tMax, 'Lines read: 10'));

// nginx / Apache escaping inside the request field.
$esc = $pline('198.51.100.9', 'GET /a/\\x2e\\x2e/x HTTP/1.1', 200) . $pline('198.51.100.9', 'GET /q\\"uote/x HTTP/1.1', 404);
file_put_contents("$pdir/esc.log", $esc);
[$code, $tEsc] = $prun(['--scope=paths', '--min-count=1', "$pdir/esc.log"]);
ipCheck('\\xHH in the request field is unescaped before judging (/a/\\x2e\\x2e/ → traversal)', (bool) preg_match('/^path_traversal\s+block\s+1\s/m', $tEsc));
ipCheck('escaped quotes do not break parsing', str_contains($tEsc, 'Request lines: 2'));

// Read-only.
ipCheck('logs are unchanged and no new files appeared',
    md5_file("$pdir/known.log") === md5($log) && array_map('basename', glob("$pdir/*") ?: []) === ['benign.log', 'esc.log', 'known.log', 'known2.log.gz']);

array_map('unlink', glob("$pdir/*") ?: []);
@rmdir($pdir);
