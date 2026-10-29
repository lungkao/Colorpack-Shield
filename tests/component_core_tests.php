<?php
/**
 * Admin component, pure classes (PLAN-ADMIN-COMPONENT.md §4, §10): LogReader, LogStats,
 * ScoreCalculator, RuleCatalog, SettingsGuard, SetupAdvisor. No Joomla needed.
 * Included by run.php after the plugin tests (reuses ipCheck and the plugin autoloader).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'Colorpack\\Component\\ColorpackShield\\Administrator\\';

    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/../com_colorpack_shield/admin/src/' . str_replace('\\', '/', substr($class, \strlen($prefix))) . '.php';

        if (is_file($file)) {
            require_once $file;
        }
    }
});

use Colorpack\Component\ColorpackShield\Administrator\Core\CsvExporter;
use Colorpack\Component\ColorpackShield\Administrator\Core\DashboardPlanner;
use Colorpack\Component\ColorpackShield\Administrator\Core\IpDiagnosis;
use Colorpack\Component\ColorpackShield\Administrator\Core\IpMasker;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Core\ProbeReport;
use Colorpack\Component\ColorpackShield\Administrator\Core\RuleCatalog;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScanFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScoreCalculator;
use Colorpack\Component\ColorpackShield\Administrator\Core\ServerDetector;
use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsPorter;
use Colorpack\Component\ColorpackShield\Administrator\Core\ServerVerify;
use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsGuard;
use Colorpack\Component\ColorpackShield\Administrator\Core\SetupAdvisor;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;

echo "== Component: LogReader ==\n";

$crTab = static fn (string $t, string $msg): string => "$t\tWARNING\t127.0.0.1\tcolorpack_shield\t$msg";
$crL1  = $crTab('2026-10-28T14:19:42+00:00', 'BLOCK client=site shield=sqli rule=union_select src=GET key=q ip=203.0.113.9 uri=/index.php?q=1 sample=1 union select 2');
$p     = LogReader::parseLine($crL1);

ipCheck('a BLOCK line is parsed into type, time and fields', $p !== null && $p['type'] === 'BLOCK' && $p['time'] === strtotime('2026-10-28T14:19:42+00:00')
    && $p['f']['rule'] === 'union_select' && $p['f']['ip'] === '203.0.113.9' && $p['f']['uri'] === '/index.php?q=1');
ipCheck('sample keeps its spaces (rest of the line)', ($p['f']['sample'] ?? '') === '1 union select 2');
ipCheck('a LOCK line with numbers', (static function () use ($crTab): bool {
    $l = LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', 'LOCK client=administrator ip=8.8.8.8 via=proxy until=1793198082 strikes=1 seconds=900'));

    return $l !== null && $l['type'] === 'LOCK' && $l['f']['seconds'] === '900' && $l['f']['via'] === 'proxy';
})());
ipCheck('upload line: file and detail may contain spaces', (static function () use ($crTab): bool {
    $l = LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', 'BLOCK client=site kind=upload reason=php_code file=my photo.php detail=has <?php tag ip=1.2.3.4 uri=/x'));

    return $l !== null && $l['f']['file'] === 'my photo.php' && $l['f']['detail'] === 'has <?php tag' && $l['f']['ip'] === '1.2.3.4';
})());
ipCheck('a NOTE with free text keeps the fields', (static function () use ($crTab): bool {
    $l = LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', 'NOTE client=site body oversize (>1000 bytes) — partial scan only ip=1.2.3.4 uri=/x'));

    return $l !== null && $l['type'] === 'NOTE' && $l['f']['ip'] === '1.2.3.4' && $l['f']['uri'] === '/x' && isset($l['f']['text']);
})());
ipCheck('header, blank, foreign-category and unknown-type lines are skipped',
    LogReader::parseLine('#Fields: datetime') === null && LogReader::parseLine('') === null
    && LogReader::parseLine("2026-10-28T14:19:42+00:00\tINFO\t-\tother\tBLOCK client=site") === null
    && LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', 'WHATEVER client=site')) === null
    && LogReader::parseLine($crTab('not a date', 'BLOCK client=site')) === null
    && LogReader::parseLine("too\tfew\tfields") === null);
ipCheck('hostile bytes in a value become "?" and values are capped', (static function () use ($crTab): bool {
    $l = LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', "BLOCK client=site rule=x ip=1.2.3.4 uri=/a\x01b sample=" . str_repeat('A', 5000) . "\xff"));

    return $l !== null && $l['f']['uri'] === '/a?b' && mb_strlen($l['f']['sample']) <= LogReader::MAX_VALUE && !preg_match('/[\x00-\x1f]/', $l['f']['sample']);
})());
ipCheck('a script tag is returned as text, never changed (escaping is the view\'s job)', (static function () use ($crTab): bool {
    $l = LogReader::parseLine($crTab('2026-10-28T14:19:42+00:00', 'BLOCK client=site rule=path_xss ip=1.2.3.4 uri=/<script>alert(1)</script> sample=<script>'));

    return $l !== null && str_contains($l['f']['uri'], '<script>') && $l['f']['sample'] === '<script>';
})());

$crDir = sys_get_temp_dir() . '/cps_logreader_' . getmypid();
@mkdir($crDir);
$crFile = $crDir . '/colorpack_shield.php';
$crHead = "#\n#<?php die('Forbidden.'); ?>\n#Fields: datetime\tpriority\tclientip\tcategory\tmessage\n";
$crBody = '';

for ($i = 0; $i < 400; $i++) {
    $crBody .= $crTab(gmdate('Y-m-d\TH:i:sP', 1790000000 + $i), "BLOCK client=site shield=sqli rule=union_select src=GET key=q ip=203.0.113.9 uri=/index.php?n=$i sample=x") . "\n";
}

file_put_contents($crFile, $crHead . $crBody);
$r = (new LogReader($crFile, 10_000_000))->read();
ipCheck('a whole file is read: header skipped, every line parsed', $r['readable'] && !$r['truncated'] && count($r['entries']) === 400);
$r = (new LogReader($crFile, 5000))->read();
ipCheck('a small budget reads the END of the file and says it is truncated', $r['truncated'] && count($r['entries']) > 0 && count($r['entries']) < 400
    && $r['entries'][count($r['entries']) - 1]['f']['uri'] === '/index.php?n=399');
ipCheck('the half line at the cut is dropped, not mis-parsed', (static function () use ($r): bool {
    foreach ($r['entries'] as $e) {
        if (($e['f']['shield'] ?? '') !== 'sqli' || ($e['f']['ip'] ?? '') !== '203.0.113.9') {
            return false;
        }
    }

    return true;
})());
ipCheck('a missing or unreadable file is "not readable", not an error', (new LogReader($crDir . '/none.php'))->read()['readable'] === false && (new LogReader(''))->read()['readable'] === false);
file_put_contents($crFile, $crHead);
ipCheck('an empty log is readable with no entries', (new LogReader($crFile))->read() === ['readable' => true, 'truncated' => false, 'size' => strlen($crHead), 'entries' => []]);
@unlink($crFile);
@rmdir($crDir);

echo "== Component: LogStats ==\n";

$ls = static fn (int $t, string $type, array $f): array => ['time' => $t, 'type' => $type, 'f' => $f];
$now = 1_800_000_000;
$entries = [
    $ls($now - 100, 'BLOCK', ['client' => 'site', 'rule' => 'union_select', 'uri' => '/index.php?id=1']),
    $ls($now - 200, 'BLOCK', ['client' => 'site', 'rule' => 'union_select', 'uri' => '/index.php?id=2']),
    $ls($now - 300, 'DETECT', ['client' => 'administrator', 'rule' => 'scanner_probe', 'uri' => '/wp-login.php']),
    $ls($now - 400, 'BLOCK', ['client' => 'api', 'kind' => 'rate', 'uri' => '/api/index.php/v1/x/123456']),
    $ls($now - 500, 'LOCK', ['client' => 'administrator']),
    $ls($now - 600, 'ALERT', ['client' => 'administrator']),
    $ls($now - 86400 * 2, 'BLOCK', ['client' => 'site', 'rule' => 'old', 'uri' => '/old']),
    $ls($now - 86400 * 9, 'BLOCK', ['client' => 'site', 'rule' => 'ancient', 'uri' => '/ancient']),
    $ls($now + 500, 'BLOCK', ['client' => 'site', 'rule' => 'future', 'uri' => '/future']),
];
$d1 = LogStats::window($entries, $now, 86400);
$d7 = LogStats::window($entries, $now, 86400 * 7);
ipCheck('24 h: exact counts of blocked, detected and lock-outs', $d1['blocked'] === 3 && $d1['detected'] === 1 && $d1['locks'] === 1);
ipCheck('7 d: includes the older entry, still excludes 9 days ago and the future', $d7['blocked'] === 4 && isset($d7['topRules']['old']) && !isset($d7['topRules']['ancient']) && !isset($d7['topRules']['future']));
ipCheck('per application counts', $d1['byClient'] === ['administrator' => ['blocked' => 0, 'detected' => 1], 'api' => ['blocked' => 1, 'detected' => 0], 'site' => ['blocked' => 2, 'detected' => 0]]);
ipCheck('top rules: most frequent first; "kind:" for lines without a rule', array_key_first($d1['topRules']) === 'union_select' && $d1['topRules']['union_select'] === 2 && isset($d1['topRules']['kind:rate']));
ipCheck('paths are shapes: query dropped, long numbers masked', isset($d1['topPaths']['/index.php']) && $d1['topPaths']['/index.php'] === 2 && isset($d1['topPaths']['/api/index.php/v1/x/*']));
ipCheck('ALERT and NOTE lines never count as blocked or detected', $d1['blocked'] + $d1['detected'] === 4);
ipCheck('an unknown application name is "other" (not echoed)', LogStats::window([$ls($now - 5, 'BLOCK', ['client' => '<b>x</b>', 'rule' => 'r'])], $now, 60)['byClient'] === ['other' => ['blocked' => 1, 'detected' => 0]]);
ipCheck('only the top five are kept, ties in name order', (static function () use ($ls, $now): bool {
    $e = [];

    foreach (['g', 'f', 'e', 'd', 'c', 'b', 'a'] as $rule) {
        $e[] = $ls($now - 1, 'BLOCK', ['client' => 'site', 'rule' => $rule]);
    }

    return array_keys(LogStats::window($e, $now, 60)['topRules']) === ['a', 'b', 'c', 'd', 'e'];
})());
ipCheck('path shape: token-like segments masked, length capped', LogStats::pathShape('/a/abcdefghijklmnopqrstuvwxyz0123/b?x=1') === '/a/*/b' && mb_strlen(LogStats::pathShape('/' . str_repeat('a/', 200))) <= 120);
ipCheck('an empty log gives zeros', LogStats::window([], $now, 86400) === ['blocked' => 0, 'detected' => 0, 'locks' => 0, 'byClient' => [], 'topRules' => [], 'topPaths' => []]);

echo "== Component: ScoreCalculator ==\n";

$good = [
    'plugin_installed' => true, 'plugin_enabled' => true, 'kill_switch' => false, 'probe' => 'safe', 'probe_age_days' => 3,
    'trust_cloudflare' => true, 'cf_age_days' => 5, 'allow_ips_count' => 1, 'auto_allow_admin' => true, 'killswitch_token_set' => true,
    'shield_sqli' => true, 'shield_xss' => true, 'shield_lfi' => true, 'shield_rfi' => true, 'header_scan' => true, 'path_scan' => true,
    'scan_body' => true, 'scan_uploads' => true, 'cover_site' => true, 'cover_admin' => true, 'cover_api' => true,
    'rate_enabled' => true, 'apcu' => true, 'server_rules' => 'refused', 'login_lockout' => true, 'mfa_enforce' => 'enforce', 'admin_door' => true, 'file_scan' => ['age' => 1, 'high' => 0],
];
$st = static function (array $f, string $id): string {
    foreach (ScoreCalculator::calculate($f)['items'] as $it) {
        if ($it['id'] === $id) {
            return $it['status'];
        }
    }

    return 'missing';
};
ipCheck('everything good → 100, eleven items, all tested', (static function () use ($good): bool {
    $r = ScoreCalculator::calculate($good);

    return $r['score'] === 100 && $r['tested'] === 11 && $r['total'] === 11;
})());
ipCheck('an empty fact list is scored on what is known (bad), not left blank', ScoreCalculator::calculate([])['score'] === 9 && ScoreCalculator::calculate([])['tested'] === 7);
ipCheck('protection: not installed, disabled or kill-switch → bad',
    $st(['plugin_installed' => false] + $good, 'protection') === 'bad' && $st(['plugin_enabled' => false] + $good, 'protection') === 'bad' && $st(['kill_switch' => true] + $good, 'protection') === 'bad');
ipCheck('real IP: untested and inconclusive are unknown, spoofable is bad, old good result is warn',
    $st(['probe' => null] + $good, 'real_ip') === 'unknown' && $st(['probe' => 'inconclusive'] + $good, 'real_ip') === 'unknown'
    && $st(['probe' => 'spoofable'] + $good, 'real_ip') === 'bad' && $st(['probe_age_days' => 91] + $good, 'real_ip') === 'warn'
    && $st(['probe' => 'no_proxy'] + $good, 'real_ip') === 'ok');
ipCheck('Cloudflare ranges: not scored when not trusted; bundled only → warn; >30 days → warn',
    $st(['trust_cloudflare' => false] + $good, 'cloudflare_ranges') === 'unknown' && $st(['cf_age_days' => null] + $good, 'cloudflare_ranges') === 'warn'
    && $st(['cf_age_days' => 31] + $good, 'cloudflare_ranges') === 'warn' && $st(['cf_age_days' => 30] + $good, 'cloudflare_ranges') === 'ok');
ipCheck('lock-out safety: both → ok, one → warn, none → bad',
    $st($good, 'lockout_safety') === 'ok' && $st(['killswitch_token_set' => false] + $good, 'lockout_safety') === 'warn'
    && $st(['allow_ips_count' => 0, 'auto_allow_admin' => false] + $good, 'lockout_safety') === 'warn'
    && $st(['allow_ips_count' => 0, 'auto_allow_admin' => false, 'killswitch_token_set' => false] + $good, 'lockout_safety') === 'bad');
ipCheck('shields: all on ok, some warn, none bad', $st($good, 'shields') === 'ok' && $st(['shield_xss' => false] + $good, 'shields') === 'warn'
    && $st(array_map(static fn ($v) => is_bool($v) ? false : $v, $good), 'shields') === 'bad');
ipCheck('coverage: three of three ok, partial warn, none bad', $st($good, 'coverage') === 'ok' && $st(['cover_api' => false] + $good, 'coverage') === 'warn'
    && $st(['cover_site' => false, 'cover_admin' => false, 'cover_api' => false] + $good, 'coverage') === 'bad');
ipCheck('rate limit: off → warn, on without APCu → bad, on with APCu → ok', $st(['rate_enabled' => false] + $good, 'rate_limit') === 'warn'
    && $st(['apcu' => false] + $good, 'rate_limit') === 'bad' && $st($good, 'rate_limit') === 'ok');
ipCheck('server rules: refused ok, open bad, anything else unknown', $st($good, 'server_rules') === 'ok' && $st(['server_rules' => 'open'] + $good, 'server_rules') === 'bad'
    && $st(['server_rules' => null] + $good, 'server_rules') === 'unknown' && $st(['server_rules' => 'could_not_test'] + $good, 'server_rules') === 'unknown');
ipCheck('admin login: lockout off bad, lockout without enforced MFA warn, both ok', $st(['login_lockout' => false] + $good, 'admin_login') === 'bad'
    && $st(['mfa_enforce' => 'warn'] + $good, 'admin_login') === 'warn' && $st($good, 'admin_login') === 'ok');
ipCheck('unknown items stay out of the number', (static function () use ($good): bool {
    $r = ScoreCalculator::calculate(['server_rules' => null, 'probe' => null] + $good);

    return $r['score'] === 100 && $r['tested'] === 9;
})());
ipCheck('administrator door: in force → ok, not set → warn (recommended, never bad)', $st($good, 'admin_door') === 'ok' && $st(['admin_door' => false] + $good, 'admin_door') === 'warn' && $st([] , 'admin_door') === 'warn');
ipCheck('file scan: never scanned → not tested; recent and clean → ok; older than 30 days → warn; any serious finding → bad (even if old)', $st(['file_scan' => null] + $good, 'file_scan') === 'unknown' && $st($good, 'file_scan') === 'ok'
    && $st(['file_scan' => ['age' => 30, 'high' => 0]] + $good, 'file_scan') === 'ok' && $st(['file_scan' => ['age' => 31, 'high' => 0]] + $good, 'file_scan') === 'warn' && $st(['file_scan' => ['age' => 0, 'high' => 1]] + $good, 'file_scan') === 'bad' && $st(['file_scan' => ['age' => 90, 'high' => 2]] + $good, 'file_scan') === 'bad');
ipCheck('a warn counts half, a bad nothing', (static function () use ($good): bool {
    // coverage (10) warn → 5 of 100 lost → 95; shields (15) bad → 15 lost → 80
    return ScoreCalculator::calculate(['cover_api' => false] + $good)['score'] === 96
        && ScoreCalculator::calculate(['cover_api' => false, 'shield_sqli' => false, 'shield_xss' => false, 'shield_lfi' => false, 'shield_rfi' => false, 'header_scan' => false, 'path_scan' => false, 'scan_body' => false, 'scan_uploads' => false] + $good)['score'] === 83;
})());

echo "== Component: RuleCatalog ==\n";

$rows = RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, []);
ipCheck('one row per rule in the plugin tables, nothing more', count($rows) === count(PathRules::RULES) + count(HeaderRules::RULES));
$byId = [];

foreach ($rows as $row) {
    $byId[$row['group'] . ':' . $row['id']] = $row;
}

ipCheck('defaults: traversal blocks, scanner probe logs, header shellshock blocks', $byId['path:path_traversal']['effective'] === 'block' && $byId['path:scanner_probe']['effective'] === 'log' && $byId['header:shellshock']['effective'] === 'block');
$rows = RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, ['path_mode' => 'log', 'path_probe_mode' => 'off', 'header_mode' => 'log']);
$byId = [];

foreach ($rows as $row) {
    $byId[$row['group'] . ':' . $row['id']] = $row;
}

ipCheck('log mode lowers every block; probes "off" shows off', $byId['path:path_traversal']['effective'] === 'log' && $byId['path:scanner_probe']['effective'] === 'off' && $byId['header:shellshock']['effective'] === 'log');
$rows = RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, ['path_mode' => 'block', 'path_probe_mode' => 'log', 'header_mode' => 'block', 'junk' => 1]);
$byId = [];

foreach ($rows as $row) {
    $byId[$row['group'] . ':' . $row['id']] = $row;
}

ipCheck('block mode raises logs; probe log stays log only if probes are log… (mode wins in the plugin)', $byId['path:php_in_data_dir']['effective'] === 'block' && $byId['header:sqli_strict']['effective'] === 'block');
ipCheck('an unknown mode value falls back to the default', RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, ['path_mode' => 'wat', 'header_mode' => ['x']])[0]['effective'] === PathRules::RULES[array_key_first(PathRules::RULES)][1]);

// The catalog's reading of the group setting must be the plugin's: compare with the real shields.
$pathProbe = static function (string $mode, string $probe, string $rule): ?string {
    $shield = new \Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield($mode, $probe);
    $paths  = ['path_traversal' => '/a/../../etc/passwd', 'scanner_probe' => '/wp-login.php', 'php_in_data_dir' => '/images/x.php'];
    $data   = new \Colorpack\Plugin\System\ColorpackShield\Waf\RequestData(['PATH' => ['path' => $paths[$rule]]]);

    foreach ($shield->inspectAll($data) as $res) {
        if ($res->rule === $rule) {
            return $res->mode;
        }
    }

    return null;
};
$catalogMatchesPlugin = true;

foreach ([['recommended', 'log'], ['recommended', 'block'], ['log', 'log'], ['block', 'log'], ['block', 'off'], ['log', 'block']] as [$pm, $pr]) {
    $cat = [];

    foreach (RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, ['path_mode' => $pm, 'path_probe_mode' => $pr]) as $row) {
        if ($row['group'] === 'path') {
            $cat[$row['id']] = $row['effective'];
        }
    }

    foreach (['path_traversal', 'scanner_probe', 'php_in_data_dir'] as $rule) {
        $real = $pathProbe($pm, $pr, $rule) ?? 'off';

        if (($cat[$rule] ?? '?') !== $real) {
            $catalogMatchesPlugin = false;
            echo "  catalog says {$cat[$rule]}, plugin says $real for $rule ($pm/$pr)\n";
        }
    }
}

ipCheck('the effective mode equals what the real PathShield does, for every group setting', $catalogMatchesPlugin);

echo "== Component: SettingsGuard ==\n";

$codes = static fn (array $list): array => array_map(static fn (array $m): string => $m['key'] . ':' . $m['code'], $list);
$r = SettingsGuard::check(['allow_ips' => "203.0.113.5\n198.51.100.0/24 # office\n"]);
ipCheck('valid addresses and ranges pass untouched', $r['errors'] === [] && $r['params']['allow_ips'] === "203.0.113.5\n198.51.100.0/24 # office\n");
$r = SettingsGuard::check(['allow_ips' => "203.0.113.5\nnot-an-ip\n10.0.0.0/4\n0.0.0.0/0\n1.2.3.4/33\n::/0"]);
ipCheck('junk, too-wide and impossible ranges are errors, one per line', $codes($r['errors']) === array_fill(0, 5, 'allow_ips:invalid_line'));
$cgList = static fn (int $n): string => implode("\n", array_map(static fn (int $i): string => '203.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1), range(0, $n - 1)));
ipCheck('50 entries are fine, 51 are one error "too_many"', SettingsGuard::check(['allow_ips' => $cgList(50)])['errors'] === []
    && $codes(SettingsGuard::check(['allow_ips' => $cgList(51)])['errors']) === ['allow_ips:too_many']);
ipCheck('the same refusals apply to every address list', count(SettingsGuard::check(['trusted_proxies' => '0.0.0.0/0', 'geo_allow_ips' => 'x', 'geo_deny_ips' => '1.1.1.1'])['errors']) === 2);
ipCheck('a hostile line is shown cut and printable', (static function (): bool {
    $r = SettingsGuard::check(['allow_ips' => "<script>alert(1)</script>" . str_repeat('A', 500) . "\x01"]);

    return mb_strlen($r['errors'][0]['detail']) <= 60 && !preg_match('/[\x00-\x1f]/', $r['errors'][0]['detail']);
})());
ipCheck('kill-switch token: empty is fine (off), short is refused, long passes',
    SettingsGuard::check(['killswitch_token' => ''])['errors'] === [] && $codes(SettingsGuard::check(['killswitch_token' => 'short'])['errors']) === ['killswitch_token:token_short']
    && SettingsGuard::check(['killswitch_token' => str_repeat('k', 12)])['errors'] === []);
ipCheck('alert e-mail must look like an address when given', $codes(SettingsGuard::check(['alert_email' => 'nope'])['errors']) === ['alert_email:email_invalid']
    && SettingsGuard::check(['alert_email' => 'a@example.com'])['errors'] === [] && SettingsGuard::check(['alert_email' => ''])['errors'] === []);
$r = SettingsGuard::check(['login_max_failures' => '0', 'login_failure_window' => '999999', 'mfa_grace_days' => '7', 'login_rate_per_minute' => '0']);
ipCheck('numbers outside the plugin\'s range are clamped with a warning, in range untouched',
    $r['params']['login_max_failures'] === 1 && $r['params']['login_failure_window'] === 86400 && $r['params']['mfa_grace_days'] === '7' && $r['params']['login_rate_per_minute'] === '0'
    && $codes($r['warnings']) === ['login_max_failures:adjusted', 'login_failure_window:adjusted'] && $r['errors'] === []);
ipCheck('a non-number is an error', $codes(SettingsGuard::check(['login_max_failures' => 'many'])['errors']) === ['login_max_failures:not_number']);
ipCheck('MFA enforce without an alert e-mail warns', $codes(SettingsGuard::check(['mfa_enforce' => 'enforce', 'alert_email' => ''])['warnings']) === ['alert_email:enforce_without_email']
    && SettingsGuard::check(['mfa_enforce' => 'enforce', 'alert_email' => 'a@example.com'])['warnings'] === []);
ipCheck('unknown keys survive a save', SettingsGuard::check(['future_setting' => 'keep', 'other' => ['a' => 1]])['params'] === ['future_setting' => 'keep', 'other' => ['a' => 1]]);
ipCheck('a setting that would block the saver is refused (callback sees the cleaned params)', (static function (): bool {
    $seen = null;
    $r    = SettingsGuard::check(['path_extra_deny' => '/administrator', 'login_max_failures' => '500'], static function (array $p) use (&$seen): bool {
        $seen = $p;

        return $p['path_extra_deny'] === '/administrator';
    });

    return $r['errors'] === [['key' => 'path_extra_deny', 'code' => 'self_lockout', 'detail' => '']] && $seen['login_max_failures'] === 100;
})());
ipCheck('the lock-out check is skipped when other errors exist, and when it says no', (static function (): bool {
    $called = false;
    SettingsGuard::check(['alert_email' => 'bad'], static function () use (&$called): bool {
        $called = true;

        return true;
    });

    return !$called && SettingsGuard::check(['x' => 1], static fn (): bool => false)['errors'] === [];
})());

$gdK = 'abcdef0123456789ABCDEF-_xyz';
$gdE = static fn (array $p, ?array $v = null): array => array_map(static fn ($m) => $m['key'] . ':' . $m['code'], SettingsGuard::check($p, null, $v)['errors']);
$gdW = static fn (array $p, ?array $v = null): array => array_map(static fn ($m) => $m['key'] . ':' . $m['code'], SettingsGuard::check($p, null, $v)['warnings']);
ipCheck('gate: a good key passes; a malformed or short one is refused even with the gate off', $gdE(['gate_enabled' => '1', 'gate_key' => $gdK]) === [] && $gdE(['gate_key' => 'short']) === ['gate_key:gate_key_invalid'] && $gdE(['gate_key' => 'has space in it 123456']) === ['gate_key:gate_key_invalid'] && $gdE(['gate_key' => '']) === []);
ipCheck('gate: switched on with no usable key is refused (the plugin would ignore it)', $gdE(['gate_enabled' => '1', 'gate_key' => '']) === ['gate_key:gate_key_invalid'] && $gdE(['gate_enabled' => '1']) === ['gate_key:gate_key_invalid']);
ipCheck('address list: on with nothing usable is refused; invalid lines are named', $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '']) === ['admin_ip_list:admin_list_empty'] && $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => "junk\n0.0.0.0/0"]) === ['admin_ip_list:invalid_line', 'admin_ip_list:invalid_line', 'admin_ip_list:admin_list_empty']);
ipCheck('address list: the saving administrator must be on it (when their address is one visitor)', $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], ['ip' => '198.51.100.9', 'enforceable' => true]) === ['admin_ip_list:admin_not_in_list']
    && $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], ['ip' => '203.0.113.5', 'enforceable' => true]) === [] && $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '198.51.100.0/24'], ['ip' => '198.51.100.9', 'enforceable' => true]) === []);
ipCheck('address list: with the access key also on, the saver is not required to be listed (they get the cookie)', $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5', 'gate_enabled' => '1', 'gate_key' => $gdK], ['ip' => '198.51.100.9', 'enforceable' => true]) === []);
ipCheck('address list: an address that is not one visitor only warns (the plugin will just observe)', $gdE(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], ['ip' => '10.0.0.1', 'enforceable' => false]) === [] && $gdW(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], ['ip' => '10.0.0.1', 'enforceable' => false]) === ['admin_ip_list:admin_ip_unenforceable']);
ipCheck('address list off: nothing is asked of the saver', $gdE(['admin_ip_enforce' => '0', 'admin_ip_list' => '203.0.113.5'], ['ip' => '198.51.100.9', 'enforceable' => true]) === [] && $gdE(['admin_ip_list' => '203.0.113.5'], null) === []);
ipCheck('cookie hours are clamped with a warning', SettingsGuard::check(['gate_cookie_hours' => '9999'])['params']['gate_cookie_hours'] === 168);

echo "== Component: SetupAdvisor ==\n";

ipCheck('step 1: a safe probe behind Cloudflare turns Cloudflare trust on if it was off', SetupAdvisor::realIp('safe', true, ['trust_cloudflare' => '0']) === ['patch' => ['trust_cloudflare' => 1], 'advice' => 'safe']);
ipCheck('step 1: nothing to change when already on, or not behind Cloudflare', SetupAdvisor::realIp('safe', true, ['trust_cloudflare' => '1'])['patch'] === [] && SetupAdvisor::realIp('no_proxy', false, ['trust_cloudflare' => '0'])['patch'] === []);
ipCheck('step 1: spoofable or untested changes nothing', SetupAdvisor::realIp('spoofable', true, [])['patch'] === [] && SetupAdvisor::realIp('spoofable', true, [])['advice'] === 'spoofable'
    && SetupAdvisor::realIp(null, true, [])['advice'] === 'untested' && SetupAdvisor::realIp('inconclusive', true, [])['advice'] === 'untested');
ipCheck('step 2: turns on auto-trust and lock-out, fills the alert e-mail only when empty and valid',
    SetupAdvisor::safety(['auto_allow_admin' => '0', 'login_lockout' => '0', 'alert_email' => ''], 'me@example.com')['patch'] === ['auto_allow_admin' => 1, 'alert_email' => 'me@example.com', 'login_lockout' => 1]
    && SetupAdvisor::safety(['alert_email' => 'keep@example.com'], 'me@example.com')['patch'] === []
    && SetupAdvisor::safety(['alert_email' => ''], 'junk')['patch'] === []);
ipCheck('step 2: defaults count as "on"', SetupAdvisor::safety([], '')['advice'] === 'already');
ipCheck('step 3: lowers block to log, never raises', SetupAdvisor::logMode(['header_mode' => 'block', 'path_mode' => 'block', 'path_probe_mode' => 'block'])['patch'] === ['header_mode' => 'log', 'path_mode' => 'log', 'path_probe_mode' => 'log']
    && SetupAdvisor::logMode(['header_mode' => 'default', 'path_mode' => 'recommended', 'path_probe_mode' => 'off'])['patch'] === []
    && SetupAdvisor::logMode([])['advice'] === 'already');

echo "== Component: LogFilter, IpMasker, CsvExporter, rule hits ==\n";

$lfNow = 1_800_000_000;
$lfE   = static fn (int $ago, string $type, array $f): array => ['time' => $lfNow - $ago, 'type' => $type, 'f' => $f];
$lfAll = [
    $lfE(100, 'BLOCK', ['client' => 'site', 'rule' => 'union_select', 'uri' => '/index.php?q=1', 'ip' => '203.0.113.9', 'sample' => 'UNION SELECT']),
    $lfE(300, 'DETECT', ['client' => 'administrator', 'rule' => 'scanner_probe', 'uri' => '/wp-login.php', 'ip' => '198.51.100.7']),
    $lfE(200, 'BLOCK', ['client' => 'api', 'kind' => 'rate', 'reason' => 'too_many', 'uri' => '/api/x', 'ip' => '203.0.113.9']),
    $lfE(400, 'LOCK', ['client' => 'administrator', 'ip' => '198.51.100.7']),
    $lfE(86400 * 10, 'BLOCK', ['client' => 'site', 'rule' => 'old', 'uri' => '/old']),
    $lfE(-60, 'BLOCK', ['client' => 'site', 'rule' => 'future']),
];
$lfC = static fn (array $raw = []): array => LogFilter::criteria($raw);

ipCheck('criteria: junk is dropped, days clamped, defaults sane', $lfC() === ['types' => [], 'client' => '', 'rule' => '', 'text' => '', 'days' => 7]
    && $lfC(['types' => ['BLOCK', 'EVIL', 5, 'BLOCK'], 'client' => 'x', 'rule' => '<b>', 'days' => '9999'])['types'] === ['BLOCK']
    && $lfC(['client' => 'api'])['client'] === 'api' && $lfC(['rule' => 'kind:rate'])['rule'] === 'kind:rate'
    && $lfC(['days' => '-5'])['days'] === 1 && $lfC(['days' => '9999'])['days'] === 90 && $lfC(['rule' => ['a']])['rule'] === ''
    && $lfC(['text' => "a\x01b" . str_repeat('x', 300)])['text'] === 'a b' . str_repeat('x', 97));
ipCheck('criteria: an unknown area or a rule with markup is dropped', $lfC(['client' => 'x'])['client'] === '' && $lfC(['rule' => '<b>x</b>'])['rule'] === '' && $lfC(['rule' => 'a b'])['rule'] === '' && $lfC(['rule' => str_repeat('a', 61)])['rule'] === '');
ipCheck('default window is 7 days, newest first, future and old entries excluded', array_map(static fn ($e) => $e['time'] - $lfNow, LogFilter::apply($lfAll, $lfC(), $lfNow)) === [-100, -200, -300, -400]);
ipCheck('a longer window brings the old entry back', count(LogFilter::apply($lfAll, $lfC(['days' => 30]), $lfNow)) === 5);
ipCheck('filter by type, area, rule and "kind:" pseudo rule', count(LogFilter::apply($lfAll, $lfC(['types' => ['BLOCK']]), $lfNow)) === 2
    && count(LogFilter::apply($lfAll, $lfC(['client' => 'administrator']), $lfNow)) === 2
    && count(LogFilter::apply($lfAll, $lfC(['rule' => 'union_select']), $lfNow)) === 1
    && count(LogFilter::apply($lfAll, $lfC(['rule' => 'kind:rate']), $lfNow)) === 1);
ipCheck('free text is a plain case-insensitive substring over path, sample, ip, rule, reason', count(LogFilter::apply($lfAll, $lfC(['text' => 'WP-LOGIN']), $lfNow)) === 1
    && count(LogFilter::apply($lfAll, $lfC(['text' => 'union select']), $lfNow)) === 1 && count(LogFilter::apply($lfAll, $lfC(['text' => '203.0.113.9']), $lfNow)) === 2
    && count(LogFilter::apply($lfAll, $lfC(['text' => 'too_many']), $lfNow)) === 1 && LogFilter::apply($lfAll, $lfC(['text' => '.*']), $lfNow) === []);
$lfPg = LogFilter::page(range(1, 125), 3, 50);
ipCheck('paging: slice, totals, clamped page numbers and per-page cap', $lfPg['rows'] === range(101, 125) && $lfPg['total'] === 125 && $lfPg['pages'] === 3
    && LogFilter::page(range(1, 5), 99, 50)['page'] === 1 && LogFilter::page(range(1, 125), -4, 50)['page'] === 1 && LogFilter::page([], 1, 50)['pages'] === 1
    && count(LogFilter::page(range(1, 999), 1, 9999)['rows']) === LogFilter::PER_PAGE_MAX && count(LogFilter::page(range(1, 9), 1, 0)['rows']) === 1);

$sfFind = [
    ['path' => 'administrator/cache/a/.htaccess', 'sev' => 'medium'],
    ['path' => 'administrator/cache/b/.htaccess', 'sev' => 'medium'],
    ['path' => 'images/shell.php', 'sev' => 'high'],
    ['path' => 'tmp/note.php', 'sev' => 'low'],
];
ipCheck('ScanFilter::criteria: only a known severity is kept, free text is trimmed and capped', ScanFilter::criteria(['sev' => 'high'])['sev'] === 'high' && ScanFilter::criteria(['sev' => 'bogus'])['sev'] === ''
    && ScanFilter::criteria(['sev' => 'bogus', 'q' => ''])['sev'] === '' && ScanFilter::criteria(['q' => '  .htaccess  '])['text'] === '.htaccess'
    && ScanFilter::criteria(['q' => str_repeat('x', 200)])['text'] === str_repeat('x', 100) && ScanFilter::criteria([])['sev'] === '' && ScanFilter::criteria([])['text'] === '');
ipCheck('ScanFilter::apply: severity and a case-insensitive path substring, combined', count(ScanFilter::apply($sfFind, ['sev' => 'medium', 'text' => ''])) === 2
    && count(ScanFilter::apply($sfFind, ['sev' => '', 'text' => '.HTACCESS'])) === 2 && count(ScanFilter::apply($sfFind, ['sev' => 'medium', 'text' => 'shell'])) === 0
    && ScanFilter::apply($sfFind, ['sev' => '', 'text' => ''])  === $sfFind);
ipCheck('ScanFilter::counts: per-severity counts over the whole list, unaffected by any filter', ScanFilter::counts($sfFind) === ['high' => 1, 'medium' => 2, 'low' => 1] && ScanFilter::counts([]) === ['high' => 0, 'medium' => 0, 'low' => 0]);

ipCheck('IpMasker: IPv4, IPv6, junk', IpMasker::mask('203.0.113.9') === '203.0.113.x' && IpMasker::mask('2001:db8:abcd:1::5') === '2001:db8:abcd::x'
    && IpMasker::mask('::1') === '0:0:0::x');
ipCheck('IpMasker: never returns the last part', !str_contains(IpMasker::mask('203.0.113.9'), '9') && !str_contains(IpMasker::mask('2001:db8:abcd:1::5'), ':5') && IpMasker::mask('not an ip') === '-' && IpMasker::mask('') === '-' && IpMasker::mask('1.2.3') === '-');

$csv = CsvExporter::build(LogFilter::apply($lfAll, $lfC(), $lfNow), false);
$csvM = CsvExporter::build(LogFilter::apply($lfAll, $lfC(), $lfNow), true);
ipCheck('CSV: header, one CRLF row per entry, quoted cells', str_starts_with($csv, '"time_utc","type","area","rule","reason","ip","uri","sample"' . "\r\n") && substr_count($csv, "\r\n") === 5 && str_contains($csv, '"203.0.113.9","/index.php?q=1","UNION SELECT"'));
ipCheck('CSV masked: address shortened, query and sample removed', str_contains($csvM, '"203.0.113.x","/index.php",""') && !str_contains($csvM, 'q=1') && !str_contains($csvM, 'UNION') && !str_contains($csvM, '203.0.113.9'));
ipCheck('CSV: formula cells get an apostrophe, quotes are doubled, newlines flattened', CsvExporter::cell('=1+1') === '"\'=1+1"' && CsvExporter::cell('+1') === '"\'+1"' && CsvExporter::cell('-2') === '"\'-2"' && CsvExporter::cell('@SUM(A1)') === '"\'@SUM(A1)"'
    && CsvExporter::cell("\t=x") === "\"'\t=x\"" && CsvExporter::cell('a"b') === '"a""b"' && CsvExporter::cell("a\r\nb") === '"a  b"' && CsvExporter::cell('') === '""' && CsvExporter::cell('safe=1') === '"safe=1"');
ipCheck('CSV: a hostile entry stays one row', (static function (): bool {
    $e   = [['time' => 1_800_000_000, 'type' => 'BLOCK', 'f' => ['client' => 'site', 'rule' => '=cmd|calc', 'uri' => "/a\r\n=HYPERLINK(\"x\")", 'ip' => '1.2.3.4', 'sample' => '@x']]];
    $out = CsvExporter::build($e, false);

    return substr_count($out, "\r\n") === 2 && str_contains($out, "'=cmd|calc") && str_contains($out, "'@x");
})());
ipCheck('CSV: row cap', substr_count(CsvExporter::build(array_fill(0, CsvExporter::MAX_ROWS + 50, ['time' => 1, 'type' => 'BLOCK', 'f' => []]), true), "\r\n") === CsvExporter::MAX_ROWS + 1);

ipCheck('ruleCounts: other event types are never counted, even with a rule field', LogStats::ruleCounts([$lfE(10, 'NOTE', ['rule' => 'x']), $lfE(10, 'LOCK', ['rule' => 'y']), $lfE(10, 'BLOCK', ['rule' => 'z'])], $lfNow, 86400) === ['z' => 1]);
ipCheck('ruleCounts: counts BLOCK and DETECT with a rule, in the window only', LogStats::ruleCounts($lfAll, $lfNow, 86400) === ['union_select' => 1, 'scanner_probe' => 1]
    && LogStats::ruleCounts($lfAll, $lfNow, 86400 * 30) === ['union_select' => 1, 'scanner_probe' => 1, 'old' => 1]);
$rh = RuleCatalog::withHits(RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, []), ['scanner_probe' => 25, 'path_traversal' => 500, 'admin_tool_probe' => 19]);
$rhBy = [];

foreach ($rh as $row) {
    $rhBy[$row['group'] . ':' . $row['id']] = $row;
}

ipCheck('withHits: hits added; "review" only for a log-only rule at 20+ hits, never for a blocking rule', $rhBy['path:scanner_probe']['hits'] === 25 && $rhBy['path:scanner_probe']['review'] === true
    && $rhBy['path:path_traversal']['hits'] === 500 && $rhBy['path:path_traversal']['review'] === false && $rhBy['path:admin_tool_probe']['review'] === false && $rhBy['path:path_ctrl']['hits'] === 0);

echo "== Component: IpDiagnosis ==\n";

$dgIn = static fn (array $o = []): array => $o + ['remote' => '203.0.113.9', 'resolved' => '203.0.113.9', 'via' => 'direct', 'headerIgnored' => false, 'hasForwarding' => false, 'hasCfHeader' => false, 'trustCloudflare' => true];
$dg   = static fn (array $o = []): string => IpDiagnosis::explain($dgIn($o))['code'] . '/' . IpDiagnosis::explain($dgIn($o))['level'];
ipCheck('direct public visitor → direct/ok', $dg() === 'direct/ok');
ipCheck('through Cloudflare → ok; Cloudflare edge without a visitor header → bad', $dg(['via' => 'cloudflare', 'resolved' => '198.51.100.4']) === 'cloudflare_ok/ok' && $dg(['via' => 'cloudflare-noheader']) === 'cloudflare_noheader/bad');
ipCheck('through a listed proxy → ok', $dg(['via' => 'proxy', 'remote' => '127.0.0.1', 'resolved' => '198.51.100.4']) === 'proxy_ok/ok');
ipCheck('a Cloudflare header that is not used (trust off, or not from Cloudflare) → warn', $dg(['hasCfHeader' => true, 'trustCloudflare' => false]) === 'cloudflare_not_trusted/warn' && $dg(['hasCfHeader' => true, 'headerIgnored' => true]) === 'cloudflare_not_trusted/warn'
    && $dg(['hasCfHeader' => true]) === 'direct/ok');
ipCheck('a private peer that forwards but is not listed → unlisted_proxy/bad (the dangerous case)', $dg(['remote' => '127.0.0.1', 'resolved' => '127.0.0.1', 'hasForwarding' => true]) === 'unlisted_proxy/bad'
    && $dg(['remote' => '10.1.2.3', 'resolved' => '10.1.2.3', 'hasForwarding' => true]) === 'unlisted_proxy/bad' && $dg(['remote' => '192.168.1.5', 'resolved' => '192.168.1.5', 'hasForwarding' => true]) === 'unlisted_proxy/bad');
ipCheck('a private peer without forwarding headers → warn, not bad', $dg(['remote' => '127.0.0.1', 'resolved' => '127.0.0.1']) === 'private_direct/warn');
ipCheck('a public peer that sends forwarding headers is still direct (headers not believed)', $dg(['hasForwarding' => true]) === 'direct/ok');
ipCheck('nothing readable → unknown/info', $dg(['remote' => '']) === 'unknown/info' && $dg(['resolved' => '']) === 'unknown/info');

echo "== Component: ServerVerify and ServerDetector ==\n";

ipCheck('verify: any served file → open, even when another is refused', ServerVerify::summarize(['/a' => 403, '/b' => 200, '/c' => 404]) === 'open' && ServerVerify::summarize(['/a' => 204]) === 'open');
ipCheck('verify: refused and none served → refused', ServerVerify::summarize(['/a' => 403, '/b' => 404]) === 'refused' && ServerVerify::summarize(['/a' => 401]) === 'refused' && ServerVerify::summarize(['/a' => 410]) === 'refused');
ipCheck('verify: all absent, errors or no answer → unknown, never "refused"', ServerVerify::summarize(['/a' => 404, '/b' => 404]) === 'unknown' && ServerVerify::summarize(['/a' => 0]) === 'unknown'
    && ServerVerify::summarize(['/a' => 500, '/b' => 301]) === 'unknown' && ServerVerify::summarize([]) === 'unknown');
ipCheck('verify: the list is fixed and holds plain paths on the site only', count(ServerVerify::PATHS) === 4 && count(array_filter(ServerVerify::PATHS, static fn ($p) => preg_match('~^/[A-Za-z0-9_./-]+$~', $p) === 1)) === 4);
ipCheck('server guess', ServerDetector::guess('Apache/2.4.58 (Unix)') === 'apache' && ServerDetector::guess('nginx/1.27') === 'nginx' && ServerDetector::guess('LiteSpeed') === 'litespeed'
    && ServerDetector::guess('OpenLiteSpeed') === 'litespeed' && ServerDetector::guess('') === 'unknown' && ServerDetector::guess('Microsoft-IIS/10') === 'unknown');
$pa = static fn (string $t): array => ServerDetector::parseAllow($t, [\Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy::class, 'validate']);
ipCheck('allow lines: valid ones kept once, comments and blanks dropped', $pa("/a/b.php\n# note\n\n/a/b.php  # again\n/folder/") === ['ok' => ['/a/b.php', '/folder/'], 'bad' => []]);
ipCheck('allow lines: invalid ones are returned apart, cut and printable, never accepted', (static function () use ($pa): bool {
    $r = $pa("re:^/x\n/ok.php\n/a/../b\nno-slash\n/with space\n/semi;colon\n\"/x\"\n/" . str_repeat('a', 200) . "\x01\n");

    return $r['ok'] === ['/ok.php'] && count($r['bad']) === 7 && max(array_map('strlen', $r['bad'])) <= 60 && !preg_match('/[\x00-\x1f]/', implode('', $r['bad']));
})());
ipCheck('allow lines: capped', count($pa(implode("\n", array_map(static fn ($i) => "/f$i.php", range(1, 500))))['ok']) <= 200);
ipCheck('a hostile allow line can never reach the generated text', (static function () use ($pa): bool {
    $r   = $pa("/x\nRewriteRule . - [R]\n/ok.php\n/a b\n");
    $txt = \Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy::render($r['ok'], true) . \Colorpack\Plugin\System\ColorpackShield\Export\NginxPathPolicy::render($r['ok'], true);

    return !str_contains($txt, '[R]') && str_contains($txt, 'ok\.php') && str_contains($txt, '/x');
})());

echo "== Component: SettingsPorter ==\n";

$spKnown = ['allow_ips', 'alert_email', 'killswitch_token', 'login_max_failures', 'mfa_groups', 'path_mode', 'gate_enabled', 'gate_key', 'admin_ip_enforce', 'admin_ip_list', 'gate_cookie_hours'];
$spParams = ['allow_ips' => "203.0.113.5\n198.51.100.0/24", 'alert_email' => 'a@example.com', 'killswitch_token' => 'S3CRET-SECRET-VALUE', 'login_max_failures' => '7', 'mfa_groups' => ['8'], 'path_mode' => 'log', 'secret_extra' => 'x', 'gate_enabled' => '1', 'gate_key' => 'GATEKEYGATEKEYGATEKEY', 'admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5', 'gate_cookie_hours' => '24'];
$spOut = SettingsPorter::export($spParams, $spKnown, '0.2.0', 1_800_000_000);
$spDoc = json_decode($spOut, true);
ipCheck('export: our format, version, time, plugin version, and a note of what is not included', $spDoc['format'] === 'colorpack-shield-settings' && $spDoc['version'] === 1 && $spDoc['exported_utc'] === '2027-01-15T08:00:00Z' && $spDoc['plugin_version'] === '0.2.0' && $spDoc['not_included'] === ['killswitch_token', 'gate_key', 'gate_enabled', 'admin_ip_enforce', 'admin_ip_list']);
ipCheck('export: no secret, nothing outside the known settings', !str_contains($spOut, 'S3CRET') && !str_contains($spOut, 'GATEKEY') && !isset($spDoc['params']['killswitch_token']) && !isset($spDoc['params']['gate_key']) && !isset($spDoc['params']['admin_ip_list']) && !isset($spDoc['params']['gate_enabled']) && !isset($spDoc['params']['admin_ip_enforce']) && !isset($spDoc['params']['secret_extra']) && ($spDoc['params']['gate_cookie_hours'] ?? '') === '24' && count($spDoc['params']) === 6);
$spRt = SettingsPorter::import($spOut, $spKnown);
ipCheck('round trip: what was exported comes back equal (as strings), nothing ignored', $spRt['error'] === '' && $spRt['params'] === ['alert_email' => 'a@example.com', 'allow_ips' => "203.0.113.5\n198.51.100.0/24", 'gate_cookie_hours' => '24', 'login_max_failures' => '7', 'mfa_groups' => ['8'], 'path_mode' => 'log'] && $spRt['ignored'] === []);
$spMk = static fn (array $over = []): string => json_encode($over + ['format' => 'colorpack-shield-settings', 'version' => 1, 'params' => ['path_mode' => 'block']]);
$spErr = static fn (string $j): string => SettingsPorter::import($j, $spKnown)['error'];
ipCheck('import: too big, not JSON, wrong format, wrong or missing version, no params', $spErr(str_repeat('a', SettingsPorter::MAX_BYTES + 1)) === 'too_big' && $spErr('{nope') === 'not_json' && $spErr('"text"') === 'not_json'
    && $spErr($spMk(['format' => 'other'])) === 'wrong_format' && $spErr($spMk(['version' => 2])) === 'newer_version' && $spErr($spMk(['version' => '1'])) === 'newer_version' && $spErr($spMk(['version' => 0])) === 'newer_version'
    && $spErr(json_encode(['format' => 'colorpack-shield-settings', 'version' => 1])) === 'no_params' && $spErr($spMk(['params' => ['a', 'b']])) === 'no_params' && $spErr($spMk(['params' => 'x'])) === 'no_params');
ipCheck('import: an empty params object is fine (nothing to change)', SettingsPorter::import($spMk(['params' => new stdClass()]), $spKnown) === ['params' => [], 'error' => '', 'ignored' => []] || SettingsPorter::import($spMk(['params' => []]), $spKnown)['error'] === '');
$spI = SettingsPorter::import($spMk(['params' => ['path_mode' => 'block', 'killswitch_token' => 'evil-token-123456', 'unknown_thing' => 'x', "b\x01ad" => '1']]), $spKnown);
ipCheck('import: the secret and unknown keys are ignored (and listed, printable), known ones kept', $spI['params'] === ['path_mode' => 'block'] && count($spI['ignored']) === 3 && !preg_match('/[\x00-\x1f]/', implode('', $spI['ignored'])));
ipCheck('import: odd value shapes refuse the whole file', $spErr($spMk(['params' => ['path_mode' => ['a' => 1]]])) === 'bad_value' && $spErr($spMk(['params' => ['path_mode' => 1.5]])) === 'bad_value' && $spErr($spMk(['params' => ['path_mode' => null]])) === 'bad_value'
    && $spErr($spMk(['params' => ['path_mode' => "a\x00b"]])) === 'bad_value' && $spErr($spMk(['params' => ['allow_ips' => str_repeat('x', SettingsPorter::MAX_VALUE + 1)]])) === 'bad_value'
    && $spErr($spMk(['params' => ['mfa_groups' => [[1]]]])) === 'bad_value' && $spErr($spMk(['params' => ['mfa_groups' => array_fill(0, 51, '1')]])) === 'bad_value');
ipCheck('import: booleans become "1"/"0", ints stay ints, newlines and tabs in text are allowed', SettingsPorter::import($spMk(['params' => ['login_max_failures' => 9, 'path_mode' => true, 'allow_ips' => "a\nb\tc"]]), $spKnown)['params'] === ['login_max_failures' => 9, 'path_mode' => '1', 'allow_ips' => "a\nb\tc"]);
ipCheck('import: deeply nested input is refused, not crashed', $spErr('{"format":"colorpack-shield-settings","version":1,"params":' . str_repeat('[', 40) . str_repeat(']', 40) . '}') !== '');

echo "== Component: ProbeReport ==\n";

$prOk = ['probe' => 1, 'remote_addr' => '127.0.0.1', 'xff' => '104.16.0.1, 203.0.113.9', 'x_real_ip' => '192.0.2.78', 'cf_connecting_ip' => '192.0.2.77', 'trusted_proxies' => ['127.0.0.1'], 'actual' => ['ip' => '203.0.113.9', 'via' => 'proxy', 'header_ignored' => false]];
$prP  = static fn (array $o = [], array $drop = []): ?array => ProbeReport::parse(json_encode(array_diff_key($o + $prOk, array_flip($drop))));
ipCheck('a real report is kept with exactly the expected fields', $prP() === $prOk);
ipCheck('extra fields are dropped, never kept', $prP(['evil' => '<script>', 'actual' => ['ip' => '1.2.3.4', 'via' => 'direct', 'header_ignored' => false, 'x' => 1]]) == ['actual' => ['ip' => '1.2.3.4', 'via' => 'direct', 'header_ignored' => false]] + $prOk && !array_key_exists('evil', $prP(['evil' => 'x'])));
ipCheck('not JSON, not our report, empty, too big → null', ProbeReport::parse('') === null && ProbeReport::parse('{nope') === null && ProbeReport::parse('"x"') === null && $prP(['probe' => 2]) === null && $prP([], ['probe']) === null
    && ProbeReport::parse(json_encode($prOk + ['pad' => str_repeat('a', 5000)])) === null);
ipCheck('the connecting address must be a real address', $prP(['remote_addr' => 'not-an-ip']) === null && $prP(['remote_addr' => '']) === null && $prP(['remote_addr' => ['1.1.1.1']]) === null && $prP([], ['remote_addr']) === null && $prP(['remote_addr' => '2001:db8::1']) !== null);
ipCheck('header copies: strings only, short, no control bytes', $prP(['xff' => ['a']]) === null && $prP(['xff' => str_repeat('a', 301)]) === null && $prP(['x_real_ip' => "a\nb"]) === null && $prP(['cf_connecting_ip' => 5]) === null && $prP(['xff' => '']) !== null);
ipCheck('trusted proxies: a short list of short strings', $prP(['trusted_proxies' => 'x']) === null && $prP(['trusted_proxies' => [1]]) === null && $prP(['trusted_proxies' => array_fill(0, 51, '1.1.1.1')]) === null && $prP(['trusted_proxies' => ['a' => '1.1.1.1']]) === null && $prP(['trusted_proxies' => []]) !== null);
ipCheck('"actual": a known via, an address or empty, a real boolean', $prP(['actual' => ['ip' => '1.1.1.1', 'via' => 'weird', 'header_ignored' => false]]) === null && $prP(['actual' => ['ip' => 'x', 'via' => 'direct', 'header_ignored' => false]]) === null
    && $prP(['actual' => ['ip' => '1.1.1.1', 'via' => 'direct', 'header_ignored' => 'no']]) === null && $prP(['actual' => 'x']) === null && $prP([], ['actual']) === null && $prP(['actual' => ['ip' => '', 'via' => 'cloudflare-noheader', 'header_ignored' => true]]) !== null);
ipCheck('deeply nested input is refused', ProbeReport::parse('{"probe":1,"remote_addr":"1.1.1.1","a":' . str_repeat('[', 30) . str_repeat(']', 30) . '}') === null);
// The verdict the screen would show for a real-looking report is the plugin's own.
ipCheck('a report fed to the plugin\'s evaluator gives its verdicts (forged value passed through → spoofable)', \Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe::evaluate(['probe' => 1, 'remote_addr' => '127.0.0.1', 'xff' => '104.16.0.1', 'x_real_ip' => '192.0.2.78', 'cf_connecting_ip' => '192.0.2.77'] , \Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges::bundled())['verdict'] === 'spoofable');

echo "== Component: language files and strings ==\n";

$cgLangDir = __DIR__ . '/../com_colorpack_shield/admin/language';
$cgKeys    = static function (string $file): array {
    $keys = [];

    foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^([A-Z0-9_]+)="/', $line, $m)) {
            $keys[$m[1]] = true;
        }
    }

    return $keys;
};

foreach (['com_colorpack_shield.ini', 'com_colorpack_shield.sys.ini'] as $cgFile) {
    $en = $cgKeys("$cgLangDir/en-GB/$cgFile");
    $th = $cgKeys("$cgLangDir/th-TH/$cgFile");
    ipCheck("$cgFile: en-GB and th-TH have exactly the same keys", array_keys($en) === array_keys($th) && $en !== []);
    ipCheck("$cgFile: both parse as ini", @parse_ini_file("$cgLangDir/en-GB/$cgFile", false, INI_SCANNER_RAW) !== false && @parse_ini_file("$cgLangDir/th-TH/$cgFile", false, INI_SCANNER_RAW) !== false);
}

$cgEn   = $cgKeys("$cgLangDir/en-GB/com_colorpack_shield.ini") + $cgKeys("$cgLangDir/en-GB/com_colorpack_shield.sys.ini");
$cgUsed = [];

foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../com_colorpack_shield/admin', FilesystemIterator::SKIP_DOTS)) as $cgF) {
    if ($cgF->getExtension() === 'php') {
        preg_match_all("/'(COM_COLORPACK_SHIELD_[A-Z0-9_]+)'/", (string) file_get_contents($cgF->getPathname()), $mm);

        foreach ($mm[1] as $k) {
            $cgUsed[$k] = $cgF->getFilename();
        }
    }
}

$cgMissing = [];

foreach ($cgUsed as $k => $where) {
    // Prefix strings such as 'COM_COLORPACK_SHIELD_ITEM_' are completed at run time and checked below.
    if (!str_ends_with($k, '_') && $k !== 'COM_COLORPACK_SHIELD_STEP' && !isset($cgEn[$k])) {
        $cgMissing[] = "$k ($where)";
    }
}

if ($cgMissing !== []) {
    echo '  missing: ' . implode(', ', $cgMissing) . "\n";
}

ipCheck('every literal string key used in the component exists', $cgMissing === []);

$cgDynamic = [];

foreach (['OK', 'WARN', 'BAD', 'UNKNOWN'] as $x) {
    $cgDynamic[] = "STATUS_$x";
}

foreach (['SETTINGS', 'SETUP'] as $x) {
    $cgDynamic[] = "ACTION_$x";
}

foreach (['SITE', 'ADMINISTRATOR', 'API', 'OTHER'] as $x) {
    $cgDynamic[] = "CLIENT_$x";
}

foreach (['SAFE', 'NO_PROXY', 'SPOOFABLE', 'UNTESTED'] as $x) {
    $cgDynamic[] = "PROBE_$x";
}

foreach (['INVALID_LINE', 'TOO_MANY', 'TOKEN_SHORT', 'EMAIL_INVALID', 'NOT_NUMBER', 'SELF_LOCKOUT', 'PLUGIN_MISSING', 'SAVE_FAILED', 'GATE_KEY_INVALID', 'ADMIN_LIST_EMPTY', 'ADMIN_NOT_IN_LIST'] as $x) {
    $cgDynamic[] = "ERR_$x";
}

foreach (['ADJUSTED', 'ENFORCE_WITHOUT_EMAIL', 'ADMIN_IP_UNENFORCEABLE'] as $x) {
    $cgDynamic[] = "WARN_$x";
}

foreach ([1, 2, 3, 4, 5] as $x) {
    $cgDynamic[] = "STEP{$x}_TITLE";
    $cgDynamic[] = "STEP{$x}_TEXT";
}

// Every (item, status) pair the calculator can produce needs a hint text.
mt_srand(7);
$cgPairs = [];

for ($i = 0; $i < 4000; $i++) {
    $f = [
        'plugin_installed' => (bool) mt_rand(0, 1), 'plugin_enabled' => (bool) mt_rand(0, 1), 'kill_switch' => (bool) mt_rand(0, 1),
        'probe' => [null, 'safe', 'no_proxy', 'spoofable', 'inconclusive'][mt_rand(0, 4)], 'probe_age_days' => [null, 3, 200][mt_rand(0, 2)],
        'trust_cloudflare' => (bool) mt_rand(0, 1), 'cf_age_days' => [null, 3, 90][mt_rand(0, 2)],
        'allow_ips_count' => mt_rand(0, 1), 'auto_allow_admin' => (bool) mt_rand(0, 1), 'killswitch_token_set' => (bool) mt_rand(0, 1),
        'rate_enabled' => (bool) mt_rand(0, 1), 'apcu' => (bool) mt_rand(0, 1), 'server_rules' => [null, 'refused', 'open', 'x'][mt_rand(0, 3)],
        'login_lockout' => (bool) mt_rand(0, 1), 'mfa_enforce' => ['off', 'warn', 'enforce'][mt_rand(0, 2)], 'admin_door' => (bool) mt_rand(0, 1), 'file_scan' => [null, ['age' => 2, 'high' => 0], ['age' => 60, 'high' => 0], ['age' => 2, 'high' => 3]][mt_rand(0, 3)],
    ];

    foreach (['cover_site', 'cover_admin', 'cover_api', 'shield_sqli', 'shield_xss', 'shield_lfi', 'shield_rfi', 'header_scan', 'path_scan', 'scan_body', 'scan_uploads'] as $k) {
        $f[$k] = (bool) mt_rand(0, 3);
    }

    foreach (ScoreCalculator::calculate($f)['items'] as $it) {
        $cgPairs[strtoupper($it['id']) . '|' . strtoupper($it['status'])] = true;
    }
}

foreach (array_keys($cgPairs) as $pair) {
    [$id, $status] = explode('|', $pair);
    $cgDynamic[]   = "ITEM_{$id}_{$status}";
    $cgDynamic[]   = "ITEM_$id";
}

$cgMissing = [];

foreach (array_unique($cgDynamic) as $k) {
    if (!isset($cgEn['COM_COLORPACK_SHIELD_' . $k])) {
        $cgMissing[] = $k;
    }
}

if ($cgMissing !== []) {
    echo '  missing: ' . implode(', ', $cgMissing) . "\n";
}

ipCheck('every run-time string key (status, item hint, error, step, probe …) exists', $cgMissing === []);
ipCheck('the random walk reached every item with all the states it can have', count($cgPairs) >= 30);

$cgMore = [];

foreach (['NOT_IN_SCAN', 'BAD_PATH', 'OUTSIDE', 'NOT_A_FILE', 'PROTECTED', 'ENTRY_POINT', 'TOO_BIG', 'UNREADABLE', 'BINARY', 'CHANGED', 'SYNTAX', 'NO_BACKUP', 'WRITE_FAILED', 'PERMISSION', 'CONFIRM', 'FAILED', 'EXISTS', 'NOT_FOUND'] as $x) {
    $cgMore[] = 'CODE_ERR_' . $x;
}

foreach (['SAVED', 'SAVING', 'LOADING', 'NO_MARKS', 'LINE', 'SYNTAX', 'BINARY', 'READONLY', 'NETWORK', 'RESTORED', 'RESTORE_OVERWRITE', 'DROP_CONFIRM', 'COPY_DROP_CONFIRM'] as $x) {
    $cgMore[] = 'CODE_' . $x;
}

foreach (['EDIT', 'DELETE', 'BEFORE_RESTORE'] as $x) {
    $cgMore[] = 'COPY_' . $x;
}

foreach (array_merge(array_keys(\Colorpack\Plugin\System\ColorpackShield\Scanner\SignatureRules::PHP), array_keys(\Colorpack\Plugin\System\ColorpackShield\Scanner\SignatureRules::HTACCESS_DATA), array_keys(\Colorpack\Plugin\System\ColorpackShield\Scanner\LocationRules::SEVERITY), ['php_in_image']) as $x) {
    $cgMore[] = 'SCANRULE_' . strtoupper($x);
}

foreach (['HIGH', 'MEDIUM', 'LOW'] as $x) {
    $cgMore[] = 'SEV_' . $x;
}

foreach (['APPLIED', 'APPLIED_REMOVED', 'REVERTED', 'CANNOT_VERIFY', 'NO_FILE', 'NOT_WRITABLE', 'WRITE_FAILED', 'BAD_ENTRY', 'APPLIED_INACTIVE'] as $x) {
    $cgMore[] = 'HTA_' . $x;
}

foreach (['SAFE', 'NO_PROXY', 'SPOOFABLE', 'INCONCLUSIVE'] as $x) {
    $cgMore[] = 'PROBE_DONE_' . $x;
}

foreach (['EMPTY', 'TOO_BIG', 'NOT_JSON', 'WRONG_FORMAT', 'NEWER_VERSION', 'NO_PARAMS', 'BAD_VALUE'] as $x) {
    $cgMore[] = 'IMPORT_ERR_' . $x;
}

foreach (['APACHE', 'LITESPEED', 'NGINX', 'UNKNOWN'] as $x) {
    $cgMore[] = 'SRV_GUESS_' . $x;
}

foreach (['APACHE', 'NGINX'] as $x) {
    $cgMore[] = 'SRV_HOW_' . $x;
}

foreach (['REFUSED', 'OPEN', 'UNKNOWN'] as $x) {
    $cgMore[] = 'VERIFY_' . $x;
    $cgMore[] = 'VERIFY_V_' . $x;
}

foreach (['DIRECT', 'CLOUDFLARE_OK', 'CLOUDFLARE_NOHEADER', 'CLOUDFLARE_NOT_TRUSTED', 'PROXY_OK', 'UNLISTED_PROXY', 'PRIVATE_DIRECT', 'UNKNOWN'] as $x) {
    $cgMore[] = 'NET_DIAG_' . $x;
}

foreach (['SAFE', 'NO_PROXY', 'SPOOFABLE', 'INCONCLUSIVE'] as $x) {
    $cgMore[] = 'PROBE_V_' . $x;
}

foreach (['BUNDLED', 'REFRESHED'] as $x) {
    $cgMore[] = 'NET_CF_SRC_' . $x;
}

foreach (array_merge(array_keys(PathRules::RULES), array_keys(HeaderRules::RULES)) as $x) {
    $cgMore[] = 'RULE_' . strtoupper($x);
}

foreach (LogFilter::TYPES as $x) {
    $cgMore[] = 'TYPE_' . $x;
}

foreach (['BLOCK', 'LOG', 'OFF'] as $x) {
    $cgMore[] = 'MODE_' . $x;
}

$cgMissing = [];

foreach ($cgMore as $k) {
    if (!isset($cgEn['COM_COLORPACK_SHIELD_' . $k])) {
        $cgMissing[] = $k;
    }
}

if ($cgMissing !== []) {
    echo '  missing: ' . implode(', ', $cgMissing) . "\n";
}

ipCheck('every rule has an explanation; every event type and mode has a label', $cgMissing === []);

$cgMore2 = ['STEP4_SAFE', 'STEP4_ON', 'STEP4_ON_NOTE', 'STEP4_ALREADY', 'STEP4_NEWKEY', 'STEP5_LATER'];
$cgMiss  = array_filter($cgMore2, static fn ($k) => !isset($cgEn['COM_COLORPACK_SHIELD_' . $k]));
ipCheck('the access-key step has all its texts', $cgMiss === []);

echo "== Component: SetupAdvisor, access key step ==\n";

$akK = 'abcdefghjk23';
ipCheck('step 4: nothing set → turn on with the new key', SetupAdvisor::accessKey([], 'NEWKEYNEWKEY') === ['patch' => ['gate_enabled' => 1, 'gate_key' => 'NEWKEYNEWKEY'], 'advice' => 'changed']);
ipCheck('step 4: a valid key stored but switched off is reused (the person may hold the link)', SetupAdvisor::accessKey(['gate_enabled' => '0', 'gate_key' => $akK], 'NEWKEYNEWKEY')['patch'] === ['gate_enabled' => 1, 'gate_key' => $akK]);
ipCheck('step 4: a bad stored key is replaced', SetupAdvisor::accessKey(['gate_key' => 'x'], 'NEWKEYNEWKEY')['patch']['gate_key'] === 'NEWKEYNEWKEY');
ipCheck('step 4: already in force (key, or address list) → nothing to change', SetupAdvisor::accessKey(['gate_enabled' => '1', 'gate_key' => $akK], 'N')['advice'] === 'already' && SetupAdvisor::accessKey(['gate_enabled' => '1', 'gate_key' => $akK], 'N')['patch'] === []
    && SetupAdvisor::accessKey(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], 'N')['patch'] === []);
ipCheck('step 4: a switch on with no usable key counts as NOT in force, so the step offers a real key', SetupAdvisor::accessKey(['gate_enabled' => '1', 'gate_key' => ''], 'NEWKEYNEWKEY')['patch']['gate_key'] === 'NEWKEYNEWKEY');

echo "== Component: HtaccessManager ==\n";

use Colorpack\Component\ColorpackShield\Administrator\Core\HtaccessManager;
use Colorpack\Plugin\System\ColorpackShield\Export\HtaccessBlock;

$hmBlock = HtaccessBlock::render();
$hmOrig  = "## Joomla\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* index.php [L]\n</IfModule>\n";
$hmRoot  = sys_get_temp_dir() . '/cps-hm-' . bin2hex(random_bytes(4));
mkdir($hmRoot);
$hmReset = static function (?string $content) use ($hmRoot): void {
    @unlink($hmRoot . '/.htaccess');
    @unlink($hmRoot . '/' . HtaccessManager::BACKUP);

    if ($content !== null) {
        file_put_contents($hmRoot . '/.htaccess', $content);
        chmod($hmRoot . '/.htaccess', 0644);
    }
};
$hmSite = static function (array $answers) use ($hmRoot): callable {
    // $answers: ['plain' => [before...], 'blocked' => [after...]] by whether our block is in the file now.
    return static function (string $p) use ($answers, $hmRoot): int {
        $has = HtaccessBlock::has((string) @file_get_contents($hmRoot . '/.htaccess'));

        return $answers[$has ? 'blocked' : 'plain'][$p];
    };
};

$hmReset(null);
ipCheck('no .htaccess: nothing is created', (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => ['/' => 200, '/administrator/' => 200]])))->apply($hmBlock)['result'] === 'no_file' && !is_file($hmRoot . '/.htaccess'));

$hmReset($hmOrig);
$m = new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => ['/' => 200, '/administrator/' => 200]]));
$r = $m->apply($hmBlock);
ipCheck('site answers the same afterwards → applied; the block is at the top, the rest untouched; a backup of the exact original exists', $r['result'] === 'applied' && HtaccessBlock::has(file_get_contents($hmRoot . '/.htaccess'))
    && str_ends_with(file_get_contents($hmRoot . '/.htaccess'), $hmOrig) && file_get_contents($hmRoot . '/' . HtaccessManager::BACKUP) === $hmOrig);
ipCheck('state reports the block and the backup; permissions are kept; no temp file is left', $m->state() === ['exists' => true, 'writable' => true, 'hasBlock' => true, 'backup' => true] && (fileperms($hmRoot . '/.htaccess') & 0777) === 0644 && !is_file($hmRoot . '/.htaccess.cps-tmp'));
$r = $m->remove();
ipCheck('remove puts the original back byte for byte', $r['result'] === 'applied' && file_get_contents($hmRoot . '/.htaccess') === $hmOrig && !$m->state()['hasBlock']);
$hmReset($hmOrig);
chmod($hmRoot . '/.htaccess', 0600);
(new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => ['/' => 200, '/administrator/' => 200]])))->apply($hmBlock);
clearstatcache();
ipCheck('the file keeps its permissions (0600 stays 0600)', (fileperms($hmRoot . '/.htaccess') & 0777) === 0600);
chmod($hmRoot . '/.htaccess', 0644);
ipCheck('applying when the block is already there (same text) changes nothing and asks nothing', (static function () use ($hmReset, $hmOrig, $hmBlock, $hmRoot): bool {
    $hmReset(HtaccessBlock::insert($hmOrig, $hmBlock));
    $asked = 0;
    $r     = (new HtaccessManager($hmRoot, static function () use (&$asked): int { $asked++; return 200; }))->apply($hmBlock);

    return $r['result'] === 'applied' && $asked === 0;
})());

foreach ([
    'a 500 after the change' => ['/' => 500, '/administrator/' => 500],
    'a front page that no longer answers' => ['/' => 0, '/administrator/' => 200],
    'a front page that became 403' => ['/' => 403, '/administrator/' => 200],
    'only the administrator changed' => ['/' => 200, '/administrator/' => 403],
] as $why => $after) {
    $hmReset($hmOrig);
    $r = (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => $after])))->apply($hmBlock);
    ipCheck("$why → the original is put back at once and the answer says so", $r['result'] === 'reverted' && file_get_contents($hmRoot . '/.htaccess') === $hmOrig && $r['after'] === $after);
}

$hmReset($hmOrig);
$r = (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 0, '/administrator/' => 0], 'blocked' => ['/' => 0, '/administrator/' => 0]])))->apply($hmBlock);
ipCheck('the site cannot be asked at all → refuses to touch the file', $r['result'] === 'cannot_verify' && file_get_contents($hmRoot . '/.htaccess') === $hmOrig && !is_file($hmRoot . '/' . HtaccessManager::BACKUP));
$hmReset($hmOrig);
$r = (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 404], 'blocked' => ['/' => 200, '/administrator/' => 404]])))->apply($hmBlock);
ipCheck('the administrator answering 404 both times (access key on) is not a change', $r['result'] === 'applied');
$hmReset($hmOrig);
chmod($hmRoot . '/.htaccess', 0444);
$r = (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => ['/' => 200, '/administrator/' => 200]])))->apply($hmBlock);
ipCheck('a read-only file is left alone (the text can still be copied by hand)', $r['result'] === 'not_writable' && file_get_contents($hmRoot . '/.htaccess') === $hmOrig);
chmod($hmRoot . '/.htaccess', 0644);
$hmReset($hmOrig);
$r = (new HtaccessManager($hmRoot, $hmSite(['plain' => ['/' => 200, '/administrator/' => 200], 'blocked' => ['/' => 500, '/administrator/' => 500]])))->remove();
ipCheck('removing when there is no block is a no-op that asks nothing', $r['result'] === 'applied' && $r['before'] === []);
exec('rm -rf ' . escapeshellarg($hmRoot));

echo "== Component: language choice ==\n";

use Colorpack\Component\ColorpackShield\Administrator\Core\IniStrings;
use Colorpack\Component\ColorpackShield\Administrator\Core\LocalePick;

ipCheck('the choice is only ever one of our two languages; anything else means "follow the administrator"', LocalePick::fromCookie('th-TH') === 'th-TH' && LocalePick::fromCookie('en-GB') === 'en-GB' && LocalePick::fromCookie('fr-FR') === '' && LocalePick::fromCookie('') === ''
    && LocalePick::fromCookie(['th-TH']) === '' && LocalePick::fromCookie(null) === '' && LocalePick::fromCookie("th-TH\r\nSet-Cookie: x") === '' && LocalePick::fromCookie('th-th') === '');
ipCheck('the language shown: the choice wins; else the administrator\'s language when it is ours; else English', LocalePick::effective('th-TH', 'en-GB') === 'th-TH' && LocalePick::effective('en-GB', 'th-TH') === 'en-GB' && LocalePick::effective('', 'th-TH') === 'th-TH' && LocalePick::effective('', 'en-GB') === 'en-GB'
    && LocalePick::effective('', 'de-DE') === 'en-GB' && LocalePick::effective('', '') === 'en-GB');
ipCheck('ini reader: quoted text, escaped quotes, comments and junk lines', IniStrings::parse("; a comment\nCOM_A=\"Hello\"\nCOM_B=\"say \\\"hi\\\"\"\nnot a key line\nlower=\"x\"\n") === ['COM_A' => 'Hello', 'COM_B' => 'say "hi"']);
ipCheck('ini reader: empty, too big and broken files give nothing or what can be read', IniStrings::parse('') === [] && IniStrings::parse(str_repeat('A', IniStrings::MAX_BYTES + 1)) === [] && IniStrings::parse("COM_OK=\"fine\"\nCOM_BAD=\"unterminated\nCOM_NEXT=\"after\"\n") !== []);
$lgDir = __DIR__ . '/../com_colorpack_shield/admin/language';

foreach (['en-GB', 'th-TH'] as $lgTag) {
    $text  = (string) file_get_contents("$lgDir/$lgTag/com_colorpack_shield.ini");
    $mine  = IniStrings::parse($text);
    preg_match_all('/^([A-Z][A-Z0-9_]*)="/m', $text, $mm);
    ipCheck("$lgTag: the reader finds every key of the real language file, none lost to a quote", count($mine) === count(array_unique($mm[1])) && count($mine) > 400);
}

$lgTh = IniStrings::parse((string) file_get_contents("$lgDir/th-TH/com_colorpack_shield.ini"));
$lgEn = IniStrings::parse((string) file_get_contents("$lgDir/en-GB/com_colorpack_shield.ini"));
ipCheck('the Thai file has the same keys as the English one, with real Thai text (and the English one has none)', array_keys($lgTh) === array_keys($lgEn) && preg_match('/[\x{0E00}-\x{0E7F}]/u', $lgTh['COM_COLORPACK_SHIELD_NAV_SETTINGS']) === 1 && preg_match('/[\x{0E00}-\x{0E7F}]/u', implode('', $lgEn)) === 0);
ipCheck('placeholders match between the two files (a %d or %s lost in translation would break a sentence)', (static function () use ($lgTh, $lgEn): bool {
    foreach ($lgEn as $k => $en) {
        preg_match_all('/%(?:\d\$)?[sd]/', $en, $a);
        preg_match_all('/%(?:\d\$)?[sd]/', $lgTh[$k] ?? '', $b);

        if (count($a[0]) !== count($b[0])) {
            echo "  placeholder mismatch in $k\n";

            return false;
        }
    }

    return true;
})());

echo "== Component: Dashboard report numbers and planner ==\n";

$dyNow = 1_800_000_000;
$dyE   = static fn (int $ago, string $type, array $f = []): array => ['time' => $dyNow - $ago, 'type' => $type, 'f' => $f];
$dy    = LogStats::daily([
    $dyE(100, 'BLOCK', ['ip' => '1.1.1.1']), $dyE(200, 'BLOCK', ['ip' => '1.1.1.1']), $dyE(300, 'DETECT'), $dyE(400, 'LOCK'), $dyE(500, 'ALERT'),
    $dyE(86400 + 100, 'BLOCK', ['ip' => '2.2.2.2']), $dyE(86400 * 20, 'BLOCK'), $dyE(-50, 'BLOCK'),
], $dyNow, 7);
ipCheck('daily: exactly the asked number of days, oldest first, ending today; empty days are zeros', count($dy) === 7 && $dy[6]['date'] === gmdate('Y-m-d', $dyNow) && $dy[0]['date'] === gmdate('Y-m-d', $dyNow - 6 * 86400) && $dy[3] === ['date' => $dy[3]['date'], 'blocked' => 0, 'detected' => 0, 'locks' => 0]);
ipCheck('daily: counts per type on the right day; older, future and other types are not counted', ($dy[6]['blocked'] + $dy[5]['blocked']) === 3 && $dy[6]['detected'] + $dy[5]['detected'] === 1 && $dy[6]['locks'] + $dy[5]['locks'] === 1 && array_sum(array_column($dy, 'blocked')) === 3);
ipCheck('daily: the number of days is clamped to 1–90', count(LogStats::daily([], $dyNow, 0)) === 1 && count(LogStats::daily([], $dyNow, 9999)) === 90);
ipCheck('unique blocked addresses: each address once, only BLOCK, only in the window, only with an address', LogStats::uniqueBlockedIps([$dyE(10, 'BLOCK', ['ip' => '1.1.1.1']), $dyE(20, 'BLOCK', ['ip' => '1.1.1.1']), $dyE(30, 'BLOCK', ['ip' => '2.2.2.2']), $dyE(40, 'DETECT', ['ip' => '3.3.3.3']), $dyE(50, 'BLOCK', ['ip' => '']), $dyE(60, 'BLOCK'), $dyE(86400 * 9, 'BLOCK', ['ip' => '4.4.4.4'])], $dyNow, 86400) === 2);
ipCheck('change against the period before: whole percent, up and down; nothing to compare with → null', LogStats::change(118, 100) === 18 && LogStats::change(94, 100) === -6 && LogStats::change(5, 0) === null && LogStats::change(0, 50) === -100);
$ae = LogStats::adminEvents([$dyE(10, 'BLOCK', ['client' => 'administrator']), $dyE(20, 'BLOCK', ['client' => 'site']), $dyE(30, 'LOCK', ['client' => 'administrator']), $dyE(40, 'ALERT', ['kind' => 'newip']), $dyE(50, 'ALERT', ['kind' => 'newadmin']), $dyE(60, 'ALERT', ['kind' => 'lockout']),
    $dyE(70, 'OBSERVE', ['client' => 'administrator']), $dyE(80, 'OBSERVE', ['client' => 'site']), $dyE(86400 * 9, 'LOCK')], $dyNow, 86400);
ipCheck('administrator events: only admin blocks, locks, observe, and the two alert kinds that matter; window respected', $ae === ['blockedAdmin' => 1, 'locks' => 1, 'newIp' => 1, 'newAdmin' => 1, 'observed' => 1]);

$dpItems = static fn (array $st): array => ['score' => 90, 'items' => array_map(static fn (string $id, string $s): array => ['id' => $id, 'weight' => 10, 'status' => $s], array_keys($st), array_values($st))];
$pl = DashboardPlanner::plan(['score' => 82, 'items' => $dpItems(['protection' => 'ok', 'real_ip' => 'unknown', 'admin_door' => 'warn', 'rate_limit' => 'warn', 'admin_login' => 'warn', 'file_scan' => 'ok', 'lockout_safety' => 'warn'])['items']]);
ipCheck('planner: the todo list holds only things not ok, warnings before "not tested", most protective first, at most three', array_column($pl['todo'], 'id') === ['admin_login', 'lockout_safety', 'admin_door'] && $pl['counts'] === ['ok' => 2, 'warn' => 4, 'bad' => 0, 'unknown' => 1]);
ipCheck('planner: each todo says which screen fixes it', array_column($pl['todo'], 'screen') === ['settings', 'setup', 'setup']);
ipCheck('planner: a critical item comes before any warning, whatever its usual order', array_column(DashboardPlanner::plan(['score' => 70, 'items' => $dpItems(['protection' => 'ok', 'rate_limit' => 'bad', 'admin_login' => 'warn'])['items']])['todo'], 'id') === ['rate_limit', 'admin_login']);
ipCheck('planner band: good needs a high number and nothing critical; one critical item caps it; low numbers are risk; no score is "none"', DashboardPlanner::plan(['score' => 90, 'items' => $dpItems(['protection' => 'ok'])['items']])['band'] === 'good'
    && DashboardPlanner::plan(['score' => 90, 'items' => $dpItems(['protection' => 'bad'])['items']])['band'] === 'watch' && DashboardPlanner::plan(['score' => 70, 'items' => $dpItems(['protection' => 'bad'])['items']])['band'] === 'risk'
    && DashboardPlanner::plan(['score' => 40, 'items' => $dpItems(['protection' => 'ok'])['items']])['band'] === 'risk' && DashboardPlanner::plan(['score' => 60, 'items' => $dpItems(['protection' => 'warn'])['items']])['band'] === 'watch'
    && DashboardPlanner::plan(['score' => null, 'items' => []])['band'] === 'none');
ipCheck('planner: an all-good list has an empty todo; an unknown item id still gets a screen', DashboardPlanner::plan(['score' => 100, 'items' => $dpItems(['protection' => 'ok'])['items']])['todo'] === [] && DashboardPlanner::plan(['score' => 50, 'items' => [['id' => 'mystery', 'weight' => 1, 'status' => 'warn']]])['todo'][0]['screen'] === 'settings');
ipCheck('planner: a Settings-screen item that maps to one field carries it, so the screen can jump straight there; others carry null', array_column(DashboardPlanner::plan(['score' => 50, 'items' => $dpItems(['admin_login' => 'warn', 'shields' => 'bad', 'coverage' => 'warn', 'rate_limit' => 'warn', 'protection' => 'bad'])['items']], 5)['todo'], 'field', 'id')
    === ['protection' => null, 'shields' => 'shield_sqli', 'admin_login' => 'login_lockout', 'coverage' => 'cover_site', 'rate_limit' => 'rate_enabled']);
ipCheck('planner: rate limit "bad" means the switch is on but the server has no APCu - nothing in Settings fixes that, so there is no screen or field to send a person to (every other status still goes to Settings)', DashboardPlanner::action('rate_limit', 'bad') === ['screen' => null, 'field' => null]
    && DashboardPlanner::action('rate_limit', 'warn') === ['screen' => 'settings', 'field' => 'rate_enabled'] && DashboardPlanner::action('rate_limit', 'ok') === ['screen' => 'settings', 'field' => 'rate_enabled']);
ipCheck('planner: the maximum is respected (at least one)', count(DashboardPlanner::plan(['score' => 50, 'items' => $dpItems(['a' => 'warn', 'b' => 'warn', 'c' => 'warn', 'd' => 'warn'])['items']], 2)['todo']) === 2 && count(DashboardPlanner::plan(['score' => 50, 'items' => $dpItems(['a' => 'warn', 'b' => 'warn'])['items']], 0)['todo']) === 1);
