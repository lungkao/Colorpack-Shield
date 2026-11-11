<?php
/**
 * The WordPress guard end to end: each case sends one request through Waf\Bootstrap in its own process.
 * Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "\n== Guard: one request at a time through Waf\\Bootstrap ==\n";

$gdir = sys_get_temp_dir() . '/cps-guard-' . bin2hex(random_bytes(4));
mkdir($gdir, 0777, true);

$guard = static function (array $case) use ($gdir): string {
    $case['dir'] ??= $gdir;

    return (string) shell_exec('php ' . escapeshellarg(__DIR__ . '/guard_run.php') . ' ' . escapeshellarg((string) json_encode($case)) . ' 2>&1');
};

/** What the guard printed, minus the reference line it now adds under "Forbidden". */
$refusal = static fn (string $out): string => trim(preg_replace('/\nReference: [0-9A-F]{8}\s*$/', '', trim($out)) ?? '');

$on = ['waf_enabled' => '1'];

ok('firewall off: nothing is inspected', $guard(['settings' => ['waf_enabled' => '0'], 'get' => ['q' => "1' OR '1'='1"]]) === 'PASSED');
ok('nothing stored: the firewall is on by default', $refusal($guard(['settings' => [], 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"], 'server' => ['REQUEST_URI' => '/?id=1']])) === 'Forbidden');
ok('scanner tool in the User-Agent is refused', $refusal($guard(['settings' => $on, 'get' => ['q' => 'hello'], 'server' => ['REQUEST_URI' => '/?q=hello', 'HTTP_USER_AGENT' => 'sqlmap/1.7']])) === 'Forbidden');
ok('scanner tool in the User-Agent: record-only mode lets it through', $guard(['settings' => $on + ['ua_mode' => 'log'], 'get' => ['q' => 'hello'], 'server' => ['REQUEST_URI' => '/?q=hello', 'HTTP_USER_AGENT' => 'sqlmap/1.7']]) === 'PASSED');
ok('scanner tool in the User-Agent: switched off', $guard(['settings' => $on + ['ua_mode' => 'off'], 'get' => ['q' => 'hello'], 'server' => ['REQUEST_URI' => '/?q=hello', 'HTTP_USER_AGENT' => 'sqlmap/1.7']]) === 'PASSED');
ok('ordinary browser User-Agent passes', $guard(['settings' => $on, 'get' => ['q' => 'hello'], 'server' => ['REQUEST_URI' => '/?q=hello', 'HTTP_USER_AGENT' => 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/130 Safari/537.36']]) === 'PASSED');
ok('command injection: only recorded by default', $guard(['settings' => $on, 'get' => ['q' => 'x; ls -la'], 'server' => ['REQUEST_URI' => '/?q=x']]) === 'PASSED');
ok('command injection: refused once the mode is block', $refusal($guard(['settings' => $on + ['shield_inject_mode' => 'block'], 'get' => ['q' => 'x; ls -la'], 'server' => ['REQUEST_URI' => '/?q=x']])) === 'Forbidden');
ok('command injection: switched off, passes even in block mode', $guard(['settings' => $on + ['shield_inject_mode' => 'block', 'shield_cmdi' => '0'], 'get' => ['q' => 'x; ls -la'], 'server' => ['REQUEST_URI' => '/?q=x']]) === 'PASSED');
ok('firewall on: an ordinary request passes', $guard(['settings' => $on, 'get' => ['q' => 'hello world'], 'server' => ['REQUEST_URI' => '/?q=hello+world']]) === 'PASSED');
ok('firewall on: an SQL injection is refused with 403 text', $refusal($guard(['settings' => $on, 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"], 'server' => ['REQUEST_URI' => '/?id=1']])) === 'Forbidden');
ok('"block silently" answers with nothing at all', $refusal($guard(['settings' => $on + ['block_silent' => '1'], 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"]])) === '');
ok('the SQL shield can be switched off on its own', $guard(['settings' => $on + ['shield_sqli' => '0', 'path_scan' => '0', 'header_scan' => '0'], 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"]]) === 'PASSED');
ok('front end not covered: the firewall leaves it alone', $guard(['settings' => $on + ['cover_site' => '0'], 'get' => ['id' => "1' UNION SELECT a FROM b-- -"]]) === 'PASSED');
ok('a path traversal in the URL is refused', $refusal($guard(['settings' => $on, 'server' => ['REQUEST_URI' => '/wp-content/../../etc/passwd']])) === 'Forbidden');
ok('a trusted address skips everything', $guard(['settings' => $on + ['allow_ips' => '198.51.100.20'], 'get' => ['id' => "1' UNION SELECT a FROM b-- -"]]) === 'PASSED');
$content = $gdir . '-content';
mkdir($content, 0777, true);
$attack = ['settings' => $on, 'content' => $content, 'get' => ['id' => "1' UNION SELECT a FROM b-- -"]];
ok('without the emergency file the attack is refused', $refusal($guard($attack)) === 'Forbidden');
touch($content . '/colorpack_shield.disable');
ok('with the emergency file in wp-content the guard steps aside', $guard($attack) === 'PASSED');
unlink($content . '/colorpack_shield.disable');
rmdir($content);

// Rate limit: with no APCu the file counter does the counting (the whole point of the fallback).
$rate = ['settings' => $on + ['rate_enabled' => '1', 'rate_limit' => '3', 'rate_window' => '60', 'path_scan' => '0', 'header_scan' => '0'], 'get' => ['q' => 'x']];
$answers = [];

for ($i = 0; $i < 6; $i++) {
    $answers[] = $refusal($guard($rate));
}

ok('rate limit with files: the first 3 pass', array_slice($answers, 0, 3) === ['PASSED', 'PASSED', 'PASSED']);
ok('rate limit with files: the 4th and later are refused', $answers[3] === 'Too Many Requests' && $answers[5] === 'Too Many Requests');
ok('rate limit: another address is not affected', $refusal($guard(['server' => ['REMOTE_ADDR' => '198.51.100.99']] + $rate)) === 'PASSED');

// Country rule.
ok('a trusted-proxy header is not believed from a direct visitor', $guard(['settings' => $on, 'server' => ['HTTP_CF_IPCOUNTRY' => 'XX']]) === 'PASSED');

// Upload scan.
ok('a PHP file uploaded as a picture is refused', $refusal($guard(['settings' => $on + ['path_scan' => '0'], 'files' => ['f' => ['name' => 'a.php', 'type' => 'image/png', 'tmp_name' => '/tmp/none', 'error' => 0, 'size' => 20]]])) === 'Forbidden');

// Clean up the guard's files.
$rm = static function (string $d) use (&$rm): void {
    foreach (glob($d . '/*') ?: [] as $f) {
        is_dir($f) ? $rm($f) : @unlink($f);
    }

    @rmdir($d);
};
$rm($gdir);

// --- public events and the ban store (what an add-on such as Colorpack Shield Fleet builds on) ------------------

$banDir  = sys_get_temp_dir() . '/cps-ban-' . bin2hex(random_bytes(4));
mkdir($banDir, 0777, true);
$probe   = ['settings' => $on + ['path_probe_mode' => 'ban'], 'dir' => $banDir, 'server' => ['REQUEST_URI' => '/phpinfo.php'], 'dump_actions' => true];
$answer  = $guard($probe);

ok('a banned probe is refused', str_contains($answer, 'Forbidden'));
ok('a ban fires the public colorpack_shield_ban action with the address and the reason', str_contains($answer, 'ACTIONS:') && str_contains($answer, '"colorpack_shield_ban"') && str_contains($answer, '198.51.100.20'));

$clean = ['server' => ['REQUEST_URI' => '/'], 'get' => ['q' => 'hello'], 'dir' => $banDir];
ok('the ban store is not read when neither the ban mode nor an add-on asks for it', $guard(['settings' => $on + ['path_probe_mode' => 'log']] + $clean) === 'PASSED');
ok('an add-on switches the ban store on through the colorpack_shield_use_ban_store filter', $refusal($guard(['settings' => $on + ['path_probe_mode' => 'log'], 'filters' => ['colorpack_shield_use_ban_store' => true]] + $clean)) === 'Forbidden');
ok('in ban mode the stored ban applies to the next request from that address', $refusal($guard(['settings' => $on + ['path_probe_mode' => 'ban']] + $clean)) === 'Forbidden');

echo "\n== Guard: the refusal shows a reference code, never the product, and the log row carries it ==\n";

$answer = $guard(['settings' => $on, 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"], 'server' => ['REQUEST_URI' => '/?id=1']]);
ok('a refusal is "Forbidden" plus a reference line', preg_match('/^Forbidden\nReference: [0-9A-F]{8}\s*$/', trim($answer)) === 1);
ok('…and does not name the product', stripos($answer, 'colorpack') === false && stripos($answer, 'shield') === false);
$html = $guard(['settings' => $on, 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"], 'server' => ['REQUEST_URI' => '/?id=1', 'HTTP_ACCEPT' => 'text/html,application/xhtml+xml']]);
ok('a browser gets a page with the same kind of reference', str_contains($html, '<code>') && preg_match('/<code>[0-9A-F]{8}<\/code>/', $html) === 1);
ok('the silent mode still shows nothing', trim($guard(['settings' => $on + ['block_silent' => '1'], 'get' => ['id' => "1' UNION SELECT user,pass FROM users-- -"], 'server' => ['REQUEST_URI' => '/?id=1']])) === '');
