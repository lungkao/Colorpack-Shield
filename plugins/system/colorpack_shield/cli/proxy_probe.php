<?php
/**
 * Proxy spoof self-test (AUDIT.md N1) — run on the server, from the command line.
 *
 * Sends the plugin a request with forged X-Forwarded-For / CF-Connecting-IP /
 * X-Real-IP and reports whether the proxy in front of PHP (nginx on HestiaCP,
 * DirectAdmin's proxy, ...) lets those forgeries through. Run it BEFORE adding
 * anything to "Own reverse proxies".
 *
 *   php proxy_probe.php --url=https://example.com/ \
 *       --config=/home/USER/domains/example.com/public_html/configuration.php \
 *       [--connect=203.0.113.10[:443]] [--insecure] [--timeout=15]
 *
 * --connect  send the request to this server IP instead of whatever the domain
 *            resolves to (e.g. Cloudflare). Use the server's PUBLIC IP, not
 *            127.0.0.1: a loopback client makes the result inconclusive.
 *
 * Exit code: 0 safe or no proxy · 2 SPOOFABLE · 3 inconclusive · 1 error.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Standalone process: lets the shared pure classes load outside Joomla.
\define('_JEXEC', 1);

$src = \dirname(__DIR__) . '/src';

foreach ([
    'Geo/CidrMatcher', 'Net/ClientIp', 'Net/CloudflareRanges', 'Net/ClientIpResolver',
    'Diagnostics/ProbeToken', 'Diagnostics/ProxyProbe',
] as $file) {
    require_once $src . '/' . $file . '.php';
}

use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProbeToken;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;

function cps_fail(string $message, int $code = 1): never
{
    fwrite(STDERR, "ERROR: $message\n");
    exit($code);
}

$opt = getopt('', ['url:', 'config:', 'connect:', 'insecure', 'timeout:', 'help']);

if (isset($opt['help']) || !isset($opt['url'], $opt['config'])) {
    fwrite(STDERR, "Usage: php proxy_probe.php --url=https://example.com/ --config=/path/to/configuration.php [--connect=IP[:PORT]] [--insecure] [--timeout=15]\n");
    exit(isset($opt['help']) ? 0 : 1);
}

if (!\extension_loaded('curl')) {
    cps_fail('The PHP curl extension is required.');
}

// Read the site secret without executing configuration.php.
$configFile = (string) $opt['config'];

if (!is_file($configFile) || !is_readable($configFile)) {
    cps_fail("Cannot read $configFile");
}

$configText = (string) file_get_contents($configFile);

if (!preg_match('/public\s+\$secret\s*=\s*([\'"])(.*?)\1\s*;/s', $configText, $m) || $m[2] === '') {
    cps_fail('Could not find a non-empty $secret in that configuration.php');
}

$secret = $m[2];

$url   = (string) $opt['url'];
$parts = parse_url($url);

if (!\is_array($parts) || !isset($parts['host'], $parts['scheme']) || !\in_array($parts['scheme'], ['http', 'https'], true)) {
    cps_fail('--url must be an http(s) URL, e.g. https://example.com/');
}

$port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);
$sep  = str_contains($url, '?') ? '&' : '?';
$ch   = curl_init($url . $sep . 'cps_probe=' . bin2hex(random_bytes(4)));

$headers = [];

foreach (ProxyProbe::requestHeaders(ProbeToken::make($secret, time())) as $name => $value) {
    $headers[] = "$name: $value";
}

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_TIMEOUT        => (int) ($opt['timeout'] ?? 15),
    CURLOPT_SSL_VERIFYPEER => !isset($opt['insecure']),
    CURLOPT_SSL_VERIFYHOST => isset($opt['insecure']) ? 0 : 2,
]);

if (isset($opt['connect'])) {
    $target = (string) $opt['connect'];
    $ip     = $target;
    $cport  = $port;

    if (preg_match('/^(.*):(\d+)$/', $target, $mm) && !str_contains($mm[1], ':')) {
        [$ip, $cport] = [$mm[1], (int) $mm[2]];
    }

    curl_setopt($ch, CURLOPT_RESOLVE, ["{$parts['host']}:{$cport}:{$ip}"]);
    $port = $cport;
}

$body   = curl_exec($ch);
$status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
$error  = curl_error($ch);
unset($ch);

if ($body === false) {
    cps_fail("Request failed: $error");
}

$report = json_decode((string) $body, true);

if (!\is_array($report) || ($report['probe'] ?? null) !== 1) {
    $hint = $status >= 300 && $status < 400
        ? 'The server redirected; pass the final URL (usually https://, with or without www).'
        : 'No probe answer. Check: the plugin is enabled, the secret in --config belongs to THIS site, and no cache/WAF in front is swallowing the request.';
    cps_fail("HTTP $status, not a probe report. $hint");
}

$result = ProxyProbe::evaluate($report, CloudflareRanges::bundled());

$labels = [
    ProxyProbe::SAFE         => 'SAFE',
    ProxyProbe::NO_PROXY     => 'NO PROXY IN PATH',
    ProxyProbe::SPOOFABLE    => 'SPOOFABLE  <-- do not trust this proxy',
    ProxyProbe::INCONCLUSIVE => 'INCONCLUSIVE',
];

echo "Colorpack Shield — proxy spoof self-test\n";
echo "----------------------------------------\n";
echo "Sent        : X-Forwarded-For=" . ProxyProbe::FAKE_EDGE . "  CF-Connecting-IP=" . ProxyProbe::MARK_VISITOR . "  X-Real-IP=" . ProxyProbe::MARK_REAL . "\n";
echo "PHP received: REMOTE_ADDR={$report['remote_addr']}  X-Forwarded-For=" . ($report['xff'] ?: '-') . "  X-Real-IP=" . ($report['x_real_ip'] ?: '-') . "  CF-Connecting-IP=" . ($report['cf_connecting_ip'] ?: '-') . "\n";
echo 'Trusted now : ' . ($report['trusted_proxies'] ? implode(', ', $report['trusted_proxies']) : '(none)') . "\n";
echo "Plugin saw  : visitor={$report['actual']['ip']}  via={$report['actual']['via']}"
    . ($report['actual']['header_ignored'] ? '  (forged CF header ignored)' : '') . "\n\n";
echo 'Verdict     : ' . $labels[$result['verdict']] . "\n";

foreach ($result['reasons'] as $reason) {
    echo "  - $reason\n";
}

// Current settings can be unsafe even if the proxy is fine.
if ($result['verdict'] === ProxyProbe::SPOOFABLE && $report['trusted_proxies']) {
    $peer = $report['remote_addr'];
    echo "\nWARNING: your current \"Own reverse proxies\" setting may already trust $peer. Empty it until the proxy is fixed.\n";
}

// Remember the verdict for the admin component's dashboard (verdict and time only, nothing
// secret). Never as root: a root-owned cache folder would stop the web user writing there.
$root = \dirname($configFile);
$dir  = $root . '/cache/colorpack_shield';
$isRoot = \function_exists('posix_geteuid') && posix_geteuid() === 0;

if (!$isRoot && (is_dir($dir) || @mkdir($dir, 0755, true))) {
    $tmp = $dir . '/probe.json.' . bin2hex(random_bytes(3));

    if (@file_put_contents($tmp, json_encode(['verdict' => $result['verdict'], 'time' => time()])) !== false && @rename($tmp, $dir . '/probe.json')) {
        echo "\nSaved the verdict for the admin dashboard.\n";
    } else {
        @unlink($tmp);
    }
} elseif ($isRoot) {
    echo "\n(Run as root: the verdict was not saved for the dashboard. Run it as the site's own user to save it.)\n";
}

exit(match ($result['verdict']) {
    ProxyProbe::SPOOFABLE    => 2,
    ProxyProbe::INCONCLUSIVE => 3,
    default                  => 0,
});
