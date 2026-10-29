<?php
/**
 * Proxy spoof self-test (AUDIT.md N1): token, evaluator, and the plugin's probe
 * endpoint. Included by run.php AFTER plugin_flow_tests.php (needs its stubs,
 * flow() helper and ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProbeToken;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\Event\Event;

echo "== N1: probe token ==\n";

$now = 1_800_000_000;
$tok = ProbeToken::make('s3cret', $now);
ipCheck('token is 64 hex chars', (bool) preg_match('/^[0-9a-f]{64}$/', $tok));
ipCheck('valid in its own window', ProbeToken::verify('s3cret', $tok, $now));
ipCheck('valid in the next window (slack)', ProbeToken::verify('s3cret', $tok, $now + ProbeToken::WINDOW));
ipCheck('expired after two windows', !ProbeToken::verify('s3cret', $tok, $now + 3 * ProbeToken::WINDOW));
ipCheck('not valid from the future', !ProbeToken::verify('s3cret', ProbeToken::make('s3cret', $now + 5 * ProbeToken::WINDOW), $now));
ipCheck('wrong secret rejected', !ProbeToken::verify('other', $tok, $now));
ipCheck('tampered token rejected', !ProbeToken::verify('s3cret', substr($tok, 0, 63) . ($tok[63] === 'a' ? 'b' : 'a'), $now));
ipCheck('empty secret disables the feature', !ProbeToken::verify('', ProbeToken::make('', $now), $now));
ipCheck('empty token rejected', !ProbeToken::verify('s3cret', '', $now));
ipCheck('short token rejected', !ProbeToken::verify('s3cret', 'abc', $now));

echo "== N1: evaluator ==\n";

$cf = CloudflareRanges::bundled();
$ev = static fn (array $r): string => ProxyProbe::evaluate($r + ['probe' => 1], $cf)['verdict'];
ipCheck('forged edge is inside the Cloudflare ranges', \Colorpack\Plugin\System\ColorpackShield\Geo\CidrMatcher::matchesAny(ProxyProbe::FAKE_EDGE, $cf));

$fake = ProxyProbe::FAKE_EDGE;
$mv   = ProxyProbe::MARK_VISITOR;
$mr   = ProxyProbe::MARK_REAL;

// Proxy passes the client's headers through untouched.
ipCheck('pass-through proxy → SPOOFABLE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => $fake, 'x_real_ip' => $mr, 'cf_connecting_ip' => $mv]) === ProxyProbe::SPOOFABLE);
ipCheck('pass-through on a private proxy address → SPOOFABLE',
    $ev(['remote_addr' => '10.0.0.2', 'xff' => $fake, 'x_real_ip' => $mr, 'cf_connecting_ip' => $mv]) === ProxyProbe::SPOOFABLE);
ipCheck('proxy drops XFF but passes X-Real-IP → SPOOFABLE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => '', 'x_real_ip' => $mr, 'cf_connecting_ip' => $mv]) === ProxyProbe::SPOOFABLE);

// Proper nginx: appends the real client to XFF, sets X-Real-IP itself.
ipCheck('nginx appending a public client → SAFE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => "$fake, 198.51.100.40", 'x_real_ip' => '198.51.100.40', 'cf_connecting_ip' => $mv]) === ProxyProbe::SAFE);
ipCheck('proxy that overwrites XFF with the client → SAFE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => '198.51.100.40', 'x_real_ip' => '198.51.100.40', 'cf_connecting_ip' => $mv]) === ProxyProbe::SAFE);
ipCheck('IPv6 client appended → SAFE',
    $ev(['remote_addr' => '::1', 'xff' => "$fake, 2001:db8::99", 'x_real_ip' => '2001:db8::99', 'cf_connecting_ip' => $mv]) === ProxyProbe::SAFE);
ipCheck('proxy overwrites X-Real-IP, no XFF → SAFE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => '', 'x_real_ip' => '198.51.100.40', 'cf_connecting_ip' => $mv]) === ProxyProbe::SAFE);

// Tester on the server itself: the proxy appends 127.0.0.1 → artefact, not a verdict.
ipCheck('loopback tester behind appending proxy → INCONCLUSIVE (not a false SPOOFABLE)',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => "$fake, 127.0.0.1", 'x_real_ip' => '127.0.0.1', 'cf_connecting_ip' => $mv]) === ProxyProbe::INCONCLUSIVE);
ipCheck('private-address tester → INCONCLUSIVE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => "$fake, 192.168.1.5", 'x_real_ip' => '192.168.1.5', 'cf_connecting_ip' => $mv]) === ProxyProbe::INCONCLUSIVE);
ipCheck('proxy strips every forwarding header → INCONCLUSIVE',
    $ev(['remote_addr' => '127.0.0.1', 'xff' => '', 'x_real_ip' => '', 'cf_connecting_ip' => '']) === ProxyProbe::INCONCLUSIVE);

// No proxy at all.
ipCheck('public REMOTE_ADDR → NO_PROXY',
    $ev(['remote_addr' => '198.51.100.40', 'xff' => $fake, 'x_real_ip' => $mr, 'cf_connecting_ip' => $mv]) === ProxyProbe::NO_PROXY);

// Garbage.
ipCheck('not a probe report → INCONCLUSIVE', ProxyProbe::evaluate(['remote_addr' => '127.0.0.1'], $cf)['verdict'] === ProxyProbe::INCONCLUSIVE);
ipCheck('invalid REMOTE_ADDR → INCONCLUSIVE', $ev(['remote_addr' => 'nope']) === ProxyProbe::INCONCLUSIVE);
ipCheck('verdict always carries a reason', ProxyProbe::evaluate(['probe' => 1, 'remote_addr' => '127.0.0.1', 'xff' => $fake], $cf)['reasons'] !== []);

echo "== N1: probe endpoint in the plugin ==\n";

/**
 * Send a request to the plugin with an app that knows the site secret.
 *
 * @return array{ended:bool,body:string,headers:array<string,string>}
 */
function probeCall(array $params, array $server, string $secret): array
{
    $_SERVER = array_merge(['REQUEST_URI' => '/index.php', 'CONTENT_TYPE' => ''], $server);
    $_GET = $_POST = $_COOKIE = $_FILES = [];

    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $app     = new FakeApp('site', ['secret' => $secret]);
    $plugin->setApplication($app);

    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $ended = false;
    } catch (RequestEnded $e) {
        $ended = true;
    }

    return ['ended' => $ended, 'body' => (string) ob_get_clean(), 'headers' => $app->headers];
}

$secret = 'site-secret-123';
$hdr    = static function (string $token): array {
    return [
        'HTTP_X_COLORPACK_PROBE' => $token,
        'HTTP_X_FORWARDED_FOR'   => ProxyProbe::FAKE_EDGE,
        'HTTP_CF_CONNECTING_IP'  => ProxyProbe::MARK_VISITOR,
        'HTTP_X_REAL_IP'         => ProxyProbe::MARK_REAL,
    ];
};

// Behaves like a pass-through proxy at 127.0.0.1.
$r = probeCall([], ['REMOTE_ADDR' => '127.0.0.1'] + $hdr(ProbeToken::make($secret, time())), $secret);
$j = json_decode($r['body'], true);
ipCheck('valid token: request ends with a JSON report', $r['ended'] && \is_array($j) && ($j['probe'] ?? null) === 1);
ipCheck('report shows what reached PHP',
    ($j['remote_addr'] ?? '') === '127.0.0.1' && ($j['xff'] ?? '') === ProxyProbe::FAKE_EDGE
    && ($j['cf_connecting_ip'] ?? '') === ProxyProbe::MARK_VISITOR && ($j['x_real_ip'] ?? '') === ProxyProbe::MARK_REAL);
ipCheck('report shows the current (default, empty) trusted proxies and a non-spoofed visitor',
    ($j['trusted_proxies'] ?? null) === [] && ($j['actual']['ip'] ?? '') === '127.0.0.1');
ipCheck('response is JSON, uncacheable', str_contains($r['headers']['Content-Type'] ?? '', 'application/json') && ($r['headers']['Cache-Control'] ?? '') === 'no-store');
ipCheck('evaluator, fed the live report, says SPOOFABLE for this pass-through setup',
    ProxyProbe::evaluate($j, $cf)['verdict'] === ProxyProbe::SPOOFABLE);

// With the proxy declared, "actual" reflects the forgery — the reason to run the test first.
$r = probeCall(['trusted_proxies' => '127.0.0.1'], ['REMOTE_ADDR' => '127.0.0.1'] + $hdr(ProbeToken::make($secret, time())), $secret);
$j = json_decode($r['body'], true);
ipCheck('after trusting a leaky proxy, the plugin itself would adopt the forged IP',
    ($j['actual']['ip'] ?? '') === ProxyProbe::MARK_VISITOR && ($j['trusted_proxies'] ?? []) === ['127.0.0.1']);

// Original REMOTE_ADDR is reported even when the override option rewrote it.
$r = probeCall(['trusted_proxies' => '127.0.0.1', 'override_remote_addr' => 1], ['REMOTE_ADDR' => '127.0.0.1'] + $hdr(ProbeToken::make($secret, time())), $secret);
$j = json_decode($r['body'], true);
ipCheck('report keeps the ORIGINAL REMOTE_ADDR when the override option is on', ($j['remote_addr'] ?? '') === '127.0.0.1');

// Requests that must NOT get a report.
$bad = [
    'wrong token'            => ['HTTP_X_COLORPACK_PROBE' => str_repeat('0', 64)],
    'token for another site' => ['HTTP_X_COLORPACK_PROBE' => ProbeToken::make('other-secret', time())],
    'expired token'          => ['HTTP_X_COLORPACK_PROBE' => ProbeToken::make($secret, time() - 3 * ProbeToken::WINDOW)],
    'garbage token'          => ['HTTP_X_COLORPACK_PROBE' => 'hello'],
];

foreach ($bad as $label => $extra) {
    $r = probeCall([], ['REMOTE_ADDR' => '198.51.100.1'] + $extra, $secret);
    ipCheck("$label: no report, request continues", !$r['ended'] && $r['body'] === '');
}

$r = probeCall([], ['REMOTE_ADDR' => '198.51.100.1', 'HTTP_X_COLORPACK_PROBE' => ProbeToken::make('', time())], '');
ipCheck('site without a secret: probe disabled', !$r['ended'] && $r['body'] === '');

$r = probeCall([], ['REMOTE_ADDR' => '198.51.100.1'], $secret);
ipCheck('ordinary request: untouched', !$r['ended'] && $r['body'] === '');

// A bad token must not weaken protection: attacks with a probe header are still inspected.
$_GET = ['q' => "1' UNION SELECT user,pass FROM x-- -"];
$_SERVER = ['REMOTE_ADDR' => '198.51.100.1', 'REQUEST_URI' => '/', 'CONTENT_TYPE' => '', 'HTTP_X_COLORPACK_PROBE' => str_repeat('0', 64)];
$_POST = $_COOKIE = $_FILES = [];
$subject = new stdClass();
$plugin  = new ColorpackShield($subject, ['params' => []]);
$plugin->setApplication(new FakeApp('site', ['secret' => $secret]));
ob_start();
try {
    $plugin->onAfterInitialise(new Event('onAfterInitialise'));
    $blocked = false;
} catch (RequestEnded $e) {
    $blocked = true;
}
ob_end_clean();
ipCheck('attack carrying an invalid probe header is still blocked by the WAF', $blocked);
