<?php
/**
 * The administrator access key ("gate") and address list, pure parts: settings, the decision,
 * the cookie, the clean redirect, log scrubbing. Ported from the Joomla edition's
 * tests/admin_gate_tests.php, minus its server-snippet section (AdminAllowSnippet is not ported
 * here - no Apache/nginx config generator exists on the WordPress side). Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\AdminProtect\AccessGate;
use Colorpack\WP\ColorpackShield\AdminProtect\AccessGateConfig;

echo "== Admin gate: settings ==\n";

$gcKey = 'abcdef0123456789ABCDEF-_xyz';
$gc    = static fn (array $p = []): AccessGateConfig => AccessGateConfig::fromArray($p);

ok('nothing set → both off, nothing missing', $gc()->off() && !$gc()->keyMissing && !$gc()->listEmpty);
ok('gate on with a good key → active, key kept, 12 h default', $gc(['gate_enabled' => '1', 'gate_key' => $gcKey])->gateActive && $gc(['gate_enabled' => 1, 'gate_key' => " $gcKey "])->key === $gcKey && $gc(['gate_enabled' => '1', 'gate_key' => $gcKey])->cookieHours === 12);
ok('gate on without a usable key → NOT active (never a gate nobody can open)', !$gc(['gate_enabled' => '1'])->gateActive && $gc(['gate_enabled' => '1'])->keyMissing
    && !$gc(['gate_enabled' => '1', 'gate_key' => 'short'])->gateActive && !$gc(['gate_enabled' => '1', 'gate_key' => 'has space in it 12345'])->gateActive
    && !$gc(['gate_enabled' => '1', 'gate_key' => str_repeat('a', 129)])->gateActive && !$gc(['gate_enabled' => '1', 'gate_key' => ['x']])->gateActive && !$gc(['gate_enabled' => '1', 'gate_key' => str_repeat('a', 9)])->gateActive
    && $gc(['gate_enabled' => '1', 'gate_key' => str_repeat('a', 10)])->gateActive);
ok('a key without the switch does nothing', $gc(['gate_key' => $gcKey])->off() && $gc(['gate_enabled' => '0', 'gate_key' => $gcKey])->off() && $gc(['gate_enabled' => 'maybe', 'gate_key' => $gcKey])->off());
ok('cookie hours are clamped to 1–168, junk gives 12', $gc(['gate_cookie_hours' => '0'])->cookieHours === 1 && $gc(['gate_cookie_hours' => '9999'])->cookieHours === 168 && $gc(['gate_cookie_hours' => 'x'])->cookieHours === 12 && $gc(['gate_cookie_hours' => '24'])->cookieHours === 24);
ok('address list: on with entries → active; empty or only invalid → NOT active', $gc(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'])->ipActive
    && !$gc(['admin_ip_enforce' => '1', 'admin_ip_list' => ''])->ipActive && $gc(['admin_ip_enforce' => '1', 'admin_ip_list' => ''])->listEmpty && !$gc(['admin_ip_enforce' => '1', 'admin_ip_list' => "nope\n0.0.0.0/0\n10.0.0.0/4"])->ipActive
    && !$gc(['admin_ip_enforce' => '0', 'admin_ip_list' => '203.0.113.5'])->ipActive && !$gc(['admin_ip_enforce' => '1', 'admin_ip_list' => ['x']])->ipActive);
ok('address list keeps only valid entries (comments, ranges)', $gc(['admin_ip_enforce' => '1', 'admin_ip_list' => "203.0.113.5 # me\n198.51.100.0/24\njunk"])->ipList === ['203.0.113.5', '198.51.100.0/24']);

ok('generated keys: 12 characters, no look-alikes, always valid, not repeating', (static function (): bool {
    $seen = [];

    for ($i = 0; $i < 200; $i++) {
        $k = AccessGateConfig::generateKey();

        if (strlen($k) !== 12 || preg_match('/^[abcdefghjkmnpqrstuvwxyz23456789]{12}$/', $k) !== 1 || !AccessGateConfig::fromArray(['gate_enabled' => '1', 'gate_key' => $k])->gateActive) {
            return false;
        }

        $seen[$k] = true;
    }

    return count($seen) === 200;
})());

echo "== Admin gate: decision, cookie ==\n";

$gSecret = 'site-secret-value';
$gUa     = 'Mozilla/5.0 test';
$gNow    = 1_800_000_000;
$gOn     = $gc(['gate_enabled' => '1', 'gate_key' => $gcKey]);
$gIp     = $gc(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5']);
$gBoth   = $gc(['gate_enabled' => '1', 'gate_key' => $gcKey, 'admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5']);
$gCk     = AccessGate::cookieValue($gSecret, $gcKey, $gUa, $gNow + 3600);
$gD      = static fn (AccessGateConfig $c, ?string $cookie = null, ?string $key = null, bool $enf = true, bool $listed = false, string $ua = 'Mozilla/5.0 test', int $now = 1_800_000_000): string => (static function (array $r): string {
    return $r['action'] . '/' . $r['reason'];
})(AccessGate::decide($c, $cookie, $key, $enf, $listed, $ua, 'site-secret-value', $now));

ok('nothing in force → allow', $gD($gc()) === 'allow/off');
ok('gate: no cookie → deny (404 elsewhere); wrong key → deny; empty key → deny', $gD($gOn) === 'deny/no_cookie' && $gD($gOn, null, 'wrong-key-wrong-key-1') === 'deny/no_cookie' && $gD($gOn, null, '') === 'deny/no_cookie');
ok('gate: the right key → exchange; case matters', $gD($gOn, null, $gcKey) === 'exchange/key' && $gD($gOn, null, strtoupper($gcKey)) === 'deny/no_cookie' && $gD($gOn, null, $gcKey . 'x') === 'deny/no_cookie');
ok('gate: a valid cookie → allow', $gD($gOn, $gCk) === 'allow/cookie');
ok('cookie: expired, from another browser, another key, another secret → refused', $gD($gOn, $gCk, null, true, false, 'Mozilla/5.0 test', $gNow + 3601) === 'deny/no_cookie' && $gD($gOn, $gCk, null, true, false, 'Other agent') === 'deny/no_cookie'
    && $gD($gc(['gate_enabled' => '1', 'gate_key' => $gcKey . 'NEW']), $gCk) === 'deny/no_cookie' && !AccessGate::verifyCookie($gCk, $gcKey, $gUa, 'another-secret', $gNow, 12));
ok('cookie: tampered expiry or hmac, bad shapes and an empty secret → refused', !AccessGate::verifyCookie(str_replace((string) ($gNow + 3600), (string) ($gNow + 7200), $gCk), $gcKey, $gUa, $gSecret, $gNow, 12)
    && !AccessGate::verifyCookie(substr($gCk, 0, -1) . (substr($gCk, -1) === '0' ? '1' : '0'), $gcKey, $gUa, $gSecret, $gNow, 12)
    && !AccessGate::verifyCookie('', $gcKey, $gUa, $gSecret, $gNow, 12) && !AccessGate::verifyCookie('abc', $gcKey, $gUa, $gSecret, $gNow, 12) && !AccessGate::verifyCookie((string) ($gNow + 10) . '.zz', $gcKey, $gUa, $gSecret, $gNow, 12)
    && !AccessGate::verifyCookie($gCk, $gcKey, $gUa, '', $gNow, 12) && !AccessGate::verifyCookie($gCk, '', $gUa, $gSecret, $gNow, 12));
ok('cookie: an expiry far beyond the configured lifetime is refused even if correctly signed', !AccessGate::verifyCookie(AccessGate::cookieValue($gSecret, $gcKey, $gUa, $gNow + 86400 * 30), $gcKey, $gUa, $gSecret, $gNow, 12)
    && AccessGate::verifyCookie(AccessGate::cookieValue($gSecret, $gcKey, $gUa, $gNow + 12 * 3600), $gcKey, $gUa, $gSecret, $gNow, 12));
ok('cookie: one made with an empty secret or an empty key (a site with no secret) is refused', !AccessGate::verifyCookie(AccessGate::cookieValue('', $gcKey, $gUa, $gNow + 3600), $gcKey, $gUa, '', $gNow, 12) && !AccessGate::verifyCookie(AccessGate::cookieValue($gSecret, '', $gUa, $gNow + 3600), '', $gUa, $gSecret, $gNow, 12));
ok('cookie: the key never appears in it', !str_contains($gCk, $gcKey) && preg_match('/^\d{10}\.[0-9a-f]{64}$/', $gCk) === 1);
ok('address list alone: listed → allow; not listed → deny', $gD($gIp, null, null, true, true) === 'allow/listed_address' && $gD($gIp, null, null, true, false) === 'deny/address_not_listed');
ok('address list alone: an address that is not one visitor (CDN edge, private proxy) is observed, never blocked, and never counts as "listed"', $gD($gIp, null, null, false, false) === 'observe/address_not_enforceable' && $gD($gIp, null, null, false, true) === 'observe/address_not_enforceable');
ok('both on: either one opens the door', $gD($gBoth, null, null, true, true) === 'allow/listed_address' && $gD($gBoth, $gCk) === 'allow/cookie' && $gD($gBoth, null, $gcKey) === 'exchange/key' && $gD($gBoth) === 'deny/no_cookie');
ok('both on, address not enforceable: the key still gates (no observe-only hole)', $gD($gBoth, null, null, false, true) === 'deny/no_cookie' && $gD($gBoth, $gCk, null, false, false) === 'allow/cookie');
ok('an inactive part never grants: a listed address with the list off, a cookie with the gate off', $gD($gOn, null, null, true, true) === 'deny/no_cookie' && $gD($gIp, $gCk, null, true, false) === 'deny/address_not_listed');

echo "== Admin gate: clean redirect and log scrubbing ==\n";

ok('cleanUri removes only the key parameter', AccessGate::cleanUri('/administrator/index.php?cpskey=SECRET') === '/administrator/index.php'
    && AccessGate::cleanUri('/administrator/index.php?option=com_x&cpskey=SECRET&view=y') === '/administrator/index.php?option=com_x&view=y'
    && AccessGate::cleanUri('/administrator/?CPSKEY=SECRET&a=1') === '/administrator/?a=1' && AccessGate::cleanUri('/administrator/?cpskey&a=1') === '/administrator/?a=1'
    && AccessGate::cleanUri('/administrator/?cpskeyx=1') === '/administrator/?cpskeyx=1' && AccessGate::cleanUri('/administrator/') === '/administrator/');
ok('cleanUri can never produce an off-site or odd target', AccessGate::cleanUri('//evil.example/x?cpskey=1') === '/' && AccessGate::cleanUri('http://evil.example/') === '/' && AccessGate::cleanUri('') === '/'
    && AccessGate::cleanUri('/\\evil.example') === '/' && AccessGate::cleanUri("/a\r\nLocation: http://evil") === '/aLocation:http://evil' && !str_contains(AccessGate::cleanUri("/a\r\nSet-Cookie: x=1"), "\n"));
ok('scrub hides the parameter value and the key itself wherever it appears', AccessGate::scrub('uri=/administrator/index.php?cpskey=SECRETVALUE&a=1 sample=x', '') === 'uri=/administrator/index.php?cpskey=*&a=1 sample=x'
    && AccessGate::scrub('rule=x sample=' . $gcKey . ' tail', $gcKey) === 'rule=x sample=* tail' && AccessGate::scrub('CPSKEY=abc', '') === 'CPSKEY=*' && AccessGate::scrub('nothing here', $gcKey) === 'nothing here');
