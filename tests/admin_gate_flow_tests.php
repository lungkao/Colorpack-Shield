<?php
/**
 * Administrator access key (A4) and address list (A5) through the real plugin class, with
 * Joomla stand-ins. Included by run.php after admin_gate_tests.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGate;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\CMS\Log\Log;
use Joomla\Event\Event;

echo "== Admin gate: plugin flow ==\n";

$gfReset = static function (): void {
    // An earlier test file leaves a FILE where the folder should be: start from nothing.
    exec('rm -rf ' . escapeshellarg(JPATH_ROOT . '/cache/colorpack_shield'));
    Log::$messages = [];
};
$gfLog = static fn (): string => implode("\n", Log::$messages);

/**
 * @return array{blocked:bool,status:string,location:string,body:string,cookie:?array,headers:array<string,string>}
 */
$gfReq = static function (array $params, array $server, array $get = [], array $cookie = [], array $appCfg = [], string $client = 'administrator'): array {
    $_SERVER = array_merge(['REQUEST_URI' => '/administrator/index.php', 'CONTENT_TYPE' => '', 'REQUEST_METHOD' => 'GET', 'HTTP_USER_AGENT' => 'Mozilla/5.0 test', 'SCRIPT_NAME' => '/administrator/index.php'], $server);
    $_GET    = $get;
    $_POST   = $_FILES = [];
    $_COOKIE = $cookie;
    $sent    = null;
    ColorpackShield::$cookieSender = static function (string $value, array $options) use (&$sent): void {
        $sent = ['value' => $value] + $options;
    };
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $app    = new FakeApp($client, $appCfg + ['secret' => 'site-secret']);
    $plugin->setApplication($app);
    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $blocked = false;
    } catch (RequestEnded $e) {
        $blocked = true;
    }

    ColorpackShield::$cookieSender = null;

    return ['blocked' => $blocked, 'status' => $app->headers['status'] ?? '', 'location' => $app->headers['Location'] ?? '', 'body' => (string) ob_get_clean(), 'cookie' => $sent, 'headers' => $app->headers];
};

$gfKey = 'abcdef0123456789ABCDEF-_xyz';
$gfOn  = ['gate_enabled' => '1', 'gate_key' => $gfKey];
$gfA   = ['REMOTE_ADDR' => '8.8.8.8'];

$gfReset();
$r = $gfReq([], $gfA);
ipCheck('nothing configured: the administrator answers as before', !$r['blocked'] && $r['status'] === '' && $r['cookie'] === null);
$r = $gfReq($gfOn, $gfA);
ipCheck('gate on, no cookie: a plain 404 that says nothing about the product', $r['blocked'] && $r['status'] === '404 Not Found' && str_contains($r['body'], 'Not Found') && !preg_match('/colorpack|shield|joomla|administrator|key/i', $r['body']));
ipCheck('…and the refusal is logged once (BLOCK kind=gate), without the key', str_contains($gfLog(), 'BLOCK client=administrator kind=gate reason=no_cookie') && !str_contains($gfLog(), $gfKey));
Log::$messages = [];

for ($i = 0; $i < 15; $i++) {
    $gfReq($gfOn, ['REMOTE_ADDR' => '8.8.' . $i . '.1']);
}

ipCheck('15 scanners from 15 addresses write one gate line per minute, not 15', substr_count($gfLog(), 'kind=gate') <= 1);
ipCheck('the front end and the API are not behind the gate', !$gfReq($gfOn, $gfA, [], [], [], 'site')['blocked'] && !$gfReq($gfOn, $gfA, [], [], [], 'api')['blocked']);

$gfReset();
$r = $gfReq($gfOn, $gfA + ['REQUEST_URI' => '/administrator/index.php?option=com_content&cpskey=' . $gfKey . '&view=x'], ['option' => 'com_content', 'cpskey' => $gfKey, 'view' => 'x']);
ipCheck('the right key: a 303 to the same page WITHOUT the key, and a cookie', $r['blocked'] && $r['status'] === '303 See Other' && $r['location'] === '/administrator/index.php?option=com_content&view=x' && $r['cookie'] !== null);
ipCheck('the redirect leaks nothing: no-store, no Referer', ($r['headers']['Cache-Control'] ?? '') === 'no-store' && ($r['headers']['Referrer-Policy'] ?? '') === 'no-referrer' && !str_contains($r['location'], 'cpskey'));
ipCheck('the cookie: signed, HttpOnly, SameSite=Lax, administrator path, ~12 hours, no key inside', $r['cookie']['httponly'] === true && $r['cookie']['samesite'] === 'Lax' && $r['cookie']['path'] === '/administrator' && $r['cookie']['secure'] === false
    && !str_contains($r['cookie']['value'], $gfKey) && abs($r['cookie']['expires'] - (time() + 12 * 3600)) < 5);
$rs = $gfReq($gfOn, $gfA, ['cpskey' => $gfKey], [], ['ssl' => true]);
$r24 = $gfReq(['gate_enabled' => '1', 'gate_key' => $gfKey, 'gate_cookie_hours' => '24'], $gfA, ['cpskey' => $gfKey]);
ipCheck('the configured lifetime is used for the cookie', abs($r24['cookie']['expires'] - (time() + 24 * 3600)) < 5);
ipCheck('on HTTPS the cookie is Secure', $rs['cookie']['secure'] === true);
Log::$messages = [];
$gfReq($gfOn, $gfA + ['REQUEST_URI' => '/index.php?cpskey=' . $gfKey . '&q=1+union+select+1'], ['cpskey' => $gfKey, 'q' => '1 union select 1'], [], [], 'site');
ipCheck('a WAF line that carries the key in its uri is scrubbed (the line exists, the key does not)', str_contains($gfLog(), 'BLOCK') && !str_contains($gfLog(), $gfKey) && str_contains($gfLog(), 'cpskey=*'));
ipCheck('the key is in no log line, whichever line is written', !str_contains($gfLog(), $gfKey));
$ck = $r['cookie']['value'];
$r2 = $gfReq($gfOn, $gfA, [], [AccessGate::COOKIE => $ck]);
ipCheck('with that cookie the administrator opens (no block, no new cookie)', !$r2['blocked'] && $r2['cookie'] === null);
ipCheck('the same cookie from another browser (user agent) does not', $gfReq($gfOn, $gfA, [], [AccessGate::COOKIE => $ck], [])['blocked'] === false && $gfReq($gfOn, $gfA + ['HTTP_USER_AGENT' => 'Evil/1.0'], [], [AccessGate::COOKIE => $ck])['status'] === '404 Not Found');
ipCheck('a changed key invalidates every cookie', $gfReq(['gate_enabled' => '1', 'gate_key' => $gfKey . 'NEW'], $gfA, [], [AccessGate::COOKIE => $ck])['status'] === '404 Not Found');
ipCheck('a wrong key, a tampered cookie, an array instead of a string: 404', $gfReq($gfOn, $gfA, ['cpskey' => 'wrong-wrong-wrong-wrong'])['status'] === '404 Not Found'
    && $gfReq($gfOn, $gfA, [], [AccessGate::COOKIE => $ck . '0'])['status'] === '404 Not Found' && $gfReq($gfOn, $gfA, ['cpskey' => [$gfKey]])['status'] === '404 Not Found' && $gfReq($gfOn, $gfA, [], [AccessGate::COOKIE => [$ck]])['status'] === '404 Not Found');
ipCheck('a site with no secret cannot validate a cookie: the gate stays shut', $gfReq($gfOn, $gfA, [], [AccessGate::COOKIE => $ck], ['secret' => ''])['status'] === '404 Not Found');

// Trust and rescue.
$gfReset();
ipCheck('a fully trusted address (the real peer) is never gated', !$gfReq($gfOn + ['allow_ips' => '8.8.8.8'], $gfA)['blocked']);
ipCheck('a soft-trusted address (seen through a listed proxy header, one visitor) is not gated', !$gfReq($gfOn + ['allow_ips' => '8.8.4.4', 'trusted_proxies' => '10.0.0.0/8'], ['REMOTE_ADDR' => '10.1.1.1', 'HTTP_X_FORWARDED_FOR' => '8.8.4.4'])['blocked']);
ipCheck('a trusted address that is NOT one visitor (private peer) does not bypass the gate', $gfReq($gfOn + ['allow_ips' => '10.9.9.9', 'trusted_proxies' => '10.1.1.1'], ['REMOTE_ADDR' => '10.1.1.1', 'HTTP_X_FORWARDED_FOR' => '10.9.9.9'])['status'] === '404 Not Found');
$f = JPATH_ROOT . '/colorpack_shield.disable';
file_put_contents($f, '');
ipCheck('the kill-switch file switches the gate off with everything else', !$gfReq($gfOn, $gfA)['blocked']);
unlink($f);
@mkdir(JPATH_ROOT . '/cache/colorpack_shield', 0777, true);
file_put_contents(JPATH_ROOT . '/cache/colorpack_shield/gate.off', '');
ipCheck('the shell rescue marker (gate.off) opens the gate and the address list', !$gfReq($gfOn, $gfA)['blocked'] && !$gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], $gfA)['blocked']);
unlink(JPATH_ROOT . '/cache/colorpack_shield/gate.off');
ipCheck('without the marker the gate is back', $gfReq($gfOn, $gfA)['status'] === '404 Not Found');
ipCheck('a gate with no usable key does nothing (never a gate nobody can open)', !$gfReq(['gate_enabled' => '1', 'gate_key' => 'short'], $gfA)['blocked'] && !$gfReq(['gate_enabled' => '1'], $gfA)['blocked']);

// A5.
$gfReset();
$gfIp = ['admin_ip_enforce' => '1', 'admin_ip_list' => "203.0.113.5\n198.51.100.0/24"];
ipCheck('address list: a listed address passes, another gets 404', !$gfReq($gfIp, ['REMOTE_ADDR' => '203.0.113.5'])['blocked'] && !$gfReq($gfIp, ['REMOTE_ADDR' => '198.51.100.77'])['blocked'] && $gfReq($gfIp, ['REMOTE_ADDR' => '203.0.113.6'])['status'] === '404 Not Found');
ipCheck('address list: the refusal says "address_not_listed" in the log', str_contains($gfLog(), 'kind=gate reason=address_not_listed'));
ipCheck('address list through Cloudflare: the real visitor address is what is compared', !$gfReq($gfIp, ['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5'])['blocked'] && $gfReq($gfIp, ['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.6'])['status'] === '404 Not Found');
ipCheck('address list: a forged Cloudflare header from a direct visitor changes nothing', $gfReq($gfIp, ['REMOTE_ADDR' => '8.8.8.8', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5'])['status'] === '404 Not Found');
Log::$messages = [];
ipCheck('address list: when the visitor address cannot be told (private peer, unlisted proxy) it is OBSERVED, never blocked', !$gfReq($gfIp, ['REMOTE_ADDR' => '10.2.2.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.99'])['blocked'] && str_contains($gfLog(), 'OBSERVE client=administrator kind=gate reason=address_not_enforceable'));
ipCheck('address list: a Cloudflare edge without a visitor header is observed, never blocked', !$gfReq($gfIp, ['REMOTE_ADDR' => '104.16.0.1'])['blocked']);
ipCheck('address list on with an empty or invalid list: off (never refuses everybody)', !$gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => ''], $gfA)['blocked'] && !$gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => "junk\n0.0.0.0/0"], $gfA)['blocked']);
$both = $gfIp + $gfOn;
ipCheck('both on: a listed address passes without the key; an unlisted one needs the key', !$gfReq($both, ['REMOTE_ADDR' => '203.0.113.5'])['blocked'] && $gfReq($both, $gfA)['status'] === '404 Not Found'
    && $gfReq($both, $gfA, ['cpskey' => $gfKey])['status'] === '303 See Other' && !$gfReq($both, $gfA, [], [AccessGate::COOKIE => $ck])['blocked']);
ipCheck('address list: IPv6 range entries work', !$gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => '2001:db8:abcd::/48'], ['REMOTE_ADDR' => '2001:db8:abcd:1::5'])['blocked'] && $gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => '2001:db8:abcd::/48'], ['REMOTE_ADDR' => '2001:db8:ffff::5'])['status'] === '404 Not Found');
ipCheck('the gate comes BEFORE the lock-out answer (a gated visitor never learns about locks)', (static function () use ($gfReq, $gfOn): bool {
    $r = $gfReq($gfOn, ['REMOTE_ADDR' => '8.8.8.8']);

    return $r['status'] === '404 Not Found';
})());
ipCheck('the plugin\'s own component is gated too (no allow-list hole)', $gfReq($gfOn, $gfA, [], [], ['input' => ['option' => 'com_colorpack_shield']])['status'] === '404 Not Found');
$gfReset();

echo "== Admin gate: rescue CLI ==\n";

$cli  = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/admin_unlock.php');
$root = JPATH_ROOT;
$gfReset();
exec('php ' . escapeshellarg($cli) . ' --root=' . escapeshellarg($root) . ' --gate-off 2>&1', $o1, $c1);
ipCheck('--gate-off writes the marker and says so', $c1 === 0 && is_file($root . '/cache/colorpack_shield/gate.off') && str_contains(implode("\n", $o1), 'OPEN'));
ipCheck('with the marker, the gate and the address list let everybody in', !$gfReq($gfOn, $gfA)['blocked'] && !$gfReq(['admin_ip_enforce' => '1', 'admin_ip_list' => '203.0.113.5'], $gfA)['blocked']);
exec('php ' . escapeshellarg($cli) . ' --root=' . escapeshellarg($root) . ' --gate-on 2>&1', $o2, $c2);
ipCheck('--gate-on removes it, and the gate is back', $c2 === 0 && !is_file($root . '/cache/colorpack_shield/gate.off') && $gfReq($gfOn, $gfA)['status'] === '404 Not Found');
exec('php ' . escapeshellarg($cli) . ' --root=' . escapeshellarg($root) . ' --gate-on 2>&1', $o3, $c3);
ipCheck('--gate-on twice is harmless; combining options is refused', $c3 === 0);
exec('php ' . escapeshellarg($cli) . ' --root=' . escapeshellarg($root) . ' --gate-on --gate-off 2>&1', $o4, $c4);
ipCheck('two actions at once are refused', $c4 === 1 && !is_file($root . '/cache/colorpack_shield/gate.off'));
$gfReset();

// The login task is compared the way Joomla reads it (lower-cased, part after the last dot).
$lgM = new ReflectionMethod(ColorpackShield::class, 'isLoginTask');
$lgO = (new ReflectionClass(ColorpackShield::class))->newInstanceWithoutConstructor();
$lgM->setAccessible(true);
ipCheck('the login task matches like Joomla reads it: LOGIN, Login, display.login, user.login; not logout, loginx or login.x', !in_array(false, array_map(static fn (string $t): bool => $lgM->invoke($lgO, $t), ['login', 'LOGIN', 'Login', 'display.login', 'user.login', 'x.y.LOGIN']), true)
    && !$lgM->invoke($lgO, 'logout') && !$lgM->invoke($lgO, '') && !$lgM->invoke($lgO, 'loginx') && !$lgM->invoke($lgO, 'login.x'));
