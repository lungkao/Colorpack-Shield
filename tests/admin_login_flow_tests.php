<?php
/**
 * Administrator login protection through the real plugin class (PLAN-ADMIN-PROTECTION.md A1),
 * with Joomla stand-ins, and the unlock CLI. Included by run.php after
 * admin_protect_tests.php (uses ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminProtectConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\CMS\Log\Log;
use Joomla\Event\Event;

echo "== Admin login protection: plugin flow ==\n";

$adminDir = JPATH_ROOT . '/cache/colorpack_shield/admin';
$aReset    = static function () use ($adminDir): void {
    exec('rm -rf ' . escapeshellarg($adminDir));
    Log::$messages = [];
};
$logText = static fn (): string => implode("\n", Log::$messages);

/** One request to the administrator (or another application) through a fresh plugin instance. */
$areq = static function (array $params, array $server, array $appCfg = [], string $client = 'administrator'): array {
    $_SERVER = array_merge(['REQUEST_URI' => '/administrator/index.php', 'CONTENT_TYPE' => '', 'REQUEST_METHOD' => 'GET'], $server);
    $_GET    = $_POST = $_COOKIE = $_FILES = [];
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $app     = new FakeApp($client, $appCfg);
    $plugin->setApplication($app);
    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $blocked = false;
    } catch (RequestEnded $e) {
        $blocked = true;
    }

    return ['blocked' => $blocked, 'status' => $app->headers['status'] ?? '', 'retry' => $app->headers['Retry-After'] ?? '', 'body' => (string) ob_get_clean()];
};

/** Dispatch onUserLoginFailure / onUserAfterLogin to a fresh plugin instance. */
$aevent = static function (string $name, array $params, array $server, array $args = [], array $appCfg = [], string $client = 'administrator') {
    $_SERVER = array_merge(['REQUEST_URI' => '/administrator/index.php', 'CONTENT_TYPE' => '', 'REQUEST_METHOD' => 'POST'], $server);
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $plugin->setApplication(new FakeApp($client, $appCfg));
    $plugin->$name(new Event($name, $args));
};
$aFail = static function (array $params, array $server, string $user = 'admin', array $appCfg = [], string $client = 'administrator') use ($aevent): void {
    $aevent('onUserLoginFailure', $params, $server, ['subject' => ['username' => $user, 'status' => 0, 'type' => 'Joomla', 'error_message' => 'x']], $appCfg, $client);
};
$aOk = static function (array $params, array $server, array $appCfg = []) use ($aevent): void {
    $aevent('onUserAfterLogin', $params, $server, ['options' => ['user' => (object) ['id' => 42]], 'subject' => ['username' => 'admin']], $appCfg);
};

$srvA   = ['REMOTE_ADDR' => '8.8.8.8'];
$srvB   = ['REMOTE_ADDR' => '9.9.9.9'];
$aSec = ['secret' => 'site-secret'];

// Lock after five failures.
$aReset();
for ($i = 0; $i < 4; $i++) {
    $aFail([], $srvA);
}

ipCheck('4 failed logins: the administrator still answers', $areq([], $srvA)['blocked'] === false);
$aFail([], $srvA, 'secretname');
$r = $areq([], $srvA);
ipCheck('the 5th failure locks the address: 429, Retry-After, neutral text', $r['blocked'] && $r['status'] === '429 Too Many Requests' && (int) $r['retry'] > 800 && (int) $r['retry'] <= 900 && $r['body'] === 'Too many attempts. Please try again later.');
ipCheck('the answer does not hint at user names or at the product', !preg_match('/user|name|password|colorpack|shield|admin/i', $r['body']));
ipCheck('the lock is logged (LOCK) and the refusal is logged (BLOCK … kind=lockout)', str_contains($logText(), 'LOCK client=administrator ip=8.8.8.8') && str_contains($logText(), 'BLOCK client=administrator kind=lockout reason=locked'));
ipCheck('no user name ever reaches the log', !str_contains($logText(), 'secretname') && !str_contains($logText(), 'username'));
ipCheck('another address is not affected', $areq([], $srvB)['blocked'] === false);
ipCheck('the front end is not affected by an administrator lock', $areq([], $srvA, [], 'site')['blocked'] === false);
Log::$messages = [];
for ($i = 0; $i < 20; $i++) {
    $areq([], $srvA);
}

ipCheck('20 refused requests write one BLOCK line per minute, not 20', substr_count($logText(), 'kind=lockout reason=locked') <= 1);
$r = $areq([], $srvA, ['input' => ['option' => 'com_colorpack_shield']]);
ipCheck('the lock comes before the WAF allow-list: even the plugin\'s own component is refused', $r['blocked'] && $r['status'] === '429 Too Many Requests');
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

Log::$messages = [];
$areq([], $srvA + ['REQUEST_URI' => '/administrator/index.php?token=LEAKME&x=1']);
ipCheck('the refusal is logged with the path only: the query string never reaches the log', str_contains($logText(), 'BLOCK client=administrator kind=lockout') && !str_contains($logText(), 'LEAKME') && preg_match('~uri=/administrator/index\.php$~m', $logText()) === 1);

// Failures counted only for the administrator, only below the limit, and switchable.
$aReset();
for ($i = 0; $i < 10; $i++) {
    $aFail([], $srvA, 'x', [], 'site');
}

ipCheck('failed logins on the front end are not counted', $areq([], $srvA)['blocked'] === false);
$aReset();
for ($i = 0; $i < 10; $i++) {
    $aFail(['login_lockout' => 0], $srvA);
}

ipCheck('login_lockout=0: nothing counted, nothing locked, nothing stored', $areq(['login_lockout' => 0], $srvA)['blocked'] === false && !is_dir($adminDir));
$aReset();
for ($i = 0; $i < 3; $i++) {
    $aFail(['login_max_failures' => 3, 'login_failure_window' => 60], $srvA);
}

ipCheck('the limit is a setting (3 failures)', $areq(['login_max_failures' => 3], $srvA)['blocked'] === true);
$aReset();
for ($i = 0; $i < 4; $i++) {
    $aFail([], $srvA);
}

$aOk([], $srvA, $aSec);
for ($i = 0; $i < 4; $i++) {
    $aFail([], $srvA);
}

ipCheck('4 failures + a successful login + 4 failures does not lock', $areq([], $srvA)['blocked'] === false);

// Event argument shapes.
$aReset();
foreach ([['subject' => ['username' => 'a']], [0 => ['username' => 'a']], ['subject' => null], ['subject' => 'junk'], [], ['subject' => ['username' => str_repeat("\xff\0'\"", 400)]]] as $args) {
    $aevent('onUserLoginFailure', [], $srvA, $args);
}

ipCheck('the failure handler accepts Joomla 5/6 and 4 argument shapes and survives junk without an exception', $areq([], $srvA)['blocked'] === true);

// Trust.
$aReset();
$aTrust = ['allow_ips' => "8.8.8.8\n"];
for ($i = 0; $i < 10; $i++) {
    $aFail($aTrust, $srvA);
}

ipCheck('a fully trusted address is never counted or locked', $areq($aTrust, $srvA)['blocked'] === false && !is_dir($adminDir));
$aReset();
$aViaCf = ['REMOTE_ADDR' => '104.16.0.5', 'HTTP_CF_CONNECTING_IP' => '8.8.8.8'];
for ($i = 0; $i < 10; $i++) {
    $aFail($aTrust, $aViaCf);
}

ipCheck('a trusted address learned from Cloudflare (soft trust) is not counted or locked either', $areq($aTrust, $aViaCf)['blocked'] === false && !is_dir($adminDir));

$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $aViaCf);
}

ipCheck('a soft-trusted address is exempt even from a lock that already exists; the same address without trust is refused', $areq($aTrust, $aViaCf)['blocked'] === false && $areq([], $aViaCf)['blocked'] === true);

// Name pressure through both argument shapes.
foreach (['subject' => 'Joomla 5/6 (named)', 0 => 'Joomla 4 (numeric)'] as $key => $label) {
    $aReset();

    for ($i = 0; $i < 12; $i++) {
        $aevent('onUserLoginFailure', [], ['REMOTE_ADDR' => '40.0.0.' . ($i % 4 + 1)], [$key => ['username' => 'victim']]);
    }

    ipCheck("many failures for one user name from several addresses are noted ($label argument shape)", str_contains($logText(), 'NOTE client=administrator kind=name_pressure reason=level1'));
}

// A successful login only counts when it happens in the administrator application.
$aReset();
for ($i = 0; $i < 4; $i++) {
    $aFail([], $srvA);
}

$aevent('onUserAfterLogin', [], $srvA, ['options' => ['user' => (object) ['id' => 1]]], $aSec, 'site');
$aFail([], $srvA);
ipCheck('a successful front-end login neither clears the counters nor marks the address as an administrator\'s (the 5th failure still locks and is enforced)', $areq([], $srvA, $aSec)['blocked'] === true);

// Cloudflare and spoofing.
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $aViaCf);
}

ipCheck('behind Cloudflare the visitor (CF-Connecting-IP) is locked, not the edge', $areq([], $aViaCf)['blocked'] === true && $areq([], ['REMOTE_ADDR' => '104.16.0.5', 'HTTP_CF_CONNECTING_IP' => '9.9.9.9'])['blocked'] === false);
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], ['REMOTE_ADDR' => '8.8.8.8', 'HTTP_CF_CONNECTING_IP' => "7.7.7.$i", 'HTTP_X_FORWARDED_FOR' => "6.6.6.$i"]);
}

ipCheck('forged forwarding headers from a direct visitor change nothing: the real address is locked', $areq([], $srvA)['blocked'] === true);
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], ['REMOTE_ADDR' => '104.16.0.5']);
}

$r = $areq([], ['REMOTE_ADDR' => '104.16.0.5']);
ipCheck('a Cloudflare edge without a visitor header is only observed, never blocked', $r['blocked'] === false && str_contains($logText(), 'OBSERVE client=administrator kind=lockout reason='));

// Addresses that stand for many visitors.
foreach (['127.0.0.1' => 'loopback', '10.1.2.3' => 'private', '172.20.0.9' => 'private'] as $addr => $label) {
    $aReset();
    for ($i = 0; $i < 5; $i++) {
        $aFail([], ['REMOTE_ADDR' => $addr]);
    }

    $r = $areq([], ['REMOTE_ADDR' => $addr]);
    ipCheck("a locked $label address ($addr) is only observed, never blocked", $r['blocked'] === false && str_contains($logText(), 'OBSERVE client=administrator kind=lockout reason=shared_address'));
}

$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail(['trusted_proxies' => '8.8.8.8'], $srvA);
}

ipCheck('an address declared as the site\'s own proxy is only observed', $areq(['trusted_proxies' => '8.8.8.8'], $srvA)['blocked'] === false);

// Known administrator addresses.
$aReset();
$aOk([], $srvA, $aSec);
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA, 'admin', $aSec);
}

$r = $areq([], $srvA, $aSec);
ipCheck('an address an administrator has logged in from is never blocked (observed instead)', $r['blocked'] === false && str_contains($logText(), 'reason=known_admin_address'));
ipCheck('…but another address still is locked after the same failures', (function () use ($aReset, $aFail, $areq, $srvB, $aSec, $srvA, $aOk) {
    $aReset();
    $aOk([], $srvA, $aSec);

    for ($i = 0; $i < 5; $i++) {
        $aFail([], $srvB, 'admin', $aSec);
    }

    return $areq([], $srvB, $aSec)['blocked'] === true;
})());
$aReset();
$aOk([], $srvA, []);   // no site secret: nothing can be remembered
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

ipCheck('without a site secret nothing is remembered (and nothing breaks): the lock applies', $areq([], $srvA)['blocked'] === true);

// IPv6.
$aReset();
for ($i = 1; $i <= 5; $i++) {
    $aFail([], ['REMOTE_ADDR' => '2a00:1450:4001:81b::' . dechex($i)]);
}

ipCheck('IPv6: failures from one /64 lock the whole /64 (another address of it is refused), not the next /64', $areq([], ['REMOTE_ADDR' => '2a00:1450:4001:81b:1:2:3:4'])['blocked'] === true && $areq([], ['REMOTE_ADDR' => '2a00:1450:4001:81c::1'])['blocked'] === false);

// Kill switch.
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

touch(JPATH_ROOT . '/colorpack_shield.disable');
ipCheck('the kill-switch file stops the lock from being enforced', $areq([], $srvA)['blocked'] === false);
Log::$messages = [];
$aReset();
for ($i = 0; $i < 7; $i++) {
    $aFail([], $srvB);
}

ipCheck('…and failures are not counted while it exists', !is_dir($adminDir));
@unlink(JPATH_ROOT . '/colorpack_shield.disable');

// Login speed limit.
$aReset();
$aPost  = ['REQUEST_METHOD' => 'POST'];
$aLogin = ['input' => ['task' => 'login', 'option' => 'com_login']];
$res   = [];
for ($i = 1; $i <= 5; $i++) {
    $res[] = $areq(['login_rate_per_minute' => 3, 'login_lockout' => 0], $srvA + $aPost, $aLogin)['blocked'];
}

ipCheck('login speed limit: attempts 1–3 pass, 4 and 5 are refused (limit 3 per minute)', $res === [false, false, false, true, true]);
$r = $areq(['login_rate_per_minute' => 3], $srvA + $aPost, $aLogin);
ipCheck('…with 429 and a Retry-After of at most a minute', $r['status'] === '429 Too Many Requests' && (int) $r['retry'] >= 1 && (int) $r['retry'] <= 60);
ipCheck('…and it is logged as kind=login_rate', str_contains($logText(), 'BLOCK client=administrator kind=login_rate reason=too_many'));
ipCheck('page views (GET) of the login page are not counted', $areq(['login_rate_per_minute' => 3], $srvA, $aLogin)['blocked'] === false);
ipCheck('other administrator requests are not blocked by the speed limit', $areq(['login_rate_per_minute' => 3], $srvA + $aPost, ['input' => ['task' => 'save']])['blocked'] === false);
ipCheck('another address has its own budget', $areq(['login_rate_per_minute' => 3], $srvB + $aPost, $aLogin)['blocked'] === false);
$aReset();
for ($i = 1; $i <= 8; $i++) {
    $r = $areq(['login_rate_per_minute' => 0, 'login_lockout' => 0], $srvA + $aPost, $aLogin);
}

ipCheck('login_rate_per_minute=0 switches the speed limit off', $r['blocked'] === false);
$aReset();
for ($i = 1; $i <= 8; $i++) {
    $r = $areq(['login_rate_per_minute' => 3, 'login_lockout' => 0], ['REMOTE_ADDR' => '127.0.0.1'] + $aPost, $aLogin);
}

ipCheck('behind an unconfigured proxy (loopback) the speed limit only observes', $r['blocked'] === false && str_contains($logText(), 'kind=login_rate reason=not_enforceable'));
$aReset();
$aOk([], $srvA, $aSec);
for ($i = 1; $i <= 5; $i++) {
    $r = $areq(['login_rate_per_minute' => 3, 'login_lockout' => 0], $srvA + $aPost, $aLogin + $aSec);
}

ipCheck('a known administrator address is still speed-limited (10 a minute is generous for a person)', $r['blocked'] === true);
$aReset();
for ($i = 1; $i <= 8; $i++) {
    $r = $areq(['login_rate_per_minute' => 3], $srvA + $aPost + ['HTTP_X_FORWARDED_FOR' => '5.5.5.5'], $aLogin);
}

ipCheck('login speed limit works with trusted_proxies empty and forged forwarding headers (counted on the real address)', $r['blocked'] === true);
$aReset();
$trustedRes = [];
for ($i = 1; $i <= 6; $i++) {
    $trustedRes[] = $areq($aTrust + ['login_rate_per_minute' => 3], $srvA + $aPost, $aLogin)['blocked'];
}

ipCheck('a fully trusted address is not speed-limited', !in_array(true, $trustedRes, true));

$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

for ($i = 0; $i < 3; $i++) {
    $areq(['login_rate_per_minute' => 3], $srvA + $aPost, $aLogin);
}

ipCheck('requests refused because of a lock do not also feed the speed counter', (new FileStateStore($adminDir))->entries('rate:', time()) === []);

// Fail open.
$aReset();
$stash = JPATH_ROOT . '/cache';
@mkdir($stash, 0777, true);
exec('rm -rf ' . escapeshellarg($stash . '/colorpack_shield'));
file_put_contents($stash . '/colorpack_shield', 'a file where the folder should be');
$threw = false;

try {
    for ($i = 0; $i < 8; $i++) {
        $aFail([], $srvA);
    }

    $r = $areq([], $srvA + $aPost, $aLogin);
    $r2 = $areq(['login_rate_per_minute' => 1], $srvA + $aPost, $aLogin);
} catch (Throwable) {
    $threw = true;
}

ipCheck('unusable storage: no exception, no lock, no speed limit (fail open)', !$threw && $r['blocked'] === false && $r2['blocked'] === false);
@unlink($stash . '/colorpack_shield');
$aReset();

// A locked address cannot be used to bypass the WAF check order: the lock answers first, normal requests are unchanged.
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

ipCheck('a locked address is refused with 429 (not 403) even when it also sends an attack', $areq([], $srvA + ['REQUEST_URI' => "/administrator/index.php?q=1'+UNION+SELECT"])['status'] === '429 Too Many Requests');
// The unlock tool against the plugin's own store.
$aReset();
for ($i = 0; $i < 5; $i++) {
    $aFail([], $srvA);
}

$lockedBefore = $areq([], $srvA)['blocked'];
$cliRun = static function (array $args) {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg((string) realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/admin_unlock.php'));

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    exec($cmd . ' 2>&1', $o, $c);

    return $c;
};
$cliCode = $cliRun(['--root=' . JPATH_ROOT, '--ip=8.8.8.8']);
ipCheck('the unlock tool works on the plugin\'s real store: a locked address is let in again', $lockedBefore === true && $cliCode === 0 && $areq([], $srvA)['blocked'] === false);
$aReset();

echo "== Admin login protection: unlock CLI ==\n";

$ucli  = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/admin_unlock.php');
$uroot = sys_get_temp_dir() . '/cps-unlock-' . bin2hex(random_bytes(4));
mkdir($uroot . '/cache/colorpack_shield/admin', 0777, true);
$urun = static function (array $args) use ($ucli): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($ucli);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    $o = [];
    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o) . "\n"];
};
$ustore = new FileStateStore($uroot . '/cache/colorpack_shield/admin');
$upol   = new LockoutPolicy(AdminProtectConfig::fromArray([]), $ustore);
$nowU   = time();
for ($i = 0; $i < 5; $i++) {
    $upol->recordFailure('8.8.8.8', 'a', $nowU);
    $upol->recordFailure('2606:4700:4700::7', 'a', $nowU);
}

$upol->recordFailure('9.9.9.9', 'a', $nowU);
$ustore->mutate('rate:8.8.8.8', $nowU, static fn (?array $e): array => ['n' => 9, 'exp' => $nowU + 300]);
$ustore->mutate('known:5', $nowU, static fn (?array $e): array => ['ips' => ['abc'], 'exp' => $nowU + 300]);

[$code, $t] = $urun(["--root=$uroot", '--list']);
ipCheck('--list shows locked addresses with the time left and the address still counting', $code === 0 && preg_match('/^8\.8\.8\.8\s+LOCKED for \d+ more seconds \(strike 1\)/m', $t) === 1 && str_contains($t, '9.9.9.9') && str_contains($t, '1 recent failure(s), not locked') && str_contains($t, '2606:4700:4700:0000::/64'));
[$code, $t] = $urun(["--root=$uroot", '--ip=8.8.8.8']);
$v6key = 'ip:' . LockoutPolicy::bucket('2606:4700:4700::7');
ipCheck('--ip lifts one address (lock and speed counter) and leaves the others', $code === 0 && str_contains($t, 'Lifted') && $ustore->get('ip:8.8.8.8', $nowU) === null && $ustore->get('rate:8.8.8.8', $nowU) === null && $ustore->get($v6key, $nowU) !== null && $ustore->get('ip:9.9.9.9', $nowU) !== null);
[$code, $t] = $urun(["--root=$uroot", '--ip=8.8.8.8']);
ipCheck('--ip on an address with nothing stored says so', $code === 0 && str_contains($t, 'Nothing was stored'));
[$code, $t] = $urun(["--root=$uroot", '--ip=not-an-ip']);
ipCheck('--ip with junk: error exit 1', $code === 1 && str_contains($t, 'not an IP'));
$ustore->mutate('rate:8.8.8.8', $nowU, static fn (?array $e): array => ['n' => 9, 'exp' => $nowU + 300]);
[$code, $t] = $urun(["--root=$uroot", '--all']);
ipCheck('--all lifts every lock and counter but keeps the remembered administrator data', $code === 0 && str_contains($t, 'Lifted') && $ustore->entries('ip:', $nowU) === [] && $ustore->get('rate:8.8.8.8', $nowU) === null && $ustore->get('known:5', $nowU) !== null);
[$code, $t] = $urun(["--root=$uroot", '--everything']);
ipCheck('--everything forgets all stored state', $code === 0 && str_contains($t, 'Forgot') && $ustore->get('known:5', $nowU) === null);
[$code, $t] = $urun(["--root=$uroot", '--list']);
ipCheck('--list on an empty store says nothing is locked', $code === 0 && str_contains($t, 'No address is locked'));
[$code, $t] = $urun(['--root=' . $uroot . '/missing', '--list']);
ipCheck('a root without state is not an error', $code === 0 && str_contains($t, 'Nothing to do'));
ipCheck('no action or two actions: usage and exit 1', $urun(["--root=$uroot"])[0] === 1 && $urun(["--root=$uroot", '--list', '--all'])[0] === 1 && $urun(['--list'])[0] === 1);
ipCheck('--help exits 0', $urun(['--help'])[0] === 0);
exec('rm -rf ' . escapeshellarg($uroot));
$aReset();
