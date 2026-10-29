<?php
/**
 * Administrator protection, foundation (PLAN-ADMIN-PROTECTION.md A0): the state
 * stores, the settings clamp, the lockout policy, the alert throttle and the
 * known-address memory. Pure PHP, no Joomla. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminProtectConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AlertThrottle;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\KnownIps;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockDecision;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LoginRateLimit;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\MemoryStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\StateStore;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;

echo "== Admin protection: state stores ==\n";

$apDir = sys_get_temp_dir() . '/cps-ap-' . bin2hex(random_bytes(4));
mkdir($apDir);
$T = 1_800_000_000;

/** @param callable():StateStore $make */
$storeSuite = static function (string $label, callable $make) use ($T): void {
    $s = $make();
    ipCheck("$label: an unknown key is absent", $s->get('k', $T) === null);
    $e = $s->mutate('k', $T, static fn (?array $e): array => ['n' => 1, 'exp' => $T + 100]);
    ipCheck("$label: mutate stores and returns the entry", $e['n'] === 1 && $s->get('k', $T)['n'] === 1 && $s->healthy());
    ipCheck("$label: a mutation sees the live entry", $s->mutate('k', $T, static fn (?array $e): array => ['n' => $e['n'] + 1, 'exp' => $T + 100])['n'] === 2);
    ipCheck("$label: an entry without 'exp' still expires (default one hour)", (function () use ($s, $T) {
        $s->mutate('noexp', $T, static fn (?array $e): array => ['n' => 1]);

        return $s->get('noexp', $T + 3599) !== null && $s->get('noexp', $T + 3601) === null;
    })());
    ipCheck("$label: expired entries are gone, and a mutation sees null for them", $s->get('k', $T + 100) === null && $s->mutate('k', $T + 200, static fn (?array $e): array => ['seen' => $e === null, 'exp' => $T + 300])['seen'] === true);
    ipCheck("$label: returning null deletes", $s->mutate('k', $T + 200, static fn (?array $e): ?array => null) === null && $s->get('k', $T + 200) === null);

    $weird = ["ключ\n\"quote\"", str_repeat('x', 5000), "emoji \u{1F512}", '', "a\0b", '../../etc/passwd'];
    $ok    = true;

    foreach ($weird as $i => $k) {
        $s->mutate($k, $T, static fn (?array $e): array => ['i' => $i, 'exp' => $T + 100]);
        $ok = $ok && ($s->get($k, $T)['i'] ?? -1) === $i;
    }

    ipCheck("$label: odd keys (unicode, newline, NUL, 5000 chars, path-like) round-trip and stay separate", $ok);
};

$storeSuite('memory store', static fn (): StateStore => new MemoryStateStore());
$storeSuite('file store', static fn (): StateStore => new FileStateStore($apDir . '/a-' . bin2hex(random_bytes(3))));

$dir = $apDir . '/files';
$fs  = new FileStateStore($dir);
$fs->mutate('x', $T, static fn (?array $e): array => ['v' => 1, 'exp' => $T + 100]);
ipCheck('file store: the folder is private (0700) and the files are 0600', (fileperms($dir) & 0777) === 0700 && array_reduce(glob($dir . '/*.json') ?: [], static fn (bool $c, string $f): bool => $c && (fileperms($f) & 0777) === 0600, true));
for ($i = 0; $i < 200; $i++) {
    $fs->mutate("spread$i", $T, static fn (?array $e): array => ['i' => $i, 'exp' => $T + 100]);
}

ipCheck('file store: keys spread over all 16 shards', count(glob($dir . '/s*.php')) === 16);
ipCheck('file store: a second instance sees the same data', (new FileStateStore($dir))->get('x', $T)['v'] === 1);
ipCheck('file store: nothing but shard files lives in the folder', array_map('basename', glob($dir . '/*') ?: []) === array_map('basename', glob($dir . '/s*.php') ?: []));

// Bounds.
$bd = new FileStateStore($apDir . '/bound', 40, 262144, 1);
for ($i = 0; $i < 400; $i++) {
    $bd->mutate("k$i", $T, static fn (?array $e): array => ['i' => $i, 'exp' => $T + 1000 + $i]);
}

$shardJson = static fn (string $f): mixed => json_decode(substr((string) file_get_contents($f), strlen(FileStateStore::HEADER)), true);
$decoded   = $shardJson($apDir . '/bound/s0.php');
ipCheck('file store: at most maxEntries entries per shard (40 of 400 kept)', count($decoded) === 40);
ipCheck('file store: the ones kept are the longest-lived', isset($decoded['k399']) && !isset($decoded['k0']) && $bd->get('k399', $T) !== null && $bd->get('k0', $T) === null);

$by       = new FileStateStore($apDir . '/bytes', 100000, 2048, 1);
$alwaysOk = true;

for ($i = 0; $i < 300; $i++) {
    $by->mutate("k$i", $T, static fn (?array $e): array => ['pad' => str_repeat('p', 40), 'exp' => $T + 1000 + $i]);

    if ($i >= 40) {   // after every single write the 20 newest entries must all still be there
        for ($j = $i - 19; $j <= $i; $j++) {
            $alwaysOk = $alwaysOk && $by->get("k$j", $T) !== null;
        }
    }
}

ipCheck('file store: a shard never grows past maxBytes, and only the oldest entries are dropped (the newest 20 are always present)', filesize($apDir . '/bytes/s0.php') <= 2048 + strlen(FileStateStore::HEADER) && $alwaysOk && $by->get('k0', $T) === null);
$one = new FileStateStore($apDir . '/big', 10, 100, 1);
$huge = $one->mutate('huge', $T, static fn (?array $e): array => ['pad' => str_repeat('z', 5000), 'exp' => $T + 100]);
ipCheck('file store: one entry bigger than the whole shard is not kept (it could never be read back) and the file stays valid', $one->get('huge', $T) === null && $shardJson($apDir . '/big/s0.php') === []);

// Damage.
file_put_contents($dir . '/s0.php', '{"broken');
$all = glob($dir . '/s*.php');
foreach ($all as $f) {
    file_put_contents($f, '{"broken');
}

ipCheck('file store: a corrupt file reads as empty', $fs->get('x', $T) === null && $fs->healthy());
ipCheck('file store: …and the next write repairs it', $fs->mutate('x', $T, static fn (?array $e): array => ['v' => 2, 'exp' => $T + 100])['v'] === 2 && $fs->get('x', $T)['v'] === 2);
foreach (glob($dir . '/s*.php') as $f) {
    file_put_contents($f, str_repeat('a', 600000));
}

ipCheck('file store: an oversized junk file is ignored and replaced', $fs->mutate('x', $T, static fn (?array $e): array => ['v' => 3, 'exp' => $T + 100])['v'] === 3);
foreach (glob($dir . '/s*.php') as $f) {
    file_put_contents($f, '[1,2,3]');
}

ipCheck('file store: JSON of the wrong shape is ignored', $fs->get('x', $T) === null && $fs->mutate('x', $T, static fn (?array $e): array => ['v' => 4, 'exp' => $T + 100])['v'] === 4);

// Unusable storage: never throws, reports unhealthy, answers null.
file_put_contents($apDir . '/afile', 'x');
$bad = new FileStateStore($apDir . '/afile/sub');
$threw = false;

try {
    $r1 = $bad->mutate('k', $T, static fn (?array $e): array => ['exp' => $T + 10]);
    $h1 = $bad->healthy();
    $r2 = $bad->get('k', $T);
} catch (Throwable) {
    $threw = true;
}

ipCheck('file store: a folder that cannot be created → null, unhealthy, no exception', !$threw && $r1 === null && $r2 === null && !$h1);

if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    mkdir($apDir . '/ro');
    chmod($apDir . '/ro', 0500);
    $ro = new FileStateStore($apDir . '/ro');
    ipCheck('file store: a read-only folder → null and unhealthy, no exception', $ro->mutate('k', $T, static fn (?array $e): array => ['exp' => $T + 10]) === null && !$ro->healthy());
    chmod($apDir . '/ro', 0700);
}

$mem = new MemoryStateStore();
$mem->failing = true;
ipCheck('memory store can simulate a failure (null + unhealthy)', $mem->mutate('k', $T, static fn (?array $e): array => ['exp' => $T + 10]) === null && $mem->get('k', $T) === null && !$mem->healthy());

// Concurrency: several processes hammering one key and different keys.
$cdir   = $apDir . '/conc';
$child  = $apDir . '/child.php';
$srcDir = realpath(__DIR__ . '/../plugins/system/colorpack_shield/src/AdminProtect');
file_put_contents($child, "<?php\ndefine('COLORPACK_SHIELD_TEST', 1);\nrequire '$srcDir/StateStore.php';\nrequire '$srcDir/FileStateStore.php';\n\$s = new Colorpack\\Plugin\\System\\ColorpackShield\\AdminProtect\\FileStateStore(\$argv[1]);\nfor (\$i = 0; \$i < (int) \$argv[2]; \$i++) {\n    \$s->mutate('shared', time(), static fn (?array \$e): array => ['n' => (\$e['n'] ?? 0) + 1, 'exp' => time() + 600]);\n    \$s->mutate('own' . \$argv[3], time(), static fn (?array \$e): array => ['n' => (\$e['n'] ?? 0) + 1, 'exp' => time() + 600]);\n}\n");
$procs = [];

for ($p = 0; $p < 6; $p++) {
    $procs[] = proc_open([PHP_BINARY, $child, $cdir, '40', (string) $p], [['file', '/dev/null', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']], $pipes);
}

foreach ($procs as $pr) {
    proc_close($pr);
}

$cs = new FileStateStore($cdir);
ipCheck('concurrency: 6 processes × 40 updates of one key lose nothing (240)', $cs->get('shared', time())['n'] === 240);
ipCheck('concurrency: each process\'s own key is intact too (40 each)', array_sum(array_map(static fn (int $p): int => $cs->get("own$p", time())['n'] ?? 0, range(0, 5))) === 240);

// purge
$pm = new MemoryStateStore();
foreach (['ip:1', 'ip:2', 'user:a', 'known:5'] as $k) {
    $pm->mutate($k, $T, static fn (?array $e): array => ['exp' => $T + 100]);
}

ipCheck('memory store purge removes exactly the keys with the prefix', $pm->purge('ip:', $T) === 2 && $pm->keys() === ['user:a', 'known:5']);
$pf = new FileStateStore($apDir . '/purge');
foreach (['ip:1', 'ip:2', 'ip:3', 'user:a', 'known:5'] as $k) {
    $pf->mutate($k, $T, static fn (?array $e): array => ['exp' => $T + 100]);
}

ipCheck('file store purge removes exactly the keys with the prefix, across all shards', $pf->purge('ip:', $T) === 3 && $pf->get('ip:1', $T) === null && $pf->get('ip:3', $T) === null && $pf->get('user:a', $T) !== null && $pf->get('known:5', $T) !== null && $pf->healthy());
ipCheck('file store purge of nothing and on a missing folder is harmless', $pf->purge('zzz:', $T) === 0 && (new FileStateStore($apDir . '/nowhere'))->purge('ip:', $T) === 0);
$pm->failing = true;
ipCheck('a failing memory store purges nothing', $pm->purge('user:', $T) === 0 && !$pm->healthy());
ipCheck('the shard files are private: ".php" with a 404 header, and answer nothing when executed', (function () use ($pf, $apDir) {
    $f = glob($apDir . '/purge/s*.php')[0] ?? '';

    if ($f === '' || !str_starts_with((string) file_get_contents($f), FileStateStore::HEADER)) {
        return false;
    }

    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($f) . ' 2>&1', $out);

    return implode('', $out) === '';
})());
ipCheck('a shard without the header (foreign or tampered) reads as empty', (function () use ($apDir, $T) {
    $d = $apDir . '/foreign';
    $s = new FileStateStore($d);
    $s->mutate('k', $T, static fn (?array $e): array => ['exp' => $T + 100]);

    foreach (glob($d . '/s*.php') as $f) {
        file_put_contents($f, substr((string) file_get_contents($f), strlen(FileStateStore::HEADER)));
    }

    return $s->get('k', $T) === null;
})());

echo "== Admin protection: settings ==\n";

$d = AdminProtectConfig::fromArray([]);
ipCheck('defaults: lockout on, 5 failures / 600 s / 15 min / 24 h, rate 10, alerts on, MFA off, group 8, grace 7', $d->lockoutEnabled && $d->maxFailures === 5 && $d->failureWindow === 600 && $d->lockMinutes === 15 && $d->lockMaxHours === 24 && $d->ratePerMinute === 10 && $d->alertNewAdmin && $d->alertNewIp && $d->alertLockouts && $d->mfaEnforce === 'off' && $d->mfaGroups === [8] && $d->mfaGraceDays === 7);
$c = AdminProtectConfig::fromArray(['login_max_failures' => '0', 'login_failure_window' => '5', 'login_lock_minutes' => '999999', 'login_lock_max_hours' => '99999', 'login_rate_per_minute' => '-5', 'mfa_grace_days' => '9999']);
ipCheck('numbers are clamped: 0 failures → 1, window 5 → 60, lock minutes → 1440, max hours → 168, negative rate → 0, grace → 90', $c->maxFailures === 1 && $c->failureWindow === 60 && $c->lockMinutes === 1440 && $c->lockMaxHours === 168 && $c->ratePerMinute === 0 && $c->mfaGraceDays === 90);
$g = AdminProtectConfig::fromArray(['login_max_failures' => 'lots', 'login_failure_window' => [], 'login_lock_minutes' => null, 'login_rate_per_minute' => true, 'mfa_grace_days' => '7abc', 'login_lock_max_hours' => 'x']);
ipCheck('garbage numbers fall back to the defaults (no accidental "off" or "forever")', $g->maxFailures === 5 && $g->failureWindow === 600 && $g->lockMinutes === 15 && $g->ratePerMinute === 10 && $g->mfaGraceDays === 7 && $g->lockMaxHours === 24);
ipCheck('numeric strings and floats are accepted', AdminProtectConfig::fromArray(['login_max_failures' => '8', 'login_lock_minutes' => 20.9])->maxFailures === 8 && AdminProtectConfig::fromArray(['login_lock_minutes' => 20.9])->lockMinutes === 20);
ipCheck('the longest lock is never shorter than the first lock', AdminProtectConfig::fromArray(['login_lock_minutes' => 600, 'login_lock_max_hours' => 1])->lockMaxHours === 10);
foreach ([['0', false], ['1', true], [0, false], [1, true], [true, true], [false, false], ['false', false], ['yes', true], ['', true], [null, true], ['banana', true]] as [$in, $want]) {
    ipCheck('switch value ' . json_encode($in) . ' → ' . json_encode($want), AdminProtectConfig::fromArray(['login_lockout' => $in, 'alert_new_ip' => $in])->lockoutEnabled === $want && AdminProtectConfig::fromArray(['alert_new_ip' => $in])->alertNewIp === $want);
}
foreach (['off', 'warn', 'enforce', ' WARN ', 'Enforce'] as $m) {
    ipCheck("mfa_enforce '$m' is understood", in_array(AdminProtectConfig::fromArray(['mfa_enforce' => $m])->mfaEnforce, ['off', 'warn', 'enforce'], true) && AdminProtectConfig::fromArray(['mfa_enforce' => $m])->mfaEnforce === strtolower(trim($m)));
}
ipCheck('an unknown mfa_enforce value means off (never an accidental lock-in)', AdminProtectConfig::fromArray(['mfa_enforce' => 'always'])->mfaEnforce === 'off' && AdminProtectConfig::fromArray(['mfa_enforce' => 1])->mfaEnforce === 'off' && AdminProtectConfig::fromArray(['mfa_enforce' => ['x']])->mfaEnforce === 'off');
ipCheck('mfa_groups: array, comma text, junk and empty', AdminProtectConfig::fromArray(['mfa_groups' => ['8', '7', 7, 'x', '0', -3]])->mfaGroups === [8, 7] && AdminProtectConfig::fromArray(['mfa_groups' => '8, 6 ,6'])->mfaGroups === [8, 6] && AdminProtectConfig::fromArray(['mfa_groups' => 'none'])->mfaGroups === [8] && AdminProtectConfig::fromArray(['mfa_groups' => []])->mfaGroups === [8]);

echo "== Admin protection: lockout policy ==\n";

$pol = static function (array $cfg = [], ?StateStore $s = null) use (&$store): LockoutPolicy {
    $store = $s ?? new MemoryStateStore();

    return new LockoutPolicy(AdminProtectConfig::fromArray($cfg), $store);
};
$A = '8.8.8.8';
$B = '9.9.9.9';

ipCheck('bucket: IPv4 as is, junk → null', LockoutPolicy::bucket($A) === '8.8.8.8' && LockoutPolicy::bucket(' 8.8.8.8 ') === '8.8.8.8' && LockoutPolicy::bucket('') === null && LockoutPolicy::bucket('nope') === null && LockoutPolicy::bucket('1.2.3') === null && LockoutPolicy::bucket('999.1.1.1') === null && LockoutPolicy::bucket("8.8.8.8\n") === '8.8.8.8');
ipCheck('bucket: IPv4-mapped IPv6 collapses to IPv4', LockoutPolicy::bucket('::ffff:8.8.8.8') === '8.8.8.8' && LockoutPolicy::bucket('::FFFF:808:808') === '8.8.8.8');
ipCheck('bucket: IPv6 by /64, in any spelling', LockoutPolicy::bucket('2001:db8:1:2::1') === LockoutPolicy::bucket('2001:DB8:1:2:ffff:ffff:ffff:ffff') && LockoutPolicy::bucket('2001:db8:1:2::1') === LockoutPolicy::bucket('2001:db8:0001:0002:0:0:0:9') && LockoutPolicy::bucket('2001:db8:1:2::1') !== LockoutPolicy::bucket('2001:db8:1:3::1') && LockoutPolicy::bucket('2001:db8:1:2::1') === '2001:0db8:0001:0002::/64');

$p = $pol();

for ($i = 1; $i <= 4; $i++) {
    $r = $p->recordFailure($A, 'admin', $T + $i);
}

ipCheck('4 failures: counted, not locked', $r['failures'] === 4 && !$r['locked'] && $r['bucket'] === $A);
$r = $p->recordFailure($A, 'admin', $T + 5);
ipCheck('the 5th failure locks for 15 minutes', $r['locked'] && $r['lockUntil'] === $T + 5 + 900 && $r['strikes'] === 1 && $r['failures'] === 0);
$r = $p->recordFailure($A, 'admin', $T + 100);
ipCheck('attempts during a lock do not extend it or add strikes', $r['locked'] && $r['lockUntil'] === $T + 5 + 900 && $r['strikes'] === 1);
$cl = new ClientIp($A, $A, ClientIp::VIA_CLOUDFLARE);
$ok = new ClientIp($A, '10.0.0.1', ClientIp::VIA_PROXY);
$dec = $p->decide($ok, CloudflareRanges::bundled(), [], true, $T + 100);
ipCheck('decide: a public address, real IP verified → LOCKED with the remaining seconds', $dec->state === LockDecision::LOCKED && $dec->retryAfter === 805 && $dec->blocks());
ipCheck('decide: another address is not affected', $p->decide(new ClientIp($B, $B, ClientIp::VIA_PROXY), CloudflareRanges::bundled(), [], true, $T + 100)->state === LockDecision::OK);
ipCheck('decide: after the lock ends the address is free', $p->decide($ok, CloudflareRanges::bundled(), [], true, $T + 5 + 900)->state === LockDecision::OK);

// Doubling, memory, cap.
$p = $pol();
$locks = [];
$t = $T;

for ($round = 1; $round <= 8; $round++) {
    for ($i = 0; $i < 5; $i++) {
        $r = $p->recordFailure($A, 'x', $t);
    }

    $locks[] = $r['lockUntil'] - $t;
    $t = $r['lockUntil'] + 1;   // the lock has ended; offend again straight away
}

ipCheck('repeat offences double the lock: 15, 30, 60, 120, 240, 480, 960 min, then capped at 24 h', $locks === [900, 1800, 3600, 7200, 14400, 28800, 57600, 86400]);
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $r = $p->recordFailure($A, 'x', $T);
}

$after = $r['lockUntil'] + 24 * 3600 + 10;
for ($i = 0; $i < 5; $i++) {
    $r2 = $p->recordFailure($A, 'x', $after);
}

ipCheck('after a quiet day the strike memory is gone: the next lock is the first one again', $r2['strikes'] === 1 && $r2['lockUntil'] - $after === 900);
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $r = $p->recordFailure($A, 'x', $T);
}

for ($i = 0; $i < 5; $i++) {
    $r2 = $p->recordFailure($A, 'x', $r['lockUntil'] + 3600);
}

ipCheck('…but one hour after a lock it still remembers (second strike = 30 min)', $r2['strikes'] === 2 && $r2['lockUntil'] - ($r['lockUntil'] + 3600) === 1800);

// Window.
$p = $pol();
$r = ['locked' => false];
for ($i = 0; $i < 20; $i++) {
    $r = $p->recordFailure($A, 'x', $T + $i * 200);   // one failure every 200 s: never 5 inside 600 s
}

ipCheck('slow failures (one per 200 s) never reach 5 inside the 600 s window', !$r['locked'] && $r['failures'] <= 3);
$p = $pol(['login_max_failures' => 3, 'login_failure_window' => 60]);
$p->recordFailure($A, 'x', $T);
$p->recordFailure($A, 'x', $T + 30);
ipCheck('the window and the limit are settings (3 in 60 s)', $p->recordFailure($A, 'x', $T + 59)['locked'] === true);
$p = $pol(['login_max_failures' => 3, 'login_failure_window' => 60]);
$p->recordFailure($A, 'x', $T);
$p->recordFailure($A, 'x', $T + 30);
ipCheck('…and a failure after the window does not count with the old ones', $p->recordFailure($A, 'x', $T + 61)['locked'] === false);

// Success, disabled, junk.
$p = $pol();
for ($i = 0; $i < 4; $i++) {
    $p->recordFailure($A, 'x', $T + $i);
}

$p->recordSuccess($A, $T + 10);
for ($i = 0; $i < 4; $i++) {
    $r = $p->recordFailure($A, 'x', $T + 20 + $i);
}

ipCheck('a successful login clears the counter (4 + success + 4 does not lock)', !$r['locked']);
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $p->recordFailure($A, 'x', $T);
}

$p->recordSuccess($A, $T + 1);
ipCheck('…but cannot undo a lock', $p->decide($ok, [], [], true, $T + 2)->state === LockDecision::LOCKED);
$p = $pol(['login_lockout' => 0]);
for ($i = 0; $i < 20; $i++) {
    $r = $p->recordFailure($A, 'x', $T);
}

$sShared = new MemoryStateStore();
$pOn     = new LockoutPolicy(AdminProtectConfig::fromArray([]), $sShared);
for ($i = 0; $i < 5; $i++) {
    $pOn->recordFailure($A, 'x', $T);
}

$pOff = new LockoutPolicy(AdminProtectConfig::fromArray(['login_lockout' => 0]), $sShared);
ipCheck('switching lockout off lifts existing locks at once', $pOn->decide($ok, [], [], true, $T + 1)->state === LockDecision::LOCKED && $pOff->decide($ok, [], [], true, $T + 1)->state === LockDecision::OK);
ipCheck('lockout switched off: nothing counted, nothing locked, nothing stored', !$r['locked'] && $r['failures'] === 0 && $store->count() === 0 && $p->decide($ok, [], [], true, $T)->state === LockDecision::OK);
$p = $pol();
ipCheck('a non-IP is never counted', $p->recordFailure('garbage', 'x', $T)['bucket'] === null && $store->count() === 0);
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $r = $p->recordFailure('2001:db8:1:2::' . dechex($i + 1), 'x', $T);
}

ipCheck('IPv6 addresses of one /64 share one counter', $r['locked']);
ipCheck('…and a neighbouring /64 is separate', $p->recordFailure('2001:db8:1:3::1', 'x', $T)['failures'] === 1);

// Safety: lock recorded but enforced only for a real single visitor.
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $p->recordFailure('127.0.0.1', 'x', $T);
    $p->recordFailure('10.1.2.3', 'x', $T);
    $p->recordFailure('104.16.0.5', 'x', $T);
    $p->recordFailure('172.31.0.9', 'x', $T);
}

$cf    = CloudflareRanges::bundled();
$dLoop = $p->decide(new ClientIp('127.0.0.1', '127.0.0.1', ClientIp::VIA_PROXY), $cf, [], true, $T + 1);
$dPriv = $p->decide(new ClientIp('10.1.2.3', '10.1.2.3', ClientIp::VIA_PROXY), $cf, [], true, $T + 1);
$dCf   = $p->decide(new ClientIp('104.16.0.5', '104.16.0.5', ClientIp::VIA_PROXY), $cf, [], true, $T + 1);
$dPrx  = $p->decide(new ClientIp('172.31.0.9', '172.31.0.9', ClientIp::VIA_PROXY), $cf, ['172.31.0.0/16'], true, $T + 1);
ipCheck('a locked loopback address is only OBSERVED (every visitor may look like it)', $dLoop->state === LockDecision::OBSERVE && $dLoop->reason === 'shared_address' && !$dLoop->blocks());
ipCheck('a locked private address is only observed', $dPriv->state === LockDecision::OBSERVE && $dPriv->reason === 'shared_address');
ipCheck('a locked Cloudflare edge address is only observed', $dCf->state === LockDecision::OBSERVE && $dCf->reason === 'shared_address');
ipCheck('a locked address of the site\'s own proxy is only observed', $dPrx->state === LockDecision::OBSERVE);
ipCheck('observing still reports how long the lock would last', $dLoop->retryAfter > 0);
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $p->recordFailure($A, 'x', $T);
}

ipCheck('real IP check not passed (false) → observe only', ($d1 = $p->decide($ok, $cf, [], false, $T + 1))->state === LockDecision::OBSERVE && $d1->reason === 'real_ip_not_verified');
ipCheck('real IP check never run (null) → observe only', $p->decide($ok, $cf, [], null, $T + 1)->state === LockDecision::OBSERVE);
ipCheck('Cloudflare without a usable header (fell back to the edge) → observe only', $p->decide(new ClientIp($A, $A, ClientIp::VIA_CLOUDFLARE_NOHEADER), $cf, [], true, $T + 1)->state === LockDecision::OBSERVE);
ipCheck('a verified public visitor behind Cloudflare IS locked', $p->decide($cl, $cf, [], true, $T + 1)->state === LockDecision::LOCKED);

// A lock-out must not be a weapon.
$p = $pol();
for ($i = 0; $i < 5; $i++) {
    $p->recordFailure('8.8.4.4', 'admin', $T + $i);
}

ipCheck('an attacker locking his own address with the admin\'s user name does not lock the admin\'s address', $p->decide(new ClientIp('8.8.4.4', '8.8.4.4', ClientIp::VIA_PROXY), $cf, [], true, $T + 10)->blocks() && !$p->decide(new ClientIp($B, $B, ClientIp::VIA_PROXY), $cf, [], true, $T + 10)->blocks());
$p = $pol();
for ($i = 0; $i < 300; $i++) {
    $p->recordFailure('20.' . intdiv($i, 250) . '.' . ($i % 250) . '.7', 'Admin', $T + $i);
}

ipCheck('300 failures for one user name from 300 addresses lock none of the OTHER addresses', !$p->decide(new ClientIp($B, $B, ClientIp::VIA_PROXY), $cf, [], true, $T + 400)->blocks());

// Pressure on a name.
$p = $pol();
for ($i = 0; $i < 60; $i++) {
    $r = $p->recordFailure($A, 'victim', $T + $i * 5);   // one address, many failures
}

ipCheck('pressure stays 0 when all the failures come from one address', $r['pressure'] === 0);
$p = $pol();
$pr = [];
for ($i = 0; $i < 30; $i++) {
    $r = $p->recordFailure('30.0.0.' . ($i % 6 + 1), 'Victim', $T + $i);
    $pr[] = $r['pressure'];
}

ipCheck('pressure rises to 1 (≥10 failures, ≥3 addresses) and 2 (≥25, ≥5 addresses) for a distributed attack on one name', $pr[8] === 0 && $pr[9] === 1 && max($pr) === 2 && $pr[29] === 2);
$p = $pol();
for ($i = 0; $i < 6; $i++) {   // 6 + 6 failures: only counted together do they reach the pressure threshold (10)
    $r = $p->recordFailure('31.0.0.' . ($i % 4 + 1), 'ADMIN', $T + $i);
    $r2 = $p->recordFailure('31.0.0.' . ($i % 4 + 1), 'admin ', $T + $i);
}

ipCheck('user names are compared case-insensitively and trimmed', $r['pressure'] >= 1 && $r2['pressure'] >= 1);
ipCheck('an empty user name adds no pressure; hostile names do not break anything', $pol()->recordFailure($A, '', $T)['pressure'] === 0 && $pol()->recordFailure($A, str_repeat("\x00é'\"", 500), $T)['failures'] === 1);

// Storage trouble means no lock.
$bad = new MemoryStateStore();
$bad->failing = true;
$p = $pol([], $bad);
for ($i = 0; $i < 10; $i++) {
    $r = $p->recordFailure($A, 'x', $T);
}

// A store that runs the change but cannot write it back (disk full, lost lock).
$lossy = new class () implements StateStore {
    public function get(string $key, int $now): ?array
    {
        return null;
    }

    public function mutate(string $key, int $now, callable $fn): ?array
    {
        $fn(null);

        return null;
    }

    public function purge(string $prefix, int $now): int
    {
        return 0;
    }

    public function healthy(): bool
    {
        return false;
    }
};
$p = $pol([], $lossy);
for ($i = 0; $i < 10; $i++) {
    $r = $p->recordFailure($A, 'x', $T);
}

ipCheck('a store that cannot write back: no lock, no exception', !$r['locked']);
ipCheck('a failing store: failures are not counted, nothing is locked, nothing throws', !$r['locked'] && $p->decide($ok, $cf, [], true, $T)->state === LockDecision::OK);

echo "== Admin protection: alert throttle ==\n";

$ms = new MemoryStateStore();
ipCheck('the first alert is sent (0 held back)', AlertThrottle::claim($ms, 'lock', $T, 3600) === ['send' => true, 'suppressed' => 0]);
ipCheck('a second one inside the interval is held back', AlertThrottle::claim($ms, 'lock', $T + 10, 3600)['send'] === false);
AlertThrottle::claim($ms, 'lock', $T + 20, 3600);
AlertThrottle::claim($ms, 'lock', $T + 30, 3600);
ipCheck('after the interval the next alert is sent and says how many were held back (3)', AlertThrottle::claim($ms, 'lock', $T + 3600, 3600) === ['send' => true, 'suppressed' => 3]);
ipCheck('…and the count starts again', AlertThrottle::claim($ms, 'lock', $T + 3601, 3600) === ['send' => false, 'suppressed' => 0] && AlertThrottle::claim($ms, 'lock', $T + 7200, 3600) === ['send' => true, 'suppressed' => 1]);
ipCheck('different kinds do not throttle each other', AlertThrottle::claim($ms, 'newip', $T + 7201, 3600)['send'] === true);
$bad = new MemoryStateStore();
$bad->failing = true;
ipCheck('a failing store sends nothing (fail closed: never a mail flood)', AlertThrottle::claim($bad, 'lock', $T, 3600) === ['send' => false, 'suppressed' => 0]);
$fsA = new FileStateStore($apDir . '/alerts');
ipCheck('a store that runs the change but cannot write it back sends nothing (otherwise every request would mail)', AlertThrottle::claim($lossy, 'lock', $T, 3600) === ['send' => false, 'suppressed' => 0]);
ipCheck('the throttle works on the file store, across instances', AlertThrottle::claim($fsA, 'k', $T, 600)['send'] === true && AlertThrottle::claim(new FileStateStore($apDir . '/alerts'), 'k', $T + 5, 600)['send'] === false);
ipCheck('the throttle entry expires on its own (a month later the first alert is sent again, nothing held back)', AlertThrottle::claim($fsA, 'k', $T + 40 * 86400, 600) === ['send' => true, 'suppressed' => 0]);

echo "== Admin protection: known addresses ==\n";

$ms = new MemoryStateStore();
$salt = 'site-salt';
ipCheck('first ever login: remembered silently (learning)', KnownIps::observe($ms, 5, $A, $salt, $T) === KnownIps::LEARNING);
ipCheck('same address again: known', KnownIps::observe($ms, 5, $A, $salt, $T + 1) === KnownIps::KNOWN);
ipCheck('a new address: new (alert), then known', KnownIps::observe($ms, 5, $B, $salt, $T + 2) === KnownIps::NEW && KnownIps::observe($ms, 5, $B, $salt, $T + 3) === KnownIps::KNOWN);
ipCheck('other users are separate', KnownIps::observe($ms, 6, $B, $salt, $T + 4) === KnownIps::LEARNING);
$ms = new MemoryStateStore();
KnownIps::observe($ms, 1, '1.0.0.1', $salt, $T);
for ($i = 2; $i <= 11; $i++) {
    KnownIps::observe($ms, 1, "1.0.0.$i", $salt, $T + $i);
}

ipCheck('at most 10 addresses are remembered: the oldest is forgotten (the 11th makes the 1st "new" again)', KnownIps::observe($ms, 1, '1.0.0.1', $salt, $T + 50) === KnownIps::NEW && KnownIps::observe($ms, 1, '1.0.0.11', $salt, $T + 51) === KnownIps::KNOWN);
$ms = new MemoryStateStore();
KnownIps::observe($ms, 1, '1.0.0.1', $salt, $T);
KnownIps::observe($ms, 1, '1.0.0.2', $salt, $T + 1);
KnownIps::observe($ms, 1, '1.0.0.1', $salt, $T + 2);   // refresh .1
for ($i = 3; $i <= 11; $i++) {
    KnownIps::observe($ms, 1, "1.0.0.$i", $salt, $T + $i);
}

ipCheck('using an address keeps it fresh (it is the unused one that is dropped)', KnownIps::observe($ms, 1, '1.0.0.1', $salt, $T + 60) === KnownIps::KNOWN && KnownIps::observe($ms, 1, '1.0.0.2', $salt, $T + 61) === KnownIps::NEW);
$ms = new MemoryStateStore();
for ($i = 1; $i <= 10; $i++) {
    KnownIps::observe($ms, 2, "1.0.1.$i", $salt, $T + $i);
}

for ($i = 0; $i < 6; $i++) {
    KnownIps::observe($ms, 2, '1.0.1.1', $salt, $T + 20 + $i);
}

ipCheck('seeing one address over and over does not push the others out of the list', KnownIps::observe($ms, 2, '1.0.1.2', $salt, $T + 40) === KnownIps::KNOWN && KnownIps::observe($ms, 2, '1.0.1.3', $salt, $T + 41) === KnownIps::KNOWN);
ipCheck('without a salt nothing is remembered or reported', KnownIps::observe(new MemoryStateStore(), 5, $A, '', $T) === KnownIps::UNAVAILABLE);
ipCheck('a bad address or user id is unavailable', KnownIps::observe(new MemoryStateStore(), 5, 'junk', $salt, $T) === KnownIps::UNAVAILABLE && KnownIps::observe(new MemoryStateStore(), 0, $A, $salt, $T) === KnownIps::UNAVAILABLE);
$bad = new MemoryStateStore();
$bad->failing = true;
ipCheck('a failing store is unavailable (no alert on a storage problem)', KnownIps::observe($bad, 5, $A, $salt, $T) === KnownIps::UNAVAILABLE && KnownIps::observe($lossy, 5, $A, $salt, $T) === KnownIps::UNAVAILABLE);
$ms = new MemoryStateStore();
KnownIps::observe($ms, 5, '2001:db8:1:2::1', $salt, $T);
ipCheck('IPv6: another address of the same /64 is known', KnownIps::observe($ms, 5, '2001:db8:1:2:abcd::7', $salt, $T + 1) === KnownIps::KNOWN && KnownIps::observe($ms, 5, '2001:db8:1:3::1', $salt, $T + 2) === KnownIps::NEW);
$kf = new FileStateStore($apDir . '/known');
KnownIps::observe($kf, 9, '203.0.113.77', $salt, $T);
$raw = implode('', array_map('file_get_contents', glob($apDir . '/known/s*.php') ?: []));
ipCheck('the file never contains the address, only a salted hash', $raw !== '' && !str_contains($raw, '203.0.113.77') && !str_contains($raw, '203.0.113'));
$kf2 = new FileStateStore($apDir . '/known2');
KnownIps::observe($kf2, 9, '203.0.113.77', 'another-salt', $T);
ipCheck('the hash depends on the salt', implode('', array_map('file_get_contents', glob($apDir . '/known/s*.php') ?: [])) !== implode('', array_map('file_get_contents', glob($apDir . '/known2/s*.php') ?: [])));
ipCheck('a different salt (site secret changed) means "learning" would not repeat, but "new": addresses must be re-learned', KnownIps::observe($kf, 9, '203.0.113.77', 'another-salt', $T + 5) === KnownIps::NEW);

echo "== Admin protection: login speed limit and administrator addresses ==\n";

$rs = new MemoryStateStore();
$h  = [];
for ($i = 1; $i <= 5; $i++) {
    $h[] = LoginRateLimit::hit($rs, '8.8.8.8', 3, $T)['over'];
}

ipCheck('speed limit: attempts 1–3 pass, 4 and 5 are over (3 per minute)', $h === [false, false, false, true, true]);
ipCheck('speed limit: Retry-After is the time to the next minute', LoginRateLimit::hit($rs, '8.8.8.8', 3, $T + 7)['retryAfter'] === 60 - (($T + 7) % 60));
ipCheck('speed limit: the next minute starts afresh', LoginRateLimit::hit($rs, '8.8.8.8', 3, $T + 60)['over'] === false);
ipCheck('speed limit: another address has its own budget', LoginRateLimit::hit($rs, '9.9.9.9', 3, $T)['over'] === false);
ipCheck('speed limit: IPv6 addresses of one /64 share a budget', (function () {
    $s = new MemoryStateStore();
    LoginRateLimit::hit($s, '2a00:1450:4001:81b::1', 1, 1_800_000_000);

    return LoginRateLimit::hit($s, '2a00:1450:4001:81b::2', 1, 1_800_000_000)['over'] === true;
})());
$z = new MemoryStateStore();
ipCheck('speed limit 0 is off: nothing counted, nothing stored', LoginRateLimit::hit($z, '8.8.8.8', 0, $T) === ['over' => false, 'retryAfter' => 0] && LoginRateLimit::hit($z, '8.8.8.8', -5, $T)['over'] === false && $z->count() === 0);
ipCheck('speed limit: a junk address is ignored', LoginRateLimit::hit($z, 'junk', 3, $T)['over'] === false && $z->count() === 0);
$bad = new MemoryStateStore();
$bad->failing = true;
ipCheck('speed limit: a failing store means no limit', LoginRateLimit::hit($bad, '8.8.8.8', 1, $T) === ['over' => false, 'retryAfter' => 0] && LoginRateLimit::hit($bad, '8.8.8.8', 1, $T)['over'] === false);
ipCheck('speed limit: the counter entry expires after the window', (function () use ($T) {
    $s = new MemoryStateStore();
    LoginRateLimit::hit($s, '8.8.8.8', 3, $T);

    return $s->get('rate:8.8.8.8', $T + 130) === null && $s->get('rate:8.8.8.8', $T + 30) !== null;
})());

$as = new MemoryStateStore();
KnownIps::rememberAdminAddress($as, '8.8.8.8', 'salt', $T);
ipCheck('administrator addresses: remembered for 30 days, then forgotten', KnownIps::isAdminAddress($as, '8.8.8.8', 'salt', $T + 29 * 86400) && !KnownIps::isAdminAddress($as, '8.8.8.8', 'salt', $T + 31 * 86400));
ipCheck('administrator addresses: another address, another salt, no salt, junk — all unknown, nothing stored for them', !KnownIps::isAdminAddress($as, '9.9.9.9', 'salt', $T) && !KnownIps::isAdminAddress($as, '8.8.8.8', 'other', $T) && !KnownIps::isAdminAddress($as, '8.8.8.8', '', $T) && (function () use ($T) {
    $s = new MemoryStateStore();
    KnownIps::rememberAdminAddress($s, '8.8.8.8', '', $T);
    KnownIps::rememberAdminAddress($s, 'junk', 'salt', $T);

    return $s->count() === 0;
})());
ipCheck('administrator addresses: IPv6 by /64, and only a salted hash is stored', KnownIps::isAdminAddress((function () use ($T) {
    $s = new MemoryStateStore();
    KnownIps::rememberAdminAddress($s, '2a00:1450:4001:81b::1', 'salt', $T);

    return $s;
})(), '2a00:1450:4001:81b:9::7', 'salt', $T) && !str_contains(implode('', $as->keys()), '8.8.8.8'));

// A shard that carries another first line is not ours, even if the rest is valid JSON.
$hd = new FileStateStore($apDir . '/hdr');
$hd->mutate('k', $T, static fn (?array $e): array => ['v' => 1, 'exp' => $T + 100]);
foreach (glob($apDir . '/hdr/s*.php') as $f) {
    $body = substr((string) file_get_contents($f), strlen(FileStateStore::HEADER));
    file_put_contents($f, str_repeat('x', strlen(FileStateStore::HEADER) - 1) . "\n" . $body);
}

ipCheck('file store: a shard with a different first line is ignored even when the JSON after it is valid', $hd->get('k', $T) === null);

exec('rm -rf ' . escapeshellarg($apDir));
