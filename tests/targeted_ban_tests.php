<?php
/**
 * TargetedBanPolicy: the persistent IP ban armed by a WafResult::MODE_BAN finding (the path
 * shield's "ban" probe mode). Pure PHP, no Joomla - the autoloader registered in
 * plugin_flow_tests.php resolves TargetedBanPolicy/MemoryStateStore/LockoutPolicy on first use.
 * Included by run.php, after path_tests.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\MemoryStateStore;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;

echo "== Targeted ban: a scanner_probe hit under \"ban\" mode persists past one request ==\n";

$T = 1_800_000_000;

$fresh = static fn (): TargetedBanPolicy => new TargetedBanPolicy(new MemoryStateStore());

ipCheck('a clean address is not banned', $fresh()->check('203.0.113.9', $T) === ['banned' => false, 'until' => 0, 'reason' => '']);

$p = $fresh();
$until = $p->ban('203.0.113.9', $T, 3600, 'scanner_probe');
ipCheck('ban() reports the new expiry', $until === $T + 3600);
ipCheck('the address is now banned, with the reason carried through', $p->check('203.0.113.9', $T) === ['banned' => true, 'until' => $T + 3600, 'reason' => 'scanner_probe']);
ipCheck('still banned a second before it lifts', $p->check('203.0.113.9', $T + 3599)['banned'] === true);
ipCheck('no longer banned once the expiry has passed', $p->check('203.0.113.9', $T + 3600)['banned'] === false);

ipCheck('a different address is never affected', $fresh()->ban('203.0.113.9', $T, 3600, 'x') > 0 && $fresh()->check('203.0.113.10', $T)['banned'] === false);

ipCheck('an empty or unbucketable address is never banned, and never reports as banned', (static function () use ($fresh, $T): bool {
    $p = $fresh();

    return $p->ban('', $T, 3600, 'x') === 0
        && $p->ban('not-an-ip', $T, 3600, 'x') === 0
        && $p->check('', $T)['banned'] === false
        && $p->check('not-an-ip', $T)['banned'] === false;
})());

ipCheck('a duration under one minute is still at least one minute', $fresh()->ban('203.0.113.9', $T, 1, 'x') === $T + 60);

ipCheck('a second ban while already banned extends the expiry and counts a strike', (static function () use ($T, $fresh): bool {
    $p = $fresh();
    $p->ban('203.0.113.9', $T, 3600, 'a');
    $p->ban('203.0.113.9', $T + 10, 7200, 'b');
    $c = $p->check('203.0.113.9', $T + 10);

    return $c['until'] === $T + 10 + 7200 && $c['reason'] === 'b';
})());

ipCheck('IPv6 addresses bucket and ban the same as IPv4 (LockoutPolicy::bucket, /64)', (static function () use ($T, $fresh): bool {
    $p = $fresh();
    $p->ban('2001:db8::1', $T, 3600, 'x');

    return $p->check('2001:db8::2', $T)['banned'] === true   // same /64
        && $p->check('2001:db9::1', $T)['banned'] === false; // different /64
})());

ipCheck('a storage failure means "not banned" rather than an error', (static function () use ($T): bool {
    $store = new MemoryStateStore();
    $p     = new TargetedBanPolicy($store);
    $p->ban('203.0.113.9', $T, 3600, 'x');
    $store->failing = true;

    return $p->check('203.0.113.9', $T)['banned'] === false && $p->ban('203.0.113.10', $T, 3600, 'x') === 0;
})());
