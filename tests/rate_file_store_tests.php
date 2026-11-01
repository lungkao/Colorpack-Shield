<?php
/**
 * Rate limiting without APCu: the file counter and the counter picker. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/AdminProtect/StateStore.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/AdminProtect/FileStateStore.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/RateLimit/FileRateStore.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/RateLimit/RateStores.php';

use Colorpack\Plugin\System\ColorpackShield\RateLimit\FileRateStore;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateLimiter;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateStores;

echo "\n== Rate limit without APCu: file counter ==\n";

$dir = sys_get_temp_dir() . '/cps-rate-' . bin2hex(random_bytes(4));
$now = 1_800_000_000;

$clock = new class ($now) {
    public function __construct(public int $t)
    {
    }
};

// A store whose clock the test moves (FileRateStore takes a fixed clock per instance, so rebuild it per tick).
$store = static fn (int $t): FileRateStore => new FileRateStore($dir, $t);

ipCheck('counter starts at 1 and counts up inside one window', $store($now)->increment('w:a', 60) === 1 && $store($now + 5)->increment('w:a', 60) === 2 && $store($now + 9)->increment('w:a', 60) === 3);
ipCheck('a different key has its own count', $store($now)->increment('w:b', 60) === 1);
ipCheck('ttl counts down to the end of the window', $store($now + 10)->ttl('w:a') === 50);
ipCheck('the window is fixed: later hits do not push the end out', $store($now + 59)->ttl('w:a') === 1);
ipCheck('after the window the count starts again', $store($now + 61)->increment('w:a', 60) === 1 && $store($now + 61)->ttl('w:a') === 60);
$store($now)->put('ban:x', 300);
ipCheck('a ban is present for its whole time and gone after', $store($now + 100)->ttl('ban:x') === 200 && $store($now + 301)->ttl('ban:x') === 0);
ipCheck('an unknown key has no time left', $store($now)->ttl('never') === 0);

$limiter = new RateLimiter($store($now), 60, 3, 2, 300, 600);
$verdicts = [];

for ($i = 0; $i < 5; $i++) {
    $verdicts[] = $limiter->decide($now, '203.0.113.9', 'site:');
}

ipCheck('the limiter built on the file counter lets 3 through and stops the 4th', $verdicts[0]->allowed && $verdicts[2]->allowed && !$verdicts[3]->allowed);
ipCheck('another address is not affected', $limiter->decide($now, '203.0.113.10', 'site:')->allowed);

// An unwritable folder must never block anybody.
$bad = new FileRateStore('/proc/cps-no-such-place/rate', $now);
ipCheck('unwritable folder: counts as 1 and does not throw (fail open)', $bad->increment('k', 60) === 1 && $bad->ttl('k') === 0);

ipCheck('picker: a writable folder gives a counter even without APCu', in_array(RateStores::kind($dir), [RateStores::APCU, RateStores::FILE], true) && RateStores::pick($dir) !== null);
ipCheck('picker: nowhere to write and no APCu gives none', RateStores::kind('/proc/cps-no-such-place/rate') === RateStores::NONE || function_exists('apcu_enabled') && apcu_enabled());

// Clean up.
foreach (glob($dir . '/*') ?: [] as $f) {
    @unlink($f);
}

@rmdir($dir);
