<?php
/**
 * Rescue tool for the administrator login protection: shows and lifts login
 * lock-outs without needing the administrator. Run it on the server.
 *
 *   php admin_unlock.php --root=/path/to/joomla --list
 *   php admin_unlock.php --root=/path/to/joomla --ip=203.0.113.10
 *   php admin_unlock.php --root=/path/to/joomla --all
 *   php admin_unlock.php --root=/path/to/joomla --everything
 *   php admin_unlock.php --root=/path/to/joomla --gate-off
 *   php admin_unlock.php --root=/path/to/joomla --gate-on
 *
 *   --list         show the addresses currently locked or counting failures (addresses are
 *                  printed because the tool runs on the server, for its operator)
 *   --ip=ADDRESS   lift the lock and counters of one address (IPv6 addresses are handled per /64)
 *   --all          lift every lock and login counter
 *   --everything   forget ALL stored state: locks, counters, alert throttles, remembered
 *                  administrator addresses (they are learned again as administrators log in)
 *
 *   --gate-off     open the administrator access key and the administrator address list (A4/A5) until
 *                  --gate-on: use it when you are locked out of your own administrator
 *   --gate-on      remove that rescue marker again
 *
 * Emergency alternatives that need no tool: create the file colorpack_shield.disable in the
 * Joomla root (switches the whole Shield off), or add your address to "Trusted IP addresses".
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

\define('_JEXEC', 1);

$src = \dirname(__DIR__) . '/src';
require_once $src . '/AdminProtect/StateStore.php';
require_once $src . '/AdminProtect/FileStateStore.php';
require_once $src . '/AdminProtect/AdminProtectConfig.php';
require_once $src . '/AdminProtect/LockDecision.php';
require_once $src . '/AdminProtect/LockoutPolicy.php';
require_once $src . '/Net/ClientIp.php';
require_once $src . '/Net/IpAllowList.php';
require_once $src . '/Geo/CidrMatcher.php';

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;

$usage = "Usage: php admin_unlock.php --root=/path/to/joomla (--list | --ip=ADDRESS | --all | --everything | --gate-off | --gate-on)\n";
$opt   = getopt('', ['root:', 'list', 'ip:', 'all', 'everything', 'gate-off', 'gate-on', 'help']);

if (isset($opt['help'])) {
    fwrite(STDOUT, $usage);
    exit(0);
}

$actions = (int) isset($opt['list']) + (int) isset($opt['ip']) + (int) isset($opt['all']) + (int) isset($opt['everything']) + (int) isset($opt['gate-off']) + (int) isset($opt['gate-on']);

if (!isset($opt['root']) || $actions !== 1) {
    fwrite(STDERR, $usage);
    exit(1);
}

$cacheDir = rtrim((string) $opt['root'], '/') . '/cache/colorpack_shield';
$marker   = $cacheDir . '/gate.off';

if (isset($opt['gate-off'])) {
    if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0755, true) && !is_dir($cacheDir)) {
        fwrite(STDERR, "ERROR: cannot create $cacheDir (is --root the Joomla folder, and are you the site's user?)\n");
        exit(1);
    }

    if (@file_put_contents($marker, "The Colorpack Shield administrator gate is open while this file exists.\n") === false) {
        fwrite(STDERR, "ERROR: cannot write $marker\n");
        exit(1);
    }

    echo "The administrator access key and address list are OPEN now. Log in, fix the settings, then run --gate-on.\n";
    exit(0);
}

if (isset($opt['gate-on'])) {
    if (is_file($marker) && !@unlink($marker)) {
        fwrite(STDERR, "ERROR: cannot remove $marker\n");
        exit(1);
    }

    echo "The rescue marker is removed: the access key and address list apply again (if they are switched on).\n";
    exit(0);
}

$dir = $cacheDir . '/admin';

if (!is_dir($dir)) {
    echo "Nothing to do: no login protection state exists under that root.\n";
    exit(0);
}

$store = new FileStateStore($dir);
$now   = time();

if (isset($opt['list'])) {
    $locks = $store->entries('ip:', $now);
    $rows  = 0;

    foreach ($locks as $key => $e) {
        $left = (int) ($e['lockUntil'] ?? 0) - $now;
        printf("%-42s %s\n", substr($key, 3), $left > 0 ? sprintf('LOCKED for %d more seconds (strike %d)', $left, (int) $e['strikes']) : sprintf('%d recent failure(s), not locked', \count((array) ($e['fails'] ?? []))));
        $rows++;
    }

    echo $rows === 0 ? "No address is locked or counting failures.\n" : '';
    exit($store->healthy() ? 0 : 1);
}

if (isset($opt['ip'])) {
    $bucket = LockoutPolicy::bucket((string) $opt['ip']);

    if ($bucket === null) {
        fwrite(STDERR, "ERROR: that is not an IP address\n");
        exit(1);
    }

    $removed = 0;

    foreach (['ip:', 'rate:'] as $prefix) {
        $removed += $store->get($prefix . $bucket, $now) !== null ? 1 : 0;
        $store->mutate($prefix . $bucket, $now, static fn (?array $e): ?array => null);
    }

    echo $removed > 0 ? "Lifted the lock and counters of $bucket.\n" : "Nothing was stored for $bucket.\n";
    exit($store->healthy() ? 0 : 1);
}

if (isset($opt['all'])) {
    $n = $store->purge('ip:', $now) + $store->purge('rate:', $now);
    echo "Lifted $n lock/counter entr" . ($n === 1 ? 'y' : 'ies') . ".\n";
    exit($store->healthy() ? 0 : 1);
}

$n = 0;

foreach (['ip:', 'rate:', 'user:', 'alert:', 'log:', 'known:', 'adminip:'] as $prefix) {
    $n += $store->purge($prefix, $now);
}

echo "Forgot $n stored entr" . ($n === 1 ? 'y' : 'ies') . ".\n";
exit($store->healthy() ? 0 : 1);
