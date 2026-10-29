<?php
/**
 * Plugin guard-flow tests (with Joomla stand-ins): proves what a trusted IP is
 * worth depending on how the IP was learned — AUDIT.md C1. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

\define('_JEXEC', 1);

$flowBase = sys_get_temp_dir() . '/cps-flow-' . bin2hex(random_bytes(4));
mkdir($flowBase . '/root/administrator', 0777, true);
\define('JPATH_ROOT', $flowBase . '/root');
\define('JPATH_ADMINISTRATOR', $flowBase . '/root/administrator');
\define('JPATH_CACHE', $flowBase . '/cache');   // nonexistent → bundled Cloudflare ranges

require_once __DIR__ . '/stubs/joomla.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'Colorpack\\Plugin\\System\\ColorpackShield\\';

    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/../plugins/system/colorpack_shield/src/' . str_replace('\\', '/', substr($class, \strlen($prefix))) . '.php';

        if (is_file($file)) {
            require_once $file;
        }
    }
});

use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\Event\Event;

/**
 * Run one request through the plugin.
 *
 * @return array{blocked:bool,status:string}
 */
function flow(array $params, array $server, array $get = [], array $files = [], string $client = 'site'): array
{
    $_SERVER = array_merge(['REQUEST_URI' => '/index.php', 'CONTENT_TYPE' => ''], $server);
    $_GET    = $get;
    $_POST   = [];
    $_COOKIE = [];
    $_FILES  = $files;

    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $app     = new FakeApp($client);
    $plugin->setApplication($app);

    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $blocked = false;
    } catch (RequestEnded $e) {
        $blocked = true;
    }

    ob_end_clean();

    return ['blocked' => $blocked, 'status' => $app->headers['status'] ?? ''];
}

function flowCheck(string $label, array $result, bool $wantBlocked): void
{
    ipCheck($label . ($wantBlocked ? ' → blocked' : ' → allowed'), $result['blocked'] === $wantBlocked);
}

echo "== Plugin flow: what a trusted IP is worth (AUDIT.md C1) ==\n";

$attack = ['q' => "1' UNION SELECT user,pass FROM x-- -"];
$benign = ['q' => 'hello world'];
$trust  = ['allow_ips' => "203.0.113.5\n"];

// Baselines.
flowCheck('attack from unlisted visitor', flow($trust, ['REMOTE_ADDR' => '198.51.100.1'], $attack), true);
flowCheck('benign from unlisted visitor', flow($trust, ['REMOTE_ADDR' => '198.51.100.1'], $benign), false);

// FULL trust: the listed address is the real TCP peer.
flowCheck('listed IP connecting directly skips everything', flow($trust, ['REMOTE_ADDR' => '203.0.113.5'], $attack), false);

// SOFT trust: listed address learned from a Cloudflare header → WAF still runs.
$viaCf = ['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5'];
flowCheck('listed IP via Cloudflare: attack still hits the WAF', flow($trust, $viaCf, $attack), true);
flowCheck('listed IP via Cloudflare: benign request passes', flow($trust, $viaCf, $benign), false);

// C1 regression: forged headers from the local host.
$forged = [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '104.16.0.1',
    'HTTP_CF_CONNECTING_IP' => '203.0.113.5',
];
flowCheck('C1 default (no proxies configured): forged request blocked by WAF', flow($trust, $forged, $attack), true);
flowCheck('C1 with loopback declared as proxy: forged request STILL blocked by WAF',
    flow($trust + ['trusted_proxies' => '127.0.0.1'], $forged, $attack), true);

// The plugin's own default must be "no proxy trusted": a forged IP that the geo
// rule denies is NOT acted on (the loopback peer's real address is used), while
// an operator who declares the proxy does get it applied.
$denyForged = ['geo_enabled' => 1, 'geo_mode' => 'deny', 'geo_deny_ips' => '203.0.113.5'];
flowCheck('plugin default: forged headers from loopback are not believed (geo denies only the forged IP)',
    flow($denyForged, $forged, $benign), false);
flowCheck('proxy declared: the same forged IP is believed and geo-denied',
    flow($denyForged + ['trusted_proxies' => '127.0.0.1'], $forged, $benign), true);

// Geo and rate-limit are what SOFT trust skips.
$geo = ['geo_enabled' => 1, 'geo_mode' => 'deny', 'geo_deny_ips' => '203.0.113.5'];
flowCheck('geo-denied IP, not trusted → blocked (control: geo works)',
    flow($geo, ['REMOTE_ADDR' => '203.0.113.5'], $benign), true);
flowCheck('geo-denied but trusted + learned via Cloudflare → geo skipped',
    flow($geo + $trust, $viaCf, $benign), false);
flowCheck('geo-denied but trusted + direct → everything skipped',
    flow($geo + $trust, ['REMOTE_ADDR' => '203.0.113.5'], $benign), false);

// Upload scanner still runs for SOFT trust.
$tmp = tempnam(sys_get_temp_dir(), 'cpsup');
file_put_contents($tmp, '<?php system($_GET[1]);');
$shell = ['f' => ['name' => 'shell.php', 'type' => 'application/octet-stream', 'tmp_name' => $tmp, 'error' => 0, 'size' => 23]];
flowCheck('trusted via Cloudflare: PHP upload still blocked', flow($trust, $viaCf, $benign, $shell), true);
flowCheck('trusted direct: PHP upload not scanned (full trust)', flow($trust, ['REMOTE_ADDR' => '203.0.113.5'], $benign, $shell), false);
@unlink($tmp);

echo "== Plugin flow: kill-switch ==\n";
flowCheck('attack blocked while no switch file', flow([], ['REMOTE_ADDR' => '198.51.100.1'], $attack), true);
touch(JPATH_ADMINISTRATOR . '/colorpack_shield.disable');
flowCheck('switch file in administrator/ turns the plugin off', flow([], ['REMOTE_ADDR' => '198.51.100.1'], $attack), false);
unlink(JPATH_ADMINISTRATOR . '/colorpack_shield.disable');
touch(JPATH_ROOT . '/colorpack_shield.disable');
flowCheck('switch file in site root turns the plugin off', flow([], ['REMOTE_ADDR' => '198.51.100.1'], $attack), false);
unlink(JPATH_ROOT . '/colorpack_shield.disable');
flowCheck('attack blocked again after the file is removed', flow([], ['REMOTE_ADDR' => '198.51.100.1'], $attack), true);

// Admin warning while switched off.
touch(JPATH_ROOT . '/colorpack_shield.disable');
$subject = new stdClass();
$plugin  = new ColorpackShield($subject, ['params' => []]);
$app     = new FakeApp('administrator');
$plugin->setApplication($app);
$plugin->onAfterRoute(new Event('onAfterRoute'));
ipCheck('administrator gets a warning while the switch file exists',
    \count($app->messages) === 1 && $app->messages[0][1] === 'warning');
$app2    = new FakeApp('site');
$plugin2 = new ColorpackShield($subject, ['params' => []]);
$plugin2->setApplication($app2);
$plugin2->onAfterRoute(new Event('onAfterRoute'));
ipCheck('site visitors get no warning', $app2->messages === []);
unlink(JPATH_ROOT . '/colorpack_shield.disable');

@rmdir($flowBase . '/root/administrator');
@rmdir($flowBase . '/root');
@rmdir($flowBase);
