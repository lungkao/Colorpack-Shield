<?php
/**
 * Cloudflare range refresh: the refresher's safety checks, the CLI script, the
 * Scheduled Task plugin (against stand-ins for Joomla's scheduler classes) and
 * the plugin picking the refreshed file up. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRefresher;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\Event\Event;

echo "== Cloudflare ranges: refresh job ==\n";

$cfdir = sys_get_temp_dir() . '/cps-cfr-' . bin2hex(random_bytes(4));
mkdir($cfdir);
$key  = CloudflareRanges::deriveKey('refresh-secret');
$path = $cfdir . '/cache/colorpack_shield/cloudflare-ips.txt';
$v4   = CloudflareRanges::V4;
$v6   = CloudflareRanges::V6;

$mk = static function (array $a4, array $a6, ?string $raw4 = null, ?string $raw6 = null): callable {
    return static fn (string $url): ?string => $url === CloudflareRefresher::URL_V4 ? ($raw4 ?? implode("\n", $a4) . "\n") : ($raw6 ?? implode("\n", $a6) . "\n");
};
$reset = static function () use ($cfdir): void {
    exec('rm -rf ' . escapeshellarg($cfdir . '/cache'));
};
$stat = static fn (array $r): string => $r['status'];

$r = CloudflareRefresher::refresh($mk($v4, $v6), $path, $key);
ipCheck('first refresh stores the list (status updated, 22 entries)', $stat($r) === 'updated' && $r['count'] === 22 && is_file($path) && is_file($path . '.sig'));
ipCheck('…the file is signed (HMAC under the derived key) and loads with the right key', hash_equals(CloudflareRanges::sign((string) file_get_contents($path), $key), trim((string) file_get_contents($path . '.sig'))) && count(CloudflareRanges::load($path, $key)) === 22);
ipCheck('…it is not world-writable', (fileperms($path) & 0002) === 0);
$mtime = filemtime($path);
sleep(1);
clearstatcache();
$r = CloudflareRefresher::refresh($mk($v4, $v6), $path, $key);
ipCheck('second refresh with the same data: unchanged, file not rewritten', $stat($r) === 'unchanged' && filemtime($path) === $mtime);

$newV4 = array_merge($v4, ['198.51.100.0/24']);
$r     = CloudflareRefresher::refresh($mk($newV4, $v6), $path, $key, CloudflareRanges::load($path, $key));
ipCheck('a genuinely new range is picked up', $stat($r) === 'updated' && \in_array('198.51.100.0/24', CloudflareRanges::load($path, $key), true) && $r['count'] === 23);
$r = CloudflareRefresher::refresh($mk(\array_slice($v4, 0, 14), $v6), $path, $key, CloudflareRanges::load($path, $key));
ipCheck('a range that Cloudflare dropped is dropped', $stat($r) === 'updated' && !\in_array($v4[14], CloudflareRanges::load($path, $key), true));

// Nothing changes on a refused or failed refresh.
$good  = file_get_contents($path);
$goodS = file_get_contents($path . '.sig');
$keep  = static function () use ($path, $good, $goodS): bool {
    return file_get_contents($path) === $good && file_get_contents($path . '.sig') === $goodS && glob(\dirname($path) . '/*.tmp*') === [];
};
$prev = CloudflareRanges::load($path, $key);

$cases = [
    'download failure (v6 missing)'            => [static fn (string $u): ?string => $u === CloudflareRefresher::URL_V4 ? implode("\n", CloudflareRanges::V4) : null, 'failed'],
    'download failure (v4 missing)'            => [static fn (string $u): ?string => $u === CloudflareRefresher::URL_V6 ? implode("\n", CloudflareRanges::V6) : null, 'failed'],
    'both downloads fail'                      => [static fn (string $u): ?string => null, 'failed'],
    'an HTML error page instead of a list'     => [$mk([], [], "<html><body>403 Forbidden</body></html>", implode("\n", $v6)), 'rejected'],
    'a malformed line'                         => [$mk(array_merge($v4, ['not-a-cidr']), $v6), 'rejected'],
    'a bare IP without a mask'                 => [$mk(array_merge($v4, ['198.51.100.7']), $v6), 'rejected'],
    '0.0.0.0/0 smuggled in'                    => [$mk(array_merge($v4, ['0.0.0.0/0']), $v6), 'rejected'],
    'a /8 smuggled in'                         => [$mk(array_merge($v4, ['10.0.0.0/8']), $v6), 'rejected'],
    '::/0 smuggled in'                         => [$mk($v4, array_merge($v6, ['::/0'])), 'rejected'],
    'an IPv6 line in the IPv4 list'            => [$mk(array_merge($v4, ['2400:cb00::/32']), $v6), 'rejected'],
    'an IPv4 line in the IPv6 list'            => [$mk($v4, array_merge($v6, ['198.51.100.0/24'])), 'rejected'],
    'a truncated IPv4 list'                    => [$mk(\array_slice($v4, 0, 3), $v6), 'rejected'],
    'a truncated IPv6 list'                    => [$mk($v4, \array_slice($v6, 0, 2)), 'rejected'],
    'empty lists'                              => [$mk([], [], '', ''), 'rejected'],
    'a completely different list'              => [$mk(array_map(static fn (int $i): string => "198.51.$i.0/24", range(1, 12)), array_map(static fn (int $i): string => "2a01:db8:$i::/48", range(1, 5))), 'rejected'],
    'a list far longer than the current one'   => [$mk(array_merge($v4, array_map(static fn (int $i): string => "198.51.$i.0/24", range(1, 120))), $v6), 'rejected'],
    'an oversized body (valid list + padding)' => [$mk($v4, $v6, implode("\n", $v4) . str_repeat("\n", 40000), implode("\n", $v6)), 'rejected'],
    'IPv4 list just under its minimum'         => [$mk(\array_slice($v4, 0, 7), $v6), 'rejected'],
];

foreach ($cases as $label => [$fetch, $want]) {
    $r = CloudflareRefresher::refresh($fetch, $path, $key, $prev);
    ipCheck("refused: $label → $want, previous list untouched", $r['status'] === $want && $keep());
}

$r = CloudflareRefresher::refresh($mk($v4, $v6), $path, '', $prev);
ipCheck('refused: no key (no site secret) → failed with that reason, nothing written', $stat($r) === 'failed' && str_contains($r['reason'], 'secret') && $keep());

// Tolerated formatting.
$reset();
$r = CloudflareRefresher::refresh($mk([], [], "  " . implode("\r\n  ", $v4) . "  \r\n\r\n", strtoupper(implode("\n\n", $v6)) . "\n"), $path, $key);
ipCheck('CRLF, blank lines, indentation and upper-case IPv6 are accepted and normalised', $stat($r) === 'updated' && !\in_array(false, array_map(static fn (string $c): bool => $c === strtolower($c), CloudflareRanges::load($path, $key)), true));
$reset();
$r = CloudflareRefresher::refresh($mk(array_merge($v4, $v4), array_merge($v6, $v6)), $path, $key);
ipCheck('duplicate lines are collapsed', $stat($r) === 'updated' && $r['count'] === 22);

// A tampered signature or a different key is not believed afterwards.
ipCheck('the stored list is ignored under another site secret', CloudflareRanges::load($path, CloudflareRanges::deriveKey('other-secret')) === CloudflareRanges::bundled());
ipCheck('only the two fixed Cloudflare URLs can be fetched (no SSRF)', CloudflareRefresher::fetch('http://169.254.169.254/latest/meta-data') === null && CloudflareRefresher::fetch('https://example.com/ips-v4') === null && CloudflareRefresher::fetch('file:///etc/passwd') === null && CloudflareRefresher::fetch('https://www.cloudflare.com/ips-v4?x=1') === null);
$reset();
ipCheck('loadStored: null when there is no file, even though load() falls back to the bundled list', CloudflareRanges::loadStored($path, $key) === null && CloudflareRanges::load($path, $key) === CloudflareRanges::bundled());
CloudflareRefresher::refresh($mk($v4, $v6), $path, $key);
ipCheck('loadStored: a stored copy equal to the bundled list is still a stored copy', CloudflareRanges::loadStored($path, $key) !== null && count(CloudflareRanges::loadStored($path, $key)) === 22);
ipCheck('loadStored: null under another key', CloudflareRanges::loadStored($path, CloudflareRanges::deriveKey('x')) === null && CloudflareRanges::loadStored($path, '') === null);
chmod($path, 0666);
clearstatcache();
ipCheck('loadStored: null for a world-writable file', CloudflareRanges::loadStored($path, $key) === null);
chmod($path, 0644);
clearstatcache();
ipCheck('defaultPath is under the Joomla root, one place for every application', CloudflareRanges::defaultPath('/var/www/site/') === '/var/www/site/cache/colorpack_shield/cloudflare-ips.txt');

echo "== Cloudflare ranges: CLI ==\n";

$cli   = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/cloudflare_ranges_refresh.php');
$root  = $cfdir . '/site';
$feed  = $cfdir . '/feed';
$marker = $cfdir . '/EXECUTED';
mkdir($root);
mkdir($feed);
file_put_contents($root . '/configuration.php', "<?php\nfile_put_contents('$marker', 'x');\nclass JConfig {\n    public \$secret = 'cli-secret-value';\n    public \$sitename = 'x';\n}\n");
file_put_contents($feed . '/ips-v4', implode("\n", $v4) . "\n");
file_put_contents($feed . '/ips-v6', implode("\n", $v6) . "\n");
$crun = static function (array $args) use ($cli): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($cli);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    $o = [];
    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o) . "\n"];
};
$cpath = CloudflareRanges::defaultPath($root);
$ckey  = CloudflareRanges::deriveKey('cli-secret-value');

[$code, $t] = $crun(["--root=$root", '--dry-run', "--from-dir=$feed"]);
ipCheck('dry run: exit 0, says dry run, writes nothing', $code === 0 && str_contains($t, 'dry run') && !is_file($cpath) && !is_dir($root . '/cache'));
[$code, $t] = $crun(["--root=$root", "--from-dir=$feed"]);
ipCheck('first run: updated, signed file at {root}/cache/colorpack_shield/', $code === 0 && str_contains($t, 'updated') && str_contains($t, '22 entries') && is_file($cpath) && is_file($cpath . '.sig'));
ipCheck('…and it is signed with the key derived from the configuration.php secret', hash_equals(CloudflareRanges::sign((string) file_get_contents($cpath), $ckey), trim((string) file_get_contents($cpath . '.sig'))));
[$code, $t] = $crun(["--root=$root", "--from-dir=$feed"]);
ipCheck('second run: unchanged, exit 0', $code === 0 && str_contains($t, 'unchanged'));
ipCheck('the secret never appears in the output', !str_contains($t, 'cli-secret-value') && !str_contains($crun(["--root=$root", "--from-dir=$feed"])[1], 'cli-secret-value'));
ipCheck('configuration.php is read as text, never executed', !is_file($marker));

file_put_contents($feed . '/ips-v4', implode("\n", array_merge($v4, ['0.0.0.0/0'])) . "\n");
$before = file_get_contents($cpath);
[$code, $t] = $crun(["--root=$root", "--from-dir=$feed"]);
ipCheck('a poisoned feed: exit 1, rejected, stored list untouched', $code === 1 && str_contains($t, 'rejected') && file_get_contents($cpath) === $before);
unlink($feed . '/ips-v6');
[$code, $t] = $crun(["--root=$root", "--from-dir=$feed"]);
ipCheck('a missing feed file: exit 1, failed', $code === 1 && str_contains($t, 'failed'));
file_put_contents($root . '/configuration.php', "<?php\nclass JConfig {\n    public \$secret = '';\n}\n");
[$code, $t] = $crun(["--root=$root", "--from-dir=$feed"]);
ipCheck('empty secret: exit 1, ERROR about the secret, nothing signed', $code === 1 && str_contains($t, 'ERROR: no site secret'));
[$code, $t] = $crun(["--root=$cfdir/nowhere"]);
ipCheck('no configuration.php: exit 1', $code === 1);
[$code, $t] = $crun([]);
ipCheck('no --root: usage, exit 1', $code === 1 && str_contains($t, 'Usage'));
ipCheck('--help exits 0', $crun(['--help'])[0] === 0);

echo "== Cloudflare ranges: the plugin uses the refreshed file ==\n";

$jroot = JPATH_ROOT;
$kp    = CloudflareRanges::defaultPath($jroot);
@mkdir(\dirname($kp), 0777, true);
@unlink($kp);
@unlink($kp . '.sig');

$cfFlow = static function (array $params, array $server, string $secret) {
    $_SERVER = $server + ['REQUEST_URI' => '/', 'CONTENT_TYPE' => ''];
    $_GET    = $_POST = $_COOKIE = $_FILES = [];
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $plugin->setApplication(new FakeApp('site', ['secret' => $secret]));
    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $blocked = false;
    } catch (RequestEnded $e) {
        $blocked = true;
    }

    ob_end_clean();

    return $blocked;
};
// An address that is "Cloudflare" only in the refreshed list; geo denies the forwarded visitor.
$deny   = ['geo_enabled' => 1, 'geo_mode' => 'deny', 'geo_deny_ips' => '203.0.113.9'];
$server = ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9'];

ipCheck('without a refreshed file, 198.51.100.7 is not Cloudflare: the header is not believed', $cfFlow($deny, $server, 'site-secret') === false);
CloudflareRanges::store($kp, array_merge($v4, $v6, ['198.51.100.0/24']), CloudflareRanges::deriveKey('site-secret'));
ipCheck('with a refreshed signed file, that range counts as Cloudflare: the forwarded IP is believed (and geo-denied)', $cfFlow($deny, $server, 'site-secret') === true);
ipCheck('…but not under a different site secret (signature does not match)', $cfFlow($deny, $server, 'another-secret') === false);
file_put_contents($kp, file_get_contents($kp) . "10.0.0.0/12\n");
ipCheck('…and not after the file is edited', $cfFlow($deny, $server, 'site-secret') === false);
@unlink($kp);
@unlink($kp . '.sig');

echo "== Cloudflare ranges: scheduled task plugin ==\n";

// Stand-ins for the Joomla scheduler classes this plugin touches (they are not part of the test stubs).
if (!class_exists('Joomla\Component\Scheduler\Administrator\Task\Status', false)) {
    eval('namespace Joomla\Component\Scheduler\Administrator\Task { final class Status { public const OK = 0; public const KNOCKOUT = 1; } }');
    eval('namespace Joomla\Component\Scheduler\Administrator\Event { class ExecuteTaskEvent {} }');
    eval('namespace Joomla\Component\Scheduler\Administrator\Traits { trait TaskPluginTrait { public array $taskLog = []; protected function logTask(string $message, string $priority = "info"): void { $this->taskLog[] = [$priority, $message]; } public function callRoutine(string $m, $e): int { return $this->$m($e); } } }');
}

require_once __DIR__ . '/../plugins/task/colorpack_shield/src/Extension/ColorpackShieldTask.php';

$taskClass = 'Colorpack\Plugin\Task\ColorpackShield\Extension\ColorpackShieldTask';
ipCheck('the task plugin advertises its three routines and the three scheduler events', (function () use ($taskClass) {
    $e = $taskClass::getSubscribedEvents();
    $r = new ReflectionClassConstant($taskClass, 'TASKS_MAP');

    return array_keys($e) === ['onTaskOptionsList', 'onExecuteTask', 'onContentPrepareForm'] && array_keys($r->getValue()) === ['colorpack_shield.cloudflare_ranges', 'colorpack_shield.file_scan', 'colorpack_shield.site_manager_sync']
        && $r->getValue()['colorpack_shield.cloudflare_ranges']['method'] === 'refreshCloudflareRanges' && $r->getValue()['colorpack_shield.file_scan']['method'] === 'scanFiles'
        && $r->getValue()['colorpack_shield.site_manager_sync']['method'] === 'syncSiteManager';
})());
ipCheck('every language key of the task is defined in en-GB and th-TH', (function () {
    $dir = __DIR__ . '/../plugins/task/colorpack_shield/language';

    foreach (['en-GB', 'th-TH'] as $lang) {
        $ini = (string) file_get_contents("$dir/$lang/plg_task_colorpack_shield.ini");

        foreach (['PLG_TASK_COLORPACK_SHIELD_CFRANGES_TITLE', 'PLG_TASK_COLORPACK_SHIELD_CFRANGES_DESC', 'PLG_TASK_COLORPACK_SHIELD_FILESCAN_TITLE', 'PLG_TASK_COLORPACK_SHIELD_FILESCAN_DESC', 'PLG_TASK_COLORPACK_SHIELD_FILESCAN_MAIL_SUBJECT', 'PLG_TASK_COLORPACK_SHIELD_FILESCAN_MAIL_BODY', 'PLG_TASK_COLORPACK_SHIELD_SITEMANAGER_TITLE', 'PLG_TASK_COLORPACK_SHIELD_SITEMANAGER_DESC', 'PLG_TASK_COLORPACK_SHIELD_XML_DESCRIPTION'] as $k) {
            if (!preg_match('/^' . $k . '="[^"]+"$/m', $ini)) {
                return false;
            }
        }
    }

    return true;
})());
ipCheck('the task manifest and the package manifest are well-formed and list the plugin', (function () {
    $x = @simplexml_load_file(__DIR__ . '/../plugins/task/colorpack_shield/colorpack_shield.xml');
    $p = @simplexml_load_file(__DIR__ . '/../pkg_colorpack_shield.xml');

    return $x !== false && $p !== false && (string) $x['group'] === 'task' && str_contains((string) $p->asXML(), 'group="task">plugins/task/colorpack_shield');
})());

// Run the routine with the download replaced; it must call the shared job and report success or failure to the scheduler.
$feeds = ['v4' => $v4, 'v6' => $v6];
$testTask = new class (new stdClass(), ['params' => []]) extends Colorpack\Plugin\Task\ColorpackShield\Extension\ColorpackShieldTask {
    public array $feeds = [];

    protected function fetcher(): callable
    {
        $f = $this->feeds;

        return static fn (string $url): ?string => $url === CloudflareRefresher::URL_V4 ? implode("\n", $f['v4']) : implode("\n", $f['v6']);
    }

    public function run(): array
    {
        $code = $this->callRoutine('refreshCloudflareRanges', new Joomla\Component\Scheduler\Administrator\Event\ExecuteTaskEvent());

        return [$code, $this->taskLog];
    }
};

if (!\defined('JPATH_PLUGINS')) {
    \define('JPATH_PLUGINS', realpath(__DIR__ . '/../plugins'));
}

$testTask->setApplication(new FakeApp('administrator', ['secret' => 'task-secret']));
$testTask->feeds = $feeds;
@unlink($kp);
@unlink($kp . '.sig');
[$code, $log] = $testTask->run();
ipCheck('task: a good feed → Status::OK, info log "updated", signed file in the shared location', $code === 0 && $log[0][0] === 'info' && str_contains($log[0][1], 'updated') && is_file($kp) && count(CloudflareRanges::load($kp, CloudflareRanges::deriveKey('task-secret'))) === 22);
[$code, $log] = $testTask->run();
ipCheck('task: the same feed again → Status::OK, "unchanged"', $code === 0 && str_contains(end($log)[1], 'unchanged'));
$testTask->feeds = ['v4' => array_merge($v4, ['0.0.0.0/0']), 'v6' => $v6];
[$code, $log] = $testTask->run();
ipCheck('task: a poisoned feed → Status::KNOCKOUT, error log, stored list unchanged', $code === 1 && end($log)[0] === 'error' && str_contains(end($log)[1], 'rejected') && count(CloudflareRanges::load($kp, CloudflareRanges::deriveKey('task-secret'))) === 22);
// The list in force (a stored copy far longer than the feed) is what the feed is judged against.
CloudflareRanges::store($kp, array_merge($v4, $v6, array_map(static fn (int $i): string => "198.51.$i.0/24", range(1, 30))), CloudflareRanges::deriveKey('task-secret'));
$testTask->feeds = $feeds;   // a clean feed: only the comparison with the list in force can reject it
[$code, $log] = $testTask->run();
ipCheck('task: the feed is judged against the stored list, not just the bundled one (too different → rejected)', $code === 1 && str_contains(end($log)[1], 'rejected'));
@unlink($kp);
@unlink($kp . '.sig');
$testTask->setApplication(new FakeApp('administrator', ['secret' => '']));
$testTask->feeds = $feeds;
[$code, $log] = $testTask->run();
ipCheck('task: no site secret → Status::KNOCKOUT (nothing can be signed)', $code === 1 && end($log)[0] === 'error');
@unlink($kp);
@unlink($kp . '.sig');

exec('rm -rf ' . escapeshellarg($cfdir));


// The file scan routine: a planted backdoor in the (temporary) site folder is found, the result is stored, the scheduler is told OK.
$scanRoot = JPATH_ROOT;
@mkdir($scanRoot . '/images', 0777, true);
file_put_contents($scanRoot . '/images/shell.php', '<?php @eval(base64_decode($_POST["z"]));');
exec('rm -rf ' . escapeshellarg($scanRoot . '/cache/colorpack_shield/scan'));
$scanTask = new class (new stdClass(), ['params' => []]) extends Colorpack\Plugin\Task\ColorpackShield\Extension\ColorpackShieldTask {
    public function run(): array
    {
        return [$this->callRoutine('scanFiles', new Joomla\Component\Scheduler\Administrator\Event\ExecuteTaskEvent()), $this->taskLog];
    }
};
$scanTask->setApplication(new FakeApp('administrator', ['secret' => 'task-secret']));
[$sc, $sl] = $scanTask->run();
$stored = (new Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore($scanRoot . '/cache/colorpack_shield/scan'))->read('result');
ipCheck('the file-scan task finishes a small site in one run, stores the result with the planted shell, and says OK', $sc === 0 && is_array($stored) && $stored['count']['high'] >= 1 && in_array('images/shell.php', array_column($stored['findings'], 'path'), true) && str_contains($sl[0][1] ?? '', 'File scan'));
ipCheck('…and a finished scan leaves no half-done state and a file list for the baseline', (new Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore($scanRoot . '/cache/colorpack_shield/scan'))->read('state') === null && is_array((new Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore($scanRoot . '/cache/colorpack_shield/scan'))->read('lastfiles')));
@unlink($scanRoot . '/images/shell.php');
exec('rm -rf ' . escapeshellarg($scanRoot . '/cache/colorpack_shield/scan'));
