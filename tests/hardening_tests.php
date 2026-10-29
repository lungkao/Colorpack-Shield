<?php
/**
 * Tests for the AUDIT.md low-severity fixes: C3 (whole-file upload scan),
 * C4 (kill-switch token + alert), C5 (generic block message). C2 is covered in
 * client_ip_tests.php. Included by run.php after plugin_flow_tests.php (uses its
 * stubs, constants and ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitch;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitchAlert;
use Colorpack\Plugin\System\ColorpackShield\Waf\UploadScanner;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\FakeMailer;
use Colorpack\Tests\RequestEnded;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\Event\Event;

/* ---------------------------------------------------------------- C3 */

echo "== C3: uploads are scanned past the first 8 KiB ==\n";

$png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');

/** Deterministic, high-entropy filler (stand-in for compressed image data). */
$filler = static function (int $n): string {
    $out = '';

    for ($i = 0; \strlen($out) < $n; $i++) {
        $out .= hash('sha512', 'cps-filler-' . $i, true);
    }

    return substr($out, 0, $n);
};

$up = static function (string $bytes, string $name = 'photo.png') {
    $t = tempnam(sys_get_temp_dir(), 'cpsu');
    file_put_contents($t, $bytes);

    return ['name' => $name, 'type' => 'image/png', 'tmp_name' => $t, 'error' => 0, 'size' => \strlen($bytes)];
};

$scan = static function (string $bytes, string $name = 'photo.png') use ($up): ?string {
    $f = $up($bytes, $name);
    $t = (new UploadScanner(0, []))->inspectFile($f);
    @unlink($f['tmp_name']);

    return $t === null ? null : $t->reason . '|' . $t->detail;
};

ipCheck('benign PNG passes', $scan($png) === null);
ipCheck('benign PNG + 3 MiB of filler passes (no false positive)', $scan($png . $filler(3 * 1024 * 1024)) === null);
ipCheck('XML declaration deep in the file passes', $scan($png . $filler(20000) . '<?xml version="1.0"?>') === null);
ipCheck('"<?php" glued to text (not a PHP tag) passes', $scan($png . $filler(20000) . '<?phpfoo') === null);
ipCheck('"<?=" without a closing tag passes', $scan($png . $filler(20000) . '<?= no end here') === null);

foreach ([100, 8000, 9000, 50000, 262144, 600000, 3 * 1024 * 1024] as $at) {
    $r = $scan($png . $filler($at) . '<?php system($_GET[1]); ?>');
    ipCheck("PHP tag at ~$at bytes is found", $r !== null && str_starts_with($r, 'executable_content'));
}

$r = $scan($png . $filler(30000) . '<?php system($_GET[1]); ?>');
ipCheck('deep hit says so in the detail', $r !== null && str_contains($r, '(deep)'));
ipCheck('upper-case tag is found', ($scan($png . $filler(30000) . "<?PHP\nsystem(\$_GET[1]);") ?? '') !== '');
ipCheck('"<?=" with closing tag is found', $scan($png . $filler(30000) . '<?= `id` ?>') !== null);
ipCheck('tag at the very end of the file (no trailing byte) is found', $scan($png . $filler(30000) . '<?php') !== null);

// A tag split across the read boundary must still be found.
// Where the second read starts, taken from the scanner's own constants so the test
// keeps straddling the real boundary if they are ever tuned.
$rc       = new ReflectionClass(UploadScanner::class);
$boundary = UploadScanner::MAX_SNIFF - $rc->getConstant('OVERLAP') + $rc->getConstant('CHUNK');
$missed   = [];

for ($pos = $boundary - 8; $pos <= $boundary + 8; $pos++) {
    $data = substr($png . $filler($pos), 0, $pos) . "<?php system(1);" . $filler(2000);

    if ($scan($data) === null) {
        $missed[] = $pos;
    }
}

ipCheck('tag straddling the chunk boundary is always found' . ($missed ? ' (missed at ' . implode(',', $missed) . ')' : ''), $missed === []);

// Larger than the whole-file limit: the tail is still checked.
$big = $png . $filler(5 * 1024 * 1024);
ipCheck('5 MiB file with a payload in its last 64 KiB is found',
    $scan(substr($big, 0, -200) . '<?php system($_GET[1]); ?>' . substr($big, -174)) !== null);
ipCheck('DOCUMENTED LIMIT: a payload in the unscanned middle of a >4 MiB file is not found',
    $scan(substr($big, 0, 4800000) . '<?php system(1);' . substr($big, 4800000)) === null);

/* ---------------------------------------------------------------- C4 */

echo "== C4: kill-switch token ==\n";

$ksBase = sys_get_temp_dir() . '/cps-ks2-' . bin2hex(random_bytes(4));
mkdir($ksBase . '/root/administrator', 0777, true);
$kr = $ksBase . '/root';
$ka = $kr . '/administrator';
$fn = KillSwitch::FILENAME;

touch("$kr/$fn");
$l = KillSwitch::locate([$kr, $ka]);
ipCheck('no token: any file is in force', $l['active'] === "$kr/$fn" && $l['present'] === "$kr/$fn");
ipCheck('find() agrees with locate()', KillSwitch::find([$kr, $ka]) === "$kr/$fn");

$l = KillSwitch::locate([$kr, $ka], 'tok-123');
ipCheck('token set, empty file: present but NOT in force', $l['present'] === "$kr/$fn" && $l['active'] === null);
file_put_contents("$kr/$fn", "wrong\n");
ipCheck('token set, wrong content: not in force', KillSwitch::find([$kr, $ka], 'tok-123') === null);
file_put_contents("$kr/$fn", "tok-123\n");
ipCheck('token set, right content (trailing newline ok): in force', KillSwitch::find([$kr, $ka], 'tok-123') === "$kr/$fn");
file_put_contents("$kr/$fn", "tok-123 and more");
ipCheck('token must match exactly, not as a prefix', KillSwitch::find([$kr, $ka], 'tok-123') === null);
file_put_contents("$kr/$fn", str_repeat('x', 5000));
ipCheck('huge file is read only a little and is not in force', KillSwitch::find([$kr, $ka], 'tok-123') === null);

touch("$ka/$fn");
file_put_contents("$ka/$fn", 'tok-123');
$l = KillSwitch::locate([$kr, $ka], 'tok-123');
ipCheck('invalid file in root does not hide a valid one in administrator/', $l['active'] === "$ka/$fn" && $l['present'] === "$kr/$fn");

echo "== C4: alert throttle ==\n";

$st = "$ksBase/state/alert.json";
$t0 = 1_800_000_000;
ipCheck('first sighting → send', KillSwitchAlert::claim($st, '/a', 100, 'active', $t0));
ipCheck('same file again → do not send', !KillSwitchAlert::claim($st, '/a', 100, 'active', $t0 + 5));
ipCheck('still quiet just before the reminder', !KillSwitchAlert::claim($st, '/a', 100, 'active', $t0 + KillSwitchAlert::REPEAT - 1));
ipCheck('daily reminder → send', KillSwitchAlert::claim($st, '/a', 100, 'active', $t0 + KillSwitchAlert::REPEAT));
ipCheck('…and quiet again right after', !KillSwitchAlert::claim($st, '/a', 100, 'active', $t0 + KillSwitchAlert::REPEAT + 1));
ipCheck('file modified (new mtime) → send', KillSwitchAlert::claim($st, '/a', 101, 'active', $t0 + KillSwitchAlert::REPEAT + 2));
ipCheck('mode changed (active→ignored) → send', KillSwitchAlert::claim($st, '/a', 101, 'ignored', $t0 + KillSwitchAlert::REPEAT + 3));
ipCheck('different path → send', KillSwitchAlert::claim($st, '/b', 101, 'ignored', $t0 + KillSwitchAlert::REPEAT + 4));
ipCheck('clock moved backwards → send (state not trusted)', KillSwitchAlert::claim($st, '/b', 101, 'ignored', $t0 - 1000));
file_put_contents($st, '{{not json');
ipCheck('corrupt state file → send, then valid again',
    KillSwitchAlert::claim($st, '/c', 1, 'active', $t0) && !KillSwitchAlert::claim($st, '/c', 1, 'active', $t0 + 1));
file_put_contents("$ksBase/blocker", 'x');
ipCheck('state directory impossible to create → do NOT send (no mail flood)',
    !KillSwitchAlert::claim("$ksBase/blocker/sub/alert.json", '/a', 1, 'active', $t0));

echo "== C4: kill-switch in the plugin (alert mail, token) ==\n";

@unlink("$kr/$fn");
@unlink("$ka/$fn");

/**
 * One request through the plugin with a configurable app (mail settings) and the
 * Joomla constants pointing at the $ksBase tree.
 *
 * @return array{blocked:bool,body:string}
 */
function ksFlow(array $params, array $appConfig, array $get = []): array
{
    $_SERVER = ['REMOTE_ADDR' => '198.51.100.1', 'REQUEST_URI' => '/', 'CONTENT_TYPE' => ''];
    $_GET    = $get;
    $_POST   = $_COOKIE = $_FILES = [];

    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $plugin->setApplication(new FakeApp('site', $appConfig));

    ob_start();

    try {
        $plugin->onAfterInitialise(new Event('onAfterInitialise'));
        $blocked = false;
    } catch (RequestEnded $e) {
        $blocked = true;
    }

    return ['blocked' => $blocked, 'body' => (string) ob_get_clean()];
}

// JPATH_* were fixed by plugin_flow_tests.php to point inside $flowBase; reuse that tree.
mkdir(JPATH_ADMINISTRATOR, 0777, true);
$cacheDir = JPATH_CACHE . '/colorpack_shield';
$switch   = JPATH_ROOT . '/' . KillSwitch::FILENAME;
$attack   = ['q' => "1' UNION SELECT user,pass FROM x-- -"];
$cfg      = ['mailfrom' => 'owner@example.test', 'sitename' => 'Demo Site'];

$clean = static function () use ($switch, $cacheDir): void {
    @unlink($switch);
    array_map('unlink', glob($cacheDir . '/*') ?: []);
};

Factory::$mailer = $mail = new FakeMailer();

$clean();
ksFlow([], $cfg, $attack);
ipCheck('no switch file → no mail', $mail->sent === []);

touch($switch);
$r = ksFlow([], $cfg, $attack);
ipCheck('switch file → protection off (attack passes)', $r['blocked'] === false);
ipCheck('switch file → exactly one alert mail', \count($mail->sent) === 1);
ipCheck('mail goes to the site mail-from address by default', ($mail->sent[0]['to'] ?? '') === 'owner@example.test');
ipCheck('mail says protection is OFF and names the file',
    str_contains($mail->sent[0]['subject'] ?? '', 'SUBJECT_ACTIVE') && str_contains($mail->sent[0]['body'] ?? '', $switch)
    && str_contains($mail->sent[0]['body'] ?? '', 'Demo Site') && str_contains($mail->sent[0]['body'] ?? '', '198.51.100.1'));

ksFlow([], $cfg, $attack);
ksFlow([], $cfg);
ipCheck('further requests do not re-send', \count($mail->sent) === 1);

touch($switch, time() + 5);   // "file changed"
clearstatcache();
ksFlow([], $cfg);
ipCheck('a changed file triggers a new mail', \count($mail->sent) === 2);

$clean();
$mail->sent = [];
touch($switch);
ksFlow(['alert_email' => 'ops@example.test'], $cfg);
ipCheck('alert_email setting overrides the default recipient', ($mail->sent[0]['to'] ?? '') === 'ops@example.test');

// Token mode.
$clean();
$mail->sent = [];
touch($switch);
$r = ksFlow(['killswitch_token' => 'tok-123'], $cfg, $attack);
ipCheck('token set, empty file: protection stays ON (attack blocked)', $r['blocked'] === true);
ipCheck('…and an "ignored" alert is sent', \count($mail->sent) === 1 && str_contains($mail->sent[0]['subject'], 'SUBJECT_IGNORED'));

$clean();
$mail->sent = [];
file_put_contents($switch, "tok-123\n");
$r = ksFlow(['killswitch_token' => 'tok-123'], $cfg, $attack);
ipCheck('token set, correct content: protection off', $r['blocked'] === false);
ipCheck('…and an "active" alert is sent', \count($mail->sent) === 1 && str_contains($mail->sent[0]['subject'], 'SUBJECT_ACTIVE'));

// Failure modes must not break the site or flood.
$clean();
$mail->sent = [];
touch($switch);
$r = ksFlow([], []);   // no recipient configured anywhere
ipCheck('no recipient: no mail, no error, switch still works', $mail->sent === [] && $r['blocked'] === false);

$clean();
Factory::$mailer = new class () extends FakeMailer {
    public function Send(): bool
    {
        throw new RuntimeException('smtp down');
    }
};
touch($switch);
$r = ksFlow([], $cfg, $attack);
ipCheck('mailer throws: site keeps working (switch still honoured)', $r['blocked'] === false);

$clean();
Factory::$mailer = $mail = new FakeMailer();
@rmdir($cacheDir);
file_put_contents($cacheDir, 'a file where the state directory should be');
touch($switch);
ksFlow([], $cfg);
ksFlow([], $cfg);
ipCheck('state cannot be saved: no mail (never flood)', $mail->sent === []);
@unlink($cacheDir);

$clean();
Factory::$mailer = null;

/* ---------------------------------------------------------------- C5 */

echo "== C5: block responses do not reveal the product ==\n";

Log::$messages = [];
$r = ksFlow([], [], $attack);
ipCheck('WAF block → 403 body is exactly "Forbidden"', $r['blocked'] === true && $r['body'] === 'Forbidden');
ipCheck('body has no product name', !preg_match('/colorpack|shield|waf/i', $r['body']));
ipCheck('the log still says what blocked it', str_contains(implode("\n", Log::$messages), 'shield=sqli'));

$tmpShell = tempnam(sys_get_temp_dir(), 'cpsx');
file_put_contents($tmpShell, '<?php system($_GET[1]);');
$_FILES = ['f' => ['name' => 'a.php', 'type' => 'x', 'tmp_name' => $tmpShell, 'error' => 0, 'size' => 23]];
$_SERVER = ['REMOTE_ADDR' => '198.51.100.1', 'REQUEST_URI' => '/', 'CONTENT_TYPE' => ''];
$_GET = $_POST = $_COOKIE = [];
$subject = new stdClass();
$plugin  = new ColorpackShield($subject, ['params' => []]);
$plugin->setApplication(new FakeApp('site'));
ob_start();
try {
    $plugin->onAfterInitialise(new Event('onAfterInitialise'));
} catch (RequestEnded $e) {
}
$body = (string) ob_get_clean();
@unlink($tmpShell);
ipCheck('upload block → body is exactly "Forbidden"', $body === 'Forbidden');

$r = ksFlow(['geo_enabled' => 1, 'geo_mode' => 'deny', 'geo_deny_ips' => '198.51.100.1'], [], []);
ipCheck('geo block → body is exactly "Forbidden"', $r['blocked'] === true && $r['body'] === 'Forbidden');

$r = ksFlow(['block_silent' => 1], [], $attack);
ipCheck('silent block still sends no body at all', $r['blocked'] === true && $r['body'] === '');

array_map('unlink', glob($cacheDir . '/*') ?: []);
@rmdir($cacheDir);
@rmdir(JPATH_CACHE);
@rmdir(JPATH_ADMINISTRATOR);
@rmdir(JPATH_ROOT);
array_map('unlink', glob("$ksBase/state/*") ?: []);
@rmdir("$ksBase/state");
@unlink("$ksBase/blocker");
@rmdir($ka);
@rmdir($kr);
@rmdir("$ksBase/root");
@rmdir($ksBase);
