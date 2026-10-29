<?php
/**
 * Administrator alerts (PLAN-ADMIN-PROTECTION.md A2): who counts as a new
 * Super User, and the mails sent for a created/promoted Super User, a login from
 * a new address and a lock-out — through the real plugin with a stub mailer.
 * Included by run.php after admin_login_flow_tests.php (reuses its helpers).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminChangeDetector;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\FakeMailer;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\Event\Event;

echo "== Admin alerts: who is a new Super User ==\n";

$isSuper = static fn (int $g): bool => in_array($g, [8, 7], true);
$chg     = static fn (?array $old, ?array $new, bool $isNew) => AdminChangeDetector::change($old, $new, $isNew, $isSuper);

ipCheck('a new user in the Super Users group → created', $chg(null, [8 => 8], true) === 'created');
ipCheck('a new user among others, one of them super → created', $chg(null, [2, 8], true) === 'created');
ipCheck('a new ordinary user → nothing', $chg(null, [2 => 2], true) === null && $chg(null, [], true) === null);
ipCheck('an existing user who gains the Super Users group → promoted', $chg([2 => 2], [2 => 2, 8 => 8], false) === 'promoted');
ipCheck('…also for another group the checker calls super', $chg([2], [2, 7], false) === 'promoted');
ipCheck('a Super User saved again with the same groups → nothing', $chg([8], [8], false) === null && $chg([2, 8], [8, 2], false) === null);
ipCheck('a demotion → nothing', $chg([8], [2], false) === null);
ipCheck('a Super User who gains an ordinary group → nothing', $chg([8], [8, 2], false) === null);
ipCheck('a save that carries no groups → nothing, whether new or not', $chg([8], null, false) === null && $chg(null, null, true) === null);
ipCheck('group ids may be strings, duplicated or junk', $chg(['2'], ['2', '8', 8, 'x', 0, -4, null, [], 1.5], false) === 'promoted' && $chg(null, ['x', 0, -8, null], true) === null);
ipCheck('the checker is asked about ids only (never junk)', (function () {
    $seen = [];
    AdminChangeDetector::change([2], [2, '8', 'x', 0], false, static function (int $g) use (&$seen): bool {
        $seen[] = $g;

        return false;
    });

    return $seen === [8];
})());
ipCheck('arrays, objects and other non-scalars in a group list are junk, not group 1', AdminChangeDetector::change(null, [[5], new stdClass(), true], true, static fn (int $g): bool => true) === null);
ipCheck('with unknown "before" groups, every group counts as gained (the plugin never asks in that case)', $chg(null, [8], false) === 'promoted');

echo "== Admin alerts: the plugin and its mails ==\n";

if (!class_exists('Joomla\CMS\Access\Access', false)) {
    eval('namespace Joomla\CMS\Access { class Access { public static function checkGroup($g, $a, $k = null, $p = true) { return (int) $g === 7 && $a === "core.admin"; } } }');
}

$mAdminDir = JPATH_ROOT . '/cache/colorpack_shield/admin';
$mReset    = static function () use ($mAdminDir): void {
    exec('rm -rf ' . escapeshellarg($mAdminDir));
    Log::$messages = [];
    Factory::$mailer = new FakeMailer();
};
$mSeq = static function (array $params, array $server, array $appCfg, array $events, string $client = 'administrator'): void {
    $_SERVER = array_merge(['REQUEST_URI' => '/administrator/index.php', 'CONTENT_TYPE' => '', 'REQUEST_METHOD' => 'POST'], $server);
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $plugin->setApplication(new FakeApp($client, $appCfg));

    foreach ($events as [$name, $args]) {
        $plugin->$name(new Event($name, $args));
    }
};
$mSave = static fn (array $user, bool $isNew, bool $result = true): array => ['onUserAfterSave', ['subject' => $user, 'isNew' => $isNew, 'savingResult' => $result, 'errorMessage' => '']];
$mPre  = static fn (array $oldUser): array => ['onUserBeforeSave', ['subject' => $oldUser, 'isNew' => false, 'data' => []]];
$mCfg  = ['mailfrom' => 'owner@example.test', 'sitename' => 'Demo Site', 'secret' => 'site-secret', 'identity' => (object) ['id' => 1, 'username' => 'root']];
$mSrv  = ['REMOTE_ADDR' => '8.8.8.8'];
$mMail = static fn (): array => Factory::$mailer->sent;

// Created.
$mReset();
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 10, 'username' => 'newboss', 'groups' => [8 => 8]], true)]);
$m = $mMail();
ipCheck('a new Super User → exactly one mail to the site\'s mail-from address', count($m) === 1 && $m[0]['to'] === 'owner@example.test');
ipCheck('…subject names the site, body says "created" with user name, id, groups, who did it and from where', str_contains($m[0]['subject'], 'MAIL_NEWADMIN_SUBJECT Demo Site') && str_contains($m[0]['body'], 'MAIL_NEWADMIN_BODY_CREATED Demo Site newboss 10 8 root (#1) 8.8.8.8 ') && preg_match('/ \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC$/', $m[0]['body']) === 1);
ipCheck('…and the event is logged without any personal data (kind only)', str_contains(implode("\n", Log::$messages), 'ALERT client=administrator kind=newadmin sent=1') && !str_contains(implode("\n", Log::$messages), 'newboss'));
$mReset();
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 11, 'username' => 'member', 'groups' => [2 => 2]], true)]);
ipCheck('a new ordinary user → no mail', $mMail() === []);

// Promoted.
$mReset();
$mSeq([], $mSrv, $mCfg, [$mPre(['id' => 12, 'groups' => [2 => 2]]), $mSave(['id' => 12, 'username' => 'editor', 'groups' => [2 => 2, 8 => 8]], false)]);
$m = $mMail();
ipCheck('an existing user promoted to Super User → a "promoted" mail', count($m) === 1 && str_contains($m[0]['body'], 'MAIL_NEWADMIN_BODY_PROMOTED Demo Site editor 12 2, 8 root (#1)'));
$mReset();
$mSeq([], $mSrv, $mCfg, [$mPre(['id' => 13, 'groups' => [2 => 2]]), $mSave(['id' => 13, 'username' => 'e', 'groups' => [2 => 2, 7 => 7]], false)]);
ipCheck('promotion to another group that holds core.admin also alerts (checked through Joomla\'s Access)', count($mMail()) === 1);
$mReset();
$mSeq([], $mSrv, $mCfg, [$mPre(['id' => 14, 'groups' => [2 => 2, 8 => 8]]), $mSave(['id' => 14, 'username' => 'su', 'groups' => [2 => 2, 8 => 8]], false)]);
ipCheck('a Super User saved again without a change → no mail', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 15, 'username' => 'su', 'groups' => [8 => 8]], false)]);
ipCheck('an existing user saved without the before-event reaching us is skipped (no guessing → no false alarm)', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, [$mPre(['id' => 16, 'groups' => [8 => 8]]), $mSave(['id' => 16, 'username' => 'x', 'groups' => [2 => 2]], false)]);
ipCheck('a demotion → no mail', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 17, 'username' => 'x', 'groups' => [8 => 8]], true, false)]);
ipCheck('a save that failed → no mail', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, [['onUserAfterSave', [0 => ['id' => 18, 'username' => 'legacy', 'groups' => [8 => 8]], 1 => true, 2 => true, 3 => '']]]);
ipCheck('the Joomla 4 (numeric) argument shape works too', count($mMail()) === 1);
$mReset();
$mSeq([], $mSrv, $mCfg, [['onUserAfterSave', ['subject' => 'junk']], ['onUserBeforeSave', ['subject' => null]], ['onUserAfterSave', []]]);
ipCheck('junk arguments are ignored without an exception', $mMail() === []);
$mReset();
$mSeq(['alert_new_admin' => 0], $mSrv, $mCfg, [$mSave(['id' => 19, 'username' => 'x', 'groups' => [8 => 8]], true)]);
ipCheck('alert_new_admin=0 → no mail', $mMail() === []);
$mReset();
touch(JPATH_ROOT . '/colorpack_shield.disable');
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 20, 'username' => 'x', 'groups' => [8 => 8]], true)]);
@unlink(JPATH_ROOT . '/colorpack_shield.disable');
ipCheck('the kill-switch file silences the Super User alert (only the switch\'s own warning mail, if any, is sent)', count(array_filter($mMail(), static fn (array $x): bool => str_contains($x['subject'], 'NEWADMIN'))) === 0);

$mReset();
$mSeq([], $mSrv, $mCfg, [$mPre(['id' => 70, 'groups' => [2 => 2]]), $mSave(['id' => 70, 'username' => 'u', 'groups' => [2 => 2]], false), $mSave(['id' => 70, 'username' => 'u', 'groups' => [2 => 2, 8 => 8]], false)]);
ipCheck('the remembered groups are used for one save only (a later save without a before-event is not compared with stale data)', $mMail() === []);

// Recipient and delivery.
$mReset();
$mSeq(['alert_email' => 'security@example.test'], $mSrv, $mCfg, [$mSave(['id' => 21, 'username' => 'x', 'groups' => [8 => 8]], true)]);
ipCheck('alert_email overrides the site address', ($mMail()[0]['to'] ?? '') === 'security@example.test');
$mReset();
$mSeq([], $mSrv, ['sitename' => 'S', 'secret' => 'x'], [$mSave(['id' => 22, 'username' => 'x', 'groups' => [8 => 8]], true)]);
ipCheck('no recipient at all → nothing sent, nothing breaks', $mMail() === []);
$mReset();
Factory::$mailer = new class () {
    public function addRecipient($t): void
    {
    }

    public function setSubject($s): void
    {
    }

    public function setBody($b): void
    {
    }

    public function Send(): bool
    {
        return false;
    }
};
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 23, 'username' => 'x', 'groups' => [8 => 8]], true)]);
ipCheck('a mailer that fails is logged as sent=0', str_contains(implode("\n", Log::$messages), 'kind=newadmin sent=0'));
Factory::$mailer = new class () {
    public function addRecipient($t): void
    {
        throw new RuntimeException('smtp down');
    }
};
$threw = false;

try {
    $mSeq([], $mSrv, $mCfg, [$mSave(['id' => 24, 'username' => 'x', 'groups' => [8 => 8]], true)]);
} catch (Throwable) {
    $threw = true;
}

ipCheck('a mailer that throws never breaks the save', !$threw);

// Throttle and hygiene.
$mReset();
$mSeq([], $mSrv, $mCfg, [$mSave(['id' => 30, 'username' => 'a', 'groups' => [8 => 8]], true), $mSave(['id' => 30, 'username' => 'a', 'groups' => [8 => 8]], true), $mSave(['id' => 31, 'username' => 'b', 'groups' => [8 => 8]], true)]);
ipCheck('the same user within five minutes mails once; another user mails on its own', count($mMail()) === 2);
$mReset();
$evil = "bad\r\nBcc: attacker@example.test\0" . str_repeat('x', 500);
$mSeq([], $mSrv, ['mailfrom' => 'owner@example.test', 'sitename' => "Site\r\nX: y", 'secret' => 's', 'identity' => (object) ['id' => 2, 'username' => $evil]], [$mSave(['id' => 32, 'username' => $evil, 'groups' => [8 => 8]], true)]);
$m = $mMail()[0] ?? ['subject' => '', 'body' => ''];
ipCheck('request-controlled text is one short printable line: no CR/LF/NUL, each value cut to 200 characters', count($mMail()) === 1 && !preg_match('/[\r\0]/', $m['subject'] . $m['body']) && substr_count($m['subject'], "\n") === 0 && !str_contains($m['body'], str_repeat('x', 201)));

// Login from a new address.
$u42 = static fn (string $name = 'boss', int $id = 42): array => [['onUserAfterLogin', ['options' => ['user' => (object) ['id' => $id, 'username' => $name]], 'subject' => ['username' => $name]]]];
$mReset();
$mSeq([], $mSrv, $mCfg, $u42());
ipCheck('first administrator login ever: remembered silently (no mail)', $mMail() === []);
$mSeq([], $mSrv, $mCfg, $u42());
ipCheck('the same address again: no mail', $mMail() === []);
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42());
$m = $mMail();
ipCheck('a new address → a mail with the user name and the address', count($m) === 1 && str_contains($m[0]['subject'], 'MAIL_NEWIP_SUBJECT Demo Site') && str_contains($m[0]['body'], 'MAIL_NEWIP_BODY Demo Site boss 9.9.9.9 '));
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42());
ipCheck('…and not again from that address', count($mMail()) === 1);
$mSeq([], ['REMOTE_ADDR' => '4.4.4.4'], $mCfg, $u42());
ipCheck('another new address within an hour for the same user is throttled (one mail per user per hour)', count($mMail()) === 1);
$mSeq([], $mSrv, $mCfg, $u42('other', 43));
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42('other', 43));
ipCheck('a different user has his own budget', count($mMail()) === 2);
$mReset();
$mSeq(['alert_new_ip' => 0], $mSrv, $mCfg, $u42());
$mSeq(['alert_new_ip' => 0], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42());
ipCheck('alert_new_ip=0 → no mail', $mMail() === []);
$mReset();
$mSeq([], $mSrv, ['mailfrom' => 'o@example.test'], $u42());
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], ['mailfrom' => 'o@example.test'], $u42());
ipCheck('without a site secret nothing is remembered and nothing is reported', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, $u42('x', 0));
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42('x', 0));
ipCheck('an unknown user id is never reported', $mMail() === []);
$mReset();
$mSeq([], ['REMOTE_ADDR' => '127.0.0.1'], $mCfg, $u42());
$mSeq([], ['REMOTE_ADDR' => '10.0.0.5'], $mCfg, $u42());
ipCheck('a login from a shared/private address (loopback behind an unconfigured proxy) is never reported — it would say nothing', $mMail() === []);
$mReset();
$mSeq([], $mSrv, $mCfg, [['onUserAfterLogin', ['options' => ['user' => ['id' => 44, 'username' => 'arr']]]]]);
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, [['onUserAfterLogin', ['options' => ['user' => ['id' => 44, 'username' => 'arr']]]]]);
ipCheck('the user may arrive as an object or as an array', count($mMail()) === 1);
$mReset();
$mSeq([], $mSrv, $mCfg, $u42(), 'site');
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42(), 'site');
ipCheck('front-end logins are not administrator logins: never reported', $mMail() === []);
$mReset();
touch(JPATH_ROOT . '/colorpack_shield.disable');
$mSeq([], $mSrv, $mCfg, $u42());
$mSeq([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg, $u42());
@unlink(JPATH_ROOT . '/colorpack_shield.disable');
ipCheck('the new-address notice is a login-time notice and still works while the kill-switch file exists (the switch only stops enforcement)', count(array_filter($mMail(), static fn (array $x): bool => str_contains($x['subject'], 'NEWIP'))) === 1);

// Lock-out summary.
$fail5 = static function (array $params, array $server, array $appCfg) use ($mSeq): void {
    $ev = [];

    for ($i = 0; $i < 5; $i++) {
        $ev[] = ['onUserLoginFailure', ['subject' => ['username' => 'victim' . $i]]];
    }

    $mSeq($params, $server, $appCfg, $ev);
};
$mReset();
$fail5([], $mSrv, $mCfg);
$m = $mMail();
ipCheck('a new lock → one mail: address, seconds, repeat offences, "enforced", nothing held back', count($m) === 1 && str_contains($m[0]['subject'], 'MAIL_LOCKOUT_SUBJECT Demo Site') && str_contains($m[0]['body'], 'MAIL_LOCKOUT_BODY Demo Site 8.8.8.8 900 1 PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_ENFORCED 0 '));
ipCheck('…and it never names the users that were tried', !str_contains($m[0]['body'], 'victim'));
$fail5([], $mSrv + ['x' => 1], $mCfg);
$fail5([], ['REMOTE_ADDR' => '9.9.9.9'], $mCfg);
ipCheck('further locks within the hour are held back (one mail per hour)', count($mMail()) === 1);
// Pretend the last mail was long ago, with two held back.
(new FileStateStore($mAdminDir))->mutate('alert:lockout', time(), static fn (?array $e): array => ['last' => time() - 4000, 'held' => 2, 'exp' => time() + 4000]);
$fail5([], ['REMOTE_ADDR' => '5.5.5.5'], $mCfg);
$m = $mMail();
ipCheck('the next mail after the hour says how many were held back (2)', count($m) === 2 && str_contains($m[1]['body'], 'MAIL_LOCKOUT_BODY Demo Site 5.5.5.5 900 1 PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_ENFORCED 2 '));
$mReset();
$fail5([], ['REMOTE_ADDR' => '127.0.0.1'], $mCfg);
$m = $mMail();
ipCheck('a lock on a shared address says "observed only"', count($m) === 1 && str_contains($m[0]['body'], 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_OBSERVED'));
$mReset();
$mSeq([], $mSrv, $mCfg, $u42());
$fail5([], $mSrv, $mCfg);
$m = $mMail();
ipCheck('a lock on an address an administrator uses says "observed only"', count($m) === 1 && str_contains($m[0]['body'], 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_OBSERVED'));
$mReset();
$fail5(['alert_lockouts' => 0], $mSrv, $mCfg);
ipCheck('alert_lockouts=0 → no mail (the lock itself still happens)', $mMail() === [] && (new FileStateStore($mAdminDir))->entries('ip:', time()) !== []);
$mReset();
$fail5([], $mSrv, $mCfg);
$mReset();
Factory::$mailer = new FakeMailer();
for ($i = 0; $i < 4; $i++) {
    $mSeq([], ['REMOTE_ADDR' => '6.6.6.6'], $mCfg, [['onUserLoginFailure', ['subject' => ['username' => 'x']]]]);
}

ipCheck('4 failures (no lock yet) → no mail', $mMail() === []);
$mReset();
$mSeq(['allow_ips' => "8.8.8.8\n"], $mSrv, $mCfg, array_fill(0, 6, ['onUserLoginFailure', ['subject' => ['username' => 'x']]]));
ipCheck('a trusted address never causes a lock mail', $mMail() === []);

// Storage trouble: the throttle is fail-closed, so nothing is mailed.
$mReset();
@mkdir(JPATH_ROOT . '/cache', 0777, true);
exec('rm -rf ' . escapeshellarg(JPATH_ROOT . '/cache/colorpack_shield'));
file_put_contents(JPATH_ROOT . '/cache/colorpack_shield', 'a file where the folder should be');
$threw = false;

try {
    $mSeq([], $mSrv, $mCfg, [$mSave(['id' => 50, 'username' => 'x', 'groups' => [8 => 8]], true)]);
    $fail5([], $mSrv, $mCfg);
    $mSeq([], $mSrv, $mCfg, $u42());
} catch (Throwable) {
    $threw = true;
}

ipCheck('unusable storage: no mail at all (fail-closed, never a flood) and no exception', !$threw && $mMail() === []);
@unlink(JPATH_ROOT . '/cache/colorpack_shield');
$mReset();
