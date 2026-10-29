<?php
/**
 * Multi-factor authentication for administrators (PLAN-ADMIN-PROTECTION.md A3):
 * the pure policy, the Joomla gateway (against stand-ins for Joomla's MFA
 * classes) and the plugin step. Included by run.php after admin_alerts_tests.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\JoomlaMfaGateway;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\MfaPolicy;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;
use Colorpack\Tests\FakeApp;
use Colorpack\Tests\RequestEnded;
use Joomla\CMS\Log\Log;
use Joomla\Event\Event;

echo "== Admin MFA: policy ==\n";

$Tn = 1_800_000_000;
$pd = static fn (string $mode, bool $applies = true, bool $has = false, int $first = 0, int $now = 0, int $grace = 7, bool $exempt = false, bool $html = true): array => MfaPolicy::decide($mode, $applies, $has, $Tn + $first, $Tn + $now, $grace, $exempt, $html);

ipCheck('mode off or unknown → nothing', $pd('off')['action'] === 'none' && $pd('junk')['action'] === 'none' && $pd('')['action'] === 'none');
ipCheck('a user the policy does not apply to, or who has MFA → nothing', $pd('enforce', false, false, 0, 99 * 86400)['action'] === 'none' && $pd('enforce', true, true, 0, 99 * 86400)['action'] === 'none' && $pd('warn', false)['action'] === 'none');
ipCheck('warn mode inside the grace: a reminder with the days left (7 on day 0)', $pd('warn') === ['action' => 'warn', 'daysLeft' => 7, 'overdue' => false]);
ipCheck('warn mode after the grace: still only a reminder, now "overdue"', $pd('warn', true, false, 0, 30 * 86400) === ['action' => 'warn', 'daysLeft' => 0, 'overdue' => true]);
ipCheck('enforce inside the grace: a reminder, never a redirect', $pd('enforce', true, false, 0, 3 * 86400)['action'] === 'warn' && $pd('enforce', true, false, 0, 3 * 86400)['daysLeft'] === 4);
ipCheck('days left are rounded up: 1 s into the grace → 7, 1 s before the end → 1, exactly at the end → overdue', $pd('enforce', true, false, 0, 1)['daysLeft'] === 7 && $pd('enforce', true, false, 0, 7 * 86400 - 1)['daysLeft'] === 1 && $pd('enforce', true, false, 0, 7 * 86400)['overdue'] === true);
ipCheck('enforce after the grace: redirect for an ordinary page, deny for ajax / json', $pd('enforce', true, false, 0, 8 * 86400)['action'] === 'redirect' && $pd('enforce', true, false, 0, 8 * 86400, 7, false, false)['action'] === 'deny');
ipCheck('enforce after the grace: the MFA pages and logout (exempt) stay reachable, with no message', $pd('enforce', true, false, 0, 8 * 86400, 7, true)['action'] === 'none' && $pd('enforce', true, false, 0, 8 * 86400, 7, true, false)['action'] === 'none');
ipCheck('inside the grace the exempt pages get no reminder either', $pd('enforce', true, false, 0, 86400, 7, true)['action'] === 'none' && $pd('warn', true, false, 0, 86400, 7, true)['action'] === 'none');
ipCheck('grace 0 means enforce at once; a negative grace is overdue at once as well', $pd('enforce', true, false, 0, 0, 0)['action'] === 'redirect' && $pd('enforce', true, false, 0, 0, -5)['action'] === 'redirect');
ipCheck('a user first seen only now (store trouble) with a grace is only reminded', $pd('enforce', true, false, 0, 0, 7)['action'] === 'warn');

echo "== Admin MFA: Joomla gateway ==\n";

if (!class_exists('Joomla\Component\Users\Administrator\Helper\Mfa', false)) {
    eval('namespace Joomla\Component\Users\Administrator\Helper { class Mfa { public static array $methods = []; public static array $records = []; public static bool $throw = false; public static function getMfaMethods(): array { if (self::$throw) { throw new \RuntimeException("x"); } return self::$methods; } public static function getUserMfaRecords(?int $id): array { if (self::$throw) { throw new \RuntimeException("x"); } return self::$records[$id] ?? []; } } }');
    eval('namespace Joomla\CMS\Component { class ComponentHelper { public static $never = []; public static function getParams(string $c) { return new class () { public function get($k, $d = null) { return $k === "neverMFAUserGroups" ? \Joomla\CMS\Component\ComponentHelper::$never : $d; } }; } } }');
    eval('namespace Joomla\CMS\Uri { class Uri { public static $base = "http://example.test/administrator/"; public static $throw = false; public static function base(bool $path = false): string { if (self::$throw) { throw new \RuntimeException("x"); } return self::$base; } } }');
}

use Joomla\CMS\Component\ComponentHelper as CH;
use Joomla\CMS\Uri\Uri as RT;
use Joomla\Component\Users\Administrator\Helper\Mfa as M;

$resetMfa = static function (): void {
    M::$methods = [['name' => 'totp']];
    M::$records = [];
    M::$throw   = false;
    CH::$never  = [];
    RT::$base   = 'http://example.test/administrator/';
    RT::$throw  = false;
};
$resetMfa();
M::$methods = [];
ipCheck('available(): false when no multi-factor method is enabled', JoomlaMfaGateway::available() === false);
M::$methods = [['name' => 'totp']];
ipCheck('available(): true when one is', JoomlaMfaGateway::available() === true);
M::$throw = true;
ipCheck('available() / userHasMfa(): a helper that throws means "no", never an exception', JoomlaMfaGateway::available() === false && JoomlaMfaGateway::userHasMfa(5) === false);
$resetMfa();
M::$records = [5 => [(object) ['method' => 'totp']], 6 => [(object) ['method' => 'oldmethod']], 7 => [(object) ['method' => 'oldmethod'], (object) ['method' => 'totp']]];
ipCheck('userHasMfa(): a record of an enabled method counts', JoomlaMfaGateway::userHasMfa(5) && JoomlaMfaGateway::userHasMfa(7));
ipCheck('userHasMfa(): a record of a method that is no longer enabled does not (Joomla would not ask for it either)', JoomlaMfaGateway::userHasMfa(6) === false);
M::$methods = ['totp' => new ArrayObject(['name' => 'totp']), 'email' => (object) ['name' => 'email']];
ipCheck('userHasMfa(): the methods may be ArrayAccess objects or plain objects, keyed by name (as on a real Joomla 6.1.4 — found there)', JoomlaMfaGateway::userHasMfa(5) === true && JoomlaMfaGateway::userHasMfa(6) === false);
M::$methods = ['totp' => ['name' => 'totp']];
ipCheck('…and keyed arrays work too', JoomlaMfaGateway::userHasMfa(5) === true && JoomlaMfaGateway::available() === true);
M::$methods = [['name' => 'totp']];
M::$records[0] = [(object) ['method' => 'totp']];
M::$records[-3] = [(object) ['method' => 'totp']];
ipCheck('userHasMfa(): id 0 or negative is never looked up (Joomla\'s helper treats an empty id as "the current user")', JoomlaMfaGateway::userHasMfa(0) === false && JoomlaMfaGateway::userHasMfa(-3) === false);
unset(M::$records[0], M::$records[-3]);
ipCheck('userHasMfa(): no records, id 0 or negative → false', JoomlaMfaGateway::userHasMfa(99) === false && JoomlaMfaGateway::userHasMfa(0) === false && JoomlaMfaGateway::userHasMfa(-3) === false);
$u1 = new class () {
    public function getAuthorisedGroups(): array
    {
        return [1, '8', 8, 'x', 0];
    }
};
$u2 = (object) ['groups' => [3 => 3, 4 => 4]];
ipCheck('userGroups(): authorised groups as unique ints; falls back to the groups property; junk → none', JoomlaMfaGateway::userGroups($u1) === [1, 8] && JoomlaMfaGateway::userGroups($u2) === [3, 4] && JoomlaMfaGateway::userGroups((object) []) === []);
CH::$never = ['7', 0, 'x', 9];
ipCheck('neverGroups(): the group ids Joomla exempts, junk dropped', JoomlaMfaGateway::neverGroups() === [7, 9]);
CH::$never = 'not an array';
ipCheck('neverGroups(): a setting that is not a list → none', JoomlaMfaGateway::neverGroups() === []);
$mkApp = static fn (array $input): FakeApp => new FakeApp('administrator', ['input' => $input]);
ipCheck('isExemptPage(): a normal page is not exempt', JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_content', 'view' => 'articles'])) === false);
ipCheck('isExemptPage(): Joomla\'s own MFA pages are (its list, asked of the application)', JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_users', 'view' => 'methods'])) === true && JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_users', 'view' => 'captive'])) === true);
ipCheck('isExemptPage(): logout is, and so are the update finalisation steps', JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_login', 'task' => 'logout'])) && JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_joomlaupdate', 'task' => 'update.finalise'])) && !JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_joomlaupdate', 'task' => 'update.install'])) && !JoomlaMfaGateway::isExemptPage($mkApp(['option' => 'com_login', 'task' => 'login'])));
ipCheck('isExemptPage(): an application that cannot answer → the page is left alone', JoomlaMfaGateway::isExemptPage(new stdClass()) === true);
ipCheck('setupUrl(): a relative address that depends on no Joomla router or base helper (so it can never be doubled)', JoomlaMfaGateway::setupUrl() === 'index.php?option=com_users&view=methods' && (function () {
    RT::$throw = true;
    RT::$base  = 'http://example.test/administrator/index.php/';
    $u = JoomlaMfaGateway::setupUrl();
    RT::$throw = false;

    return $u === 'index.php?option=com_users&view=methods';
})());

echo "== Admin MFA: the plugin step ==\n";

$mfaDir = JPATH_ROOT . '/cache/colorpack_shield/admin';
$resetPlug = static function () use ($mfaDir, $resetMfa): void {
    exec('rm -rf ' . escapeshellarg($mfaDir));
    Log::$messages = [];
    $resetMfa();
};
$mkUser = static fn (int $id, array $groups, bool $guest = false): object => new class ($id, $groups, $guest) {
    public function __construct(public int $id, private array $groups, public bool $guest)
    {
    }

    public function getAuthorisedGroups(): array
    {
        return $this->groups;
    }
};
/** Run onAfterRoute; returns what happened. */
$route = static function (array $params, ?object $user, array $input = [], string $client = 'administrator') use ($mkUser): array {
    $_SERVER = ['REMOTE_ADDR' => '8.8.8.8', 'REQUEST_URI' => '/administrator/index.php', 'CONTENT_TYPE' => '', 'REQUEST_METHOD' => 'GET'];
    $subject = new stdClass();
    $plugin  = new ColorpackShield($subject, ['params' => $params]);
    $app     = new FakeApp($client, ['identity' => $user, 'input' => $input, 'secret' => 's']);
    $plugin->setApplication($app);
    $threw = null;

    try {
        $plugin->onAfterRoute(new Event('onAfterRoute'));
    } catch (RequestEnded) {
        $threw = 'ended';
    } catch (RuntimeException $e) {
        $threw = 'runtime:' . $e->getCode();
    }

    return ['redirects' => $app->redirects, 'messages' => $app->messages, 'threw' => $threw];
};
$su    = $mkUser(60, [1, 8]);
$page  = ['option' => 'com_content', 'view' => 'articles'];
$warn  = ['mfa_enforce' => 'warn'];
$force = ['mfa_enforce' => 'enforce'];
$setStart = static function (int $userId, int $firstSeenOffset) use ($mfaDir): void {
    (new FileStateStore($mfaDir))->mutate('mfa:' . $userId, time(), static fn (?array $e): array => ['first' => time() + $firstSeenOffset, 'exp' => time() + 400 * 86400]);
};

$resetPlug();
$r = $route([], $su, $page);
ipCheck('mfa_enforce off (the default): no message, no redirect, nothing stored', $r['messages'] === [] && $r['redirects'] === [] && !is_dir($mfaDir));
$r = $route($warn, $su, $page);
ipCheck('warn: a reminder with the days left (7) and the setup address; no redirect', count($r['messages']) === 1 && $r['redirects'] === [] && str_contains($r['messages'][0][0], 'MFA_MSG_GRACE 7 index.php?option=com_users&amp;view=methods') && $r['messages'][0][1] === 'warning');
$first = (new FileStateStore($mfaDir))->get('mfa:60', time())['first'] ?? 0;
$exp1 = (new FileStateStore($mfaDir))->get('mfa:60', time())['exp'] ?? 0;
sleep(1);
$route($warn, $su, $page);
ipCheck('the grace starts at the first sighting and later requests do not move it', $first > 0 && ((new FileStateStore($mfaDir))->get('mfa:60', time())['first'] ?? -1) === $first);
ipCheck('…and they do not even write to the store (one write per user, not one per page view)', ((new FileStateStore($mfaDir))->get('mfa:60', time())['exp'] ?? -1) === $exp1);
$resetPlug();
(new FileStateStore($mfaDir))->mutate('mfa:60', time(), static fn (?array $e): array => ['first' => time() - 8 * 86400, 'exp' => time() + 10 * 86400]);
$r = $route($force, $su, $page);
ipCheck('an entry close to expiry is extended but its first-sighting date is kept (the grace is not restarted)', $r['threw'] === 'ended' && ((new FileStateStore($mfaDir))->get('mfa:60', time())['exp'] ?? 0) > time() + 60 * 86400);
$resetPlug();
$route($warn, $su, $page);
$setStart(60, -30 * 86400);
$r = $route($warn, $su, $page);
ipCheck('warn after the grace: the "overdue" reminder, still no redirect', count($r['messages']) === 1 && $r['redirects'] === [] && str_contains($r['messages'][0][0], 'MFA_MSG_OVERDUE index.php?option=com_users&amp;view=methods'));
$resetPlug();
$route($force, $su, $page);
$setStart(60, -3 * 86400);
$r = $route($force, $su, $page);
ipCheck('enforce inside the grace: a reminder with the days left (4), no redirect', count($r['messages']) === 1 && $r['redirects'] === [] && str_contains($r['messages'][0][0], 'MFA_MSG_GRACE 4 '));
$setStart(60, -8 * 86400);
$r = $route($force, $su, $page);
ipCheck('enforce after the grace: a 307 redirect to the setup page and a "required" message', $r['threw'] === 'ended' && $r['redirects'] === [['index.php?option=com_users&view=methods', 307]] && str_contains($r['messages'][0][0] ?? '', 'MFA_MSG_REQUIRED'));
ipCheck('…and it is logged without the user\'s name', str_contains(implode("\n", Log::$messages), 'NOTE client=administrator kind=mfa reason=redirect_to_setup') && !str_contains(implode("\n", Log::$messages), 'root'));
Log::$messages = [];
for ($i = 0; $i < 5; $i++) {
    $route($force, $su, $page);
}

ipCheck('the log line is written once a minute, not once per redirect', substr_count(implode("\n", Log::$messages), 'kind=mfa') <= 1);
foreach ([
    'the MFA setup page' => ['option' => 'com_users', 'view' => 'methods'],
    'the MFA captive page' => ['option' => 'com_users', 'view' => 'captive'],
    'logout' => ['option' => 'com_login', 'task' => 'logout'],
    'the Joomla update finalisation' => ['option' => 'com_joomlaupdate', 'task' => 'update.finalise'],
] as $label => $in) {
    $r = $route($force, $su, $in);
    ipCheck("enforce after the grace: $label stays reachable (no redirect, no message — no loop)", $r['threw'] === null && $r['redirects'] === [] && $r['messages'] === []);
}

$r = $route($force, $su, ['option' => 'com_ajax', 'format' => 'json']);
ipCheck('enforce after the grace: a json / ajax request is refused with 403 (as Joomla does for a pending MFA)', $r['threw'] === 'runtime:403' && $r['redirects'] === []);
$resetPlug();
M::$records[60] = [(object) ['method' => 'totp']];
$setStart(60, -30 * 86400);
$r = $route($force, $su, $page);
ipCheck('a user who has MFA is left alone (Joomla\'s captive page does its own work)', $r['threw'] === null && $r['redirects'] === [] && $r['messages'] === []);
M::$records[60] = [(object) ['method' => 'oldmethod']];
$r = $route($force, $su, $page);
ipCheck('a record of a disabled method is no MFA: still enforced', $r['threw'] === 'ended');
$resetPlug();
$setStart(61, -30 * 86400);
$r = $route($force, $mkUser(61, [1, 2]), $page);
ipCheck('a user outside the configured groups is not affected', $r['threw'] === null && $r['messages'] === []);
$r = $route($force + ['mfa_groups' => [7]], $mkUser(61, [1, 2, 7]), $page);
ipCheck('mfa_groups can name another group (7 here)', $r['threw'] === 'ended');
CH::$never = [7];
$r = $route($force + ['mfa_groups' => [7]], $mkUser(61, [1, 2, 7]), $page);
ipCheck('a group Joomla exempts from MFA ("Disable Multi-factor Authentication") is respected', $r['threw'] === null && $r['messages'] === []);
$resetPlug();
$r = $route($force, null, $page);
$r2 = $route($force, $mkUser(0, [8]), $page);
$r3 = $route($force, $mkUser(62, [8], true), $page);
ipCheck('no identity, id 0 or a guest → nothing', $r['threw'] === null && $r2['threw'] === null && $r3['threw'] === null && !is_dir($mfaDir));
$r = $route($force, $su, $page, 'site');
ipCheck('only the administrator application is touched', $r['threw'] === null && $r['messages'] === []);
$setStart(60, -30 * 86400);
touch(JPATH_ROOT . '/colorpack_shield.disable');
$r = $route($force, $su, $page);
@unlink(JPATH_ROOT . '/colorpack_shield.disable');
ipCheck('the kill-switch file lifts the enforcement (the existing "switched off" notice is all that is shown)', $r['threw'] === null && $r['redirects'] === [] && count(array_filter($r['messages'], static fn (array $m): bool => str_contains($m[0], 'MFA_MSG'))) === 0);
$resetPlug();
M::$methods = [];
$setStart(60, -30 * 86400);
$r = $route($force, $su, $page);
ipCheck('with no multi-factor method enabled in Joomla there is nothing to set up: nothing is enforced', $r['threw'] === null && $r['messages'] === []);
$resetPlug();
M::$throw = true;
$r = $route($force, $su, $page);
ipCheck('Joomla\'s MFA classes failing → nothing happens, nothing breaks', $r['threw'] === null && $r['messages'] === []);
$resetPlug();
$r = $route($force + ['mfa_grace_days' => 0], $su, $page);
ipCheck('grace 0 with enforce: redirected at once', $r['threw'] === 'ended');

// Unusable storage: no grace can be tracked, so a grace means only reminders.
$resetPlug();
@mkdir(JPATH_ROOT . '/cache', 0777, true);
exec('rm -rf ' . escapeshellarg(JPATH_ROOT . '/cache/colorpack_shield'));
file_put_contents(JPATH_ROOT . '/cache/colorpack_shield', 'a file where the folder should be');
$r = $route($force, $su, $page);
ipCheck('unusable storage with a grace: only a reminder (never a redirect)', $r['threw'] === null && count($r['messages']) === 1 && str_contains($r['messages'][0][0], 'MFA_MSG_GRACE 7'));
@unlink(JPATH_ROOT . '/colorpack_shield');
$resetPlug();

$resetPlug();
