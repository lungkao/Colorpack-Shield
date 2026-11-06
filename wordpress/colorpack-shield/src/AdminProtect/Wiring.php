<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\AdminProtect;

use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\Geo\CidrMatcher;
use Colorpack\WP\ColorpackShield\Mfa\BackupCodes;
use Colorpack\WP\ColorpackShield\Mfa\MfaChallenge;
use Colorpack\WP\ColorpackShield\Mfa\MfaStore;
use Colorpack\WP\ColorpackShield\Mfa\Totp;
use Colorpack\WP\ColorpackShield\Net\ClientIp;
use Colorpack\WP\ColorpackShield\Net\ClientIpResolver;
use Colorpack\WP\ColorpackShield\Net\IpAllowList;

\defined('ABSPATH') || die;

/**
 * Wires the pure AdminProtect classes (ported from the Joomla edition) into WordPress's own
 * login lifecycle and wp-admin request flow - the WordPress equivalent of the login-protection
 * parts of the Joomla edition's `Extension\ColorpackShield`.
 *
 * Off by default, same as every other server-facing feature in this plugin: nothing here runs
 * unless `Settings::get()['login_protect_enabled']` (or the gate's own toggle) is on. MFA is the
 * exception - it is this port's own TOTP (`Mfa\Totp`), not a bridge to a host CMS API the way the
 * Joomla edition's `JoomlaMfaGateway` is, and a user's own enrollment (once confirmed) is always
 * required at login regardless of the site-wide `mfa_mode` policy, the same way any personal
 * second factor works - `mfa_mode`/`mfa_grace_days` only govern the nag/enforcement for
 * administrators who have *not* enrolled yet.
 *
 * New-admin/promotion alerts (`AdminChangeDetector`, re-worked for WordPress's string role
 * slugs - see its own docblock) are wired to `user_register`/`profile_update`, the WordPress
 * equivalents of the Joomla edition's `onUserBeforeSave`/`onUserAfterSave` pair - WordPress
 * hands the pre-update roles straight to `profile_update` via its `$old_user_data` argument, so
 * no separate "remember the before state" step is needed the way the Joomla plugin needs one.
 */
final class Wiring
{
    /** A fixed, deliberately low limit on MFA-code guesses, independent of the Settings login rate limit - a brute-force surface this specific, this sensitive, is worth protecting even when the operator has left the general rate limit off. */
    private const MFA_ATTEMPTS_PER_MINUTE = 8;

    public static function boot(): void
    {
        // Priority 1: answers a pending MFA challenge before WP core's own username/password
        // check (priority 20) runs - see maybeVerifyMfaChallenge()'s own docblock for why this
        // ordering matters.
        add_filter('authenticate', [self::class, 'maybeVerifyMfaChallenge'], 1, 3);
        add_filter('authenticate', [self::class, 'maybeBlockLocked'], 30, 3);
        add_filter('authenticate', [self::class, 'maybeChallengeMfa'], 40, 3);
        add_action('wp_login_failed', [self::class, 'onLoginFailed'], 10, 1);
        add_action('wp_login', [self::class, 'onLoginSucceeded'], 10, 2);
        add_action('login_init', [self::class, 'maybeGate']);
        add_action('admin_init', [self::class, 'maybeGate']);
        add_action('admin_init', [self::class, 'maybeEnforceMfa']);
        add_action('admin_notices', [self::class, 'maybeMfaNotice']);
        add_action('user_register', [self::class, 'onUserRegistered'], 20, 1);
        add_action('profile_update', [self::class, 'onProfileUpdated'], 20, 2);
    }

    /**
     * Refuses an already-locked address regardless of whether the password was right - matches
     * the Joomla edition's "a lock-out must not be a weapon" rule: this never fires FROM a
     * failed attempt (that's onLoginFailed()'s job), only blocks ones already locked out.
     */
    public static function maybeBlockLocked($user, string $username, string $password)
    {
        $cfg = Settings::get();

        if (!$cfg['login_protect_enabled'] || $username === '' || $password === '') {
            return $user;
        }

        $client = self::client();
        $store  = self::store();
        $apCfg  = AdminProtectConfig::fromArray($cfg);
        $known  = KnownIps::isAdminAddress($store, $client->ip, self::salt(), time());
        $policy = new LockoutPolicy($apCfg, $store);
        $decide = $policy->decide($client, [], [], true, time(), $known);

        if ($decide->blocks()) {
            return new \WP_Error('cps_locked', __('Too many failed login attempts. Please try again later.', 'colorpack-shield'));
        }

        return $user;
    }

    public static function onLoginFailed(string $username): void
    {
        $cfg = Settings::get();

        if (!$cfg['login_protect_enabled']) {
            return;
        }

        $client = self::client();
        $store  = self::store();
        $apCfg  = AdminProtectConfig::fromArray($cfg);
        $result = (new LockoutPolicy($apCfg, $store))->recordFailure($client->ip, $username, time());

        if ($result['locked'] ?? false) {
            // Public event; carries no username or address. Add-ons may listen (nothing is sent from here).
            do_action('colorpack_shield_lockout', time());
        }

        if (($result['locked'] ?? false) && $apCfg->alertLockouts) {
            self::alert($store, 'lock:' . ($result['bucket'] ?? 'unknown'), 60, static function () use ($username): void {
                $admin = get_option('admin_email');

                if (\is_string($admin) && $admin !== '') {
                    wp_mail(
                        $admin,
                        __('Colorpack Shield: login lockout', 'colorpack-shield'),
                        sprintf(__('An address was locked out after repeated failed logins for user "%s".', 'colorpack-shield'), $username)
                    );
                }
            });
        }
    }

    public static function onLoginSucceeded(string $userLogin, \WP_User $user): void
    {
        $cfg = Settings::get();

        if (!$cfg['login_protect_enabled']) {
            return;
        }

        $client = self::client();
        $store  = self::store();
        $apCfg  = AdminProtectConfig::fromArray($cfg);
        (new LockoutPolicy($apCfg, $store))->recordSuccess($client->ip, time());
        KnownIps::rememberAdminAddress($store, $client->ip, self::salt(), time());

        if (!user_can($user, 'manage_options')) {
            return;
        }

        $seen = KnownIps::observe($store, $user->ID, $client->ip, self::salt(), time());

        if ($seen === KnownIps::NEW && $apCfg->alertNewIp && IpAllowList::isSafeToAutoAdd($client, [], [])) {
            self::alert($store, 'newip:' . $user->ID, 3600, static function () use ($user): void {
                $admin = get_option('admin_email');

                if (\is_string($admin) && $admin !== '') {
                    wp_mail(
                        $admin,
                        __('Colorpack Shield: administrator sign-in from a new address', 'colorpack-shield'),
                        sprintf(__('"%s" signed in from an address not seen before.', 'colorpack-shield'), $user->user_login)
                    );
                }
            });
        }
    }

    /** A brand-new user was inserted: alert if the role they were given is super. */
    public static function onUserRegistered(int $userId): void
    {
        $apCfg = AdminProtectConfig::fromArray(Settings::get());

        if (!$apCfg->alertNewAdmin) {
            return;
        }

        $user = get_userdata($userId);

        if ($user === false) {
            return;
        }

        $kind = AdminChangeDetector::change([], array_values($user->roles), true, [self::class, 'isSuperRole']);

        if ($kind !== null) {
            self::notifyAdminChange($kind, $user, null);
        }
    }

    /**
     * An existing user was updated: WordPress hands us their roles from just before the save
     * (`$oldUserData`), so - unlike the Joomla edition's own onUserBeforeSave/onUserAfterSave
     * pair - no separate "remember the before state" step is needed here.
     */
    public static function onProfileUpdated(int $userId, \WP_User $oldUserData): void
    {
        $apCfg = AdminProtectConfig::fromArray(Settings::get());

        if (!$apCfg->alertNewAdmin) {
            return;
        }

        $user = get_userdata($userId);

        if ($user === false) {
            return;
        }

        $kind = AdminChangeDetector::change(array_values($oldUserData->roles), array_values($user->roles), false, [self::class, 'isSuperRole']);

        if ($kind !== null) {
            self::notifyAdminChange($kind, $user, wp_get_current_user());
        }
    }

    /** Mails the site admin that a user was just created or promoted with administrator-level powers. */
    private static function notifyAdminChange(string $kind, \WP_User $user, ?\WP_User $actor): void
    {
        self::alert(self::store(), 'newadmin:' . $user->ID, 300, static function () use ($kind, $user, $actor): void {
            $admin = get_option('admin_email');

            if (!\is_string($admin) || $admin === '') {
                return;
            }

            $actorLabel = $actor !== null && $actor->ID > 0 ? sprintf('%s (#%d)', $actor->user_login, $actor->ID) : '-';

            wp_mail(
                $admin,
                __('Colorpack Shield: new administrator', 'colorpack-shield'),
                $kind === AdminChangeDetector::CREATED
                    ? sprintf(__('A new user, "%1$s" (#%2$d), was created with administrator powers. Changed by: %3$s.', 'colorpack-shield'), $user->user_login, $user->ID, $actorLabel)
                    : sprintf(__('The user "%1$s" (#%2$d) was just given administrator powers. Changed by: %3$s.', 'colorpack-shield'), $user->user_login, $user->ID, $actorLabel)
            );
        });
    }

    /**
     * Does this role grant administrator-level powers? Checked via the `manage_options`
     * capability (the same capability WP core itself gates wp-admin on), not a hardcoded
     * 'administrator' slug, so a custom role a plugin grants that capability to still counts -
     * the WordPress equivalent of the Joomla edition's own `Access::checkGroup($id, 'core.admin')`
     * check.
     */
    public static function isSuperRole(string $role): bool
    {
        if ($role === '') {
            return false;
        }

        $roleObj = wp_roles()->get_role($role);

        return $roleObj instanceof \WP_Role && $roleObj->has_cap('manage_options');
    }

    /**
     * The access key "door" - runs on both the login screen and every wp-admin page, exactly
     * like the Joomla edition's `adminAccessGate()` runs for the whole /administrator path,
     * regardless of whether a session already exists (defense in depth, not a session check).
     */
    public static function maybeGate(): void
    {
        $cfg = AccessGateConfig::fromArray(Settings::get());

        if ($cfg->off()) {
            return;
        }

        $client        = self::client();
        $ipEnforceable = $client->via === ClientIp::VIA_DIRECT || $client->via === ClientIp::VIA_PROXY;
        $ipListed      = $ipEnforceable && CidrMatcher::matchesAny($client->ip, $cfg->ipList);
        $cookie        = $_COOKIE[AccessGate::COOKIE] ?? null;
        $given         = $_GET[AccessGate::PARAM] ?? null;

        $d = AccessGate::decide(
            $cfg,
            \is_string($cookie) ? $cookie : null,
            \is_string($given) ? $given : null,
            $ipEnforceable,
            $ipListed,
            (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''),
            wp_salt('auth'),
            time()
        );

        if ($d['action'] === AccessGate::ALLOW || $d['action'] === AccessGate::OBSERVE) {
            return;
        }

        if ($d['action'] === AccessGate::EXCHANGE) {
            $expiry = time() + $cfg->cookieHours * 3600;
            setcookie(
                AccessGate::COOKIE,
                AccessGate::cookieValue(wp_salt('auth'), $cfg->key, (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), $expiry),
                ['expires' => $expiry, 'path' => '/', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']
            );
            wp_safe_redirect(AccessGate::cleanUri((string) ($_SERVER['REQUEST_URI'] ?? '/')));
            exit;
        }

        // DENY: a generic 404, same as the Joomla edition - never reveal that a door exists here.
        // A plain, dependency-free 404 (not the active theme's template.php, which this runs too
        // early to safely load on every wp-admin/login_init hit, and may not even exist).
        status_header(404);
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');
        exit('<!doctype html><title>404 Not Found</title><h1>Not Found</h1>');
    }

    /**
     * Answers a pending MFA challenge, if this POST is one - runs at priority 1, before WP
     * core's own `wp_authenticate_username_password` (priority 20), so that on this POST
     * (`cps_mfa_token`/`cps_mfa_code`, never `log`/`pwd`) core sees `$username === ''` and, per
     * its own first lines (`if ($user instanceof WP_User) return $user;` /
     * `if (is_wp_error($user)) return $user;` once both credentials are empty), passes our result
     * straight through unchanged - the same is true of every later `authenticate` callback here,
     * since each one is itself a no-op on empty username/password. This is what lets `wp_signon()`
     * finish the login (set the auth cookie, fire `wp_login`) exactly as it would for an ordinary
     * successful username/password check.
     */
    public static function maybeVerifyMfaChallenge($user, string $username, string $password)
    {
        if (!isset($_POST['cps_mfa_token'], $_POST['cps_mfa_code'])) {
            return $user;
        }

        $store = self::store();
        $now   = time();
        $token = (string) wp_unslash($_POST['cps_mfa_token']);
        $code  = (string) wp_unslash($_POST['cps_mfa_code']);

        $client = self::client();
        $rate   = LoginRateLimit::hit($store, $client->ip, self::MFA_ATTEMPTS_PER_MINUTE, $now);

        if ($rate['over']) {
            return new \WP_Error('cps_mfa_rate', self::challengeForm($token, MfaChallenge::remember($store, $token, $now), __('Too many attempts. Please wait a minute and try again.', 'colorpack-shield')));
        }

        $userId = MfaChallenge::userId($store, $token, $now);
        $wpUser = $userId !== null ? get_user_by('id', $userId) : false;

        if ($userId === null || !$wpUser instanceof \WP_User) {
            return new \WP_Error('cps_mfa_expired', __('That sign-in attempt has expired. Please sign in again.', 'colorpack-shield'));
        }

        $remember = MfaChallenge::remember($store, $token, $now);
        $d        = MfaStore::get($userId);

        if ($d['secret'] !== null && Totp::verify($d['secret'], $code, $now)) {
            MfaChallenge::consume($store, $token, $now);

            return $wpUser;
        }

        $backup = BackupCodes::verifyAndConsume($d['backup_codes'], $code, wp_salt('auth'));

        if ($backup['ok']) {
            MfaStore::setBackupCodes($userId, $backup['remaining']);
            MfaChallenge::consume($store, $token, $now);

            return $wpUser;
        }

        // Wrong code: a fresh token (the old one is spent either way) so the retry form still
        // works, with the original "remember me" choice carried forward.
        MfaChallenge::consume($store, $token, $now);
        $newToken = MfaChallenge::create($store, $userId, $now, $remember);

        return new \WP_Error('cps_mfa_invalid', self::challengeForm($newToken, $remember, __('That code was not right. Please try again.', 'colorpack-shield')));
    }

    /**
     * Issues the challenge once username/password (and any lock-out check) have already
     * succeeded for a user with confirmed MFA. Runs after maybeBlockLocked() (priority 40 vs 30)
     * so a locked-out address never even reaches here.
     */
    public static function maybeChallengeMfa($user, string $username, string $password)
    {
        if (isset($_POST['cps_mfa_token'], $_POST['cps_mfa_code'])) {
            return $user; // the challenge POST itself (token and code) - already resolved at priority 1. A token alone must not skip the challenge.
        }

        if (!$user instanceof \WP_User || !user_can($user, 'manage_options') || !MfaStore::hasConfirmedMfa($user->ID)) {
            return $user;
        }

        $remember = !empty($_POST['rememberme']);
        $token    = MfaChallenge::create(self::store(), $user->ID, time(), $remember);

        return new \WP_Error('cps_mfa_required', self::challengeForm($token, $remember, ''));
    }

    private static function challengeForm(string $token, bool $remember, string $error): string
    {
        ob_start();
        ?>
        <style>#loginform{display:none}#cps-mfa-form{margin-top:1em}</style>
        <?php if ($error !== '') : ?>
            <p class="message"><?php echo esc_html($error); ?></p>
        <?php endif; ?>
        <form name="cps_mfa_form" id="cps-mfa-form" action="<?php echo esc_url(wp_login_url()); ?>" method="post">
            <p>
                <label for="cps_mfa_code"><?php esc_html_e('Authentication code', 'colorpack-shield'); ?></label>
                <input type="text" name="cps_mfa_code" id="cps_mfa_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" autofocus="autofocus" />
            </p>
            <input type="hidden" name="cps_mfa_token" value="<?php echo esc_attr($token); ?>" />
            <?php if ($remember) : ?>
                <input type="hidden" name="rememberme" value="forever" />
            <?php endif; ?>
            <?php if (isset($_REQUEST['redirect_to'])) : ?>
                <input type="hidden" name="redirect_to" value="<?php echo esc_url((string) wp_unslash($_REQUEST['redirect_to'])); ?>" />
            <?php endif; ?>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Verify', 'colorpack-shield'); ?>" />
            </p>
            <p><?php esc_html_e('Lost your device? You can enter one of your backup codes instead of a 6-digit code.', 'colorpack-shield'); ?></p>
        </form>
        <?php

        return (string) ob_get_clean();
    }

    /**
     * Redirects (or, for an ajax/json request, refuses) a manage_options user who has not
     * enrolled MFA once the grace period is over - the WordPress equivalent of the Joomla
     * edition's captive page, running on every wp-admin request the same way maybeGate() does.
     * Does nothing for a "warn" decision (maybeMfaNotice() shows that) or once enrolled.
     */
    public static function maybeEnforceMfa(): void
    {
        $d = self::mfaDecision();

        if ($d === null || $d['action'] === MfaPolicy::NONE || $d['action'] === MfaPolicy::WARN) {
            return;
        }

        if ($d['action'] === MfaPolicy::REDIRECT) {
            wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-mfa'));
            exit;
        }

        status_header(403);
        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        exit((string) wp_json_encode(['success' => false, 'data' => 'cps_mfa_required']));
    }

    public static function maybeMfaNotice(): void
    {
        $d = self::mfaDecision();

        if ($d === null || $d['action'] !== MfaPolicy::WARN) {
            return;
        }

        $days = max(1, $d['daysLeft']);
        $url  = admin_url('admin.php?page=colorpack-shield-mfa');

        printf(
            '<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
            esc_html(sprintf(
                /* translators: %d: days left before MFA is required */
                _n('Set up two-factor authentication within %d day to keep wp-admin access once the grace period ends.', 'Set up two-factor authentication within %d days to keep wp-admin access once the grace period ends.', $days, 'colorpack-shield'),
                $days
            )),
            esc_url($url),
            esc_html__('Set it up now', 'colorpack-shield')
        );
    }

    /** @return array{action:string,daysLeft:int,overdue:bool}|null null when MFA policy does not apply to the current request at all */
    private static function mfaDecision(): ?array
    {
        $cfg = Settings::get();

        if ($cfg['mfa_mode'] === 'off') {
            return null;
        }

        $user = wp_get_current_user();

        if (!$user instanceof \WP_User || $user->ID === 0 || !user_can($user, 'manage_options') || MfaStore::hasConfirmedMfa($user->ID)) {
            return null;
        }

        if (self::isMfaExemptRequest()) {
            return null;
        }

        $firstSeen = MfaStore::markFirstSeenWithoutMfa($user->ID, time());

        return MfaPolicy::decide($cfg['mfa_mode'], true, false, $firstSeen, time(), $cfg['mfa_grace_days'], false, !wp_doing_ajax());
    }

    /** The MFA setup screen itself, and its own ajax/post actions, must always stay reachable. */
    private static function isMfaExemptRequest(): bool
    {
        $page = isset($_GET['page']) ? sanitize_text_field((string) wp_unslash($_GET['page'])) : '';

        if ($page === 'colorpack-shield-mfa') {
            return true;
        }

        $action = isset($_REQUEST['action']) ? sanitize_text_field((string) wp_unslash($_REQUEST['action'])) : '';

        return str_starts_with($action, 'cps_mfa_');
    }

    private static function client(): ClientIp
    {
        $ip = ClientIpResolver::normalise((string) ($_SERVER['REMOTE_ADDR'] ?? ''));

        return new ClientIp($ip, $ip, ClientIp::VIA_DIRECT);
    }

    private static function store(): StateStore
    {
        return new FileStateStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/adminprotect');
    }

    /** A per-site salt for KnownIps' hashed address history - never the raw address is stored. */
    private static function salt(): string
    {
        return wp_salt('auth');
    }

    private static function alert(StateStore $store, string $key, int $intervalSeconds, callable $send): void
    {
        if (AlertThrottle::claim($store, $key, time(), $intervalSeconds)['send']) {
            $send();
        }
    }
}
