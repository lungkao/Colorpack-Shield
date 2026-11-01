<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Mfa\BackupCodes;
use Colorpack\WP\ColorpackShield\Mfa\MfaStore;
use Colorpack\WP\ColorpackShield\Mfa\Totp;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > MFA" screen: set up, confirm, and manage this port's own TOTP
 * second factor - self-service, always reachable, independent of the site-wide `mfa_mode` policy
 * (which only nags/enforces administrators who have not enrolled; see `AdminProtect\Wiring`).
 *
 * No QR code (no bundled QR-rendering library, matching the project's dependency-free
 * convention - see `Mfa\Totp`'s own docblock): the manual-entry key and an `otpauth://` link are
 * shown instead, which every TOTP app accepts.
 */
final class MfaPage
{
    public const ACTION_START   = 'cps_mfa_start';
    public const ACTION_CANCEL  = 'cps_mfa_cancel';
    public const ACTION_CONFIRM = 'cps_mfa_confirm';
    public const ACTION_REGEN   = 'cps_mfa_regen';
    public const ACTION_DISABLE = 'cps_mfa_disable';

    private const NONCE = 'cps_mfa';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        $userId = get_current_user_id();
        $d      = MfaStore::get($userId);

        $justSetUp = null;

        if (($_GET['mfa_setup'] ?? '') === '1') {
            $codes = get_transient(self::codesKey($userId));

            if (\is_array($codes)) {
                $justSetUp = $codes;
                delete_transient(self::codesKey($userId));
            }
        }

        $error = ($_GET['mfa_error'] ?? '') === '1' ? __('That code was not right.', 'colorpack-shield') : '';
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-mfa'); ?>

                <?php if ($error !== '') : ?>
                    <div class="cps-alert cps-alert-bad"><p><?php echo esc_html($error); ?></p></div>
                <?php endif; ?>

                <?php if ($justSetUp !== null) : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Save these backup codes now', 'colorpack-shield'); ?></h2>
                        <div class="cps-alert cps-alert-warn">
                            <p><?php esc_html_e('Each one signs you in once if you lose access to your authenticator app. They will not be shown again - write them down or save them somewhere safe before leaving this page.', 'colorpack-shield'); ?></p>
                        </div>
                        <p class="cps-mono"><?php echo esc_html(implode('  ', $justSetUp)); ?></p>
                        <a class="cps-btn cps-btn-primary" href="<?php echo esc_url(self::url()); ?>"><?php esc_html_e("I've saved them", 'colorpack-shield'); ?></a>
                    </section>
                <?php elseif ($d['confirmed']) : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Two-factor authentication', 'colorpack-shield'); ?></h2>
                        <p><span class="cps-badge cps-badge-ok"><?php esc_html_e('Enabled', 'colorpack-shield'); ?></span></p>
                        <p class="cps-help"><?php echo esc_html(sprintf(
                            /* translators: %d: number of unused backup codes left */
                            _n('%d backup code left.', '%d backup codes left.', \count($d['backup_codes']), 'colorpack-shield'),
                            \count($d['backup_codes'])
                        )); ?></p>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Regenerate backup codes', 'colorpack-shield'); ?></h2>
                        <p class="cps-help"><?php esc_html_e('Replaces every unused backup code with a fresh set. Enter a current code from your app (or an unused backup code) to confirm.', 'colorpack-shield'); ?></p>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_REGEN); ?>">
                            <div class="cps-fields">
                                <div class="cps-field">
                                    <label for="cps-mfa-regen-code"><?php esc_html_e('Code', 'colorpack-shield'); ?></label>
                                    <input type="text" id="cps-mfa-regen-code" name="cps_mfa_code" autocomplete="one-time-code" inputmode="numeric">
                                </div>
                            </div>
                            <button type="submit" class="cps-btn"><?php esc_html_e('Regenerate', 'colorpack-shield'); ?></button>
                        </form>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Disable two-factor authentication', 'colorpack-shield'); ?></h2>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_DISABLE); ?>">
                            <div class="cps-fields">
                                <div class="cps-field">
                                    <label for="cps-mfa-disable-code"><?php esc_html_e('Code', 'colorpack-shield'); ?></label>
                                    <input type="text" id="cps-mfa-disable-code" name="cps_mfa_code" autocomplete="one-time-code" inputmode="numeric">
                                </div>
                            </div>
                            <button type="submit" class="cps-btn cps-btn-danger"><?php esc_html_e('Disable', 'colorpack-shield'); ?></button>
                        </form>
                    </section>
                <?php elseif ($d['secret'] !== null) : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Set up two-factor authentication', 'colorpack-shield'); ?></h2>
                        <p><?php esc_html_e('In your authenticator app (Google Authenticator, Authy, 1Password, ...), add an account using this key:', 'colorpack-shield'); ?></p>
                        <p class="cps-mono"><?php echo esc_html(implode(' ', str_split($d['secret'], 4))); ?></p>
                        <p class="cps-small cps-muted">
                            <a href="<?php echo esc_url(Totp::uri($d['secret'], wp_get_current_user()->user_login, get_bloginfo('name') ?: 'WordPress')); ?>"><?php esc_html_e('Or open this link on the same device as your authenticator app', 'colorpack-shield'); ?></a>
                        </p>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_CONFIRM); ?>">
                            <div class="cps-fields">
                                <div class="cps-field">
                                    <label for="cps-mfa-confirm-code"><?php esc_html_e('Enter the 6-digit code it shows', 'colorpack-shield'); ?></label>
                                    <input type="text" id="cps-mfa-confirm-code" name="cps_mfa_code" autocomplete="one-time-code" inputmode="numeric" autofocus="autofocus">
                                </div>
                            </div>
                            <button type="submit" class="cps-btn cps-btn-primary"><?php esc_html_e('Confirm', 'colorpack-shield'); ?></button>
                        </form>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_CANCEL); ?>">
                            <button type="submit" class="cps-btn"><?php esc_html_e('Cancel', 'colorpack-shield'); ?></button>
                        </form>
                    </section>
                <?php else : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Two-factor authentication', 'colorpack-shield'); ?></h2>
                        <p><span class="cps-badge cps-badge-warn"><?php esc_html_e('Not set up', 'colorpack-shield'); ?></span></p>
                        <p class="cps-help"><?php esc_html_e('Adds a one-time code from an authenticator app on top of your password.', 'colorpack-shield'); ?></p>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_START); ?>">
                            <button type="submit" class="cps-btn cps-btn-primary"><?php esc_html_e('Set it up', 'colorpack-shield'); ?></button>
                        </form>
                    </section>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    public static function handleStart(): void
    {
        check_admin_referer(self::NONCE);
        self::guard();

        MfaStore::startEnrollment(get_current_user_id(), Totp::generateSecret());
        wp_safe_redirect(self::url());
        exit;
    }

    public static function handleCancel(): void
    {
        check_admin_referer(self::NONCE);
        self::guard();

        MfaStore::disable(get_current_user_id());
        wp_safe_redirect(self::url());
        exit;
    }

    public static function handleConfirm(): void
    {
        check_admin_referer(self::NONCE);
        self::guard();

        $userId = get_current_user_id();
        $d      = MfaStore::get($userId);
        $code   = self::postedCode();

        if ($d['secret'] === null || !Totp::verify($d['secret'], $code, time())) {
            wp_safe_redirect(self::url(['mfa_error' => '1']));
            exit;
        }

        self::issueBackupCodes($userId, static function (array $hashed) use ($userId): void {
            MfaStore::confirm($userId, $hashed);
        });
    }

    public static function handleRegen(): void
    {
        check_admin_referer(self::NONCE);
        self::guard();

        $userId = get_current_user_id();

        if (!self::currentlyVerified($userId)) {
            wp_safe_redirect(self::url(['mfa_error' => '1']));
            exit;
        }

        self::issueBackupCodes($userId, static function (array $hashed) use ($userId): void {
            MfaStore::setBackupCodes($userId, $hashed);
        });
    }

    public static function handleDisable(): void
    {
        check_admin_referer(self::NONCE);
        self::guard();

        $userId = get_current_user_id();

        if (!self::currentlyVerified($userId)) {
            wp_safe_redirect(self::url(['mfa_error' => '1']));
            exit;
        }

        MfaStore::disable($userId);
        wp_safe_redirect(self::url());
        exit;
    }

    private static function guard(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }
    }

    /** A current TOTP code, or an unused backup code (consuming it) - the same proof either management action below requires. */
    private static function currentlyVerified(int $userId): bool
    {
        $d    = MfaStore::get($userId);
        $code = self::postedCode();

        if (!$d['confirmed'] || $d['secret'] === null) {
            return false;
        }

        if (Totp::verify($d['secret'], $code, time())) {
            return true;
        }

        $backup = BackupCodes::verifyAndConsume($d['backup_codes'], $code, wp_salt('auth'));

        if ($backup['ok']) {
            MfaStore::setBackupCodes($userId, $backup['remaining']);

            return true;
        }

        return false;
    }

    private static function postedCode(): string
    {
        return isset($_POST['cps_mfa_code']) ? trim((string) wp_unslash($_POST['cps_mfa_code'])) : '';
    }

    private static function issueBackupCodes(int $userId, callable $save): void
    {
        $plain  = BackupCodes::generate();
        $hashed = array_map(static fn (string $c): string => BackupCodes::hash($c, wp_salt('auth')), $plain);
        $save($hashed);
        set_transient(self::codesKey($userId), $plain, 120);
        wp_safe_redirect(self::url(['mfa_setup' => '1']));
        exit;
    }

    private static function codesKey(int $userId): string
    {
        return 'cps_mfa_codes_' . $userId;
    }

    /**
     * @param  array<string,string>  $args
     */
    private static function url(array $args = []): string
    {
        return add_query_arg($args, admin_url('admin.php?page=colorpack-shield-mfa'));
    }
}
