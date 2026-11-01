<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Gemini\Config;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > Settings" screen: WAF on/off and the Gemini advisor's own
 * settings. Markup uses the Colorpack design system (`cps-*` classes, ported from the Joomla
 * edition's media/css/cps.css) instead of WordPress's native form-table styling, so the two
 * editions look the same.
 */
final class SettingsPage
{
    private const NONCE_ACTION = 'cps_save_settings';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            self::handleSave();
        }

        $s = Settings::get();
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-settings'); ?>

                <?php settings_errors('colorpack_shield'); ?>

                <form method="post">
                    <?php wp_nonce_field(self::NONCE_ACTION); ?>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Web Application Firewall', 'colorpack-shield'); ?></h2>
                        <div class="cps-field">
                            <label><?php esc_html_e('Enabled', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="waf_enabled" value="1" <?php checked($s['waf_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="waf_enabled" value="0" <?php checked(!$s['waf_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Inspect every request for SQL injection, XSS, LFI/RFI, and suspicious paths/headers.', 'colorpack-shield'); ?></p>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Admin Login Protection', 'colorpack-shield'); ?></h2>
                        <div class="cps-field">
                            <label><?php esc_html_e('Enabled', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="login_protect_enabled" value="1" <?php checked($s['login_protect_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="login_protect_enabled" value="0" <?php checked(!$s['login_protect_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Locks out an address after repeated failed logins and limits login attempts per minute.', 'colorpack-shield'); ?></p>
                        </div>
                        <div class="cps-fields">
                            <div class="cps-field">
                                <label for="cps-max-failures"><?php esc_html_e('Failures before lock', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-max-failures" name="login_max_failures" min="1" max="100" value="<?php echo esc_attr((string) $s['login_max_failures']); ?>">
                            </div>
                            <div class="cps-field">
                                <label for="cps-failure-window"><?php esc_html_e('...within this many seconds', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-failure-window" name="login_failure_window" min="60" max="86400" value="<?php echo esc_attr((string) $s['login_failure_window']); ?>">
                            </div>
                            <div class="cps-field">
                                <label for="cps-lock-minutes"><?php esc_html_e('First lock (minutes)', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-lock-minutes" name="login_lock_minutes" min="1" max="1440" value="<?php echo esc_attr((string) $s['login_lock_minutes']); ?>">
                            </div>
                            <div class="cps-field">
                                <label for="cps-lock-max-hours"><?php esc_html_e('Longest lock (hours)', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-lock-max-hours" name="login_lock_max_hours" min="1" max="168" value="<?php echo esc_attr((string) $s['login_lock_max_hours']); ?>">
                            </div>
                            <div class="cps-field">
                                <label for="cps-rate-limit"><?php esc_html_e('Login attempts per minute', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-rate-limit" name="login_rate_per_minute" min="0" max="600" value="<?php echo esc_attr((string) $s['login_rate_per_minute']); ?>">
                            </div>
                        </div>
                        <div class="cps-field">
                            <label><?php esc_html_e('Email the site admin about', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="checkbox" name="alert_lockouts" value="1" <?php checked($s['alert_lockouts']); ?>> <?php esc_html_e('Lockouts', 'colorpack-shield'); ?></label>
                                <label><input type="checkbox" name="alert_new_ip" value="1" <?php checked($s['alert_new_ip']); ?>> <?php esc_html_e('Sign-ins from a new address', 'colorpack-shield'); ?></label>
                                <label><input type="checkbox" name="alert_new_admin" value="1" <?php checked($s['alert_new_admin']); ?>> <?php esc_html_e('A new administrator, or someone promoted to one', 'colorpack-shield'); ?></label>
                            </div>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Administrator Door', 'colorpack-shield'); ?></h2>
                        <div class="cps-alert cps-alert-warn">
                            <p><?php esc_html_e('Advanced. A wrong key or address list can lock you out of wp-admin and wp-login.php entirely - test in a private/incognito window before closing this one, and keep this URL at hand to fix it via FTP/phpMyAdmin (the colorpack_shield_settings option) if it goes wrong.', 'colorpack-shield'); ?></p>
                        </div>
                        <div class="cps-field">
                            <label><?php esc_html_e('Require a secret key', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="gate_enabled" value="1" <?php checked($s['gate_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="gate_enabled" value="0" <?php checked(!$s['gate_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Visiting wp-login.php or wp-admin without ?cpskey=<key> once (to receive the unlock cookie) shows a plain 404.', 'colorpack-shield'); ?></p>
                        </div>
                        <div class="cps-fields">
                            <div class="cps-field cps-wide">
                                <label for="cps-gate-key"><?php esc_html_e('Key (10-128 letters/numbers/-/_)', 'colorpack-shield'); ?></label>
                                <input type="text" id="cps-gate-key" name="gate_key" autocomplete="off" value="<?php echo esc_attr($s['gate_key']); ?>">
                            </div>
                            <div class="cps-field">
                                <label for="cps-gate-hours"><?php esc_html_e('Unlock cookie lifetime (hours)', 'colorpack-shield'); ?></label>
                                <input type="number" id="cps-gate-hours" name="gate_cookie_hours" min="1" max="168" value="<?php echo esc_attr((string) $s['gate_cookie_hours']); ?>">
                            </div>
                        </div>
                        <div class="cps-field">
                            <label><?php esc_html_e('Require a listed address', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="admin_ip_enforce" value="1" <?php checked($s['admin_ip_enforce']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="admin_ip_enforce" value="0" <?php checked(!$s['admin_ip_enforce']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                        </div>
                        <div class="cps-field">
                            <label for="cps-ip-list"><?php esc_html_e('Addresses (one per line; IP or CIDR, "#" for comments)', 'colorpack-shield'); ?></label>
                            <textarea id="cps-ip-list" name="admin_ip_list" rows="4"><?php echo esc_textarea($s['admin_ip_list']); ?></textarea>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Two-Factor Authentication', 'colorpack-shield'); ?></h2>
                        <p class="cps-help"><?php esc_html_e('Administrators can always set up their own authenticator app on the MFA screen, regardless of this setting. This only controls whether (and how firmly) administrators who have not are reminded.', 'colorpack-shield'); ?></p>
                        <div class="cps-field">
                            <label for="cps-mfa-mode"><?php esc_html_e('For administrators without it', 'colorpack-shield'); ?></label>
                            <select id="cps-mfa-mode" name="mfa_mode">
                                <option value="off" <?php selected($s['mfa_mode'], 'off'); ?>><?php esc_html_e('Off - no reminder', 'colorpack-shield'); ?></option>
                                <option value="warn" <?php selected($s['mfa_mode'], 'warn'); ?>><?php esc_html_e('Warn - a reminder, never blocks access', 'colorpack-shield'); ?></option>
                                <option value="enforce" <?php selected($s['mfa_mode'], 'enforce'); ?>><?php esc_html_e('Enforce - required once the grace period ends', 'colorpack-shield'); ?></option>
                            </select>
                        </div>
                        <div class="cps-field">
                            <label for="cps-mfa-grace"><?php esc_html_e('Grace period (days)', 'colorpack-shield'); ?></label>
                            <input type="number" id="cps-mfa-grace" name="mfa_grace_days" min="0" max="90" value="<?php echo esc_attr((string) $s['mfa_grace_days']); ?>">
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Colorpack Site Manager', 'colorpack-shield'); ?></h2>
                        <p class="cps-help"><?php esc_html_e('Reports lock-outs, banned attackers and a daily health check to your Colorpack Site Manager. Works only when the Colorpack Agent is installed on this site; nothing is sent otherwise.', 'colorpack-shield'); ?></p>
                        <div class="cps-field">
                            <label><?php esc_html_e('Report to Site Manager', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="site_manager_enabled" value="1" <?php checked($s['site_manager_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="site_manager_enabled" value="0" <?php checked(!$s['site_manager_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                        </div>
                        <div class="cps-field">
                            <label><?php esc_html_e('Block attackers shared by your other sites', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="fleet_ban" value="1" <?php checked($s['fleet_ban']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="fleet_ban" value="0" <?php checked(!$s['fleet_ban']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Addresses that attacked two or more of your sites in the last 7 days are blocked here for 24 hours (only while the firewall is on).', 'colorpack-shield'); ?></p>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('IP country', 'colorpack-shield'); ?></h2>
                        <div class="cps-field">
                            <label><?php esc_html_e('Show the country of an IP address', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="ip_country_lookup" value="1" <?php checked($s['ip_country_lookup']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="ip_country_lookup" value="0" <?php checked(!$s['ip_country_lookup']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Behind Cloudflare the country is read from Cloudflare itself. For other addresses in the log, the public address (never a visitor name or page) is sent to ipwho.is, at most a dozen per page view, and the answer is kept for 30 days. Turn off to never send an address anywhere.', 'colorpack-shield'); ?></p>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Scheduled File Scan', 'colorpack-shield'); ?></h2>
                        <div class="cps-field">
                            <label><?php esc_html_e('Enabled', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="scan_schedule_enabled" value="1" <?php checked($s['scan_schedule_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="scan_schedule_enabled" value="0" <?php checked(!$s['scan_schedule_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Runs a background scan twice a day (WP-Cron) and emails the site admin if it finds something new and high severity.', 'colorpack-shield'); ?></p>
                        </div>
                    </section>

                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('AI Advisor (Gemini)', 'colorpack-shield'); ?></h2>
                        <p class="cps-help">
                            <?php esc_html_e('Off by default. Uses your own Gemini API key to explain WAF activity in plain language. Nothing is sent unless you turn this on and provide a key.', 'colorpack-shield'); ?>
                        </p>

                        <div class="cps-field">
                            <label><?php esc_html_e('Enabled', 'colorpack-shield'); ?></label>
                            <div class="cps-radio">
                                <label><input type="radio" name="gemini_enabled" value="1" <?php checked($s['gemini_enabled']); ?>> <?php esc_html_e('Yes', 'colorpack-shield'); ?></label>
                                <label><input type="radio" name="gemini_enabled" value="0" <?php checked(!$s['gemini_enabled']); ?>> <?php esc_html_e('No', 'colorpack-shield'); ?></label>
                            </div>
                            <p class="cps-help"><?php esc_html_e('Shows the "Analyze with AI" button on the Activity screen.', 'colorpack-shield'); ?></p>
                        </div>

                        <div class="cps-fields">
                            <div class="cps-field cps-wide">
                                <label for="cps-gemini-key"><?php esc_html_e('API key', 'colorpack-shield'); ?></label>
                                <input type="password" id="cps-gemini-key" name="gemini_api_key" autocomplete="off" value="<?php echo esc_attr($s['gemini_api_key']); ?>">
                                <p class="cps-help"><?php esc_html_e('From Google AI Studio. Stored in your own database only, never logged or shared.', 'colorpack-shield'); ?></p>
                            </div>
                            <div class="cps-field cps-wide">
                                <label for="cps-gemini-model"><?php esc_html_e('Model', 'colorpack-shield'); ?></label>
                                <input type="text" id="cps-gemini-model" name="gemini_model" placeholder="<?php echo esc_attr(Config::DEFAULT_MODEL); ?>" value="<?php echo esc_attr($s['gemini_model']); ?>">
                            </div>
                        </div>
                    </section>

                    <div class="cps-card-foot">
                        <button type="submit" class="cps-btn cps-btn-primary"><?php esc_html_e('Save', 'colorpack-shield'); ?></button>
                    </div>
                </form>
            </div>
        </div>
        <?php
    }

    private static function handleSave(): void
    {
        check_admin_referer(self::NONCE_ACTION);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        Settings::save($_POST);
        add_settings_error('colorpack_shield', 'settings_saved', __('Settings saved.', 'colorpack-shield'), 'success');
    }
}
