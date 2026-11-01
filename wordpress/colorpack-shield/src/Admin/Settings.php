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
 * A single WP option holding every setting this plugin stores - the WordPress-native equivalent
 * of the Joomla edition's one-params-blob-per-extension approach, and the normal WordPress
 * convention for a handful of related settings (one row in wp_options, not one per field).
 *
 * The AdminProtect fields use the exact same keys `AdminProtectConfig::fromArray()` /
 * `AccessGateConfig::fromArray()` already expect (`login_lockout`, `gate_key`, ...) so this class
 * stays a thin passthrough - validation/clamping is those classes' job, not this one's, same
 * split the Joomla edition uses (plugin params in, `AdminProtectConfig` clamps on the way out).
 *
 * This is a thin WordPress-function wrapper (get_option/update_option), not independently unit
 * tested - same split the Joomla edition uses for ShieldPlugin, which also just wraps the host
 * framework's own params storage.
 */
final class Settings
{
    private const OPTION = 'colorpack_shield_settings';

    /**
     * @return array<string,mixed>
     */
    public static function get(): array
    {
        $stored = get_option(self::OPTION, []);
        $stored = \is_array($stored) ? $stored : [];

        return [
            'waf_enabled'    => !empty($stored['waf_enabled']),
            'gemini_enabled' => !empty($stored['gemini_enabled']),
            'gemini_api_key' => \is_string($stored['gemini_api_key'] ?? null) ? $stored['gemini_api_key'] : '',
            'gemini_model'   => \is_string($stored['gemini_model'] ?? null) && $stored['gemini_model'] !== ''
                ? $stored['gemini_model']
                : Config::DEFAULT_MODEL,

            // Admin login protection - master switch. On until an operator turns it off: locking an address
            // out after repeated wrong passwords is safe for real users and is what fleet sites need first.
            'login_protect_enabled' => \array_key_exists('login_protect_enabled', $stored) ? !empty($stored['login_protect_enabled']) : true,
            'login_lockout'         => \array_key_exists('login_lockout', $stored) ? !empty($stored['login_lockout']) : true,
            'login_max_failures'    => \is_numeric($stored['login_max_failures'] ?? null) ? (int) $stored['login_max_failures'] : 5,
            'login_failure_window'  => \is_numeric($stored['login_failure_window'] ?? null) ? (int) $stored['login_failure_window'] : 600,
            'login_lock_minutes'    => \is_numeric($stored['login_lock_minutes'] ?? null) ? (int) $stored['login_lock_minutes'] : 15,
            'login_lock_max_hours'  => \is_numeric($stored['login_lock_max_hours'] ?? null) ? (int) $stored['login_lock_max_hours'] : 24,
            'login_rate_per_minute' => \is_numeric($stored['login_rate_per_minute'] ?? null) ? (int) $stored['login_rate_per_minute'] : 10,
            'alert_new_ip'          => \array_key_exists('alert_new_ip', $stored) ? !empty($stored['alert_new_ip']) : true,
            'alert_lockouts'        => \array_key_exists('alert_lockouts', $stored) ? !empty($stored['alert_lockouts']) : true,
            'alert_new_admin'       => \array_key_exists('alert_new_admin', $stored) ? !empty($stored['alert_new_admin']) : true,

            // The "gate" (access key / address list door) - off by default.
            'gate_enabled'      => !empty($stored['gate_enabled']),
            'gate_key'          => \is_string($stored['gate_key'] ?? null) ? $stored['gate_key'] : '',
            'gate_cookie_hours' => \is_numeric($stored['gate_cookie_hours'] ?? null) ? (int) $stored['gate_cookie_hours'] : 12,
            'admin_ip_enforce'  => !empty($stored['admin_ip_enforce']),
            'admin_ip_list'     => \is_string($stored['admin_ip_list'] ?? null) ? $stored['admin_ip_list'] : '',

            // Scheduled file scan (WP-Cron) - on until turned off; it only reads files and emails the site admin.
            'scan_schedule_enabled' => \array_key_exists('scan_schedule_enabled', $stored) ? !empty($stored['scan_schedule_enabled']) : true,

            // Colorpack Site Manager reporting (needs the Colorpack Agent on the same site) - on by
            // default, it only ever sends when the Agent is installed and configured.
            'site_manager_enabled' => \array_key_exists('site_manager_enabled', $stored) ? !empty($stored['site_manager_enabled']) : true,
            'fleet_ban'            => \array_key_exists('fleet_ban', $stored) ? !empty($stored['fleet_ban']) : true,

            // Show the country next to an IP address in the admin screens (may ask ipwho.is for addresses Cloudflare did not label).
            'ip_country_lookup'    => \array_key_exists('ip_country_lookup', $stored) ? !empty($stored['ip_country_lookup']) : true,

            // MFA (TOTP, this port's own - off by default; "warn" reminds, "enforce" redirects
            // administrators to set it up once their grace period runs out).
            'mfa_mode'       => \in_array($stored['mfa_mode'] ?? null, ['off', 'warn', 'enforce'], true) ? $stored['mfa_mode'] : 'off',
            'mfa_grace_days' => \is_numeric($stored['mfa_grace_days'] ?? null) ? max(0, min(90, (int) $stored['mfa_grace_days'])) : 7,
        ];
    }

    /**
     * @param  array<string,mixed>  $raw  POSTed values, never trusted as-is
     */
    public static function save(array $raw): void
    {
        // wp_unslash() first: WordPress adds backslashes to every superglobal
        // (wp_magic_quotes()), which would otherwise corrupt a key/model/list containing a quote.
        $raw = wp_unslash($raw);

        update_option(self::OPTION, [
            'waf_enabled'    => !empty($raw['waf_enabled']),
            'gemini_enabled' => !empty($raw['gemini_enabled']),
            // The API key is an operator-entered secret, not attacker-influenced request data -
            // stored as-is beyond trimming (no sanitize_text_field mangling), same as the Joomla
            // edition's filter="raw" field for its own secrets.
            'gemini_api_key' => \is_string($raw['gemini_api_key'] ?? null) ? trim($raw['gemini_api_key']) : '',
            'gemini_model'   => \is_string($raw['gemini_model'] ?? null) ? sanitize_text_field($raw['gemini_model']) : '',

            'login_protect_enabled' => !empty($raw['login_protect_enabled']),
            'login_lockout'         => !empty($raw['login_lockout']),
            'login_max_failures'    => \is_numeric($raw['login_max_failures'] ?? null) ? (int) $raw['login_max_failures'] : 5,
            'login_failure_window'  => \is_numeric($raw['login_failure_window'] ?? null) ? (int) $raw['login_failure_window'] : 600,
            'login_lock_minutes'    => \is_numeric($raw['login_lock_minutes'] ?? null) ? (int) $raw['login_lock_minutes'] : 15,
            'login_lock_max_hours'  => \is_numeric($raw['login_lock_max_hours'] ?? null) ? (int) $raw['login_lock_max_hours'] : 24,
            'login_rate_per_minute' => \is_numeric($raw['login_rate_per_minute'] ?? null) ? (int) $raw['login_rate_per_minute'] : 10,
            'alert_new_ip'          => !empty($raw['alert_new_ip']),
            'alert_lockouts'        => !empty($raw['alert_lockouts']),
            'alert_new_admin'       => !empty($raw['alert_new_admin']),

            'gate_enabled'      => !empty($raw['gate_enabled']),
            // Not sanitize_text_field() - the key is matched with hash_equals() against a fixed
            // character class in AccessGateConfig itself, which is where it's validated.
            'gate_key'          => \is_string($raw['gate_key'] ?? null) ? trim($raw['gate_key']) : '',
            'gate_cookie_hours' => \is_numeric($raw['gate_cookie_hours'] ?? null) ? (int) $raw['gate_cookie_hours'] : 12,
            'admin_ip_enforce'  => !empty($raw['admin_ip_enforce']),
            'admin_ip_list'     => \is_string($raw['admin_ip_list'] ?? null) ? $raw['admin_ip_list'] : '',

            'scan_schedule_enabled' => !empty($raw['scan_schedule_enabled']),

            'site_manager_enabled' => !empty($raw['site_manager_enabled']),
            'fleet_ban'            => !empty($raw['fleet_ban']),
            'ip_country_lookup'    => !empty($raw['ip_country_lookup']),

            'mfa_mode'       => \in_array($raw['mfa_mode'] ?? null, ['off', 'warn', 'enforce'], true) ? $raw['mfa_mode'] : 'off',
            'mfa_grace_days' => \is_numeric($raw['mfa_grace_days'] ?? null) ? max(0, min(90, (int) $raw['mfa_grace_days'])) : 7,
        ]);

        ScheduledScan::reschedule();
    }

    public static function geminiConfig(): ?Config
    {
        $s = self::get();

        return Config::fromParams($s['gemini_api_key'], $s['gemini_enabled'], $s['gemini_model'], false, 24);
    }
}
