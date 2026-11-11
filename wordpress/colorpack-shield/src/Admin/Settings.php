<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Gemini\Config;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

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
     * Every setting with its stored value (or default), typed by {@see SettingsSchema}: switches are
     * booleans, numbers are integers kept within their range, the rest are strings. The older
     * `login_protect_enabled` / `mfa_mode` names stay available as aliases of `login_lockout` /
     * `mfa_enforce` so code written against them keeps working.
     *
     * @return array<string,mixed>
     */
    public static function get(): array
    {
        $stored = get_option(self::OPTION, []);

        return self::normalise(\is_array($stored) ? $stored : []);
    }

    /**
     * @param  array<string,mixed>  $stored
     *
     * @return array<string,mixed>
     */
    public static function normalise(array $stored): array
    {
        // Settings saved by the first WordPress releases used two names that the Joomla form does not have.
        if (!\array_key_exists('login_lockout', $stored) && \array_key_exists('login_protect_enabled', $stored)) {
            $stored['login_lockout'] = !empty($stored['login_protect_enabled']) && (!\array_key_exists('login_lockout', $stored) || !empty($stored['login_lockout']));
        }

        if (!\array_key_exists('mfa_enforce', $stored) && \array_key_exists('mfa_mode', $stored)) {
            $stored['mfa_enforce'] = $stored['mfa_mode'];
        }

        $out = [];

        foreach (SettingsSchema::fields() as $name => $field) {
            $out[$name] = self::cast($field, \array_key_exists($name, $stored) ? $stored[$name] : $field['default']);
        }

        $out['login_protect_enabled'] = $out['login_lockout'];
        $out['mfa_mode']              = $out['mfa_enforce'];

        return $out;
    }

    /**
     * @param  array<string,mixed>  $field
     */
    private static function cast(array $field, mixed $value): mixed
    {
        switch ($field['type']) {
            case 'switch':
                return filter_var($value, FILTER_VALIDATE_BOOLEAN);

            case 'number':
                $n = is_numeric($value) ? (int) $value : (int) $field['default'];

                return max((int) ($field['min'] ?? PHP_INT_MIN), min((int) ($field['max'] ?? PHP_INT_MAX), $n));

            case 'list':
                $v = \is_string($value) ? $value : '';

                return isset($field['options'][$v]) ? $v : (string) $field['default'];

            default:
                return \is_string($value) ? $value : (string) $field['default'];
        }
    }

    /**
     * @param  array<string,mixed>  $raw  POSTed values, never trusted as-is
     */
    public static function save(array $raw): void
    {
        update_option(self::OPTION, self::clean(wp_unslash($raw)));

        ScheduledScan::reschedule();
    }

    /**
     * Store settings that are already clean values (read from get() and changed by code, not posted by a form):
     * no unslashing, so a stored backslash is kept.
     *
     * @param  array<string,mixed>  $settings
     */
    public static function store(array $settings): void
    {
        update_option(self::OPTION, self::clean($settings));
    }

    /**
     * Turn posted values into what is stored: only the fields in the schema, each cast to its type
     * (a number outside its range is moved to the nearest end; an unknown list value becomes the default).
     *
     * @param  array<string,mixed>  $raw
     *
     * @return array<string,mixed>
     */
    public static function clean(array $raw): array
    {
        $out = [];

        foreach (SettingsSchema::fields() as $name => $field) {
            $value = $raw[$name] ?? ($field['type'] === 'switch' ? '0' : $field['default']);

            if (\is_string($value) && !\in_array($field['type'], ['textarea'], true)) {
                $value = trim($value);
            }

            $out[$name] = self::cast($field, $value);
        }

        return $out;
    }

    public static function geminiConfig(): ?Config
    {
        $s = self::get();

        return Config::fromParams($s['gemini_api_key'], $s['gemini_enabled'], $s['gemini_model'], false, 24);
    }
}
