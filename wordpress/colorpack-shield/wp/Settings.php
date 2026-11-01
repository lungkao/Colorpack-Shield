<?php

namespace Colorpack\Shield\Wp;

defined('ABSPATH') || die;

/**
 * The plugin's settings: one option row, read once per request. Key names match the Joomla package's
 * plugin parameters so the shared engine classes (AdminProtectConfig, shields) read them unchanged.
 */
final class Settings
{
    public const OPTION = 'colorpack_shield';

    /** Detect-only on first install: a firewall that blocks a customer's real visitors is worse than none. */
    public const DEFAULTS = [
        'waf_enforce'          => 0,
        'cover_site'           => 1,
        'cover_admin'          => 1,
        'cover_api'            => 1,
        'shield_sqli'          => 1,
        'shield_xss'           => 1,
        'shield_lfi'           => 1,
        'shield_rfi'           => 1,
        'header_scan'          => 1,
        'header_mode'          => 'default',
        'path_scan'            => 1,
        'path_mode'            => 'recommended',
        'path_probe_mode'      => 'log',
        'path_probe_ban_hours' => 24,
        'scan_uploads'         => 1,
        'upload_max_bytes'     => 10485760,
        'scan_body'            => 1,
        'allow_ips'            => '',
        'trust_cloudflare'     => 1,
        'trusted_proxies'      => '',
        'login_lockout'        => 1,
        'login_max_failures'   => 5,
        'login_failure_window' => 600,
        'login_lock_minutes'   => 15,
        'login_lock_max_hours' => 24,
        'login_rate_per_minute' => 10,
        'site_manager_enabled' => 1,
    ];

    private static ?array $cache = null;

    /** @return array<string,mixed> */
    public static function all(): array
    {
        if (self::$cache === null) {
            $stored      = get_option(self::OPTION, []);
            self::$cache = array_merge(self::DEFAULTS, is_array($stored) ? $stored : []);
        }

        return self::$cache;
    }

    public static function get(string $key): mixed
    {
        return self::all()[$key] ?? self::DEFAULTS[$key] ?? null;
    }

    /**
     * Accepts only known keys, coerces each to the type of its default, keeps the rest.
     *
     * @param  array<string,mixed>  $input
     */
    public static function save(array $input): void
    {
        $out = self::all();

        foreach (self::DEFAULTS as $key => $default) {
            if (!array_key_exists($key, $input)) {
                continue;
            }

            $out[$key] = is_int($default) ? (int) $input[$key] : sanitize_textarea_field((string) $input[$key]);
        }

        foreach (['header_mode' => ['default', 'log', 'block'], 'path_mode' => ['recommended', 'log', 'block'], 'path_probe_mode' => ['off', 'log', 'block', 'ban']] as $key => $allowed) {
            if (!in_array($out[$key], $allowed, true)) {
                $out[$key] = self::DEFAULTS[$key];
            }
        }

        update_option(self::OPTION, $out, true);
        self::$cache = $out;
    }

    /** Where state, logs and scan results live: outside any web-served index, every file starts with a die() guard. */
    public static function stateDir(string $sub = ''): string
    {
        $dir = rtrim(WP_CONTENT_DIR, '/') . '/colorpack-shield' . ($sub === '' ? '' : '/' . $sub);

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $root = rtrim(WP_CONTENT_DIR, '/') . '/colorpack-shield';

        if (!is_file($root . '/.htaccess')) {
            @file_put_contents($root . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            @file_put_contents($root . '/index.php', "<?php // silence\n");
        }

        return $dir;
    }
}
