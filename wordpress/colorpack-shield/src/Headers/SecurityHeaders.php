<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Headers;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * HTTP security headers (response headers the browser enforces): nosniff, clickjacking protection,
 * referrer policy, permissions policy, HSTS and an optional Content-Security-Policy.
 *
 * {@see build()} is pure - settings in, header list out - so it is tested without WordPress.
 * {@see boot()} sends them: on the public site at `send_headers`, and on wp-admin / wp-login.php at
 * `admin_init` / `login_init` with a smaller set (WordPress already frames-protects its own screens, and
 * a site-wide CSP would break the admin, so the CSP and the frame header stay on the public site only).
 */
final class SecurityHeaders
{
    public const SITE = 'site';

    public const ADMIN = 'admin';

    /** HSTS lifetimes the settings offer, in seconds. */
    public const HSTS_AGES = ['m6' => 15552000, 'y1' => 31536000, 'y2' => 63072000];

    private const MAX_VALUE_LENGTH = 4000;

    public static function boot(): void
    {
        add_action('send_headers', static fn () => self::send(self::SITE));
        add_action('admin_init', static fn () => self::send(self::ADMIN), 1);
        add_action('login_init', static fn () => self::send(self::ADMIN), 1);
    }

    private static function send(string $context): void
    {
        if (headers_sent()) {
            return;
        }

        $cfg = \Colorpack\WP\ColorpackShield\Admin\Settings::get();

        if (empty($cfg['sec_headers_enabled'])) {
            return;
        }

        $cfg['sec_frame'] = self::relaxForCustomizer((string) $cfg['sec_frame']);

        foreach (self::build($cfg, is_ssl(), $context) as $name => $value) {
            header($name . ': ' . $value, true);
        }
    }

    /** The Customizer previews the site in a frame of the same site, so "deny" would blank it. */
    private static function relaxForCustomizer(string $frame): string
    {
        return $frame === 'deny' && \function_exists('is_customize_preview') && is_customize_preview() ? 'sameorigin' : $frame;
    }

    /**
     * @param  array<string,mixed>  $cfg    normalised settings ({@see \Colorpack\WP\ColorpackShield\Admin\Settings::normalise()})
     * @param  string               $context self::SITE or self::ADMIN
     *
     * @return array<string,string>  header name => value
     */
    public static function build(array $cfg, bool $https, string $context = self::SITE): array
    {
        if (empty($cfg['sec_headers_enabled'])) {
            return [];
        }

        $out = [];

        if (!empty($cfg['sec_nosniff'])) {
            $out['X-Content-Type-Options'] = 'nosniff';
        }

        if ($context === self::SITE && ($cfg['sec_frame'] ?? 'off') === 'sameorigin') {
            $out['X-Frame-Options'] = 'SAMEORIGIN';
        } elseif ($context === self::SITE && ($cfg['sec_frame'] ?? 'off') === 'deny') {
            $out['X-Frame-Options'] = 'DENY';
        }

        $referrer = (string) ($cfg['sec_referrer'] ?? 'off');

        if ($referrer !== 'off' && $referrer !== '') {
            $out['Referrer-Policy'] = $referrer;
        }

        $permissions = self::clean((string) ($cfg['sec_permissions'] ?? ''));

        if ($permissions !== '') {
            $out['Permissions-Policy'] = $permissions;
        }

        $hsts = self::HSTS_AGES[$cfg['sec_hsts'] ?? 'off'] ?? null;

        // Browsers ignore HSTS sent over plain HTTP, and it must never be promised on a site that is not served over HTTPS.
        if ($hsts !== null && $https) {
            $out['Strict-Transport-Security'] = 'max-age=' . $hsts . (!empty($cfg['sec_hsts_subdomains']) ? '; includeSubDomains' : '');
        }

        $csp = self::clean((string) ($cfg['sec_csp'] ?? ''));

        if ($context === self::SITE && $csp !== '') {
            $out[!empty($cfg['sec_csp_report_only']) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy'] = $csp;
        }

        return $out;
    }

    /** One line, printable characters only: a header value must never be able to start a second header. */
    public static function clean(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]+/', ' ', $value);
        $value = trim((string) preg_replace('/\s{2,}/', ' ', $value));

        return substr($value, 0, self::MAX_VALUE_LENGTH);
    }
}
