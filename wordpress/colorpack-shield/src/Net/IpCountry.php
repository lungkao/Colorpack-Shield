<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Net;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Which country an IP address comes from, for display next to the address in the admin screens.
 *
 * Two sources, cheapest first, both cached for 30 days (WordPress transients):
 *  1. Cloudflare's own CF-IPCountry header, captured while the request is being handled ({@see remember()});
 *     free, exact, and the address never leaves the server;
 *  2. a lookup against ipwho.is for addresses seen only in the log - only for public addresses, at most
 *     {@see MAX_LOOKUPS} per page view, 2-second timeout, and only when the "look up IP country" setting is on.
 *
 * Fails quiet: any problem returns null and the screen just shows the address.
 */
final class IpCountry
{
    public const MAX_LOOKUPS = 12;

    private const TTL = 30 * 86400;

    private static int $lookups = 0;

    /** Keep the country Cloudflare reported for this visitor (never trust anything but two letters). */
    public static function remember(string $ip, string $code): void
    {
        $code = strtoupper(trim($code));

        if (preg_match('/^[A-Z]{2}$/', $code) !== 1 || $code === 'XX' || $code === 'T1' || !self::isPublic($ip)) {
            return;
        }

        set_transient(self::key($ip), $code, self::TTL);
    }

    /**
     * @param  callable(string):?string|null  $fetch  returns a two-letter code for a public address (null = unknown); defaults to ipwho.is
     */
    public static function lookup(string $ip, bool $allowRemote, ?callable $fetch = null): ?string
    {
        if (!self::isPublic($ip)) {
            return null;
        }

        $cached = get_transient(self::key($ip));

        if (\is_string($cached)) {
            return $cached === '' ? null : $cached;
        }

        if (!$allowRemote || self::$lookups >= self::MAX_LOOKUPS) {
            return null;
        }

        self::$lookups++;
        $code = ($fetch ?? [self::class, 'fetchRemote'])($ip);
        $code = \is_string($code) && preg_match('/^[A-Za-z]{2}$/', $code) === 1 ? strtoupper($code) : null;
        // An unknown answer is remembered too (empty string) for a day, so a dead service is not asked again and again.
        set_transient(self::key($ip), $code ?? '', $code === null ? 86400 : self::TTL);

        return $code;
    }

    /** "🇹🇭 TH" - the code always shown, the flag only as decoration. */
    public static function label(string $code): string
    {
        $flag = '';

        foreach (str_split($code) as $c) {
            $flag .= mb_chr(0x1F1E6 + ord($c) - ord('A'), 'UTF-8');
        }

        return $flag . ' ' . $code;
    }

    public static function isPublic(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private static function key(string $ip): string
    {
        return 'cps_cc_' . substr(hash('sha256', $ip), 0, 24);
    }

    private static function fetchRemote(string $ip): ?string
    {
        $r = wp_remote_get('https://ipwho.is/' . rawurlencode($ip) . '?fields=success,country_code', ['timeout' => 2, 'redirection' => 0]);

        if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) {
            return null;
        }

        $j = json_decode((string) wp_remote_retrieve_body($r), true);

        return \is_array($j) && ($j['success'] ?? false) === true && \is_string($j['country_code'] ?? null) ? $j['country_code'] : null;
    }
}
