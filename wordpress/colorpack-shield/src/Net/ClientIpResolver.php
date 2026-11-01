<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Net;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * IP-address parsing used by the WAF's header shield to validate IP-carrying
 * headers (X-Forwarded-For, X-Real-IP, …).
 *
 * Only the pure, static part of the Joomla edition's resolver is ported this
 * round: full "which hop is the real visitor" resolution (trusted proxies,
 * Cloudflare ranges) belongs with admin-login/rate-limiting, a later round —
 * this WAF-core round only needs to tell a valid address from garbage.
 */
final class ClientIpResolver
{
    /**
     * Trim, strip brackets / ":port", reject non-IPs, and unmap IPv4-mapped
     * IPv6 (::ffff:1.2.3.4 → 1.2.3.4) so CIDR comparison is family-correct.
     * Returns '' when not a valid IP.
     */
    public static function normalise(string $raw): string
    {
        $raw = trim($raw);

        if ($raw === '' || \strlen($raw) > 64) {
            return '';
        }

        // "[2001:db8::1]:443" or "[2001:db8::1]"
        if ($raw[0] === '[') {
            $end = strpos($raw, ']');

            if ($end === false) {
                return '';
            }

            $raw = substr($raw, 1, $end - 1);
        } elseif (substr_count($raw, ':') === 1 && str_contains($raw, '.')) {
            // "1.2.3.4:5678"
            $raw = substr($raw, 0, (int) strpos($raw, ':'));
        }

        if (filter_var($raw, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        $bin = @inet_pton($raw);

        if ($bin === false) {
            return '';
        }

        if (\strlen($bin) === 16 && strncmp($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) {
            return (string) inet_ntop(substr($bin, 12));
        }

        return (string) inet_ntop($bin);
    }
}
