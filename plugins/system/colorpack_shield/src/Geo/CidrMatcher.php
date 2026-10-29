<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Geo;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Binary-safe IPv4/IPv6 CIDR membership test.
 *
 * Works on inet_pton() byte strings so it is family-correct: a v4 address never
 * matches a v6 subnet and vice-versa. A bare address (no "/") matches only
 * itself. Pure and Joomla-free so it is unit-testable — reused by the GeoIP
 * allow/deny overrides now and the trusted-proxy set (P3.3) later.
 */
final class CidrMatcher
{
    public static function matches(string $ip, string $cidr): bool
    {
        $addr = @inet_pton($ip);

        if ($addr === false) {
            return false;
        }

        $cidr = trim($cidr);

        // Bare address: exact match only.
        if (!str_contains($cidr, '/')) {
            $net = @inet_pton($cidr);

            return $net !== false && $net === $addr;
        }

        [$subnet, $bitsRaw] = explode('/', $cidr, 2);
        $net                = @inet_pton(trim($subnet));

        if ($net === false || \strlen($net) !== \strlen($addr)) {
            return false;
        }

        $bits    = (int) $bitsRaw;
        $maxBits = \strlen($addr) * 8;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $whole = $bits >> 3;

        if ($whole > 0 && strncmp($addr, $net, $whole) !== 0) {
            return false;
        }

        $remBits = $bits & 7;

        if ($remBits === 0) {
            return true;
        }

        $mask = 0xff << (8 - $remBits) & 0xff;

        return (\ord($addr[$whole]) & $mask) === (\ord($net[$whole]) & $mask);
    }

    /**
     * @param  string[]  $cidrs
     */
    public static function matchesAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if ($cidr !== '' && self::matches($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }
}
