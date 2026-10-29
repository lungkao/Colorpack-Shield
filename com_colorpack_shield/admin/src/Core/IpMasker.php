<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Hides the last part of an address for screenshots and exports: 203.0.113.9 → 203.0.113.x,
 * 2001:db8:abcd:1::5 → 2001:db8:abcd::x. Anything that is not an address becomes "-".
 */
final class IpMasker
{
    public static function mask(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $p = explode('.', $ip);

            return $p[0] . '.' . $p[1] . '.' . $p[2] . '.x';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $bin = inet_pton($ip);
            $hex = bin2hex($bin === false ? '' : $bin);
            $g   = str_split($hex, 4);

            return dechex((int) hexdec($g[0])) . ':' . dechex((int) hexdec($g[1])) . ':' . dechex((int) hexdec($g[2])) . '::x';
        }

        return '-';
    }
}
