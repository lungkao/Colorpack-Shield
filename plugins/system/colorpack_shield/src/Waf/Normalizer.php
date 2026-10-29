<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The anti-shading normalisation shared by every shield: peel up to two layers
 * of percent-encoding, drop NUL bytes, collapse whitespace, lowercase.
 *
 * Note "+" is NOT turned into a space (rawurldecode): a search query such as
 * "joomla+union+select+tutorial" in a Referer must not become "union select".
 */
final class Normalizer
{
    public static function normalize(string $raw): string
    {
        $s = $raw;

        for ($i = 0; $i < 2; $i++) {
            $decoded = rawurldecode($s);

            if ($decoded === $s) {
                break;
            }

            $s = $decoded;
        }

        $s = str_replace("\0", '', $s);
        $s = preg_replace('/\s+/', ' ', $s) ?? $s;

        return strtolower($s);
    }
}
