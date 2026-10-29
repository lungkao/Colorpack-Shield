<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Reads a Joomla language file (KEY="text" lines) into an array, the way Joomla does. Used to show
 * the component in Thai or English whatever language the administrator is set to. Keys are upper
 * case, values are plain text; anything that is not a KEY="…" line is ignored.
 */
final class IniStrings
{
    public const MAX_BYTES = 1048576;

    /**
     * @return array<string,string>
     */
    public static function parse(string $text): array
    {
        if ($text === '' || \strlen($text) > self::MAX_BYTES) {
            return [];
        }

        // Joomla's own reader: PHP's ini parser with the normal scanner (so \" inside quotes works).
        $parsed = @parse_ini_string($text, false, INI_SCANNER_NORMAL);
        $out    = [];

        if (\is_array($parsed)) {
            foreach ($parsed as $k => $v) {
                if (\is_string($v) && preg_match('/^[A-Z][A-Z0-9_]{0,120}$/', (string) $k) === 1) {
                    $out[(string) $k] = $v;
                }
            }

            return $out;
        }

        // One bad line must not lose the whole file: read line by line.
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            if (preg_match('/^([A-Z][A-Z0-9_]{0,120})="(.*)"\s*$/', $line, $m) === 1) {
                $out[$m[1]] = str_replace('\\"', '"', $m[2]);
            }
        }

        return $out;
    }
}
