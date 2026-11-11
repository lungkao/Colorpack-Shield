<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Builds the "allow this field" line from a BLOCK row of the log (the format is described in
 * Waf\ExceptionRules: rule | source | field | path | page). The plugin checks every line again when it reads it.
 */
final class ExceptionLine
{
    private const SHIELDS = ['sqli', 'xss', 'lfi', 'rfi', 'cmdi', 'ssrf', 'xxe', 'ssti'];

    private const SOURCES = ['GET', 'POST', 'COOKIE', 'JSON', 'XML'];

    /**
     * @param  array<string,string>  $f  the fields of a BLOCK row
     */
    public static function fromRow(array $f): ?string
    {
        $shield = strtolower($f['shield'] ?? '');
        $source = strtoupper($f['src'] ?? '');
        $key    = $f['key'] ?? '';
        $uri    = $f['uri'] ?? '';

        // Headers, paths, uploads, address bans and rate limits have their own controls.
        if (!\in_array($shield, self::SHIELDS, true) || !\in_array($source, self::SOURCES, true) || $key === '' || $uri === '') {
            return null;
        }

        $path   = (string) (parse_url($uri, PHP_URL_PATH) ?? '');
        $query  = (string) (parse_url($uri, PHP_URL_QUERY) ?? '');
        $option = '';

        if ($query !== '') {
            parse_str($query, $q);
            $pick   = $q['page'] ?? $q['action'] ?? '';
            $option = \is_string($pick) && preg_match('/^[a-z0-9_\-]{1,60}$/', $pick) === 1 ? $pick : '';
        }

        if ($path === '' || $path[0] !== '/' || preg_match('/[\x00-\x1f\x7f|*]/', $key . $path) === 1 || \strlen($key) > 200 || \strlen($path) > 200) {
            return null;
        }

        return rtrim(implode('|', [$shield, $source, $key, $path, $option]), '|');
    }

    public static function contains(string $current, string $line): bool
    {
        foreach (preg_split('/\R/', $current) ?: [] as $l) {
            if (trim($l) === $line) {
                return true;
            }
        }

        return false;
    }

    public static function append(string $current, string $line): string
    {
        $current = rtrim($current);

        return ($current === '' ? '' : $current . "\n") . $line;
    }
}
