<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Builds the "allow this field" line from a BLOCK row of the log (the format is described in the plugin's
 * ExceptionRules: rule | source | field | path | component). The plugin checks every line again when it reads it.
 */
final class ExceptionLine
{
    private const SHIELDS = ['sqli', 'xss', 'lfi', 'rfi', 'cmdi', 'ssrf', 'xxe', 'ssti'];

    private const SOURCES = ['GET', 'POST', 'COOKIE', 'JSON', 'XML'];

    /** Rules a field may be watched for: the low and medium ones of the plugin's Tolerance. Real attack patterns are never watch-only. */
    public const WATCHABLE_RULES = ['sql_comment', 'boolean_tautology', 'css_expr', 'risky_tag'];

    /** How long a field is watched. */
    public const WATCH_SECONDS = 7 * 86400;

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
            $option = isset($q['option']) && \is_string($q['option']) && preg_match('/^[a-z0-9_]{1,60}$/', $q['option']) === 1 ? $q['option'] : '';
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

    public static function isWatchable(string $rule): bool
    {
        return \in_array(strtolower($rule), self::WATCHABLE_RULES, true);
    }

    /** "shield|source|key|path|option|watch:<until>" for a five-column line. */
    public static function watchLine(string $line, int $until): string
    {
        $p = explode('|', $line);

        return implode('|', [$p[0], $p[1], $p[2], $p[3], $p[4] ?? '', 'watch:' . $until]);
    }

    /**
     * The exceptions text with this field watched until $until: expired watch lines are dropped, an older watch
     * line for the same field is replaced, and a permanent line for the field is left alone.
     */
    public static function withWatch(string $current, string $line, int $until, int $now): string
    {
        $out = [];

        foreach (self::lines($current) as $l) {
            if (self::watchExpired($l, $now) || self::isWatchOf($l, $line)) {
                continue;
            }

            $out[] = $l;
        }

        $out[] = self::watchLine($line, $until);

        return implode("\n", $out);
    }

    /** The exceptions text without watch lines for this field (a permanent Allow replaces watching). */
    public static function withoutWatch(string $current, string $line): string
    {
        return implode("\n", array_values(array_filter(self::lines($current), static fn (string $l): bool => !self::isWatchOf($l, $line))));
    }

    /** @return string[] */
    private static function lines(string $text): array
    {
        return array_values(array_filter(array_map('rtrim', preg_split('/\R/', $text) ?: []), static fn (string $l): bool => trim($l) !== ''));
    }

    private static function watchExpired(string $l, int $now): bool
    {
        return preg_match('/\|watch:(\d+)\s*$/', $l, $m) === 1 && (int) $m[1] <= $now;
    }

    private static function isWatchOf(string $l, string $line): bool
    {
        return preg_match('/^(.*)\|watch:\d+\s*$/', trim($l), $m) === 1 && self::watchLine($line, 0) === $m[1] . '|watch:0';
    }
}
