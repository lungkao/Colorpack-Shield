<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The plugin's own texts in Thai and English, read from languages/th-TH.ini and en-GB.ini (the same
 * files the Joomla edition ships, plus a WordPress section). Like the Joomla edition, a person can
 * pick Thai or English with a button regardless of the language WordPress is set to; the choice is
 * kept per user. With no choice the user's WordPress language decides (Thai if it is Thai, else English).
 */
final class Lang
{
    public const META = 'cps_lang';

    /** @var array<string,array<string,string>> */
    private static array $cache = [];

    private static ?string $forced = null;

    /** @var array<string,string>|null */
    private static ?array $wp = null;

    /** For tests and for rendering one request in a fixed language. */
    public static function force(?string $tag): void
    {
        self::$forced = $tag;
    }

    public static function tag(): string
    {
        if (self::$forced !== null) {
            return self::$forced;
        }

        $chosen = '';

        if (\function_exists('get_user_meta') && \function_exists('get_current_user_id') && get_current_user_id() > 0) {
            $chosen = LocalePick::fromCookie(get_user_meta(get_current_user_id(), self::META, true));
        }

        $site = \function_exists('get_user_locale') ? (str_starts_with((string) get_user_locale(), 'th') ? 'th-TH' : 'en-GB') : 'en-GB';

        return LocalePick::effective($chosen, $site);
    }

    public static function remember(string $tag): void
    {
        $tag = LocalePick::fromCookie($tag);

        if ($tag !== '' && \function_exists('update_user_meta') && get_current_user_id() > 0) {
            update_user_meta(get_current_user_id(), self::META, $tag);
        }
    }

    /**
     * @param  string  $key   a language key (for example "PLG_SYSTEM_COLORPACK_SHIELD_COVER_SITE_LABEL")
     * @param  mixed   ...$args  values for sprintf placeholders
     */
    public static function t(string $key, mixed ...$args): string
    {
        $map  = self::map(self::tag());
        $text = $map[$key] ?? self::map('en-GB')[$key] ?? $key;

        return $args === [] ? $text : vsprintf($text, $args);
    }

    /**
     * Thai for a string the screens write in English (WordPress gettext, domain "colorpack-shield").
     * English stays English when the Thai button is off or no Thai text is listed.
     */
    public static function translate(string $english): string
    {
        if (self::tag() !== 'th-TH') {
            return $english;
        }

        if (self::$wp === null) {
            $file     = \dirname(__DIR__, 2) . '/languages/th-wp.php';
            self::$wp = is_file($file) ? (array) (include $file) : [];
        }

        return self::$wp[$english] ?? $english;
    }

    public static function has(string $key): bool
    {
        return isset(self::map(self::tag())[$key]) || isset(self::map('en-GB')[$key]);
    }

    /**
     * @return array<string,string>
     */
    private static function map(string $tag): array
    {
        if (!isset(self::$cache[$tag])) {
            $file = \dirname(__DIR__, 2) . '/languages/' . $tag . '.ini';
            $text = is_file($file) && is_readable($file) ? (string) @file_get_contents($file) : '';

            self::$cache[$tag] = IniStrings::parse($text);
        }

        return self::$cache[$tag];
    }
}
