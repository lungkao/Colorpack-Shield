<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Colorpack\Component\ColorpackShield\Administrator\Core\IniStrings;
use Colorpack\Component\ColorpackShield\Administrator\Core\LocalePick;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Language;

\defined('_JEXEC') || die;

/**
 * Lets a person use the component in Thai while the administrator is in English (or the other way
 * round). Only the component's own texts and the plugin's settings labels are switched: the texts
 * come straight from the language files that travel with the extension, so it works even when
 * the second language is not installed in Joomla. The choice is a small cookie; nothing else changes.
 */
final class Locale
{
    public const COOKIE = 'cps_lang';

    /** The tag the component is shown in for this request. */
    public static function tag(): string
    {
        $app    = Factory::getApplication();
        $chosen = LocalePick::fromCookie($app->getInput()->cookie->getString(self::COOKIE, ''));

        return LocalePick::effective($chosen, $app->getLanguage()->getTag());
    }

    /**
     * Put the texts of the chosen language over the loaded ones. Safe to call again after the
     * plugin's own language file was loaded (it would otherwise put its texts back).
     */
    public static function apply(): void
    {
        try {
            $lang = Factory::getApplication()->getLanguage();
            $tag  = self::tag();

            // The administrator's own language already shows its files: nothing to do.
            if ($tag === $lang->getTag() && self::installed($tag)) {
                return;
            }

            $map = [];

            foreach ([
                JPATH_ADMINISTRATOR . '/components/com_colorpack_shield/language/' . $tag . '/com_colorpack_shield.ini',
                JPATH_PLUGINS . '/system/colorpack_shield/language/' . $tag . '/plg_system_colorpack_shield.ini',
            ] as $file) {
                if (is_file($file) && is_readable($file) && (int) @filesize($file) <= IniStrings::MAX_BYTES) {
                    $map += IniStrings::parse((string) @file_get_contents($file));
                }
            }

            if ($map === []) {
                return;
            }

            \Closure::bind(function (array $strings): void {
                $this->strings = $strings + $this->strings;
            }, $lang, Language::class)($map);
        } catch (\Throwable) {
            // The component simply stays in the administrator's language.
        }
    }

    /** Is this language installed in Joomla with our files (then Joomla itself loaded them)? */
    private static function installed(string $tag): bool
    {
        return is_file(JPATH_ADMINISTRATOR . '/language/' . $tag . '/com_colorpack_shield.ini');
    }

    /**
     * Remember a choice ('' = follow the administrator language).
     */
    public static function remember(string $choice): void
    {
        $choice = LocalePick::fromCookie($choice);

        setcookie(self::COOKIE, $choice, [
            'expires'  => $choice === '' ? time() - 3600 : time() + 365 * 86400,
            'path'     => '/',
            'secure'   => Factory::getApplication()->isSSLConnection(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
