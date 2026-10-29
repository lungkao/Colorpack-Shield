<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Which of the two languages the component speaks for this person: their own choice (a cookie, set
 * with the language buttons), else none, which means "follow the administrator's language".
 */
final class LocalePick
{
    public const TAGS = ['th-TH', 'en-GB'];

    /** @return string  a tag from TAGS, or '' for "follow the administrator language" */
    public static function fromCookie(mixed $value): string
    {
        return \is_string($value) && \in_array($value, self::TAGS, true) ? $value : '';
    }

    /**
     * @param  string  $chosen  from {@see fromCookie()}
     * @param  string  $site    the administrator's own language tag
     *
     * @return string  the tag whose texts to show: the choice, else the site language if it is one of ours, else en-GB
     */
    public static function effective(string $chosen, string $site): string
    {
        if ($chosen !== '') {
            return $chosen;
        }

        return \in_array($site, self::TAGS, true) ? $site : 'en-GB';
    }
}
