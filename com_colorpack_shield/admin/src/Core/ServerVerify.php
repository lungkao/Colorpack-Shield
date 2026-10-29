<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The "Verify" check for the server rules: harmless files of a stock Joomla that the rules
 * should refuse. The list is fixed, so nothing the person types can name a URL.
 */
final class ServerVerify
{
    /** Files a stock Joomla ships at these places; none is needed to run a site. */
    public const PATHS = ['/htaccess.txt', '/web.config.txt', '/administrator/manifests/files/joomla.xml', '/README.txt'];

    public const OPEN    = 'open';
    public const REFUSED = 'refused';
    public const UNKNOWN = 'unknown';

    /**
     * @param  array<string,int>  $statuses  path => HTTP status (0 = no answer)
     *
     * @return string  open: a file was served · refused: at least one was refused and none served ·
     *                 unknown: nothing conclusive (404 = file absent, 0 = could not connect)
     */
    public static function summarize(array $statuses): string
    {
        $refused = false;

        foreach ($statuses as $status) {
            if ($status >= 200 && $status < 300) {
                return self::OPEN;
            }

            if ($status === 403 || $status === 401 || $status === 410) {
                $refused = true;
            }
        }

        return $refused ? self::REFUSED : self::UNKNOWN;
    }
}
