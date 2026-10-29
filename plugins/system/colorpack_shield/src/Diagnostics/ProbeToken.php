<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Diagnostics;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Short-lived token that lets the server's own admin tooling ask the plugin
 * "what do you see?" (proxy self-test, AUDIT.md N1). It is an HMAC of the
 * current 5-minute window under Joomla's site secret, so only someone who can
 * read configuration.php can make one, and a captured token dies within ~10
 * minutes.
 */
final class ProbeToken
{
    public const WINDOW = 300;

    public static function make(string $secret, int $now): string
    {
        return self::forWindow($secret, intdiv($now, self::WINDOW));
    }

    /**
     * Valid for the current and the previous window (clock/boundary slack).
     * An empty secret disables the feature: nothing verifies.
     */
    public static function verify(string $secret, string $token, int $now): bool
    {
        if ($secret === '' || $token === '' || \strlen($token) !== 64) {
            return false;
        }

        $window = intdiv($now, self::WINDOW);

        return hash_equals(self::forWindow($secret, $window), $token)
            || hash_equals(self::forWindow($secret, $window - 1), $token);
    }

    private static function forWindow(string $secret, int $window): string
    {
        return hash_hmac('sha256', 'colorpack_shield-probe|' . $window, $secret);
    }
}
