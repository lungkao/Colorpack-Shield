<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || die;

/**
 * Loads the Colorpack design system (ported from the Joomla edition's media/css/cps.css +
 * media/js/cps.js) on this plugin's own wp-admin pages only - never site-wide, and never on
 * someone else's admin screen.
 */
final class Assets
{
    public static function boot(): void
    {
        add_action('admin_enqueue_scripts', [self::class, 'maybeEnqueue']);
    }

    public static function maybeEnqueue(string $hookSuffix): void
    {
        if (!str_contains($hookSuffix, 'colorpack-shield')) {
            return;
        }

        wp_enqueue_style(
            'colorpack-shield-cps',
            COLORPACK_SHIELD_WP_URL . 'assets/css/cps.css',
            [],
            COLORPACK_SHIELD_WP_VERSION
        );

        wp_enqueue_script(
            'colorpack-shield-cps',
            COLORPACK_SHIELD_WP_URL . 'assets/js/cps.js',
            [],
            COLORPACK_SHIELD_WP_VERSION,
            true
        );
    }
}
