<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || die;

/**
 * The `.cps-head`/`.cps-nav` banner shared by every screen - the WP equivalent of the Joomla
 * edition's `admin/tmpl/nav.php`. No in-plugin language switcher here (unlike the Joomla
 * edition's th-TH/English cookie buttons): this side follows the admin's own WordPress profile
 * language (`get_user_locale()`) instead, since there's no equivalent "our own button" yet.
 */
final class Nav
{
    private const SCREENS = [
        'colorpack-shield'          => 'Dashboard',
        'colorpack-shield-settings' => 'Settings',
        'colorpack-shield-activity' => 'Activity',
        'colorpack-shield-scan'     => 'Files',
        'colorpack-shield-mfa'      => 'MFA',
    ];

    public static function render(string $currentSlug): void
    {
        ?>
        <div class="cps-head">
            <div class="cps-brand">
                <h1 class="cps-h3" style="margin:0"><?php esc_html_e('Colorpack Shield', 'colorpack-shield'); ?></h1>
            </div>
            <nav class="cps-nav" aria-label="<?php echo esc_attr__('Colorpack Shield', 'colorpack-shield'); ?>">
                <?php foreach (self::SCREENS as $slug => $label) : ?>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=' . $slug)); ?>"<?php echo $currentSlug === $slug ? ' aria-current="page"' : ''; ?>><?php echo esc_html__($label, 'colorpack-shield'); ?></a>
                <?php endforeach; ?>
            </nav>
        </div>
        <?php
    }
}
