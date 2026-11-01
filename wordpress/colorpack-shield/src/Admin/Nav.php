<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || die;

/**
 * The `.cps-head`/`.cps-nav` banner shared by every screen - the WordPress counterpart of the Joomla
 * edition's `admin/tmpl/nav.php`: the logo, one tab per screen, and the Thai/English buttons.
 */
final class Nav
{
    public const LANG_ACTION = 'colorpack_shield_lang';

    /** screen slug => language key, in tab order (same order as the Joomla edition). */
    private const SCREENS = [
        'colorpack-shield'          => 'COM_COLORPACK_SHIELD_NAV_DASHBOARD',
        'colorpack-shield-settings' => 'COM_COLORPACK_SHIELD_NAV_SETTINGS',
        'colorpack-shield-scan'     => 'COM_COLORPACK_SHIELD_NAV_SCAN',
        'colorpack-shield-activity' => 'COM_COLORPACK_SHIELD_NAV_ACTIVITY',
        'colorpack-shield-mfa'      => 'WPS_NAV_MFA',
        'colorpack-shield-tools'    => 'COM_COLORPACK_SHIELD_NAV_TOOLS',
    ];

    public static function render(string $currentSlug): void
    {
        $tag = Lang::tag();
        ?>
        <div class="cps-head">
            <div class="cps-brand">
                <img class="cps-logo" src="<?php echo esc_url(COLORPACK_SHIELD_WP_URL . 'assets/images/logo.png'); ?>" alt="" width="36" height="36" loading="lazy">
                <h1><?php esc_html_e('Colorpack Shield', 'colorpack-shield'); ?></h1>
            </div>
            <nav class="cps-nav" aria-label="<?php echo esc_attr__('Colorpack Shield', 'colorpack-shield'); ?>">
                <?php foreach (self::SCREENS as $slug => $key) : ?>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=' . $slug)); ?>"<?php echo $currentSlug === $slug ? ' aria-current="page"' : ''; ?>><?php echo esc_html(Lang::t($key)); ?></a>
                <?php endforeach; ?>
            </nav>
            <form class="cps-lang" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" method="post" role="group" aria-label="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_LANG')); ?>">
                <input type="hidden" name="action" value="<?php echo esc_attr(self::LANG_ACTION); ?>">
                <input type="hidden" name="return" value="<?php echo esc_attr($currentSlug); ?>">
                <?php wp_nonce_field(self::LANG_ACTION); ?>
                <button type="submit" name="lang" value="th-TH" lang="th"<?php echo $tag === 'th-TH' ? ' aria-current="true"' : ''; ?>>ไทย</button>
                <button type="submit" name="lang" value="en-GB" lang="en"<?php echo $tag === 'en-GB' ? ' aria-current="true"' : ''; ?>>English</button>
            </form>
        </div>
        <?php
    }

    /** admin-post.php handler for the language buttons: remember the choice for this user and go back. */
    public static function handleLang(): void
    {
        check_admin_referer(self::LANG_ACTION);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        Lang::remember(isset($_POST['lang']) && \is_string($_POST['lang']) ? sanitize_text_field(wp_unslash($_POST['lang'])) : '');

        $page = isset($_POST['return']) && \is_string($_POST['return']) ? sanitize_key(wp_unslash($_POST['return'])) : 'colorpack-shield';
        $page = \in_array($page, array_keys(self::SCREENS), true) ? $page : 'colorpack-shield';

        wp_safe_redirect(admin_url('admin.php?page=' . $page));
        exit;
    }
}
