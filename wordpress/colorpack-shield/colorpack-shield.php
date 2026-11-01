<?php
/**
 * Plugin Name:       Colorpack Shield
 * Plugin URI:         https://colorpack.co.th
 * Description:        Fleet-hardening security for WordPress, built for shared hosting - the same WAF, login protection, file scan and Colorpack Site Manager reporting as the Joomla edition.
 * Version:            0.11.0
 * Requires at least:  6.0
 * Requires PHP:       8.1
 * Author:             COLORPACK CREATION CO., LTD.
 * Author URI:         https://colorpack.co.th
 * License:            GPL v3 or later
 * License URI:        https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:        colorpack-shield
 * Domain Path:        /languages
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

defined('ABSPATH') || die;

/**
 * Status: WAF core, the Gemini AI advisor, admin login protection, a file scanner (view/edit/
 * delete, quarantine/restore, and an optional WP-Cron background scan), a Dashboard score page,
 * MFA (this port's own TOTP), and new-administrator/promotion alerts are all wired up under the
 * "Colorpack Shield" wp-admin menu (Dashboard, Settings, Activity, Files, MFA), styled with the
 * same Colorpack design system as the Joomla edition. Every server-facing feature is off by
 * default - turn each on from Settings, or override the WAF alone with the wp-config.php filter:
 * src/Waf/Bootstrap.php.
 */

const COLORPACK_SHIELD_WP_VERSION = '0.11.0';
const COLORPACK_SHIELD_WP_FILE    = __FILE__;
define('COLORPACK_SHIELD_WP_DIR', plugin_dir_path(__FILE__));
define('COLORPACK_SHIELD_WP_URL', plugin_dir_url(__FILE__));

/**
 * PSR-4-ish autoloader for this plugin's own classes, same convention as the Joomla edition's
 * test-harness autoloaders (manual, no Composer step, so the shipped zip stays self-contained
 * on shared hosting with no `vendor/` to install).
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Colorpack\\WP\\ColorpackShield\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $file = COLORPACK_SHIELD_WP_DIR . 'src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});

add_action('init', static function (): void {
    load_plugin_textdomain('colorpack-shield', false, dirname(plugin_basename(COLORPACK_SHIELD_WP_FILE)) . '/languages');
});

\Colorpack\WP\ColorpackShield\Waf\Bootstrap::boot();
\Colorpack\WP\ColorpackShield\AdminProtect\Wiring::boot();
\Colorpack\WP\ColorpackShield\Admin\ScheduledScan::boot();
add_action('init', [\Colorpack\WP\ColorpackShield\Admin\ScheduledScan::class, 'reschedule']);
\Colorpack\WP\ColorpackShield\SiteManager\Reporter::boot();

add_action('admin_menu', static function (): void {
    add_menu_page(
        __('Colorpack Shield', 'colorpack-shield'),
        __('Colorpack Shield', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield',
        [\Colorpack\WP\ColorpackShield\Admin\DashboardPage::class, 'render'],
        'dashicons-shield'
    );
    add_submenu_page(
        'colorpack-shield',
        __('Dashboard', 'colorpack-shield'),
        __('Dashboard', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield',
        [\Colorpack\WP\ColorpackShield\Admin\DashboardPage::class, 'render']
    );
    add_submenu_page(
        'colorpack-shield',
        __('Settings', 'colorpack-shield'),
        __('Settings', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield-settings',
        [\Colorpack\WP\ColorpackShield\Admin\SettingsPage::class, 'render']
    );
    add_submenu_page(
        'colorpack-shield',
        __('Activity', 'colorpack-shield'),
        __('Activity', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield-activity',
        [\Colorpack\WP\ColorpackShield\Admin\ActivityPage::class, 'render']
    );
    add_submenu_page(
        'colorpack-shield',
        __('Files', 'colorpack-shield'),
        __('Files', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield-scan',
        [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'render']
    );
    add_submenu_page(
        'colorpack-shield',
        __('MFA', 'colorpack-shield'),
        __('MFA', 'colorpack-shield'),
        'manage_options',
        'colorpack-shield-mfa',
        [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'render']
    );
});

add_action('admin_post_' . \Colorpack\WP\ColorpackShield\Admin\MfaPage::ACTION_START, [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'handleStart']);
add_action('admin_post_' . \Colorpack\WP\ColorpackShield\Admin\MfaPage::ACTION_CANCEL, [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'handleCancel']);
add_action('admin_post_' . \Colorpack\WP\ColorpackShield\Admin\MfaPage::ACTION_CONFIRM, [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'handleConfirm']);
add_action('admin_post_' . \Colorpack\WP\ColorpackShield\Admin\MfaPage::ACTION_REGEN, [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'handleRegen']);
add_action('admin_post_' . \Colorpack\WP\ColorpackShield\Admin\MfaPage::ACTION_DISABLE, [\Colorpack\WP\ColorpackShield\Admin\MfaPage::class, 'handleDisable']);

add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ActivityPage::AI_ACTION,
    [\Colorpack\WP\ColorpackShield\Admin\ActivityPage::class, 'handleAnalyze']
);

add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_MARK_SAFE,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'handleMarkSafe']
);
add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_AI_ANALYZE,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'handleAiAnalyze']
);
add_action(
    'wp_ajax_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_START,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'ajaxStart']
);
add_action(
    'wp_ajax_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_STEP,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'ajaxStep']
);
add_action(
    'wp_ajax_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_VIEW,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'ajaxView']
);
add_action(
    'wp_ajax_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_SAVE,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'ajaxSave']
);
add_action(
    'wp_ajax_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_DELETE,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'ajaxDelete']
);
add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_BULK,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'handleBulk']
);
add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_RESTORE,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'handleRestore']
);
add_action(
    'admin_post_' . \Colorpack\WP\ColorpackShield\Admin\ScanPage::AJAX_DROP_COPY,
    [\Colorpack\WP\ColorpackShield\Admin\ScanPage::class, 'handleDropCopy']
);

\Colorpack\WP\ColorpackShield\Admin\Assets::boot();

register_activation_hook(__FILE__, static function (): void {
    // Nothing to set up yet at the scaffold stage.
});

register_deactivation_hook(__FILE__, static function (): void {
    \Colorpack\WP\ColorpackShield\SiteManager\Reporter::unschedule();

    $scheduled = wp_next_scheduled(\Colorpack\WP\ColorpackShield\Admin\ScheduledScan::HOOK);

    if ($scheduled !== false) {
        wp_unschedule_event($scheduled, \Colorpack\WP\ColorpackShield\Admin\ScheduledScan::HOOK);
    }
});
