<?php
/**
 * Plugin Name:       Colorpack Shield
 * Description:       Fleet-hardening security for WordPress: request firewall (WAF), login lock-out, file-integrity scan, and reporting to Colorpack Site Manager.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            COLORPACK CREATION CO., LTD.
 * Author URI:        https://colorpack.co.th
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       colorpack-shield
 */

defined('ABSPATH') || die;

define('COLORPACK_SHIELD_WP_VERSION', '0.1.0');
define('COLORPACK_SHIELD_WP_DIR', __DIR__);

// Two namespaces, one autoloader: the shared engine (WAF, IP, lock-out, scanner, Site Manager client)
// lives in src/ under the same names as the Joomla package; the WordPress glue lives in wp/.
spl_autoload_register(static function (string $class): void {
    foreach (['Colorpack\\Plugin\\System\\ColorpackShield\\' => '/src/', 'Colorpack\\Shield\\Wp\\' => '/wp/'] as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = COLORPACK_SHIELD_WP_DIR . $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

            if (is_file($file)) {
                require_once $file;
            }

            return;
        }
    }
});

if (PHP_VERSION_ID < 80100) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p>Colorpack Shield needs PHP 8.1 or newer.</p></div>';
    });

    return;
}

\Colorpack\Shield\Wp\Plugin::boot();
