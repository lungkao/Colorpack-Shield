<?php

namespace Colorpack\Shield\Wp;

defined('ABSPATH') || die;

/** Wires the pieces to WordPress. The firewall runs right now (while plugins load); everything else on its own hook. */
final class Plugin
{
    public static function boot(): void
    {
        Guard::run();
        Login::hooks();
        Admin::hooks();

        add_filter('cron_schedules', [Reporter::class, 'schedules']);
        add_action(Reporter::HOOK, [Reporter::class, 'sync']);
        add_action('init', [Reporter::class, 'schedule']);

        register_deactivation_hook(COLORPACK_SHIELD_WP_DIR . '/colorpack-shield.php', static function (): void {
            wp_clear_scheduled_hook(Reporter::HOOK);
        });
    }
}
