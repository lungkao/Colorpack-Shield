<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\AdminProtect\AlertThrottle;
use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\WP\ColorpackShield\Scanner\FileScanner;
use Colorpack\WP\ColorpackShield\Scanner\ScanStore;

\defined('ABSPATH') || die;

/**
 * A background scan on WP-Cron, off by default - the WordPress equivalent of the Joomla
 * edition's `colorpack_shield.file_scan` Scheduled Task. Reuses the exact same
 * `FileScanner::step()`/`result()` pair the on-demand "Start scan" button on the Files screen
 * uses, and the same `ScanStore` location, so a scheduled run and a manual one show up as the
 * same result either way.
 *
 * WP-Cron requests aren't shared-hosting PHP-time-limited the same way a page load is, but a very
 * large site could still outrun one invocation - the loop below still saves its `state` after
 * every step (same as the AJAX step controller), so an interrupted run resumes cleanly on the
 * next scheduled firing instead of starting over.
 */
final class ScheduledScan
{
    public const HOOK = 'cps_scheduled_scan';

    /** Total wall-clock seconds one cron firing may spend scanning, win or lose. */
    private const MAX_RUNTIME = 50.0;

    public static function boot(): void
    {
        add_action(self::HOOK, [self::class, 'run']);
    }

    /** Called whenever Settings are saved - schedules or cancels the cron event to match. */
    public static function reschedule(): void
    {
        $enabled   = Settings::get()['scan_schedule_enabled'];
        $scheduled = wp_next_scheduled(self::HOOK);

        if ($enabled && $scheduled === false) {
            wp_schedule_event(time() + 300, 'twicedaily', self::HOOK);
        } elseif (!$enabled && $scheduled !== false) {
            wp_unschedule_event($scheduled, self::HOOK);
        }
    }

    public static function run(): void
    {
        if (!Settings::get()['scan_schedule_enabled']) {
            return;
        }

        $store = new ScanStore(self::storeDir());
        $prev  = $store->read('result');
        $prevHigh = [];

        foreach ((array) ($prev['findings'] ?? []) as $f) {
            if (($f['sev'] ?? '') === 'high' && \is_string($f['path'] ?? null)) {
                $prevHigh[$f['path']] = true;
            }
        }

        $state = $store->read('state') ?? FileScanner::newState(time());
        $ignore = $store->read('ignore');
        $ignore = \is_array($ignore) ? array_map('strval', $ignore) : [];
        $deadline = microtime(true) + self::MAX_RUNTIME;

        while (!$state['done'] && microtime(true) < $deadline) {
            $state = FileScanner::step($state, ABSPATH, microtime(true) + self::budget(), $ignore);
            $store->write('state', $state);
        }

        if (!$state['done']) {
            // Out of time this firing - the saved state picks up here next time.
            return;
        }

        $now  = time();
        $base = $store->read('baseline');
        $result = FileScanner::result($state, $base, $now);
        $store->write('result', $result);
        $store->write('lastfiles', ['at' => $now, 'files' => $state['tracked'] ? $state['files'] : null]);
        $store->delete('state');

        $newHigh = [];

        foreach ($result['findings'] as $f) {
            if ($f['sev'] === 'high' && !isset($prevHigh[$f['path']])) {
                $newHigh[] = $f['path'];
            }
        }

        if ($newHigh !== []) {
            self::alert($newHigh, (int) ($result['count']['high'] ?? 0));
        }
    }

    private static function alert(array $newPaths, int $totalHigh): void
    {
        $throttleStore = new FileStateStore(self::adminProtectDir());

        if (!AlertThrottle::claim($throttleStore, 'scan_new_high', time(), 3600)['send']) {
            return;
        }

        $admin = get_option('admin_email');

        if (!\is_string($admin) || $admin === '') {
            return;
        }

        $list = implode("\n", array_map(static fn (string $p): string => '- ' . $p, \array_slice($newPaths, 0, 20)));

        wp_mail(
            $admin,
            __('Colorpack Shield: the scheduled file scan found new high-severity items', 'colorpack-shield'),
            sprintf(
                /* translators: 1: number of new high-severity findings, 2: list of paths, 3: total high-severity findings */
                __("%1\$d new high-severity finding(s):\n%2\$s\n\n%3\$d high-severity finding(s) in total. Review them on the Files screen.", 'colorpack-shield'),
                \count($newPaths),
                $list,
                $totalHigh
            )
        );
    }

    private static function storeDir(): string
    {
        return trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/scan';
    }

    private static function adminProtectDir(): string
    {
        return trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/adminprotect';
    }

    /** Seconds one step may work: well inside the host's PHP time limit, never more than 6. */
    private static function budget(): float
    {
        $max = (int) ini_get('max_execution_time');

        return $max > 0 ? max(1.0, min(6.0, $max * 0.35)) : 6.0;
    }
}
