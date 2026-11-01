<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\SiteManager;

use Colorpack\WP\ColorpackShield\Admin\ActivityLog;
use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\WP\ColorpackShield\Waf\TargetedBanPolicy;

defined('ABSPATH') || die;

/**
 * The scheduled sync to Colorpack Site Manager: queued events, banned-attacker reports and the daily health
 * result go up in one signed request; the reply carries the fleet's shared attacker list, which is banned here
 * when "fleet ban" is on. Quiet and fail-open: no Agent config, a bad reply or no network means nothing happens.
 */
final class Reporter
{
    public const HOOK = 'colorpack_shield_sync';

    public static function boot(): void
    {
        add_filter('cron_schedules', [self::class, 'schedules']);
        add_action(self::HOOK, [self::class, 'sync']);
        add_action('init', [self::class, 'schedule']);
    }

    public static function store(): FileStateStore
    {
        return new FileStateStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/sitemanager');
    }

    public static function banStore(): FileStateStore
    {
        return new FileStateStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/bans');
    }

    public static function schedule(): void
    {
        if (!wp_next_scheduled(self::HOOK)) {
            wp_schedule_event(time() + 120, 'colorpack_shield_15min', self::HOOK);
        }
    }

    public static function unschedule(): void
    {
        $next = wp_next_scheduled(self::HOOK);

        if ($next !== false) {
            wp_unschedule_event($next, self::HOOK);
        }
    }

    /** @param  array<string,mixed>  $schedules */
    public static function schedules(array $schedules): array
    {
        $schedules['colorpack_shield_15min'] = ['interval' => 900, 'display' => 'Every 15 minutes (Colorpack Shield)'];

        return $schedules;
    }

    /** Queue one event for the Site Manager (lock-out, login burst ...). Best effort, never throws. */
    public static function event(string $type, string $severity, string $detail, int $count = 1): void
    {
        try {
            if (!Settings::get()['site_manager_enabled'] || AgentConfig::load() === null) {
                return;
            }

            $now = time();
            (new EventQueue(self::store()))->enqueue([
                'id'       => gmdate('Y-m-d\TH:i:s\Z', $now) . '-' . $type . '-' . bin2hex(random_bytes(4)),
                'at'       => gmdate('Y-m-d\TH:i:s\Z', $now),
                'type'     => $type,
                'severity' => $severity,
                'count'    => max(1, $count),
                'detail'   => substr($detail, 0, 300),
            ], $now);
        } catch (\Throwable) {
            // Reporting must never break a request.
        }
    }

    /** Tell the Site Manager about a deliberately banned attacker (never a visitor), once per address per day. */
    public static function threat(string $ip, string $reason): void
    {
        try {
            if (!Settings::get()['site_manager_enabled'] || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return;
            }

            $now = time();
            (new EventQueue(self::store(), 'threats'))->enqueue([
                'id'     => substr(hash('sha256', $ip), 0, 16) . '-' . gmdate('Ymd', $now),
                'at'     => gmdate('Y-m-d\TH:i:s\Z', $now),
                'ip'     => $ip,
                'reason' => substr($reason, 0, 60),
            ], $now);
        } catch (\Throwable) {
            // Best effort.
        }
    }

    /** @return int  addresses banned from the fleet list, -1 when nothing could be sent */
    public static function sync(): int
    {
        if (!Settings::get()['site_manager_enabled'] || ($config = AgentConfig::load()) === null) {
            return -1;
        }

        $now     = time();
        $store   = self::store();
        $events  = new EventQueue($store);
        $threats = new EventQueue($store, 'threats');
        $health  = new HealthCache($store);

        // The health result is rebuilt here (cheap) once a day, so no admin page visit is needed to keep it fresh.
        if ($health->peek($now) === null || $health->dueToday($now)) {
            $health->put(Health::build(), $now);
        }

        $payload     = [];
        $sendEvents  = $events->drain(100, $now);
        $sendThreats = $threats->drain(100, $now);
        $sendHealth  = $health->dueToday($now);

        if ($sendEvents !== []) {
            $payload['events'] = $sendEvents;
        }

        if ($sendThreats !== []) {
            $payload['threats'] = $sendThreats;
        }

        if ($sendHealth && ($h = $health->peek($now)) !== null) {
            $payload['health'] = $h;
        } else {
            $sendHealth = false;
        }

        if ($payload === []) {
            return -1;
        }

        $result = (new Client(new WpTransport()))->send($config, $payload);

        if ($result === null) {
            return -1;
        }

        $ids = static fn (array $rows): array => array_map(static fn (array $r): string => (string) ($r['id'] ?? ''), $rows);
        $events->ack($ids($sendEvents), $now);
        $threats->ack($ids($sendThreats), $now);

        if ($sendHealth) {
            $health->markSent($now);
        }

        return self::applyFeed($result['feed'] ?? [], $now);
    }

    /** @param  array<int,string>  $feed */
    private static function applyFeed(array $feed, int $now): int
    {
        if ($feed === [] || !Settings::get()['fleet_ban']) {
            return 0;
        }

        $ban = new TargetedBanPolicy(self::banStore());
        $n   = 0;

        foreach (array_slice($feed, 0, 500) as $ip) {
            if (is_string($ip) && $ban->ban($ip, $now, 24 * 3600, 'fleet') > 0) {
                $n++;
            }
        }

        if ($n > 0) {
            (new ActivityLog(ActivityLog::defaultPath()))->write('NOTE', ['client' => 'site', 'detail' => sprintf('fleet ban list applied: %d address(es)', $n)], '');
        }

        return $n;
    }
}
