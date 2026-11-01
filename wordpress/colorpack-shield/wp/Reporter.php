<?php

namespace Colorpack\Shield\Wp;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\Client;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\EventQueue;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\HealthCache;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;

defined('ABSPATH') || die;

/**
 * The scheduled sync to Colorpack Site Manager: queued events, banned-attacker reports and the daily health
 * result go up in one signed request; the reply carries the fleet's shared attacker list, which is banned here
 * when the probe mode is "ban". Quiet and fail-open: no Agent config, a bad reply or no network means nothing happens.
 */
final class Reporter
{
    public const HOOK = 'colorpack_shield_sync';

    public static function store(): FileStateStore
    {
        return new FileStateStore(Settings::stateDir('sitemanager'));
    }

    public static function schedule(): void
    {
        if (!wp_next_scheduled(self::HOOK)) {
            wp_schedule_event(time() + 120, 'colorpack_shield_15min', self::HOOK);
        }
    }

    /** @param  array<string,mixed>  $schedules */
    public static function schedules(array $schedules): array
    {
        $schedules['colorpack_shield_15min'] = ['interval' => 900, 'display' => 'Every 15 minutes (Colorpack Shield)'];

        return $schedules;
    }

    /** @return int  addresses banned from the fleet list, -1 when nothing could be sent */
    public static function sync(): int
    {
        if (!Settings::get('site_manager_enabled') || ($config = AgentConfig::load()) === null) {
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

        $payload = [];
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
            Logger::add('NOTE site_manager sync failed (will retry)');

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
        if ($feed === [] || (string) Settings::get('path_probe_mode') !== 'ban') {
            return 0;
        }

        $ban   = new TargetedBanPolicy(Guard::banStore());
        $hours = max(1, (int) Settings::get('path_probe_ban_hours'));
        $n     = 0;

        foreach (array_slice($feed, 0, 500) as $ip) {
            if (is_string($ip) && $ban->ban($ip, $now, $hours * 3600, 'fleet') > 0) {
                $n++;
            }
        }

        if ($n > 0) {
            Logger::add(sprintf('NOTE fleet ban list applied: %d address(es)', $n));
        }

        return $n;
    }
}
