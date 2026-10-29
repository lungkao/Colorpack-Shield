<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns the checklist into what the Dashboard says first: one headline for the whole picture, and
 * the few things worth doing next, most important first. Pure: it only orders and words what the
 * checks already found.
 */
final class DashboardPlanner
{
    public const GOOD  = 'good';
    public const WATCH = 'watch';
    public const RISK  = 'risk';
    public const NONE  = 'none';

    /** Importance when two items are in the same state: what protects the most comes first. */
    private const PRIORITY = ['protection', 'admin_login', 'lockout_safety', 'file_scan', 'real_ip', 'admin_door', 'shields', 'coverage', 'cloudflare_ranges', 'rate_limit', 'server_rules'];

    /** Where each item is fixed. */
    private const FIX = [
        'protection' => 'settings', 'admin_login' => 'settings', 'lockout_safety' => 'setup', 'file_scan' => 'scan', 'real_ip' => 'setup', 'admin_door' => 'setup',
        'shields' => 'settings', 'coverage' => 'settings', 'cloudflare_ranges' => 'network', 'rate_limit' => 'settings', 'server_rules' => 'server',
    ];

    /**
     * On the Settings screen only: the one field that opens the right tab (and reveals it if it is
     * an "advanced" one) when a person follows a recommendation here, instead of landing on the
     * screen and having to go hunting for it themselves.
     */
    private const FIELD = [
        'admin_login' => 'login_lockout', 'shields' => 'shield_sqli', 'coverage' => 'cover_site', 'rate_limit' => 'rate_enabled',
    ];

    /**
     * @param  array{score:?int,items:array<int,array{id:string,weight:int,status:string}>}  $score
     *
     * @return array{band:string,todo:array<int,array{id:string,status:string,screen:string,field:?string}>,counts:array{ok:int,warn:int,bad:int,unknown:int}}
     */
    public static function plan(array $score, int $max = 3): array
    {
        $counts = ['ok' => 0, 'warn' => 0, 'bad' => 0, 'unknown' => 0];
        $rank   = ['bad' => 0, 'warn' => 1, 'unknown' => 2];
        $todo   = [];

        foreach ($score['items'] as $it) {
            $counts[$it['status']] = ($counts[$it['status']] ?? 0) + 1;

            if ($it['status'] !== 'ok' && isset($rank[$it['status']])) {
                $todo[] = ['id' => $it['id'], 'status' => $it['status'], 'screen' => self::FIX[$it['id']] ?? 'settings', 'field' => self::FIELD[$it['id']] ?? null];
            }
        }

        usort($todo, static function (array $a, array $b) use ($rank): int {
            $pa = array_search($a['id'], self::PRIORITY, true);
            $pb = array_search($b['id'], self::PRIORITY, true);

            return [$rank[$a['status']], $pa === false ? 99 : $pa] <=> [$rank[$b['status']], $pb === false ? 99 : $pb];
        });

        $s = $score['score'];

        if ($s === null) {
            $band = self::NONE;
        } elseif ($s < 50 || ($counts['bad'] > 0 && $s < 80)) {
            $band = self::RISK;
        } elseif ($s >= 80 && $counts['bad'] === 0) {
            $band = self::GOOD;
        } else {
            // Includes "a good number with one critical item": never "all good" while something is critical.
            $band = self::WATCH;
        }

        return ['band' => $band, 'todo' => \array_slice($todo, 0, max(1, $max)), 'counts' => $counts];
    }
}
