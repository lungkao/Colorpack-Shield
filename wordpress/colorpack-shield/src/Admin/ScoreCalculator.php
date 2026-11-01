<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The checklist behind the Dashboard number - a WordPress-specific rewrite of the Joomla
 * edition's `ScoreCalculator`, not a port. The Joomla version scores 11 items; four of them
 * (`real_ip`/`cloudflare_ranges`/`rate_limit`/`server_rules`) score subsystems this port never
 * built at all (no real-IP-behind-proxy prober, no rate limiter, no server-rule checker), and two
 * more (`shields`/`coverage`) are redundant here: the Joomla edition has per-shield toggles and
 * separate site/admin/api coverage switches, but this port's WAF (`Waf\Bootstrap`) turns every
 * shield on together, covering both `site` and `admin` scopes unconditionally, under one
 * `waf_enabled` switch - there is no partial state for either item to report. Passing WP through
 * the Joomla calculator unmodified would show permanent, unfixable warnings pointing at Settings
 * fields that don't exist here - a broken recommendation, not a graceful "not tested" item (see
 * `isUnknown`-style degradation in the Joomla version: `rate_limit`/`cloudflare_ranges` don't
 * degrade to `UNKNOWN` cleanly even when their subsystem is absent).
 *
 * Only the four items this port genuinely has an independent signal for are scored, re-weighted
 * to still sum to 100.
 */
final class ScoreCalculator
{
    public const OK      = 'ok';
    public const WARN    = 'warn';
    public const BAD     = 'bad';
    public const UNKNOWN = 'unknown';

    /**
     * @param  array<string,mixed>  $facts
     *
     * @return array{score:?int,tested:int,total:int,items:array<int,array{id:string,weight:int,status:string}>}
     */
    public static function calculate(array $facts): array
    {
        $items = [
            self::item('protection', 30, self::protection($facts)),
            self::item('admin_login', 30, self::adminLogin($facts)),
            self::item('admin_door', 15, self::adminDoor($facts)),
            self::item('file_scan', 25, self::fileScan($facts)),
        ];

        $earned = 0.0;
        $known  = 0;
        $tested = 0;

        foreach ($items as $it) {
            if ($it['status'] === self::UNKNOWN) {
                continue;
            }

            $tested++;
            $known  += $it['weight'];
            $earned += $it['status'] === self::OK ? $it['weight'] : 0;
        }

        return [
            'score'  => $known > 0 ? (int) round($earned / $known * 100) : null,
            'tested' => $tested,
            'total'  => \count($items),
            'items'  => $items,
        ];
    }

    /**
     * @return array{id:string,weight:int,status:string}
     */
    private static function item(string $id, int $weight, string $status): array
    {
        return ['id' => $id, 'weight' => $weight, 'status' => $status];
    }

    /** The WAF itself - this port's single on/off switch for every shield at once. */
    private static function protection(array $f): string
    {
        return ($f['waf_enabled'] ?? false) ? self::OK : self::BAD;
    }

    /** Same three-state shape as the Joomla edition's own `adminLogin()`: lock-out off is a failure; lock-out on without MFA enforced is a recommendation, not a failure. */
    private static function adminLogin(array $f): string
    {
        if (!($f['login_lockout'] ?? false)) {
            return self::BAD;
        }

        return ($f['mfa_enforce'] ?? 'off') === 'enforce' ? self::OK : self::WARN;
    }

    /** The access-key "door": recommended, so "not set" is a warning, not a failure. */
    private static function adminDoor(array $f): string
    {
        return ($f['admin_door'] ?? false) ? self::OK : self::WARN;
    }

    /** Never scanned is "not tested"; a high-severity finding is bad; an old scan is only a warning. */
    private static function fileScan(array $f): string
    {
        $s = $f['file_scan'] ?? null;

        if (!\is_array($s)) {
            return self::UNKNOWN;
        }

        if (((int) ($s['high'] ?? 0)) > 0) {
            return self::BAD;
        }

        return ((int) ($s['age'] ?? 0)) > 30 ? self::WARN : self::OK;
    }
}
