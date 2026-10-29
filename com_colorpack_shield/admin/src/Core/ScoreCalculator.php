<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The checklist behind the dashboard number (PLAN-ADMIN-COMPONENT.md §5). Only facts the
 * component can really verify are scored; "unknown" items are shown grey and left out of
 * the number, so an untested thing is never counted as good or as bad.
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
            self::item('protection', 20, self::protection($facts)),
            self::item('real_ip', 15, self::realIp($facts)),
            self::item('cloudflare_ranges', 5, self::ranges($facts)),
            self::item('lockout_safety', 10, self::lockoutSafety($facts)),
            self::item('shields', 15, self::shields($facts)),
            self::item('coverage', 10, self::coverage($facts)),
            self::item('rate_limit', 5, self::rate($facts)),
            self::item('server_rules', 10, self::server($facts)),
            self::item('admin_login', 10, self::adminLogin($facts)),
            self::item('admin_door', 10, self::adminDoor($facts)),
            self::item('file_scan', 10, self::fileScan($facts)),
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
            $earned += match ($it['status']) {
                self::OK   => $it['weight'],
                self::WARN => $it['weight'] / 2,
                default    => 0,
            };
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

    private static function protection(array $f): string
    {
        if (!($f['plugin_installed'] ?? false) || !($f['plugin_enabled'] ?? false)) {
            return self::BAD;
        }

        return ($f['kill_switch'] ?? false) ? self::BAD : self::OK;
    }

    private static function realIp(array $f): string
    {
        $v   = $f['probe'] ?? null;
        $age = $f['probe_age_days'] ?? null;

        // "inconclusive" means the probe could not tell: neither good nor bad.
        if ($v === null || $v === 'inconclusive') {
            return self::UNKNOWN;
        }

        if ($v !== 'safe' && $v !== 'no_proxy') {
            return self::BAD;
        }

        // A good result that is more than 90 days old is worth repeating, not worth trusting.
        return \is_int($age) && $age > 90 ? self::WARN : self::OK;
    }

    private static function ranges(array $f): string
    {
        if (!($f['trust_cloudflare'] ?? false)) {
            return self::UNKNOWN;
        }

        $age = $f['cf_age_days'] ?? null;

        if (!\is_int($age)) {
            return self::WARN;
        }

        return $age > 30 ? self::WARN : self::OK;
    }

    private static function lockoutSafety(array $f): string
    {
        $trusted = ((int) ($f['allow_ips_count'] ?? 0)) > 0 || ($f['auto_allow_admin'] ?? false);
        $token   = (bool) ($f['killswitch_token_set'] ?? false);

        if ($trusted && $token) {
            return self::OK;
        }

        return $trusted || $token ? self::WARN : self::BAD;
    }

    private static function shields(array $f): string
    {
        $keys = ['shield_sqli', 'shield_xss', 'shield_lfi', 'shield_rfi', 'header_scan', 'path_scan', 'scan_body', 'scan_uploads'];
        $on   = 0;

        foreach ($keys as $k) {
            if ($f[$k] ?? false) {
                $on++;
            }
        }

        return match (true) {
            $on === \count($keys) => self::OK,
            $on === 0             => self::BAD,
            default               => self::WARN,
        };
    }

    private static function coverage(array $f): string
    {
        $on = (int) (bool) ($f['cover_site'] ?? false) + (int) (bool) ($f['cover_admin'] ?? false) + (int) (bool) ($f['cover_api'] ?? false);

        return match (true) {
            $on === 3 => self::OK,
            $on === 0 => self::BAD,
            default   => self::WARN,
        };
    }

    private static function rate(array $f): string
    {
        if (!($f['rate_enabled'] ?? false)) {
            return self::WARN;
        }

        // Counting needs shared memory; without APCu the limiter silently does nothing.
        return ($f['apcu'] ?? false) ? self::OK : self::BAD;
    }

    private static function server(array $f): string
    {
        return match ($f['server_rules'] ?? null) {
            'refused' => self::OK,
            'open'    => self::BAD,
            default   => self::UNKNOWN,
        };
    }

    private static function adminLogin(array $f): string
    {
        if (!($f['login_lockout'] ?? false)) {
            return self::BAD;
        }

        return ($f['mfa_enforce'] ?? 'off') === 'enforce' ? self::OK : self::WARN;
    }

    /** The administrator door: an access key or an address list in force. Recommended, so "not set" is a warning, not a failure. */
    private static function adminDoor(array $f): string
    {
        return ($f['admin_door'] ?? false) ? self::OK : self::WARN;
    }

    /** Never scanned is "not tested"; serious findings are bad; an old scan is only a warning. */
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
