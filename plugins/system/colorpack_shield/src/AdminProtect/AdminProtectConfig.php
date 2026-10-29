<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The administrator-protection settings (PLAN-ADMIN-PROTECTION.md §6), read from
 * the plugin parameters and clamped to sane ranges: a typo such as "0" or
 * "99999999" in a setting can never switch the protection off by accident or
 * lock every visitor out for a year.
 */
final class AdminProtectConfig
{
    public const MFA_OFF     = 'off';
    public const MFA_WARN    = 'warn';
    public const MFA_ENFORCE = 'enforce';

    /**
     * @param  int[]  $mfaGroups
     */
    private function __construct(
        public readonly bool $lockoutEnabled,
        public readonly int $maxFailures,
        public readonly int $failureWindow,
        public readonly int $lockMinutes,
        public readonly int $lockMaxHours,
        public readonly int $ratePerMinute,
        public readonly bool $alertNewAdmin,
        public readonly bool $alertNewIp,
        public readonly bool $alertLockouts,
        public readonly string $mfaEnforce,
        public readonly array $mfaGroups,
        public readonly int $mfaGraceDays
    ) {
    }

    /**
     * @param  array<string,mixed>  $p  plugin parameters (Registry::toArray(), or a plain array)
     */
    public static function fromArray(array $p): self
    {
        $int = static function (mixed $v, int $default, int $min, int $max): int {
            if (!is_numeric($v)) {
                return $default;
            }

            return max($min, min($max, (int) $v));
        };
        $bool = static fn (mixed $v, bool $default): bool => $v === null || $v === '' ? $default : filter_var($v, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? $default;

        $lockMinutes = $int($p['login_lock_minutes'] ?? null, 15, 1, 1440);
        $lockHours   = max($int($p['login_lock_max_hours'] ?? null, 24, 1, 168), (int) ceil($lockMinutes / 60));

        $mfa = \is_string($p['mfa_enforce'] ?? null) ? strtolower(trim($p['mfa_enforce'])) : self::MFA_OFF;

        if (!\in_array($mfa, [self::MFA_OFF, self::MFA_WARN, self::MFA_ENFORCE], true)) {
            $mfa = self::MFA_OFF;
        }

        $groups = $p['mfa_groups'] ?? [8];
        $groups = \is_array($groups) ? $groups : preg_split('/[\s,]+/', (string) $groups, -1, PREG_SPLIT_NO_EMPTY);
        $groups = array_values(array_unique(array_filter(array_map(static fn ($g): int => is_numeric($g) ? (int) $g : 0, $groups ?: []), static fn (int $g): bool => $g > 0)));

        return new self(
            $bool($p['login_lockout'] ?? null, true),
            $int($p['login_max_failures'] ?? null, 5, 1, 100),
            $int($p['login_failure_window'] ?? null, 600, 60, 86400),
            $lockMinutes,
            $lockHours,
            $int($p['login_rate_per_minute'] ?? null, 10, 0, 600),
            $bool($p['alert_new_admin'] ?? null, true),
            $bool($p['alert_new_ip'] ?? null, true),
            $bool($p['alert_lockouts'] ?? null, true),
            $mfa,
            $groups === [] ? [8] : $groups,
            $int($p['mfa_grace_days'] ?? null, 7, 0, 90)
        );
    }
}
