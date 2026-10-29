<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What to do about an administrator who has no multi-factor authentication
 * (PLAN-ADMIN-PROTECTION.md A3), free of Joomla.
 *
 * Joomla can already force MFA for whole user groups, but only at once and
 * without a warning period. This policy adds the grace period: "warn" only
 * reminds; "enforce" reminds until the grace has run out, then sends the user
 * to the setup page — except on the pages that must stay reachable (the MFA
 * pages themselves, logout), which the caller marks as `$exempt` using Joomla's
 * own list so that no redirect loop can arise.
 */
final class MfaPolicy
{
    public const NONE     = 'none';
    public const WARN     = 'warn';
    public const REDIRECT = 'redirect';
    public const DENY     = 'deny';

    /**
     * @param  string  $mode       AdminProtectConfig::MFA_OFF | MFA_WARN | MFA_ENFORCE
     * @param  bool    $applies    the user is in a group that needs MFA, is not exempted by Joomla, and an MFA method exists
     * @param  bool    $hasMfa     the user has a usable MFA method
     * @param  int     $firstSeen  when the user was first seen without MFA (unix time)
     * @param  bool    $exempt     this request is an MFA page, a logout or another page that must stay reachable
     * @param  bool    $isHtml     an ordinary page (false: ajax / json / raw output)
     *
     * @return array{action:string,daysLeft:int,overdue:bool}
     */
    public static function decide(string $mode, bool $applies, bool $hasMfa, int $firstSeen, int $now, int $graceDays, bool $exempt, bool $isHtml): array
    {
        $none = ['action' => self::NONE, 'daysLeft' => 0, 'overdue' => false];

        if ($mode !== AdminProtectConfig::MFA_WARN && $mode !== AdminProtectConfig::MFA_ENFORCE) {
            return $none;
        }

        if (!$applies || $hasMfa) {
            return $none;
        }

        $deadline = $firstSeen + $graceDays * 86400;
        $overdue  = $now >= $deadline;
        $daysLeft = $overdue ? 0 : (int) ceil(($deadline - $now) / 86400);

        if ($mode === AdminProtectConfig::MFA_WARN || !$overdue) {
            return ['action' => $exempt ? self::NONE : self::WARN, 'daysLeft' => $daysLeft, 'overdue' => $overdue];
        }

        if ($exempt) {
            return ['action' => self::NONE, 'daysLeft' => 0, 'overdue' => true];
        }

        return ['action' => $isHtml ? self::REDIRECT : self::DENY, 'daysLeft' => 0, 'overdue' => true];
    }
}
