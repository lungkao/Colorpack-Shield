<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * A strict speed limit for the administrator login form: at most N login
 * attempts per minute per address, counted before Joomla spends time (and a
 * password hash) on them. Fixed one-minute windows in the {@see StateStore};
 * 0 switches it off. A store that cannot be used means "no limit" (fail open).
 */
final class LoginRateLimit
{
    /**
     * Count one attempt.
     *
     * @return array{over:bool,retryAfter:int}  over = this attempt exceeds the limit; retryAfter = seconds to the next window
     */
    public static function hit(StateStore $store, string $ip, int $limitPerMinute, int $now): array
    {
        $b = LockoutPolicy::bucket($ip);

        if ($limitPerMinute <= 0 || $b === null) {
            return ['over' => false, 'retryAfter' => 0];
        }

        $window = intdiv($now, 60);

        $e = $store->mutate('rate:' . $b, $now, static function (?array $e) use ($window, $now): array {
            $n = ($e !== null && (int) ($e['w'] ?? -1) === $window) ? (int) $e['n'] + 1 : 1;

            return ['w' => $window, 'n' => min($n, 1000000), 'exp' => ($window + 1) * 60 + 60];
        });

        if ($e === null) {
            return ['over' => false, 'retryAfter' => 0];
        }

        return ['over' => (int) $e['n'] > $limitPerMinute, 'retryAfter' => max(1, ($window + 1) * 60 - $now)];
    }
}
