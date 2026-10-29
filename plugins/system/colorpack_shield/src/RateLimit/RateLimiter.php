<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\RateLimit;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * P1.3: a real per-IP (+route) rate limiter — the fleet baseline only counts
 * failed logins, not request volume. Fixed-window counter: cheap, bounded
 * storage, and crucially NO blocking sleep() in the request path (that would
 * pin a PHP-FPM worker).
 *
 * Escalation:
 *   - within a window, once the request count passes $limit the request gets a
 *     soft block (HTTP 429 + Retry-After to the window boundary);
 *   - each soft block is also a "violation"; once $banThreshold violations
 *     accrue inside $banWindow the IP is temp-banned for $banDuration and every
 *     request is blocked until the ban expires.
 *
 * Pure and Joomla-free: time is injected and all state lives behind
 * {@see RateStore}, so the whole escalation is unit-testable against an
 * in-memory fake with a controllable clock.
 */
final class RateLimiter
{
    public function __construct(
        private readonly RateStore $store,
        private readonly int $window,
        private readonly int $limit,
        private readonly int $banThreshold = 0,
        private readonly int $banWindow = 300,
        private readonly int $banDuration = 3600
    ) {
    }

    /**
     * @param  int     $now    current unix time (injected for testability)
     * @param  string  $ip     client IP
     * @param  string  $route  bucket discriminator (e.g. the app + component)
     */
    public function decide(int $now, string $ip, string $route): RateVerdict
    {
        if ($this->window <= 0 || $this->limit <= 0) {
            return RateVerdict::allow();
        }

        $banKey    = 'fgrl:ban:' . $ip;
        $banRemain = $this->store->ttl($banKey);

        if ($banRemain > 0) {
            return RateVerdict::block('rate_banned', $banRemain);
        }

        $bucket = intdiv($now, $this->window);
        $winKey = 'fgrl:w:' . $ip . ':' . $route . ':' . $bucket;
        $count  = $this->store->increment($winKey, $this->window);

        if ($count <= $this->limit) {
            return RateVerdict::allow();
        }

        // Seconds left in the current window → Retry-After for the soft block.
        $retryAfter = $this->window - ($now % $this->window);

        // Repeat offenders escalate to a temp ban.
        if ($this->banThreshold > 0) {
            $violations = $this->store->increment('fgrl:v:' . $ip, $this->banWindow);

            if ($violations >= $this->banThreshold) {
                $this->store->put($banKey, $this->banDuration);

                return RateVerdict::block('rate_banned', $this->banDuration);
            }
        }

        return RateVerdict::block('rate_limited', $retryAfter);
    }
}
