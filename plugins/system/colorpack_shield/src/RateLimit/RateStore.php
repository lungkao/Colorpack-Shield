<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\RateLimit;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Minimal counter store behind the rate limiter. Kept tiny (three operations)
 * so it can be backed by APCu, Redis, or a DB table interchangeably, and so the
 * limiter itself stays pure and unit-testable against an in-memory fake.
 */
interface RateStore
{
    /**
     * Atomically increment $key by one, creating it with $ttl seconds to live
     * on first touch, and return the new value.
     */
    public function increment(string $key, int $ttl): int;

    /**
     * Remaining seconds before $key expires, or 0 if it is absent/expired.
     * Used both for the ban countdown and the soft-limit Retry-After.
     */
    public function ttl(string $key): int;

    /**
     * Mark $key present for exactly $ttl seconds (used to arm a temp ban).
     */
    public function put(string $key, int $ttl): void;
}
