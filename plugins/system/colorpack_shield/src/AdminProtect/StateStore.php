<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * A tiny, bounded key → entry store for the administrator protections
 * (login failures, locks, alert throttles, known IPs).
 *
 * Every entry is an array with an integer 'exp' (unix time after which it is
 * forgotten). Implementations never throw: a store that cannot read or write
 * answers null, and every caller treats that as "unknown → do not block, do not
 * mail" (an admin gate must never turn a storage problem into an outage).
 */
interface StateStore
{
    /**
     * @return array<string,mixed>|null  the live entry, or null when absent, expired or unreadable
     */
    public function get(string $key, int $now): ?array;

    /**
     * Atomically read, change and write one entry.
     *
     * @param  callable(array<string,mixed>|null):(array<string,mixed>|null)  $fn  gets the live entry (or null) and returns the new one; null deletes it
     *
     * @return array<string,mixed>|null  the stored entry; null when it was deleted or the store failed
     */
    public function mutate(string $key, int $now, callable $fn): ?array;

    /**
     * Forget every entry whose key starts with $prefix (the "unlock" tool and housekeeping).
     *
     * @return int  how many entries were removed (0 when nothing matched or the store failed)
     */
    public function purge(string $prefix, int $now): int;

    /** False when the last operation could not be completed. */
    public function healthy(): bool;
}
