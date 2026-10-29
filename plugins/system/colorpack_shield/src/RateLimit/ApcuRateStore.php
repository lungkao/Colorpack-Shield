<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\RateLimit;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * APCu-backed {@see RateStore}. In-process shared memory: atomic apcu_inc(),
 * automatic TTL expiry, no schema, no network — the right default on the shared
 * hosting the fleet targets when the extension is present. If APCu is absent the
 * caller ({@see \Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield}) skips
 * rate limiting entirely (fail-open) rather than instantiating this.
 *
 * Counters use apcu_inc()'s native TTL. The ban key is stored as an absolute
 * expiry epoch so ttl() can report an accurate countdown without relying on
 * apcu_key_info(), whose availability varies by build.
 */
final class ApcuRateStore implements RateStore
{
    public static function isAvailable(): bool
    {
        return \function_exists('apcu_enabled') && apcu_enabled();
    }

    public function increment(string $key, int $ttl): int
    {
        $ok  = false;
        $new = apcu_inc($key, 1, $ok, $ttl);

        // On a cold key some APCu builds return false; seed it explicitly.
        if ($new === false || !$ok) {
            apcu_store($key, 1, $ttl);

            return 1;
        }

        return (int) $new;
    }

    public function ttl(string $key): int
    {
        $expiry = apcu_fetch($key, $found);

        if (!$found || !\is_int($expiry)) {
            return 0;
        }

        $remaining = $expiry - time();

        return $remaining > 0 ? $remaining : 0;
    }

    public function put(string $key, int $ttl): void
    {
        // Value IS the expiry epoch; APCu TTL evicts the row on its own.
        apcu_store($key, time() + $ttl, $ttl);
    }
}
