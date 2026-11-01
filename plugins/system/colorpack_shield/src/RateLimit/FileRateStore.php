<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\RateLimit;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * {@see RateStore} for servers without APCu: counters live in a few small flock-guarded JSON files
 * ({@see FileStateStore}), one shard per slice of the key space so two visitors rarely wait on the
 * same file. It is slower than shared memory (one small write per request that is counted), but it
 * works on any host where the cache folder is writable, so the rate limit does something real
 * instead of silently doing nothing.
 *
 * A window counter keeps the expiry it was created with (a fixed window); a ban key holds nothing
 * but its expiry. Nothing here throws: when the folder cannot be written the answers are "no hits yet",
 * so a broken disk can never turn into a block (fail-open, same as the APCu store).
 */
final class FileRateStore implements RateStore
{
    private readonly FileStateStore $state;

    public function __construct(string $dir, private readonly ?int $clock = null)
    {
        // Many shards and a small bound each: this store takes a write on every counted request.
        $this->state = new FileStateStore($dir, 400, 65536, 64);
    }

    public function increment(string $key, int $ttl): int
    {
        $now = $this->now();
        $n   = 0;

        $this->state->mutate($key, $now, static function (?array $e) use ($ttl, $now, &$n): array {
            $n = (int) ($e['n'] ?? 0) + 1;

            return ['n' => $n, 'exp' => $e !== null ? (int) $e['exp'] : $now + max(1, $ttl)];
        });

        return max(1, $n);
    }

    public function ttl(string $key): int
    {
        $now = $this->now();
        $e   = $this->state->get($key, $now);

        return $e === null ? 0 : max(0, (int) $e['exp'] - $now);
    }

    public function put(string $key, int $ttl): void
    {
        $now = $this->now();

        $this->state->mutate($key, $now, static fn (?array $e): array => ['n' => 1, 'exp' => $now + max(1, $ttl)]);
    }

    private function now(): int
    {
        return $this->clock ?? time();
    }
}
