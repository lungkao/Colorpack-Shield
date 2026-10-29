<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * In-memory {@see StateStore}: used by tests and as a stand-in when no writable
 * folder exists. {@see $failing} simulates a broken store.
 */
final class MemoryStateStore implements StateStore
{
    /** @var array<string,array<string,mixed>> */
    private array $data = [];

    public bool $failing = false;

    private bool $ok = true;

    public function get(string $key, int $now): ?array
    {
        $this->ok = !$this->failing;

        if ($this->failing) {
            return null;
        }

        $e = $this->data[$key] ?? null;

        return $e !== null && (int) ($e['exp'] ?? 0) > $now ? $e : null;
    }

    public function mutate(string $key, int $now, callable $fn): ?array
    {
        $this->ok = !$this->failing;

        if ($this->failing) {
            return null;
        }

        $cur = $this->get($key, $now);
        $new = $fn($cur);

        if ($new === null) {
            unset($this->data[$key]);

            return null;
        }

        $new['exp']        = (int) ($new['exp'] ?? $now + 3600);
        $this->data[$key]  = $new;

        return $new;
    }

    public function purge(string $prefix, int $now): int
    {
        $this->ok = !$this->failing;

        if ($this->failing) {
            return 0;
        }

        $n = 0;

        foreach (array_keys($this->data) as $k) {
            if (str_starts_with((string) $k, $prefix)) {
                unset($this->data[$k]);
                $n++;
            }
        }

        return $n;
    }

    public function healthy(): bool
    {
        return $this->ok;
    }

    public function count(): int
    {
        return \count($this->data);
    }

    /** @return string[] */
    public function keys(): array
    {
        return array_map('strval', array_keys($this->data));
    }
}
