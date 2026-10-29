<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\SiteManager;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\StateStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The most recent "health" payload (P6), already built by the admin component from the Dashboard
 * score whenever it is computed (Dashboard view, or a Settings save). The scheduled task only
 * reads whatever is here - it never computes the score itself, so it has no dependency on the
 * admin component's classes.
 *
 * `dueToday()` is the "at least once a day" rule from the spec: health is only sent once per
 * calendar day of task runs unless {@see put()} was called since the last send (a settings
 * change marks it due again immediately, picked up on the next task tick).
 */
final class HealthCache
{
    private const KEY  = 'health';
    private const KEEP = 90 * 86400;

    public function __construct(private readonly StateStore $store)
    {
    }

    /**
     * @param  array{score:?int,items:array<int,array<string,mixed>>}  $payload
     */
    public function put(array $payload, int $now): void
    {
        $this->store->mutate(self::KEY, $now, static fn (?array $e): array => [
            'payload' => $payload,
            'sentAt'  => 0,
            'exp'     => $now + self::KEEP,
        ]);
    }

    /**
     * @return array{score:?int,items:array<int,array<string,mixed>>}|null
     */
    public function peek(int $now): ?array
    {
        $e = $this->store->get(self::KEY, $now);

        return \is_array($e['payload'] ?? null) ? $e['payload'] : null;
    }

    public function dueToday(int $now): bool
    {
        $e = $this->store->get(self::KEY, $now);

        if ($e === null) {
            return false;
        }

        return (int) ($e['sentAt'] ?? 0) < $now - 86400;
    }

    public function markSent(int $now): void
    {
        $this->store->mutate(self::KEY, $now, static function (?array $e) use ($now): ?array {
            if ($e === null) {
                return null;
            }

            $e['sentAt'] = $now;
            $e['exp']    = $now + self::KEEP;

            return $e;
        });
    }
}
