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
 * Events waiting to be sent to the Site Manager, on one {@see StateStore} entry. `drain()` only
 * peeks (never removes) so a send that fails leaves every event intact for the next attempt;
 * `ack()` removes only the ids a confirmed send actually delivered. The Site Manager also
 * dedupes by id, so resending an already-delivered event after a lost reply is harmless.
 */
final class EventQueue
{
    private const MAX_QUEUE = 500;
    private const KEEP      = 30 * 86400;

    /** @param  string  $key  'events' for the event queue; 'threats' keeps banned-attacker reports on their own entry */
    public function __construct(private readonly StateStore $store, private readonly string $key = 'events')
    {
    }

    /**
     * @param  array<string,mixed>  $event  must carry a string `id`; an item whose id is already queued is not added twice
     */
    public function enqueue(array $event, int $now): void
    {
        $this->store->mutate($this->key, $now, function (?array $e) use ($event, $now): array {
            $items   = \is_array($e['items'] ?? null) ? $e['items'] : [];
            foreach ($items as $it) {
                if (($it['id'] ?? null) === ($event['id'] ?? false)) {
                    return ['items' => $items, 'exp' => $now + self::KEEP];
                }
            }

            $items[] = $event;

            if (\count($items) > self::MAX_QUEUE) {
                $items = \array_slice($items, -self::MAX_QUEUE);
            }

            return ['items' => $items, 'exp' => $now + self::KEEP];
        });
    }

    /**
     * Up to $max oldest queued events, oldest first. Does not remove them - call {@see ack()}
     * once a send is confirmed.
     *
     * @return array<int,array<string,mixed>>
     */
    public function drain(int $max, int $now): array
    {
        $e = $this->store->get($this->key, $now);
        $items = \is_array($e['items'] ?? null) ? $e['items'] : [];

        return \array_slice($items, 0, max(0, $max));
    }

    /**
     * @param  string[]  $ids
     */
    public function ack(array $ids, int $now): void
    {
        if ($ids === []) {
            return;
        }

        $idSet = array_fill_keys($ids, true);

        $this->store->mutate($this->key, $now, function (?array $e) use ($idSet, $now): ?array {
            $items = array_values(array_filter(
                \is_array($e['items'] ?? null) ? $e['items'] : [],
                static fn (array $it): bool => !isset($idSet[(string) ($it['id'] ?? '')])
            ));

            return $items === [] ? null : ['items' => $items, 'exp' => $now + self::KEEP];
        });
    }
}
