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
    private const KEY       = 'events';
    private const MAX_QUEUE = 500;
    private const KEEP      = 30 * 86400;

    public function __construct(private readonly StateStore $store)
    {
    }

    /**
     * @param  array{id:string,at:string,type:string,severity:string,count:int,detail:string}  $event
     */
    public function enqueue(array $event, int $now): void
    {
        $this->store->mutate(self::KEY, $now, static function (?array $e) use ($event, $now): array {
            $items   = \is_array($e['items'] ?? null) ? $e['items'] : [];
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
        $e = $this->store->get(self::KEY, $now);
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

        $this->store->mutate(self::KEY, $now, static function (?array $e) use ($idSet, $now): ?array {
            $items = array_values(array_filter(
                \is_array($e['items'] ?? null) ? $e['items'] : [],
                static fn (array $it): bool => !isset($idSet[(string) ($it['id'] ?? '')])
            ));

            return $items === [] ? null : ['items' => $items, 'exp' => $now + self::KEEP];
        });
    }
}
