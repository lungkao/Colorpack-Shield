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
 * How many new lock-outs have happened in the last 10 minutes - the only fact `login_burst`
 * (P4) needs. No identifiers are kept, only timestamps.
 */
final class BurstWindow
{
    private const KEY    = 'burst';
    private const WINDOW = 600;
    private const KEEP   = 1000;

    public function __construct(private readonly StateStore $store)
    {
    }

    /** Records one new lock-out; returns the lock-out count in the trailing 10-minute window (including this one). */
    public function recordLock(int $now): int
    {
        $count = 0;

        $this->store->mutate(self::KEY, $now, static function (?array $e) use ($now, &$count): array {
            $ts = array_values(array_filter(
                \is_array($e['ts'] ?? null) ? $e['ts'] : [],
                static fn ($t): bool => (int) $t > $now - self::WINDOW
            ));
            $ts[]  = $now;
            $ts    = \array_slice($ts, -self::KEEP);
            $count = \count($ts);

            return ['ts' => $ts, 'exp' => $now + self::WINDOW + 60];
        });

        return $this->store->healthy() ? $count : 0;
    }
}
