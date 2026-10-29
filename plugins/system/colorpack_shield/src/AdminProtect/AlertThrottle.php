<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * "At most one alert per kind per interval", with a count of what was held back
 * so the next mail can say "and 12 more since". Fail-closed: when the store
 * cannot be used no alert is sent, so a broken store can never become a mail flood.
 */
final class AlertThrottle
{
    /**
     * @return array{send:bool,suppressed:int}  suppressed = alerts held back since the last one sent
     */
    public static function claim(StateStore $store, string $kind, int $now, int $minInterval): array
    {
        $send       = false;
        $suppressed = 0;

        $store->mutate('alert:' . $kind, $now, static function (?array $e) use ($now, $minInterval, &$send, &$suppressed): array {
            $e ??= ['last' => 0, 'held' => 0];

            if ($now - (int) $e['last'] >= $minInterval) {
                $send       = true;
                $suppressed = (int) $e['held'];

                return ['last' => $now, 'held' => 0, 'exp' => $now + max(2 * $minInterval, 3600)];
            }

            return ['last' => (int) $e['last'], 'held' => min((int) $e['held'] + 1, 1000000), 'exp' => (int) $e['last'] + max(2 * $minInterval, 3600)];
        });

        if (!$store->healthy()) {
            return ['send' => false, 'suppressed' => 0];
        }

        return ['send' => $send, 'suppressed' => $suppressed];
    }
}
