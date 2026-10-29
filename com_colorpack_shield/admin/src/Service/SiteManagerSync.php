<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Colorpack\Component\ColorpackShield\Administrator\Core\HealthReport;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScoreCalculator;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\HealthCache;

\defined('_JEXEC') || die;

/**
 * Keeps the Site Manager integration's "health" cache (P6) fresh whenever the Dashboard
 * recomputes the score or Settings are saved - the scheduled task then only has to read it, never
 * recompute it, so it has no dependency on this component's classes.
 *
 * Off by default: does nothing at all, not even touching the cache file, unless the system
 * plugin's own "site_manager_enabled" switch is on. Never throws - a storage problem here must
 * never break the Dashboard or a Settings save.
 */
final class SiteManagerSync
{
    /**
     * @param  array{score:?int,items:array<int,array{id:string,weight:int,status:string}>}  $score  {@see ScoreCalculator::calculate()}'s output
     */
    public static function refresh(ShieldPlugin $plugin, array $score, string $shieldVersion): void
    {
        try {
            if (!filter_var($plugin->params()['site_manager_enabled'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
                return;
            }

            $store = new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/sitemanager');
            (new HealthCache($store))->put(HealthReport::build($score, $shieldVersion), time());
        } catch (\Throwable) {
            // Never let the Site Manager integration break the Dashboard or a Settings save.
        }
    }
}
