<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\DashboardPlanner;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScoreCalculator;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Component\ColorpackShield\Administrator\Service\SiteManagerSync;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Read-only: everything the Dashboard shows. Nothing here writes.
 */
class DashboardModel extends BaseDatabaseModel
{
    /**
     * @return array<string,mixed>
     */
    public function getSummary(): array
    {
        $plugin = new ShieldPlugin($this->getDatabase());
        $now    = time();
        $out    = [
            'installed' => $plugin->installed(),
            'enabled'   => $plugin->enabled(),
            'version'   => $plugin->version(),
            'php_ok'    => version_compare(PHP_VERSION, '8.1.0', '>='),
            'score'     => null,
            'log'       => ['readable' => false, 'truncated' => false, 'size' => 0],
            'day'       => null,
            'week'      => null,
            'plan'      => null,
            'daily'     => [],
            'change'    => null,
            'admin'     => null,
            'scan'      => null,
        ];

        if (!$out['installed']) {
            return $out;
        }

        $out['score'] = ScoreCalculator::calculate($plugin->facts($plugin->params()));
        $out['plan']  = DashboardPlanner::plan($out['score'], 4);
        SiteManagerSync::refresh($plugin, $out['score'], $out['version']);
        $out['scan']  = $this->lastScan();
        $log          = (new LogReader($plugin->logFile()))->read();
        $out['log']   = ['readable' => $log['readable'], 'truncated' => $log['truncated'], 'size' => $log['size']];

        if ($log['readable']) {
            $out['day']  = LogStats::window($log['entries'], $now, 86400);
            $out['week'] = LogStats::window($log['entries'], $now, 86400 * 7);
            $out['daily']  = LogStats::daily($log['entries'], $now, 7);
            $out['change'] = LogStats::change($out['week']['blocked'], LogStats::window($log['entries'], $now - 86400 * 7, 86400 * 7)['blocked']);
            $out['admin']  = LogStats::adminEvents($log['entries'], $now, 86400 * 7);
        }

        return $out;
    }

    /**
     * What the last file scan found, for the report card; null when there has never been one.
     *
     * @return array{finished:int,high:int,medium:int,changed:int}|null
     */
    private function lastScan(): ?array
    {
        $r = (new \Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore(JPATH_ROOT . '/cache/colorpack_shield/scan'))->read('result');

        if (!\is_array($r) || !isset($r['finished'], $r['count']['high'])) {
            return null;
        }

        return [
            'finished' => (int) $r['finished'],
            'high'     => (int) $r['count']['high'],
            'medium'   => (int) ($r['count']['medium'] ?? 0),
            'changed'  => \count((array) ($r['changes']['new'] ?? [])) + \count((array) ($r['changes']['changed'] ?? [])),
        ];
    }
}
