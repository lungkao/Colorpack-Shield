<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\LogFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Read-only: the log, filtered. The file is always the plugin's own log; nothing in the request
 * names a file.
 */
class ActivityModel extends BaseDatabaseModel
{
    public const PER_PAGE = 50;

    /**
     * @param  array<string,mixed>  $request  GET values
     *
     * @return array{criteria:array<string,mixed>,readable:bool,truncated:bool,list:array{rows:array<int,mixed>,total:int,page:int,pages:int},all:array<int,mixed>}
     */
    public function getActivity(array $request): array
    {
        $plugin   = new ShieldPlugin($this->getDatabase());
        $criteria = LogFilter::criteria($request);
        $log      = (new LogReader($plugin->logFile()))->read();
        $rows     = LogFilter::apply($log['entries'], $criteria, time());

        return [
            'criteria'  => $criteria,
            'readable'  => $log['readable'],
            'truncated' => $log['truncated'],
            'list'      => LogFilter::page($rows, (int) ($request['page'] ?? 1), self::PER_PAGE),
            'all'       => $rows,
            'report'    => $log['readable'] ? $this->report($log['entries'], time()) : null,
        ];
    }

    /**
     * The numbers above the filter: the last 7 days against the 7 before, and 14 days of bars. Always
     * the whole log, whatever the filter below is set to.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array<string,mixed>
     */
    private function report(array $entries, int $now): array
    {
        $week = LogStats::window($entries, $now, 86400 * 7);
        $prev = LogStats::window($entries, $now - 86400 * 7, 86400 * 7);

        return [
            'week'    => $week,
            'blocked' => LogStats::change($week['blocked'], $prev['blocked']),
            'logged'  => LogStats::change($week['detected'], $prev['detected']),
            'unique'  => LogStats::uniqueBlockedIps($entries, $now, 86400 * 7),
            'daily'   => LogStats::daily($entries, $now, 14),
        ];
    }
}
