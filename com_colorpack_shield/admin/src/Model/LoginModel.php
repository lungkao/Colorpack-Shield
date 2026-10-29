<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Read-only: the back-end door, the sign-in events from the log and two-step coverage. Failed
 * sign-ins are not logged one by one (Joomla does not tell us), so the report shows what the
 * firewall itself saw: blocked requests to the administrator, lock-outs and alerts.
 */
class LoginModel extends BaseDatabaseModel
{
    private const EVENT_TYPES = ['LOCK', 'ALERT', 'OBSERVE', 'BLOCK'];

    /**
     * @return array<string,mixed>
     */
    public function getReport(): array
    {
        $plugin = new ShieldPlugin($this->getDatabase());
        $out    = ['installed' => $plugin->installed(), 'door' => false, 'list' => false, 'mfaMode' => 'off', 'mfa' => null, 'daily' => [], 'events' => [], 'counts' => null, 'readable' => false, 'previous' => null];

        if (!$out['installed']) {
            return $out;
        }

        $p              = $plugin->params();
        $gate           = AccessGateConfig::fromArray($p);
        $out['door']    = !$gate->off();
        $out['list']    = filter_var($p['admin_ip_enforce'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $out['mfaMode'] = \in_array(($p['mfa_enforce'] ?? 'off'), ['off', 'remind', 'enforce'], true) ? (string) $p['mfa_enforce'] : 'off';
        $out['mfa']     = $this->mfa();

        $log             = (new LogReader($plugin->logFile()))->read();
        $out['readable'] = $log['readable'];

        if ($log['readable']) {
            $now = time();
            $adm = array_values(array_filter($log['entries'], static fn (array $e): bool => ($e['type'] === 'BLOCK' && ($e['f']['client'] ?? '') === 'administrator') || $e['type'] === 'LOCK'));

            $out['counts']   = LogStats::adminEvents($log['entries'], $now, 86400 * 7);
            $out['previous'] = LogStats::adminEvents($log['entries'], $now - 86400 * 7, 86400 * 7);
            $out['daily']    = LogStats::daily($adm, $now, 14);

            $events = array_filter($log['entries'], static function (array $e): bool {
                $f = $e['f'];

                return match ($e['type']) {
                    'LOCK'    => true,
                    'ALERT'   => \in_array($f['kind'] ?? '', ['newip', 'newadmin', 'lockout', 'mfa'], true),
                    'OBSERVE', 'BLOCK' => ($f['client'] ?? '') === 'administrator',
                    default   => false,
                };
            });
            usort($events, static fn (array $a, array $b): int => $b['time'] <=> $a['time']);
            $out['events'] = \array_slice($events, 0, 10);
        }

        return $out;
    }

    /**
     * Super Users with and without a second step. Null when Joomla's tables cannot be read (older
     * versions, other table names): the screen then says so instead of guessing.
     *
     * @return array{total:int,with:int,missing:array<int,string>}|null
     */
    private function mfa(): ?array
    {
        try {
            $db    = $this->getDatabase();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['u.id', 'u.username']))
                ->from($db->quoteName('#__users', 'u'))
                ->join('INNER', $db->quoteName('#__user_usergroup_map', 'm') . ' ON ' . $db->quoteName('m.user_id') . ' = ' . $db->quoteName('u.id'))
                ->where($db->quoteName('m.group_id') . ' = 8')
                ->where($db->quoteName('u.block') . ' = 0')
                ->group($db->quoteName(['u.id', 'u.username']));
            $users = $db->setQuery($query)->loadObjectList();

            $query = $db->getQuery(true)->select('DISTINCT ' . $db->quoteName('user_id'))->from($db->quoteName('#__user_mfa'));
            $with  = array_map('intval', $db->setQuery($query)->loadColumn());
        } catch (\Throwable) {
            return null;
        }

        $missing = [];
        $have    = 0;

        foreach ($users as $u) {
            if (\in_array((int) $u->id, $with, true)) {
                $have++;
            } else {
                $missing[] = (string) $u->username;
            }
        }

        return ['total' => \count($users), 'with' => $have, 'missing' => \array_slice($missing, 0, 10)];
    }
}
