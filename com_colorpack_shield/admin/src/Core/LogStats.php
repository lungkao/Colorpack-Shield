<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Counts for the Dashboard: exact numbers over a time window from parsed log entries.
 */
final class LogStats
{
    public const TOP = 5;

    /**
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array{blocked:int,detected:int,locks:int,byClient:array<string,array{blocked:int,detected:int}>,topRules:array<string,int>,topPaths:array<string,int>}
     */
    public static function window(array $entries, int $now, int $seconds): array
    {
        $from = $now - $seconds;
        $out  = ['blocked' => 0, 'detected' => 0, 'locks' => 0, 'byClient' => [], 'topRules' => [], 'topPaths' => []];

        foreach ($entries as $e) {
            if ($e['time'] < $from || $e['time'] > $now) {
                continue;
            }

            $type = $e['type'];
            $f    = $e['f'];

            if ($type === 'LOCK') {
                $out['locks']++;

                continue;
            }

            if ($type !== 'BLOCK' && $type !== 'DETECT') {
                continue;
            }

            $client = self::client($f['client'] ?? '');
            $out['byClient'][$client] ??= ['blocked' => 0, 'detected' => 0];

            if ($type === 'BLOCK') {
                $out['blocked']++;
                $out['byClient'][$client]['blocked']++;
            } else {
                $out['detected']++;
                $out['byClient'][$client]['detected']++;
            }

            $rule = $f['rule'] ?? (isset($f['kind']) ? 'kind:' . $f['kind'] : 'other');
            $out['topRules'][$rule] = ($out['topRules'][$rule] ?? 0) + 1;

            if (isset($f['uri']) && $f['uri'] !== '-') {
                $shape = self::pathShape($f['uri']);
                $out['topPaths'][$shape] = ($out['topPaths'][$shape] ?? 0) + 1;
            }
        }

        $out['topRules'] = self::top($out['topRules']);
        $out['topPaths'] = self::top($out['topPaths']);
        ksort($out['byClient']);

        return $out;
    }

    /**
     * Every rule with its count (BLOCK and DETECT lines) in the window; for the Rules screen.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array<string,int>
     */
    public static function ruleCounts(array $entries, int $now, int $seconds): array
    {
        $out = [];

        foreach ($entries as $e) {
            if ($e['time'] < $now - $seconds || $e['time'] > $now || ($e['type'] !== 'BLOCK' && $e['type'] !== 'DETECT') || !isset($e['f']['rule'])) {
                continue;
            }

            $out[$e['f']['rule']] = ($out[$e['f']['rule']] ?? 0) + 1;
        }

        return $out;
    }

    /**
     * The path without query string, numbers and long tokens replaced by "*", so the list
     * shows a shape of what was asked for, not an id or a token.
     */
    public static function pathShape(string $uri): string
    {
        $q = strpos($uri, '?');
        $p = $q === false ? $uri : substr($uri, 0, $q);
        $p = preg_replace('~(?<=/)[0-9]{3,}(?=/|$)~', '*', $p) ?? $p;
        $p = preg_replace('~(?<=/)[A-Za-z0-9_-]{24,}(?=/|$)~', '*', $p) ?? $p;

        return mb_substr($p, 0, 120);
    }

    private static function client(string $c): string
    {
        return \in_array($c, ['site', 'administrator', 'api'], true) ? $c : 'other';
    }

    /**
     * @param  array<string,int>  $counts
     *
     * @return array<string,int>
     */
    private static function top(array $counts): array
    {
        // Count descending, then name, so equal counts come out in a stable order.
        uksort($counts, static fn (string $a, string $b): int => [$counts[$b], $a] <=> [$counts[$a], $b]);

        return \array_slice($counts, 0, self::TOP, true);
    }

    /**
     * Blocked and logged-only per day, oldest first, for a bar chart. Days are UTC calendar days
     * ending at the day of $now; a day with nothing is a zero, never missing.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array<int,array{date:string,blocked:int,detected:int,locks:int}>
     */
    public static function daily(array $entries, int $now, int $days): array
    {
        $days  = max(1, min(90, $days));
        $today = intdiv($now, 86400);
        $out   = [];

        for ($i = $days - 1; $i >= 0; $i--) {
            $out[$today - $i] = ['date' => gmdate('Y-m-d', ($today - $i) * 86400), 'blocked' => 0, 'detected' => 0, 'locks' => 0];
        }

        foreach ($entries as $e) {
            $d = intdiv($e['time'], 86400);

            if ($e['time'] > $now || !isset($out[$d])) {
                continue;
            }

            match ($e['type']) {
                'BLOCK'  => $out[$d]['blocked']++,
                'DETECT' => $out[$d]['detected']++,
                'LOCK'   => $out[$d]['locks']++,
                default  => null,
            };
        }

        return array_values($out);
    }

    /**
     * How many different addresses were blocked in the window (a measure of "how many attackers",
     * not "how many requests").
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     */
    public static function uniqueBlockedIps(array $entries, int $now, int $seconds): int
    {
        $seen = [];

        foreach ($entries as $e) {
            if ($e['type'] === 'BLOCK' && $e['time'] >= $now - $seconds && $e['time'] <= $now && isset($e['f']['ip']) && $e['f']['ip'] !== '') {
                $seen[$e['f']['ip']] = 1;
            }
        }

        return \count($seen);
    }

    /**
     * Change against the period before, in whole percent; null when there is nothing to compare with.
     */
    public static function change(int $now, int $before): ?int
    {
        return $before > 0 ? (int) round(($now - $before) / $before * 100) : null;
    }

    /**
     * Counts of the administrator-side events in the window.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array{blockedAdmin:int,locks:int,newIp:int,newAdmin:int,observed:int}
     */
    public static function adminEvents(array $entries, int $now, int $seconds): array
    {
        $o = ['blockedAdmin' => 0, 'locks' => 0, 'newIp' => 0, 'newAdmin' => 0, 'observed' => 0];

        foreach ($entries as $e) {
            if ($e['time'] < $now - $seconds || $e['time'] > $now) {
                continue;
            }

            $f = $e['f'];

            if ($e['type'] === 'BLOCK' && ($f['client'] ?? '') === 'administrator') {
                $o['blockedAdmin']++;
            } elseif ($e['type'] === 'LOCK') {
                $o['locks']++;
            } elseif ($e['type'] === 'OBSERVE' && ($f['client'] ?? '') === 'administrator') {
                $o['observed']++;
            } elseif ($e['type'] === 'ALERT') {
                if (($f['kind'] ?? '') === 'newip') {
                    $o['newIp']++;
                } elseif (($f['kind'] ?? '') === 'newadmin') {
                    $o['newAdmin']++;
                }
            }
        }

        return $o;
    }
}
