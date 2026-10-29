<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Filter, order and page parsed log entries for the Activity screen.
 */
final class LogFilter
{
    public const PER_PAGE_MAX = 200;

    public const TYPES = ['BLOCK', 'DETECT', 'LOCK', 'OBSERVE', 'ALERT', 'NOTE'];

    /**
     * Turns raw request values into safe criteria; anything unknown is dropped, never trusted.
     *
     * @param  array<string,mixed>  $raw
     *
     * @return array{types:string[],client:string,rule:string,text:string,days:int}
     */
    public static function criteria(array $raw): array
    {
        $types = [];

        foreach ((array) ($raw['types'] ?? []) as $t) {
            if (\is_string($t) && \in_array($t, self::TYPES, true)) {
                $types[$t] = $t;
            }
        }

        $client = \is_string($raw['client'] ?? null) && \in_array($raw['client'], ['site', 'administrator', 'api'], true) ? $raw['client'] : '';
        $rule   = \is_string($raw['rule'] ?? null) && preg_match('/^[A-Za-z0-9_:.\-]{1,60}$/', $raw['rule']) ? $raw['rule'] : '';
        $text   = \is_string($raw['text'] ?? null) ? mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/', ' ', $raw['text']) ?? ''), 0, 100) : '';
        $days   = \is_numeric($raw['days'] ?? null) ? (int) $raw['days'] : 7;

        return ['types' => array_values($types), 'client' => $client, 'rule' => $rule, 'text' => $text, 'days' => max(1, min(90, $days))];
    }

    /**
     * Newest first.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     * @param  array{types:string[],client:string,rule:string,text:string,days:int}  $c
     *
     * @return array<int,array{time:int,type:string,f:array<string,string>}>
     */
    public static function apply(array $entries, array $c, int $now): array
    {
        $from = $now - $c['days'] * 86400;
        $out  = [];

        foreach ($entries as $e) {
            if ($e['time'] < $from || $e['time'] > $now) {
                continue;
            }

            if ($c['types'] !== [] && !\in_array($e['type'], $c['types'], true)) {
                continue;
            }

            if ($c['client'] !== '' && ($e['f']['client'] ?? '') !== $c['client']) {
                continue;
            }

            if ($c['rule'] !== '' && self::ruleOf($e) !== $c['rule']) {
                continue;
            }

            if ($c['text'] !== '' && !self::contains($e, $c['text'])) {
                continue;
            }

            $out[] = $e;
        }

        usort($out, static fn (array $a, array $b): int => $b['time'] <=> $a['time']);

        return $out;
    }

    /**
     * @param  array<int,mixed>  $rows
     *
     * @return array{rows:array<int,mixed>,total:int,page:int,pages:int}
     */
    public static function page(array $rows, int $page, int $per): array
    {
        $per   = max(1, min(self::PER_PAGE_MAX, $per));
        $total = \count($rows);
        $pages = max(1, (int) ceil($total / $per));
        $page  = max(1, min($pages, $page));

        return ['rows' => \array_slice($rows, ($page - 1) * $per, $per), 'total' => $total, 'page' => $page, 'pages' => $pages];
    }

    /**
     * @param  array{time:int,type:string,f:array<string,string>}  $e
     */
    public static function ruleOf(array $e): string
    {
        return $e['f']['rule'] ?? (isset($e['f']['kind']) ? 'kind:' . $e['f']['kind'] : '');
    }

    /**
     * Plain, case-insensitive substring over the fields a person would search; no pattern syntax.
     *
     * @param  array{time:int,type:string,f:array<string,string>}  $e
     */
    private static function contains(array $e, string $needle): bool
    {
        foreach (['uri', 'sample', 'rule', 'kind', 'reason', 'ip', 'file'] as $k) {
            if (isset($e['f'][$k]) && mb_stripos($e['f'][$k], $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
