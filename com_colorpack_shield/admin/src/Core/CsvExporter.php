<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * CSV of log entries. Spreadsheet formulas are neutralised (a cell that starts with = + - @ or a
 * control character gets a leading apostrophe), and in masked mode addresses are shortened and
 * query strings and samples are left out.
 */
final class CsvExporter
{
    public const MAX_ROWS = 5000;

    public const HEADER = ['time_utc', 'type', 'area', 'rule', 'reason', 'ip', 'uri', 'sample'];

    /**
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     */
    public static function build(array $entries, bool $mask): string
    {
        $out = self::row(self::HEADER);

        foreach (\array_slice($entries, 0, self::MAX_ROWS) as $e) {
            $f   = $e['f'];
            $uri = $f['uri'] ?? '';

            if ($mask && ($q = strpos($uri, '?')) !== false) {
                $uri = substr($uri, 0, $q);
            }

            $out .= self::row([
                gmdate('Y-m-d\TH:i:s\Z', $e['time']),
                $e['type'],
                $f['client'] ?? '',
                LogFilter::ruleOf($e),
                $f['reason'] ?? '',
                $mask ? IpMasker::mask($f['ip'] ?? '') : ($f['ip'] ?? ''),
                $uri,
                $mask ? '' : ($f['sample'] ?? ''),
            ]);
        }

        return $out;
    }

    /**
     * @param  string[]  $cells
     */
    private static function row(array $cells): string
    {
        return implode(',', array_map([self::class, 'cell'], $cells)) . "\r\n";
    }

    public static function cell(string $v): string
    {
        $v = str_replace(["\r", "\n"], ' ', $v);

        if ($v !== '' && strpbrk($v[0], "=+-@\t") !== false) {
            $v = "'" . $v;
        }

        return '"' . str_replace('"', '""', $v) . '"';
    }
}
