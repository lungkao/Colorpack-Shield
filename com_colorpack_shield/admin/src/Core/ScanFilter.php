<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Filter the file-scan findings list by severity and a plain path substring, for the File scan
 * screen (the same files can repeat by the hundreds — e.g. a .htaccess dropped in every backup
 * chunk folder — so a person needs to narrow the list down before acting on it).
 */
final class ScanFilter
{
    public const SEVS = ['high', 'medium', 'low'];

    /**
     * @param  array<string,mixed>  $raw
     *
     * @return array{sev:string,text:string}
     */
    public static function criteria(array $raw): array
    {
        $sev  = \is_string($raw['sev'] ?? null) && \in_array($raw['sev'], self::SEVS, true) ? $raw['sev'] : '';
        $text = \is_string($raw['q'] ?? null) ? mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/', ' ', $raw['q']) ?? ''), 0, 100) : '';

        return ['sev' => $sev, 'text' => $text];
    }

    /**
     * @param  array<int,array{path:string,sev:string}>  $findings
     * @param  array{sev:string,text:string}  $c
     *
     * @return array<int,array{path:string,sev:string}>
     */
    public static function apply(array $findings, array $c): array
    {
        return array_values(array_filter($findings, static function (array $f) use ($c): bool {
            if ($c['sev'] !== '' && ($f['sev'] ?? '') !== $c['sev']) {
                return false;
            }

            if ($c['text'] !== '' && mb_stripos((string) ($f['path'] ?? ''), $c['text']) === false) {
                return false;
            }

            return true;
        }));
    }

    /**
     * Per-severity counts over the UNFILTERED list, for the tab badges (so a tab never disappears
     * just because another filter is narrowing the table beneath it).
     *
     * @param  array<int,array{sev:string}>  $findings
     *
     * @return array{high:int,medium:int,low:int}
     */
    public static function counts(array $findings): array
    {
        $out = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($findings as $f) {
            if (isset($out[$f['sev'] ?? ''])) {
                $out[$f['sev']]++;
            }
        }

        return $out;
    }
}
