<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * A guess from SERVER_SOFTWARE, which is only what PHP's own web server says. With nginx in
 * front of Apache it says "Apache", so the screen always offers both texts.
 */
final class ServerDetector
{
    public static function guess(string $software): string
    {
        $s = strtolower($software);

        return match (true) {
            str_contains($s, 'litespeed') => 'litespeed',
            str_contains($s, 'nginx')     => 'nginx',
            str_contains($s, 'apache')    => 'apache',
            default                       => 'unknown',
        };
    }

    /**
     * Allow-list lines typed in a text box: one plain path per line; "#" starts a comment.
     * Entries that cannot be used are returned apart so they can be shown, never rendered.
     *
     * @param  callable(string):string  $validate  throws \InvalidArgumentException for a bad entry
     *
     * @return array{ok:string[],bad:string[]}
     */
    public static function parseAllow(string $text, callable $validate): array
    {
        $ok  = [];
        $bad = [];

        foreach (preg_split('/\R/', mb_substr($text, 0, 4000)) ?: [] as $line) {
            $hash = strpos($line, '#');
            $line = trim($hash === false ? $line : substr($line, 0, $hash));

            if ($line === '' || \count($ok) + \count($bad) >= 200) {
                continue;
            }

            try {
                $ok[$validate($line)] = true;
            } catch (\InvalidArgumentException) {
                $bad[] = mb_substr(preg_replace('/[^\x20-\x7e]/', '?', $line) ?? '', 0, 60);
            }
        }

        return ['ok' => array_keys($ok), 'bad' => $bad];
    }
}
