<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Which lines of a file make the scanner suspicious, for the code viewer: the same patterns the
 * scan uses, reported by line number so the person can jump straight to them.
 */
final class LineMarker
{
    public const MAX_MARKS = 200;

    /**
     * @param  string  $kind  'php' | 'htaccess' | 'image'
     *
     * @return array<int,array{line:int,rule:string}>  sorted by line
     */
    public static function marks(string $content, string $kind = 'php', bool $inDataDir = false): array
    {
        $rules = match ($kind) {
            'htaccess' => $inDataDir ? SignatureRules::HTACCESS_DATA : SignatureRules::HTACCESS_ANY,
            'image'    => ['php_in_image' => [SignatureRules::HIGH, SignatureRules::PHP_IN_IMAGE]],
            default    => SignatureRules::PHP,
        };
        $out = [];

        foreach ($rules as $id => [, $pattern]) {
            if (@preg_match_all($pattern, $content, $m, PREG_OFFSET_CAPTURE) === false) {
                continue;
            }

            foreach (\array_slice($m[0], 0, 50) as [, $offset]) {
                $line = substr_count($content, "\n", 0, (int) $offset) + 1;
                $out[$line . '|' . $id] = ['line' => $line, 'rule' => $id];

                if (\count($out) >= self::MAX_MARKS) {
                    break 2;
                }
            }
        }

        $out = array_values($out);
        usort($out, static fn (array $a, array $b): int => [$a['line'], $a['rule']] <=> [$b['line'], $b['rule']]);

        return $out;
    }

    /** What kind of file this is, for choosing the patterns. */
    public static function kindOf(string $rel): string
    {
        $base = strtolower(basename($rel));

        if ($base === '.htaccess') {
            return 'htaccess';
        }

        if (preg_match('/\.(?:' . LocationRules::PHP_EXT . ')$/', $base) === 1) {
            return 'php';
        }

        return preg_match('/\.(?:jpg|jpeg|png|gif|ico|bmp|webp|pdf)$/', $base) === 1 ? 'image' : 'php';
    }
}
