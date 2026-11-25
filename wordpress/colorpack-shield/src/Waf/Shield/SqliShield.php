<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Generic SQL-injection signatures. Patterns run against the normalized
 * (decoded, whitespace-collapsed, lowercased) value, so classic shading via
 * casing, encoding, and inline spacing is defeated upstream.
 */
final class SqliShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'sqli';
    }

    /**
     * An HTML comment ("<!-- note -->") is not an SQL comment, yet its opening "<!-- " looks like one - so pasting any
     * HTML with a comment into an article was refused. For the sql_comment rule only, the delimiters of a complete HTML
     * comment are set aside; what is written inside it is still checked, an unclosed "<!--" or a bare "-- " still counts,
     * and every other SQL rule sees the whole value.
     */
    protected function subject(string $rule, string $normalized): string
    {
        if ($rule !== 'sql_comment' || !str_contains($normalized, '<!--')) {
            return $normalized;
        }

        return preg_replace('/<!--(.*?)-->/s', ' $1 ', $normalized) ?? $normalized;
    }

    protected function patterns(): array
    {
        return [
            'union_select'      => '/\bunion\b\s+(?:all\s+)?\bselect\b/',
            'stacked_query'     => '/;\s*(?:select|insert|update|delete|drop|alter|create|truncate|grant)\b/',
            'boolean_tautology' => '/\b(?:or|and)\b\s+[\'"]?\d{1,6}[\'"]?\s*=\s*[\'"]?\d{1,6}/',
            'sql_comment'       => '#/\*.{0,80}?\*/|(?:--|\#)[\s-]#',
            'time_based'        => '/\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message)\s*\(/',
            'error_based'       => '/\b(?:updatexml|extractvalue|floor\s*\(\s*rand|group_concat)\s*\(/',
            'meta_tables'       => '/\b(?:information_schema|sysobjects|msysobjects|pg_catalog)\b/',
            'file_access'       => '/\b(?:load_file\s*\(|into\s+(?:out|dump)file\b)/',
        ];
    }
}
