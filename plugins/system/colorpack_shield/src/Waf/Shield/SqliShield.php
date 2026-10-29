<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

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
