<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * How one Activity row is explained to a site owner: a level (how worried to be) and the language key of a plain
 * sentence about what happened. Pure, so it is testable and the screen stays a thin template.
 */
final class EventPresenter
{
    public const HIGH   = 'high';
    public const MEDIUM = 'medium';
    public const LOW    = 'low';
    public const INFO   = 'info';

    /** Rules that are an actual injection or file-access attempt, not just a probe or an oddity. */
    private const SERIOUS = [
        'union_select', 'stacked_query', 'boolean_tautology', 'sql_comment', 'time_based', 'error_based', 'file_access',
        'script_tag', 'js_uri', 'vbscript_uri', 'event_handler', 'risky_tag', 'img_handler', 'data_html', 'css_expr',
        'deep_traversal', 'sensitive_file', 'php_wrapper', 'traversal_hit', 'traversal', 'path_traversal',
        'remote_script', 'remote_wrapper', 'null_terminate', 'jndi_lookup', 'php_object_injection', 'php_open_tag', 'shellshock',
        'sqli_strict', 'xss_strict', 'path_php_tag', 'path_jndi', 'path_wrapper', 'path_sqli', 'path_xss',
    ];

    /**
     * @param  array{time:int,type:string,f:array<string,string>}  $e  a row from LogReader
     */
    public static function level(array $e): string
    {
        $rule = LogFilter::ruleOf($e);

        return match ($e['type']) {
            'LOCK'  => self::HIGH,
            'BLOCK' => \in_array($rule, self::SERIOUS, true) || ($e['f']['kind'] ?? '') === 'upload' ? self::HIGH : self::MEDIUM,
            'ALERT' => self::MEDIUM,
            'DETECT', 'OBSERVE' => self::LOW,
            default => self::INFO,
        };
    }

    /**
     * The language key (without Text::_) of the sentence for a row: the rule's own explanation when this screen has one,
     * otherwise the explanation of the row's type.
     *
     * @param  array{time:int,type:string,f:array<string,string>}  $e
     * @param  string[]                                           $knownRules  rule ids that have a COM_COLORPACK_SHIELD_RULE_<ID> string
     */
    public static function descriptionKey(array $e, array $knownRules): string
    {
        $rule = LogFilter::ruleOf($e);

        if ($rule !== '' && \in_array($rule, $knownRules, true)) {
            return 'COM_COLORPACK_SHIELD_RULE_' . strtoupper($rule);
        }

        return \in_array($e['type'], ['BLOCK', 'DETECT', 'LOCK', 'OBSERVE', 'ALERT'], true) ? 'COM_COLORPACK_SHIELD_TYPE_' . $e['type'] . '_HINT' : 'COM_COLORPACK_SHIELD_TYPE_NOTE';
    }
}
