<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Inventory;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Decides, by tokenising (never by grepping), whether a PHP file is something a
 * browser could usefully request directly (PLAN-WAF-PATH-P2.md §4.2).
 *
 * Verdicts:
 *   bootstrap  the file starts Joomla itself (defines _JEXEC / JPATH_BASE or loads
 *              framework.php / defines.php): a real direct endpoint
 *   unguarded  top-level executable code, no guard, and it reads request input ($_GET, $_POST,
 *              $_FILES, php://input ...): something an attacker could drive
 *   no_input   top-level code but no guard and no request input (view layouts, tables of data ...)
 *   guarded    has a guard ("defined('_JEXEC') or die", or a leading die/exit): answers nothing when requested directly
 *   inert      only declarations (classes, functions, namespace, use, return of data)
 *   error      cannot be parsed
 *
 * The class reads source text only; it never executes anything.
 */
final class EndpointClassifier
{
    public const BOOTSTRAP = 'bootstrap';
    public const UNGUARDED = 'unguarded';
    public const NO_INPUT  = 'no_input';
    public const GUARDED   = 'guarded';
    public const INERT     = 'inert';
    public const ERROR     = 'error';

    /** "defined('_JEXEC') or die", "|| exit", "if (!defined('X')) { die; }" — the guard must actually stop the script. */
    private const GUARD = '/defined\s*\(\s*[\'"](?:_JEXEC|JPATH_PLATFORM|JPATH_BASE|JPATH_ROOT|ABSPATH|_VALID_MOS|WPINC)[\'"]\s*\)[^;]{0,16}?\\\\?\b(?:die|exit)\b/i';

    private const INPUT = '/\$_(?:GET|POST|REQUEST|FILES|COOKIE)\b|php:\/\/input|getallheaders\s*\(|\$HTTP_RAW_POST_DATA/';

    /** A leading die/exit; plain text before the open tag is allowed (Joomla's "#<?php die('Forbidden.'); ?>" log files). */
    private const DIE_FIRST = '/^[^<]*<\?php\s+(?:die|exit)\b|^\s*(?:die|exit)\b/i';

    private const BOOT = '/\bdefine\s*\(\s*[\'"](?:_JEXEC|JPATH_BASE)[\'"]|\b(?:require|include)(?:_once)?\b[^;]{0,200}\b(?:framework|defines)\.php/';

    public static function classify(string $source): string
    {
        // Third-party sources may trigger parse-time deprecations; they are not ours to report.
        $level = error_reporting(0);

        try {
            $tokens = token_get_all($source, TOKEN_PARSE);
        } catch (\Throwable) {
            return self::ERROR;
        } finally {
            error_reporting($level);
        }

        // Judge the code, not the comments: "// defined('_JEXEC') or die" guards nothing.
        $code = '';

        foreach ($tokens as $token) {
            if (\is_array($token)) {
                if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                    continue;
                }

                $code .= $token[1];
            } else {
                $code .= $token;
            }
        }

        $head = substr($code, 0, 8192);

        if (preg_match(self::BOOT, $head) === 1) {
            return self::BOOTSTRAP;
        }

        if (preg_match(self::GUARD, $head) === 1 || preg_match(self::DIE_FIRST, $head) === 1) {
            return self::GUARDED;
        }

        if (!self::hasTopLevelCode($tokens)) {
            return self::INERT;
        }

        return preg_match(self::INPUT, $code) === 1 ? self::UNGUARDED : self::NO_INPUT;
    }

    /**
     * @param  array<int,mixed>  $tokens
     */
    private static function hasTopLevelCode(array $tokens): bool
    {
        $skip = [T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_CLOSE_TAG];
        $decl = [T_NAMESPACE, T_USE, T_DECLARE, T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM, T_FUNCTION, T_CONST, T_ABSTRACT, T_FINAL, T_READONLY, T_ATTRIBUTE, T_RETURN];

        $depth    = 0;
        $atStart  = true;
        $inDecl   = false;

        foreach ($tokens as $token) {
            $id = \is_array($token) ? $token[0] : null;
            $s  = \is_array($token) ? $token[1] : $token;

            if (\in_array($id, $skip, true)) {
                continue;
            }

            if ($id === T_INLINE_HTML) {
                if (trim($s) !== '') {
                    return true;
                }

                continue;
            }

            if ($depth === 0 && $atStart) {
                if (!\in_array($id, $decl, true)) {
                    return true;
                }

                $inDecl  = true;
                $atStart = false;
            }

            if ($s === '{' || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
                $depth++;
            } elseif ($s === '}') {
                $depth--;

                if ($depth === 0 && $inDecl) {
                    $inDecl  = false;
                    $atStart = true;
                }
            } elseif ($s === ';' && $depth === 0) {
                $inDecl  = false;
                $atStart = true;
            }
        }

        return false;
    }
}
