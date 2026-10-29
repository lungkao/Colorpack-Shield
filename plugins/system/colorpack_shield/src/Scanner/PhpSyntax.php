<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Does this text still parse as PHP? Used before a file is saved from the editor: a typo in a
 * file would otherwise turn the whole site into an error page. Parsing only: nothing is run.
 */
final class PhpSyntax
{
    /**
     * @return array{line:int,message:string}|null  null when it parses
     */
    public static function error(string $code): ?array
    {
        if (!\defined('TOKEN_PARSE')) {
            return null;
        }

        try {
            token_get_all($code, TOKEN_PARSE);
        } catch (\ParseError $e) {
            return ['line' => (int) $e->getLine(), 'message' => substr(preg_replace('/[\x00-\x1f\x7f]/', ' ', $e->getMessage()) ?? '', 0, 200)];
        } catch (\Throwable) {
            return null;
        }

        return null;
    }
}
