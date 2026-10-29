<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Local file inclusion / path traversal / PHP-wrapper signatures.
 *
 * A single "../" is common in legitimate relative paths, so traversal only
 * fires on repeated segments or traversal that lands on a sensitive target —
 * keeping false positives low while still catching real LFI.
 */
final class LfiShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'lfi';
    }

    protected function patterns(): array
    {
        return [
            'deep_traversal' => '#(?:\.\.[\/\\\\]){2,}#',
            'sensitive_file' => '#(?:/etc/(?:passwd|shadow|hosts)|/proc/self/environ|boot\.ini|win\.ini|/\.htaccess|wp-config\.php|configuration\.php)\b#',
            'php_wrapper'    => '#php://(?:filter|input|memory|temp|data)|phar://|zip://|glob://|expect://#',
            'traversal_hit'  => '#\.\.[\/\\\\][^\n]{0,120}(?:etc[\/\\\\]passwd|boot\.ini|win\.ini|self[\/\\\\]environ)#',
        ];
    }
}
