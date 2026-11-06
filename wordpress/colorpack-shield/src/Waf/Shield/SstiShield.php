<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Server-side template injection signatures: the arithmetic probes scanners send to find a template
 * engine ({{7*7}}, ${7*7}, <%= 7*7 %>) and the object-walking chains used to reach code execution.
 */
final class SstiShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'ssti';
    }

    protected function patterns(): array
    {
        return [
            'math_probe'   => '~\{\{\s*\d+\s*[*+]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|#\{\s*\d+\s*\*\s*\d+\s*\}|<%=?\s*\d+\s*[*+]\s*\d+\s*%>~',
            'object_chain' => '~\{\{[^}]{0,80}(?:__class__|__mro__|__globals__|__subclasses__|__builtins__|\.constructor\b|config\.items|lipsum\.|cycler\.|joiner\.)~',
            'java_el'      => '~\$\{\s*(?:t\s*\(\s*java\.|@java|new\s+java|\w+\.getclass\(|runtime\.getruntime)~',
        ];
    }
}
