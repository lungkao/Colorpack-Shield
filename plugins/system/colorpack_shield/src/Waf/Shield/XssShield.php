<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Generic reflected/stored XSS signatures.
 */
final class XssShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'xss';
    }

    protected function patterns(): array
    {
        return [
            'script_tag'    => '/<\s*script[\s>\/]/',
            'js_uri'        => '/javascript\s*:/',
            'vbscript_uri'  => '/vbscript\s*:/',
            'event_handler' => '/\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|animationstart|beforeprint|pageshow)\s*=/',
            'risky_tag'     => '/<\s*(?:iframe|svg|object|embed|video|audio|details|marquee|base|form|math)[\s>\/]/',
            'img_handler'   => '/<\s*img[^>]{0,120}\bon[a-z]+\s*=/',
            'data_html'     => '/data\s*:\s*text\/html/',
            'css_expr'      => '/expression\s*\(|@import\b|behavior\s*:/',
        ];
    }
}
