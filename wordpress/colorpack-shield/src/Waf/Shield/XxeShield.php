<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * XML external entity (XXE) signatures: entity declarations that read an outside resource, parameter
 * entities, and XInclude. Ordinary XML that has no DOCTYPE entity block is not touched.
 */
final class XxeShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'xxe';
    }

    protected function patterns(): array
    {
        return [
            'external_entity'  => '~<!entity\b[^>]{0,300}\b(?:system|public)\b~',
            'parameter_entity' => '~<!entity\s+%~',
            'doctype_entity'   => '~<!doctype\b[^>]{0,300}\[\s*<!entity~',
            'xinclude'         => '~xmlns:xi\s*=\s*["\']?http://www\.w3\.org/2001/xinclude~',
        ];
    }
}
