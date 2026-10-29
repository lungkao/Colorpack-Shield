<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Remote file inclusion signatures. Kept conservative — a bare "http://" in a
 * value is often a legitimate return URL, so we only fire on a remote resource
 * that looks includable (remote script extension) or a remote/data wrapper.
 */
final class RfiShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'rfi';
    }

    protected function patterns(): array
    {
        return [
            'remote_script'  => '#(?:https?|ftp)://[^\s?\#]{1,200}\.(?:php|phtml|php[357]|module|inc|pht)\b#',
            'remote_wrapper' => '#(?:data|expect|ssh2|ogg|rar)://#',
            'null_terminate' => '#(?:https?|ftp)://[^\s]{1,200}%00#',
        ];
    }
}
