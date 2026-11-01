<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\SiteManager;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The same HMAC the Agent plugin (`plg_system_colorpack`) and the Site Manager already use
 * between themselves - Shield signs its own traffic to the same Site Manager the same way, with
 * the same per-site secret, so no new credential or verification path is introduced.
 */
final class Signer
{
    public static function sign(string $secret, string $time, string $body): string
    {
        return hash_hmac('sha256', $time . '.' . $body, $secret);
    }
}
