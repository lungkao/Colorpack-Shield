<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Where deliberately banned addresses are kept (the "ban" path mode, and any add-on that feeds a shared attacker list
 * through the `colorpack_shield_use_ban_store` filter). One folder under uploads, same place as always.
 */
final class BanStore
{
    public static function get(): FileStateStore
    {
        return new FileStateStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/bans');
    }
}
