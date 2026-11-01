<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\WP\ColorpackShield\Gemini\AnalysisHistory;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Where the kept AI analyses live on a WordPress site (a few small files under uploads/colorpack-shield/gemini),
 * and what "clear AI analyses" removes: the history and the two "latest answer" options the Activity and
 * Files screens show.
 */
final class AiStore
{
    public static function history(): AnalysisHistory
    {
        return new AnalysisHistory(new FileStateStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/gemini'));
    }

    /** Forget every kept analysis. Returns how many history entries were removed. */
    public static function clear(): int
    {
        delete_option('colorpack_shield_ai_latest');
        delete_option('colorpack_shield_scan_ai_latest');

        return self::history()->clear(time());
    }
}
