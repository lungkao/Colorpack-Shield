<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\RateLimit;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Picks the counter the rate limiter uses on this server: APCu (shared memory, fastest) when the
 * server has it, otherwise small files in the cache folder, otherwise nothing (and the limiter is
 * skipped rather than guessed at).
 */
final class RateStores
{
    public const APCU = 'apcu';
    public const FILE = 'file';
    public const NONE = 'none';

    /** Which kind of counter this server can offer, without creating anything. */
    public static function kind(string $dir): string
    {
        if (ApcuRateStore::isAvailable()) {
            return self::APCU;
        }

        return self::writable($dir) ? self::FILE : self::NONE;
    }

    public static function pick(string $dir): ?RateStore
    {
        return match (self::kind($dir)) {
            self::APCU => new ApcuRateStore(),
            self::FILE => new FileRateStore($dir),
            default    => null,
        };
    }

    private static function writable(string $dir): bool
    {
        if ($dir === '') {
            return false;
        }

        if (!is_dir($dir)) {
            // The folder is created on first use; ask whether that would work.
            $parent = \dirname($dir);

            while ($parent !== '' && !is_dir($parent) && $parent !== \dirname($parent)) {
                $parent = \dirname($parent);
            }

            return $parent !== '' && is_dir($parent) && is_writable($parent);
        }

        return is_writable($dir);
    }
}
