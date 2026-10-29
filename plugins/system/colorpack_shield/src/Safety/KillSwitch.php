<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Safety;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Emergency disable: if a file named "colorpack_shield.disable" exists in the
 * site root or the administrator folder, the plugin does nothing at all.
 *
 * The point is recovery without the admin panel: a Super User who is blocked
 * (or whose settings broke the site) creates a file over FTP / the hosting file
 * manager, gets back in, fixes the settings, deletes the file.
 *
 * Optional token (AUDIT.md C4): when the plugin has a "kill-switch token"
 * configured, the file only counts if its content equals that token. Someone
 * who can write files into the web root but cannot read the plugin settings
 * (a file-upload bug, say) then cannot silently switch protection off. Without
 * a token any file counts — the easiest option when you are locked out.
 * Either way the plugin alerts the admin when the file appears (see
 * KillSwitchAlert).
 *
 * Two stat() calls per request when no file exists.
 */
final class KillSwitch
{
    public const FILENAME = 'colorpack_shield.disable';

    /** Bytes of the file compared with the token. */
    private const MAX_TOKEN_BYTES = 256;

    /**
     * @param  string[]  $dirs   Directories to look in (site root, administrator).
     * @param  string    $token  Required file content; '' = any file counts.
     *
     * @return array{present:?string,active:?string}
     *         present = first switch file found, whatever its content;
     *         active  = first one that actually switches protection off.
     */
    public static function locate(array $dirs, string $token = ''): array
    {
        $present = null;

        foreach ($dirs as $dir) {
            if ($dir === '') {
                continue;
            }

            $path = rtrim($dir, '/\\') . '/' . self::FILENAME;

            if (!is_file($path)) {
                continue;
            }

            $present ??= $path;

            if (self::matches($path, $token)) {
                return ['present' => $present, 'active' => $path];
            }
        }

        return ['present' => $present, 'active' => null];
    }

    /**
     * @param  string[]  $dirs
     *
     * @return string|null  Full path of the first switch file that is in force, or null.
     */
    public static function find(array $dirs, string $token = ''): ?string
    {
        return self::locate($dirs, $token)['active'];
    }

    private static function matches(string $path, string $token): bool
    {
        if ($token === '') {
            return true;
        }

        $content = @file_get_contents($path, false, null, 0, self::MAX_TOKEN_BYTES);

        return $content !== false && hash_equals($token, trim($content));
    }
}
