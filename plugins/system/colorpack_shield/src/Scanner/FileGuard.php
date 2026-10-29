<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Decides whether a file may be shown, edited or deleted from the scan screen. The answer is always a
 * code, never a path the caller made up: the file must be one the last scan reported, must really
 * live inside the site folder (no symbolic link on the way, no "..", not a folder), and a few files
 * are never touched from here (site configuration, the scanner's own folders; Joomla's entry
 * points cannot be deleted, only edited).
 */
final class FileGuard
{
    public const OK        = 'ok';
    public const BAD_PATH  = 'bad_path';
    public const NOT_SCAN  = 'not_in_scan';
    public const OUTSIDE   = 'outside';
    public const NOT_FILE  = 'not_a_file';
    public const PROTECTED = 'protected';
    public const ENTRY     = 'entry_point';

    /** Joomla's front controllers: editing is allowed (they can be infected), deleting would take the site down. */
    private const ENTRY_POINTS = ['index.php', 'administrator/index.php', 'api/index.php', 'cli/joomla.php'];

    /** Folders of Colorpack Shield itself and its stored data. */
    private const OWN = ['cache/colorpack_shield/', 'plugins/system/colorpack_shield/', 'plugins/task/colorpack_shield/', 'administrator/components/com_colorpack_shield/', 'media/com_colorpack_shield/'];

    /**
     * @param  string               $root     the site folder
     * @param  string               $rel      path below it, "/" separated (as the scan reported it)
     * @param  array<string,mixed>  $allowed  paths the last scan reported (keys)
     * @param  string               $action   view | edit | delete
     *
     * @return array{code:string,real:?string}
     */
    public static function check(string $root, string $rel, array $allowed, string $action): array
    {
        $no = static fn (string $code): array => ['code' => $code, 'real' => null];

        if ($rel === '' || strlen($rel) > 500 || str_contains($rel, "\0") || str_contains($rel, '\\') || str_starts_with($rel, '/') || preg_match('~(?:^|/)\.\.?(?:/|$)~', $rel) === 1) {
            return $no(self::BAD_PATH);
        }

        if (!isset($allowed[$rel])) {
            return $no(self::NOT_SCAN);
        }

        $realRoot = realpath($root);

        if ($realRoot === false) {
            return $no(self::OUTSIDE);
        }

        $abs  = $realRoot . '/' . $rel;
        $real = realpath($abs);

        // The real path must be exactly the path asked for: any symbolic link on the way changes it.
        if ($real === false || $real !== $abs) {
            return $no(self::OUTSIDE);
        }

        if (is_link($abs) || !is_file($real)) {
            return $no(is_link($abs) ? self::OUTSIDE : self::NOT_FILE);
        }

        if (self::isProtected($rel)) {
            return $no(self::PROTECTED);
        }

        $lower = strtolower($rel);

        if ($action === 'delete' && \in_array($lower, self::ENTRY_POINTS, true)) {
            return $no(self::ENTRY);
        }

        return ['code' => self::OK, 'real' => $real];
    }

    /**
     * Files nothing in the scan screen may write: the site's configuration and this package's own
     * folders. Shared with Quarantine::restore, so a copy cannot be used to get around it.
     */
    public static function isProtected(string $rel): bool
    {
        $lower = strtolower($rel);

        if ($lower === 'configuration.php') {
            return true;
        }

        foreach (self::OWN as $own) {
            if (str_starts_with($lower, $own)) {
                return true;
            }
        }

        return false;
    }
}
