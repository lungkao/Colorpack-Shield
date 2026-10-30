<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What the file scanner flags from a file's NAME and place alone. Joomla itself keeps PHP files in
 * cache/ and logs/ (cache files and "die()"-guarded log files), so those folders are not flagged
 * for holding PHP; images/ (user uploads) and tmp/ are.
 */
final class LocationRules
{
    /** "php" with any digit suffix (php3, php56, …) rather than an enumerated list, so a made-up variant is still caught. */
    public const PHP_EXT = 'php\d*|phtml|pht|phar|inc';

    /** Rule id => severity. */
    public const SEVERITY = [
        'php_in_uploads'     => 'high',
        'php_in_tmp'         => 'medium',
        'double_extension'   => 'medium',
        'hidden_php'         => 'medium',
        'shell_name'         => 'high',
        'foreign_cms_file'   => 'medium',
        'world_writable'     => 'low',
        // From a real incident (asianpa.org, 2026-10-30): both found on files that no existing rule
        // named by extension or location alone.
        'question_mark_name' => 'high',
        'quarantined'        => 'high',
    ];

    /**
     * @param  string  $rel    path below the site folder, "/" separated, no leading slash
     * @param  int     $perms  file permission bits (0 when unknown)
     *
     * @return string[]  rule ids
     */
    public static function check(string $rel, int $perms): array
    {
        $rel   = ltrim(str_replace('\\', '/', $rel), '/');
        $lower = strtolower($rel);
        $base  = basename($lower);
        $isPhp = preg_match('/\.(?:' . self::PHP_EXT . ')$/', $base) === 1;
        $out   = [];

        // "images/" anywhere in the path, not just at the top level - a real incident had PHP
        // planted under media/mailto/images/, which a top-level-only anchor would have missed.
        if (preg_match('~(?:^|/)images/~', $lower) && ($isPhp || preg_match('/\.(?:' . self::PHP_EXT . ')\./', $base) === 1)) {
            $out[] = 'php_in_uploads';
        } elseif (preg_match('~^(?:tmp|administrator/tmp)/~', $lower) && $isPhp) {
            $out[] = 'php_in_tmp';
        }

        // A literal "?" in a stored file name is not something any CMS or upload handler produces
        // on its own; every sample from the same incident that used a disguised extension
        // (image.jpg?.php, image.jpg?.phar, …) had one.
        if (str_contains($base, '?')) {
            $out[] = 'question_mark_name';
        }

        // Some hosts rename malware they already detected to ".suspected" rather than deleting it;
        // if that's still sitting in the site, it is worth surfacing even though it can no longer run.
        if (str_ends_with($base, '.suspected')) {
            $out[] = 'quarantined';
        }

        if (preg_match('/\.(?:php\d*|phtml|phar|pht)\.[a-z0-9]{1,5}$/', $base) === 1) {
            $out[] = 'double_extension';
        }

        if ($isPhp && str_starts_with($base, '.')) {
            $out[] = 'hidden_php';
        }

        if (preg_match('/^(?:shell|cmd|c99|r57|wso|alfa|bypass|uploader|webshell|b374k|indoxploit|mini|priv8|marijuana|sym|symlink)\d*\.(?:' . self::PHP_EXT . ')$/', $base) === 1) {
            $out[] = 'shell_name';
        }

        if (preg_match('/^wp-[a-z0-9-]+\.php$/', $base) === 1) {
            $out[] = 'foreign_cms_file';
        }

        if ($isPhp && ($perms & 0002) !== 0) {
            $out[] = 'world_writable';
        }

        return array_values(array_unique($out));
    }
}
