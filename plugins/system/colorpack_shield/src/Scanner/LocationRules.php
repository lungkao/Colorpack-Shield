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
    public const PHP_EXT = 'php|php3|php4|php5|php7|php8|phtml|pht|phar|inc';

    /** Rule id => severity. */
    public const SEVERITY = [
        'php_in_uploads'   => 'high',
        'php_in_tmp'       => 'medium',
        'double_extension' => 'medium',
        'hidden_php'       => 'medium',
        'shell_name'       => 'high',
        'foreign_cms_file' => 'medium',
        'world_writable'   => 'low',
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

        if (preg_match('~^images/~', $lower) && ($isPhp || preg_match('/\.(?:' . self::PHP_EXT . ')\./', $base) === 1)) {
            $out[] = 'php_in_uploads';
        } elseif (preg_match('~^(?:tmp|administrator/tmp)/~', $lower) && $isPhp) {
            $out[] = 'php_in_tmp';
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
