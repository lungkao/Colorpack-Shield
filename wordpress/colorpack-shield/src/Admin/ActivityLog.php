<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Writes one line per WAF event, in the exact wire format {@see LogReader} already parses (the
 * Joomla edition's own "text_file" logger format): a tab-separated
 * "datetime\tpriority\tclientip\tcategory\tTYPE key=value key=value ..." line. Takes its target
 * path as a constructor argument rather than reading a WordPress constant, so it needs no
 * WordPress function stub to test.
 */
final class ActivityLog
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * The real path on an actual WordPress install: wp-content/uploads is writable on ordinary
     * shared hosting (unlike the plugin's own directory, which an auto-updater may replace
     * wholesale), matching the "no server administrator rights, maybe no shell" constraint this
     * project is built around. Kept separate from the constructor so the class itself never calls
     * a WordPress function and needs no stub to test.
     */
    public static function defaultPath(): string
    {
        return trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/activity.log';
    }

    /**
     * @param  array<string,string>  $fields  "client" should normally be one of them (matches
     *                                         what LogFilter::apply()'s client criterion checks).
     *                                         LogReader::parseLine() treats "sample"/"detail"/
     *                                         "file" as taking the rest of the line (so their
     *                                         value can contain spaces) - put one of those last
     *                                         if present, or a later field is swallowed into it.
     */
    public function write(string $type, array $fields, string $clientIp): void
    {
        $dir = \dirname($this->path);

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $parts = [$type];

        foreach ($fields as $key => $value) {
            // One event, one line: a hostile value must not be able to forge a second log line
            // by smuggling a tab or newline into a field (e.g. a crafted "uri" or "sample").
            $parts[] = $key . '=' . (preg_replace('/[\x00-\x1f\x7f]/', '?', $value) ?? '');
        }

        $line = sprintf(
            "%s\tWARNING\t%s\tcolorpack_shield\t%s\n",
            gmdate('c'),
            $clientIp !== '' ? $clientIp : '-',
            implode(' ', $parts)
        );

        $fh = @fopen($this->path, 'ab');

        if ($fh === false) {
            return;
        }

        @flock($fh, \LOCK_EX);
        fwrite($fh, $line);
        @flock($fh, \LOCK_UN);
        fclose($fh);
    }
}
