<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns the raw request path (REQUEST_URI up to "?") into something rules can
 * be matched against, and reports how the path was tampered with
 * (PLAN-WAF-PATH-P2.md §3.3).
 *
 * Two views are produced:
 *
 *   decoded    percent-decoded (up to three layers), "\" read as "/", lower-case,
 *              NOT otherwise rewritten — for injection patterns that need the
 *              characters exactly as sent ("php://", "; drop table");
 *   canonical  the same, with ";param" stripped from each segment, "//" and
 *              "/./" collapsed and ".." resolved — for "where does this point"
 *              rules (PHP in a data folder, dot-files, leftovers).
 *
 * Valid UTF-8 (Thai slugs) passes untouched; only ASCII is lower-cased.
 * The class is pure and Joomla-free.
 */
final class PathNormalizer
{
    public const F_TRAVERSAL    = 'path_traversal';
    public const F_CTRL         = 'path_ctrl';
    public const F_OVERLONG     = 'path_overlong_utf8';
    public const F_PARAM_TRICK  = 'path_param_trick';
    public const F_DOUBLE_ENC   = 'path_double_encoded';
    public const F_BAD_UTF8     = 'path_bad_utf8';
    public const F_BACKSLASH    = 'path_backslash';
    public const F_DOUBLE_SLASH = 'path_double_slash';
    public const F_OVERSIZE     = 'path_oversize';

    /** A longer path is flagged. */
    public const MAX_NORMAL = 2048;

    /** Bytes analysed at most, so an enormous path cannot cost CPU. */
    public const MAX_ANALYSED = 8192;

    /** Percent-decoding layers peeled at most. */
    public const MAX_LAYERS = 3;

    /**
     * @return array{canonical:string,decoded:string,flags:string[]}
     */
    public static function normalize(string $rawUri): array
    {
        $flags = [];

        // Absolute-form request target ("GET http://host/path"): keep only the path.
        if (preg_match('~^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/?#]*~', $rawUri, $m) === 1) {
            $rawUri = substr($rawUri, \strlen($m[0]));
        }

        $raw = substr($rawUri, 0, strcspn($rawUri, '?#'));

        if (\strlen($raw) > self::MAX_NORMAL) {
            $flags[self::F_OVERSIZE] = true;
        }

        $raw = substr($raw, 0, self::MAX_ANALYSED);

        // 3. percent-decode until stable.
        $s      = $raw;
        $layers = 0;

        for ($i = 0; $i < self::MAX_LAYERS; $i++) {
            $d = rawurldecode($s);

            if ($d === $s) {
                break;
            }

            $s = $d;
            $layers++;
        }

        if ($layers >= 2) {
            $flags[self::F_DOUBLE_ENC] = true;
        }

        // 2 + 4. control bytes, raw or decoded (NUL, CR, LF, tab, DEL …).
        if (preg_match('/[\x00-\x1f\x7f]/', $s) === 1) {
            $flags[self::F_CTRL] = true;
        }

        // 5. UTF-8: an overlong form is only ever an attack; other invalid
        // sequences (old Latin-1 links) are merely odd.
        if (preg_match('/\xC0[\x80-\xBF]|\xC1[\x80-\xBF]|\xE0[\x80-\x9F][\x80-\xBF]|\xF0[\x80-\x8F][\x80-\xBF]{2}/', $s) === 1) {
            $flags[self::F_OVERLONG] = true;
        } elseif (preg_match('//u', $s) !== 1) {
            $flags[self::F_BAD_UTF8] = true;
        }

        // 6. backslash is a separator on some servers.
        if (str_contains($s, '\\')) {
            $flags[self::F_BACKSLASH] = true;
            $s = str_replace('\\', '/', $s);
        }

        $s       = self::lower($s);
        $decoded = $s;

        // 7 + 8. segment by segment: strip ";params", look for "..", collapse.
        $out      = [];
        $segments = explode('/', $s);
        $last     = \count($segments) - 1;

        foreach ($segments as $i => $seg) {
            $semi = strpos($seg, ';');

            if ($semi !== false) {
                $seg = substr($seg, 0, $semi);

                if ($seg === '.' || $seg === '..') {
                    $flags[self::F_PARAM_TRICK] = true;
                }
            }

            if ($seg === '..') {
                $flags[self::F_TRAVERSAL] = true;
                array_pop($out);

                continue;
            }

            if ($seg === '.') {
                continue;
            }

            if ($seg === '') {
                // Leading "/" gives one empty first segment; a trailing "/" is normal.
                if ($i !== 0 && $i !== $last) {
                    $flags[self::F_DOUBLE_SLASH] = true;
                }

                continue;
            }

            $out[] = $seg;
        }

        $canonical = '/' . implode('/', $out);

        // A trailing slash is kept so "dir/" and "dir" stay distinguishable.
        if ($out !== [] && str_ends_with($s, '/') ) {
            $canonical .= '/';
        }

        return ['canonical' => $canonical, 'decoded' => $decoded, 'flags' => array_keys($flags)];
    }

    /** ASCII-only lower-casing: multi-byte (Thai) sequences are left intact. */
    private static function lower(string $s): string
    {
        return strtr($s, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    }
}
