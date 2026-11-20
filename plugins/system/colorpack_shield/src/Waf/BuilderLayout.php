<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Page-builder bodies (YOOtheme Pro) are one JSON document stored in an HTML comment at the start of the
 * article text. Inside it, an "html" element may hold a <script type="application/ld+json"> block, which is
 * data (structured data for search engines), not code that runs.
 *
 * For a field that really is such a layout (starts with the comment marker, ends with the closing marker and
 * the JSON in between parses), the JSON-LD blocks whose own body parses as JSON are taken out of the copy that
 * the rules look at. Everything else in the field is still scanned by every rule. Used only for a signed-in
 * editor in the administrator area; the request itself is never changed.
 */
final class BuilderLayout
{
    private const OPEN = '<!-- {"type":"layout"';

    private const CLOSE = '-->';

    /** Layouts above this size are not examined (and so scanned as they are). */
    private const MAX_BYTES = 2097152;

    /**
     * @param  array<mixed>  $bag  e.g. $_POST
     * @return array<mixed>
     */
    public static function relax(array $bag, int $depth = 0): array
    {
        if ($depth > RequestData::MAX_DEPTH) {
            return $bag;
        }

        foreach ($bag as $k => $v) {
            if (\is_array($v)) {
                $bag[$k] = self::relax($v, $depth + 1);
            } elseif (\is_string($v) && str_starts_with($v, self::OPEN)) {
                $bag[$k] = self::relaxValue($v);
            }
        }

        return $bag;
    }

    public static function relaxValue(string $value): string
    {
        $trim = rtrim($value);

        if (\strlen($trim) > self::MAX_BYTES || !str_ends_with($trim, self::CLOSE)) {
            return $value;
        }

        $json = substr($trim, 5, -3);   // between "<!-- " and "-->"

        if (!\is_array(json_decode($json, true)) || json_last_error() !== JSON_ERROR_NONE) {
            return $value;
        }

        // The JSON is one string once decoded; JSON-LD blocks appear in it with escaped slashes and quotes, so
        // look in the decoded text of every string value, and also in the raw text.
        $out = preg_replace_callback(
            '#<script\b[^>]*\btype\s*=\s*(?:\\\\?["\'])application/ld\+json(?:\\\\?["\'])[^>]*>(.*?)</script\s*>#is',
            static function (array $m): string {
                $body = stripcslashes($m[1]);

                return \is_array(json_decode($body, true)) && json_last_error() === JSON_ERROR_NONE ? '' : $m[0];
            },
            $value
        );

        return \is_string($out) ? $out : $value;
    }
}
