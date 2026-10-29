<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Picks the request headers worth inspecting out of $_SERVER and gives them
 * back as a name => value bag for {@see RequestData} (source "HEADER").
 *
 * Only headers named in {@see HeaderRules} are returned, plus any the operator
 * lists. Secrets and structured metadata (Authorization, tokens, CF-*, Sec-*)
 * are never returned, so they can be neither falsely flagged nor logged.
 */
final class RequestMeta
{
    /**
     * @param  array<string,mixed>  $server   Normally $_SERVER.
     * @param  string[]             $extra    Extra header names to scan as free text.
     * @param  string[]             $ignored  Header names to skip entirely.
     *
     * @return array<string,string>  canonical header name => value
     */
    public static function headers(array $server, array $extra = [], array $ignored = []): array
    {
        $extra   = array_map('strtolower', $extra);
        $ignored = array_map('strtolower', $ignored);
        $out     = [];

        foreach ($server as $key => $value) {
            // nginx/FPM sets CONTENT_TYPE and CONTENT_LENGTH to "" when the
            // request has none: an empty value is "no header", not a finding.
            if (!\is_string($key) || !\is_string($value) || $value === '') {
                continue;
            }

            if (str_starts_with($key, 'HTTP_')) {
                $name = substr($key, 5);
            } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                $name = $key;
            } else {
                continue;
            }

            $lower = strtolower(str_replace('_', '-', $name));

            if (\in_array($lower, $ignored, true)) {
                continue;
            }

            $profile = HeaderRules::profile($lower);

            if ($profile === HeaderRules::P_NEVER) {
                continue;
            }

            if ($profile === HeaderRules::P_UNKNOWN && !\in_array($lower, $extra, true)) {
                continue;
            }

            $out[ucwords($lower, '-')] = $value;
        }

        return $out;
    }
}
