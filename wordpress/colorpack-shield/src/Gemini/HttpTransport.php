<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Gemini;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The one seam {@see Client} talks through, so tests can fake the network instead of making a
 * real request. Same shape as the Joomla edition's Gemini\HttpTransport.
 */
interface HttpTransport
{
    /**
     * @param  array<string,string>  $headers
     *
     * @return array{status:int,body:string}|null  null on any failure (DNS, TLS, timeout, ...) - never throws
     */
    public function post(string $url, array $headers, string $body, int $timeoutSeconds): ?array;
}
