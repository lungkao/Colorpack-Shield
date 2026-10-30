<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Gemini;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The one seam {@see Client} talks through, so tests can fake the network instead of making a
 * real request - same shape as {@see \Colorpack\Plugin\System\ColorpackShield\SiteManager\HttpTransport},
 * kept as its own small interface per this project's house style of one transport per feature.
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
