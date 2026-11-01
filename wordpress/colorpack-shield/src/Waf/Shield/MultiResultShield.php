<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\WafResult;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * A shield that reports every hit, each with its own mode (block or log), so
 * that a log-only finding never hides a blocking one found later.
 */
interface MultiResultShield extends ShieldInterface
{
    /**
     * @return WafResult[]
     */
    public function inspectAll(RequestData $data): array;
}
