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

interface ShieldInterface
{
    /**
     * Stable identifier used in config keys and log rows (e.g. "sqli").
     */
    public function id(): string;

    /**
     * Inspect the request; return a hit on the first offending value, else clean.
     */
    public function inspect(RequestData $data): WafResult;
}
