<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

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
