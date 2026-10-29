<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\RateLimit;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Immutable outcome of a rate-limit check. An allowed verdict carries no reason;
 * a blocked one carries a stable reason token ("rate_limited" for the soft 429,
 * "rate_banned" once the IP is temp-banned) and the Retry-After seconds.
 */
final class RateVerdict
{
    private function __construct(
        public readonly bool $allowed,
        public readonly string $reason = '',
        public readonly int $retryAfter = 0
    ) {
    }

    public static function allow(): self
    {
        return new self(true);
    }

    public static function block(string $reason, int $retryAfter): self
    {
        return new self(false, $reason, max(1, $retryAfter));
    }
}
