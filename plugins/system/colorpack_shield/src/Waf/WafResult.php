<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Immutable outcome of running the WAF over one request.
 *
 * A "clean" result has matched=false. A "hit" carries the shield that fired,
 * the offending request source/key, and a truncated sample for the log.
 */
final class WafResult
{
    /** The request is refused. */
    public const MODE_BLOCK = 'block';

    /** The hit is recorded but the request goes on (detect-only rules). */
    public const MODE_LOG = 'log';

    private function __construct(
        public readonly bool $matched,
        public readonly string $shield = '',
        public readonly string $rule = '',
        public readonly string $source = '',
        public readonly string $key = '',
        public readonly string $sample = '',
        public readonly string $mode = self::MODE_BLOCK
    ) {
    }

    public static function clean(): self
    {
        return new self(false);
    }

    public static function hit(string $shield, string $rule, string $source, string $key, string $sample, string $mode = self::MODE_BLOCK): self
    {
        // Bound the sample so a giant payload never bloats the log row.
        if (\strlen($sample) > 200) {
            $sample = substr($sample, 0, 200) . '…';
        }

        return new self(true, $shield, $rule, $source, $key, $sample, $mode);
    }
}
