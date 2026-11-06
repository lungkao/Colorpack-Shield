<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

use Colorpack\WP\ColorpackShield\Waf\Normalizer;
use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\WafResult;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Base class for signature shields: runs a named regex table over every
 * flattened request value (and its key) and returns the first hit.
 *
 * Concrete shields supply patterns() only. All patterns are matched against a
 * URL-decoded + lowercased copy so single/double encoding and case tricks do
 * not shade the signature. Values are already length-capped by RequestData,
 * bounding regex cost.
 */
abstract class AbstractRegexShield implements ShieldInterface
{
    /**
     * @param  string  $mode  WafResult::MODE_BLOCK (refuse the request) or MODE_LOG (record it and let it through)
     */
    public function __construct(protected readonly string $mode = WafResult::MODE_BLOCK)
    {
    }

    /**
     * @return array<string, string>  ruleName => PCRE pattern (with delimiters/flags)
     */
    abstract protected function patterns(): array;

    public function inspect(RequestData $data): WafResult
    {
        $patterns = $this->patterns();

        foreach ($data->items() as $item) {
            // Headers and the URL path have their own shields: these
            // parameter-tuned signatures raise false positives on them.
            if ($item['source'] === 'HEADER' || $item['source'] === 'PATH') {
                continue;
            }

            // Scan both the value and the parameter name.
            foreach ([$item['value'], $item['key']] as $raw) {
                if ($raw === '') {
                    continue;
                }

                $norm = $this->normalize($raw);

                foreach ($patterns as $rule => $pattern) {
                    if (preg_match($pattern, $norm) === 1) {
                        return WafResult::hit($this->id(), $rule, $item['source'], $item['key'], $raw, $this->mode);
                    }
                }
            }
        }

        return WafResult::clean();
    }

    /**
     * Decode up to two encoding layers, strip null bytes, collapse whitespace,
     * and lowercase — the anti-shading normalization all shields share.
     */
    protected function normalize(string $raw): string
    {
        return Normalizer::normalize($raw);
    }
}
