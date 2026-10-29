<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

use Colorpack\Plugin\System\ColorpackShield\Waf\Normalizer;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

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
     * @return array<string, string>  ruleName => PCRE pattern (with delimiters/flags)
     */
    abstract protected function patterns(): array;

    public function inspect(RequestData $data): WafResult
    {
        $patterns = $this->patterns();

        foreach ($data->items() as $item) {
            // Headers and the URL path have their own shields: these
            // parameter-tuned signatures raise false positives on them
            // (PLAN-WAF-HEADERS-PATHS.md §1).
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
                        return WafResult::hit($this->id(), $rule, $item['source'], $item['key'], $raw);
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
