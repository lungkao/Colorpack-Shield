<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

use Colorpack\Plugin\System\ColorpackShield\Waf\Normalizer;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Tolerance;
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

    /** @var string[] rule ids tolerated on form fields (see Tolerance) */
    private array $tolerated = [];

    /** @var array<int,array{shield:string,source:string,key:string}> fields under observation (see ExceptionRules, "watch:") */
    private array $watched = [];

    /**
     * A copy of this shield that skips the given rules on form fields (POST/JSON) only. A skipped rule that
     * matches is still reported, as a log-only hit with the note "tolerated".
     *
     * @param  string[]  $rules
     */
    public function withTolerance(array $rules): static
    {
        $copy            = clone $this;
        $copy->tolerated = $rules;

        return $copy;
    }

    /**
     * A copy of this shield that only observes the given fields (low and medium rules are logged, not blocked,
     * with the note "watch"). Rules for real attack patterns still block on those fields.
     *
     * @param  array<int,array{shield:string,source:string,key:string}>  $rules
     */
    public function withWatch(array $rules): static
    {
        $copy          = clone $this;
        $copy->watched = array_values(array_filter($rules, fn (array $r): bool => $r['shield'] === $this->id()));

        return $copy;
    }

    public function inspect(RequestData $data): WafResult
    {
        $patterns = $this->patterns();
        $skipped  = null;

        foreach ($data->items() as $item) {
            // Headers and the URL path have their own shields: these
            // parameter-tuned signatures raise false positives on them
            // (PLAN-WAF-HEADERS-PATHS.md §1).
            if ($item['source'] === 'HEADER' || $item['source'] === 'PATH') {
                continue;
            }

            $isField = $item['source'] === 'POST' || $item['source'] === 'JSON';

            // Scan both the value and the parameter name.
            foreach ([$item['value'], $item['key']] as $raw) {
                if ($raw === '') {
                    continue;
                }

                $norm = $this->normalize($raw);

                foreach ($patterns as $rule => $pattern) {
                    if (preg_match($pattern, $norm) !== 1) {
                        continue;
                    }

                    $note = '';

                    if ($isField && $this->tolerated !== [] && \in_array($rule, $this->tolerated, true)) {
                        $note = 'tolerated';
                    } elseif ($this->isWatched($item['source'], $item['key']) && \in_array($rule, Tolerance::rulesFor(Tolerance::MEDIUM), true)) {
                        $note = 'watch';
                    }

                    if ($note === '') {
                        return WafResult::hit($this->id(), $rule, $item['source'], $item['key'], $raw);
                    }

                    $skipped ??= WafResult::hit($this->id(), $rule, $item['source'], $item['key'], $raw, WafResult::MODE_LOG, $note);
                }
            }
        }

        return $skipped ?? WafResult::clean();
    }

    private function isWatched(string $source, string $key): bool
    {
        foreach ($this->watched as $r) {
            $keyMatch = str_ends_with($r['key'], '*') ? str_starts_with($key, substr($r['key'], 0, -1)) : $key === $r['key'];

            if ($keyMatch && ($r['source'] === '*' || $r['source'] === $source)) {
                return true;
            }
        }

        return false;
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
