<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

use Colorpack\Plugin\System\ColorpackShield\Waf\Normalizer;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Inspects the "HEADER" source (see RequestMeta). Per header, in this order:
 *
 *   1. control characters (CR/LF/NUL … — header splitting);
 *   2. high-confidence injection (PHP object injection, Shellshock, JNDI,
 *      PHP tag) — in every scanned header;
 *   3. the header's grammar, where it has one (IP lists, Forwarded, Accept*,
 *      Content-Type, Host);
 *   4. for free-text headers only: strict SQLi/XSS/traversal and oversize.
 *
 * At most one finding per header, so one odd header cannot flood the log.
 * Each rule carries a mode (block / log); {@see $modeOverride} can force all
 * of them to "log" or "block".
 */
final class HeaderShield implements MultiResultShield
{
    /** Findings reported per request, at most. */
    private const MAX_FINDINGS = 8;

    /** @var array<string,string>|null */
    private static ?array $injection = null;

    /** @var array<string,string[]>|null */
    private static ?array $strict = null;

    /**
     * @param  string  $modeOverride  'default' (per-rule defaults) | 'log' | 'block'
     */
    public function __construct(private readonly string $modeOverride = 'default')
    {
    }

    public function id(): string
    {
        return 'header';
    }

    public function inspect(RequestData $data): WafResult
    {
        $first = null;

        foreach ($this->inspectAll($data) as $result) {
            if ($result->mode === WafResult::MODE_BLOCK) {
                return $result;
            }

            $first ??= $result;
        }

        return $first ?? WafResult::clean();
    }

    /**
     * @return WafResult[]
     */
    public function inspectAll(RequestData $data): array
    {
        self::$injection ??= HeaderRules::injectionPatterns();
        self::$strict    ??= HeaderRules::strictPatterns();

        $out = [];

        foreach ($data->items() as $item) {
            if ($item['source'] !== 'HEADER') {
                continue;
            }

            $rule = $this->check($item['key'], $item['value']);

            if ($rule !== null) {
                $out[] = WafResult::hit($this->id(), $rule, 'HEADER', $item['key'], $item['value'], $this->modeFor($rule));

                if (\count($out) >= self::MAX_FINDINGS) {
                    break;
                }
            }
        }

        return $out;
    }

    /**
     * @return string|null  rule id of the first finding, or null if the header is fine
     */
    private function check(string $name, string $raw): ?string
    {
        $lower   = strtolower($name);
        $profile = HeaderRules::profile($lower);

        if ($profile === HeaderRules::P_NEVER) {
            return null;
        }

        // 1. control characters (tab is legal inside a header value)
        if (preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $raw) === 1) {
            return 'control_chars';
        }

        // 2. high-confidence injection, on the normalised value
        $norm = Normalizer::normalize($raw);

        foreach (self::$injection as $rule => $pattern) {
            if (preg_match($pattern, $norm) === 1) {
                return $rule;
            }
        }

        // 3. grammar
        switch ($profile) {
            case HeaderRules::P_IP:
                return HeaderRules::validIpList($raw) ? null : 'malformed_ip_header';

            case HeaderRules::P_FORWARDED:
                return HeaderRules::validForwarded($raw) ? null : 'malformed_forwarded';

            case HeaderRules::P_NEGOTIATION:
                return HeaderRules::validNegotiation($lower, $raw) ? null : 'malformed_negotiation';

            case HeaderRules::P_CONTENTTYPE:
                return HeaderRules::validContentType($raw) ? null : 'malformed_content_type';

            case HeaderRules::P_HOST:
                return HeaderRules::validHost($raw) ? null : 'malformed_host';
        }

        // 4. free text (user-agent, referer, origin, operator-listed headers)
        return $this->checkFreeText($lower, $raw, $norm);
    }

    private function checkFreeText(string $lower, string $raw, string $norm): ?string
    {
        // A Referer/Origin is a URL from somebody else's site: SQL words in its
        // QUERY string are normal ("…search?q=union+select+tutorial"), so SQLi
        // is judged on the path part only.
        $isUrl  = $lower === 'referer' || $lower === 'origin';
        $sqlSrc = $norm;

        if ($isUrl) {
            $cut    = strcspn($raw, '?#');
            $sqlSrc = Normalizer::normalize(substr($raw, 0, $cut));
        }

        foreach (self::$strict as $rule => $patterns) {
            $subject = $rule === 'sqli_strict' ? $sqlSrc : $norm;

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $subject) === 1) {
                    return $rule;
                }
            }
        }

        if (\strlen($raw) > HeaderRules::MAX_FREETEXT) {
            return 'oversize';
        }

        return null;
    }

    private function modeFor(string $rule): string
    {
        if ($this->modeOverride === 'log') {
            return WafResult::MODE_LOG;
        }

        if ($this->modeOverride === 'block') {
            return WafResult::MODE_BLOCK;
        }

        return (HeaderRules::RULES[$rule] ?? 'log') === 'block' ? WafResult::MODE_BLOCK : WafResult::MODE_LOG;
    }
}
