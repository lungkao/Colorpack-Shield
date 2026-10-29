<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Shield;

use Colorpack\Plugin\System\ColorpackShield\Waf\PathNormalizer;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Inspects the "PATH" source: key "path" is the raw request path (REQUEST_URI up
 * to "?"), keys "php_self" / "path_info" are extra carriers checked for
 * injection only.
 *
 * For the raw path: integrity flags (class A) → injection (B) → location rules
 * (C–F, skipped for exempt paths such as /.well-known/). Every finding carries
 * its own mode; {@see $mode} / {@see $probeMode} adjust them (PLAN-WAF-PATH-P2.md §3.6).
 *
 * The sample is the canonical path, never the query string, with control bytes
 * made printable so that a hostile path cannot forge log lines.
 */
final class PathShield implements MultiResultShield
{
    /** Findings reported per request, at most. */
    private const MAX_FINDINGS = 6;

    /** @var array<string,string>|null */
    private static ?array $injection = null;

    /** @var array<string,string>|null */
    private static ?array $location = null;

    /** @var string[] */
    private array $allowPrefixes = [];

    /** @var string[] */
    private array $allowRegex = [];

    /** @var string[] */
    private array $denyPrefixes = [];

    /** @var string[] */
    private array $denyRegex = [];

    /** @var string[] */
    private array $toolsExempt;

    /**
     * @param  string    $mode         'recommended' (per-rule defaults) | 'log' | 'block'
     * @param  string    $probeMode    scanner probes (class F): 'off' | 'log' | 'block'
     * @param  string[]  $allow        operator exemptions: "/prefix" or "re:PATTERN" lines
     * @param  string[]  $extraDeny    operator deny list, same syntax
     * @param  string[]  $toolsExempt  admin tools (phpmyadmin …) left alone by the probe rules
     */
    public function __construct(
        private readonly string $mode = 'recommended',
        private readonly string $probeMode = 'log',
        array $allow = [],
        array $extraDeny = [],
        ?array $toolsExempt = null
    ) {
        [$this->allowPrefixes, $this->allowRegex] = self::parseEntries($allow);
        [$this->denyPrefixes, $this->denyRegex]   = self::parseEntries($extraDeny);
        $this->toolsExempt = array_map('strtolower', $toolsExempt ?? PathRules::DEFAULT_TOOLS_EXEMPT);
    }

    public function id(): string
    {
        return 'path';
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
     * @return WafResult[]  block-mode findings first
     */
    public function inspectAll(RequestData $data): array
    {
        $out = [];

        foreach ($data->items() as $item) {
            if ($item['source'] !== 'PATH' || $item['value'] === '') {
                continue;
            }

            $found = $item['key'] === 'path'
                ? $this->inspectPath($item['value'])
                : $this->inspectCarrier($item['key'], $item['value']);

            foreach ($found as $result) {
                $out[] = $result;

                if (\count($out) >= self::MAX_FINDINGS) {
                    break 2;
                }
            }
        }

        // Blocking findings first, so the first one in the list is the reason for a block.
        usort($out, static fn (WafResult $a, WafResult $b): int => ($b->mode === WafResult::MODE_BLOCK) <=> ($a->mode === WafResult::MODE_BLOCK));

        return $out;
    }

    /**
     * @return WafResult[]
     */
    private function inspectPath(string $rawPath): array
    {
        self::$injection ??= PathRules::injectionPatterns();
        self::$location  ??= PathRules::locationPatterns();

        $n      = PathNormalizer::normalize($rawPath);
        $sample = self::printable($n['canonical']);
        $out    = [];

        $add = function (string $rule) use (&$out, $sample): void {
            $mode = $this->modeFor($rule);

            if ($mode !== null) {
                $out[] = WafResult::hit($this->id(), $rule, 'PATH', 'path', $sample, $mode);
            }
        };

        // A. integrity
        foreach ($n['flags'] as $flag) {
            $add($flag);
        }

        // B. injection (never exempt)
        foreach (self::$injection as $rule => $pattern) {
            if (preg_match($pattern, $n['decoded']) === 1) {
                $add($rule);
            }
        }

        $path = $n['canonical'];

        // The operator's own deny list also overrides the exemptions below.
        if (self::matches($path, $this->denyPrefixes, $this->denyRegex)) {
            $add('path_extra_deny');
        }

        if ($this->exempt($path)) {
            return $out;
        }

        // C–F, location based.
        $entry = self::anyMatch($path, PathRules::directEntryPoints());

        foreach (['php_in_data_dir', 'direct_php_in_code', 'joomla_internal', 'scanner_probe'] as $rule) {
            if ($entry && ($rule === 'direct_php_in_code' || $rule === 'joomla_internal')) {
                continue;
            }

            if (preg_match(self::$location[$rule], $path) === 1) {
                $add($rule);
            }
        }

        if (preg_match(self::$location['admin_tool_probe'], $path, $m) === 1 && !$this->toolExempt($m[1])) {
            $add('admin_tool_probe');
        }

        return $out;
    }

    /**
     * PATH_INFO / PHP_SELF: the server has already decoded them once, so only
     * the injection class applies, on the value as received.
     *
     * @return WafResult[]
     */
    private function inspectCarrier(string $key, string $value): array
    {
        self::$injection ??= PathRules::injectionPatterns();

        $lower = strtr(rawurldecode($value), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
        $out   = [];

        foreach (self::$injection as $rule => $pattern) {
            $mode = $this->modeFor($rule);

            if ($mode !== null && preg_match($pattern, $lower) === 1) {
                $out[] = WafResult::hit($this->id(), $rule, 'PATH', $key, self::printable($value), $mode);
            }
        }

        return $out;
    }

    private function exempt(string $path): bool
    {
        return self::anyMatch($path, PathRules::exemptions())
            || self::matches($path, $this->allowPrefixes, $this->allowRegex);
    }

    private function toolExempt(string $segment): bool
    {
        foreach ($this->toolsExempt as $tool) {
            if ($tool !== '' && str_starts_with($segment, $tool)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string|null  'block' | 'log', or null when the rule is switched off
     */
    private function modeFor(string $rule): ?string
    {
        [$class, $default] = PathRules::RULES[$rule] ?? [PathRules::CLASS_A, 'log'];

        if ($class === PathRules::CLASS_F) {
            if ($this->probeMode === 'off') {
                return null;
            }

            $default = $this->probeMode === 'block' ? WafResult::MODE_BLOCK : WafResult::MODE_LOG;
        }

        if ($this->mode === 'log') {
            return WafResult::MODE_LOG;
        }

        if ($this->mode === 'block') {
            return WafResult::MODE_BLOCK;
        }

        return $default === 'block' ? WafResult::MODE_BLOCK : WafResult::MODE_LOG;
    }

    /**
     * @param  string[]  $lines
     *
     * @return array{0:string[],1:string[]}  prefixes (lower-case, start with "/") and compiled regexes
     */
    private static function parseEntries(array $lines): array
    {
        $prefixes = [];
        $regexes  = [];

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || $line[0] === '#') {
                continue;
            }

            if (str_starts_with($line, 're:')) {
                $pattern = '~' . str_replace('~', '\~', substr($line, 3)) . '~i';

                if (@preg_match($pattern, '') !== false) {
                    $regexes[] = $pattern;
                }

                continue;
            }

            if ($line[0] === '/') {
                $prefixes[] = strtolower($line);
            }
        }

        return [$prefixes, $regexes];
    }

    /**
     * @param  string[]  $prefixes
     * @param  string[]  $regexes
     */
    private static function matches(string $path, array $prefixes, array $regexes): bool
    {
        foreach ($prefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        return self::anyMatch($path, $regexes);
    }

    /**
     * @param  string[]  $patterns
     */
    private static function anyMatch(string $path, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $path) === 1) {
                return true;
            }
        }

        return false;
    }

    /** Make a hostile path safe to write to a one-line log. */
    private static function printable(string $s): string
    {
        $s = preg_replace('/[\x00-\x1f\x7f]/', '?', $s) ?? '';

        if (preg_match('//u', $s) !== 1) {
            $s = preg_replace('/[\x80-\xff]/', '?', $s) ?? '';
        }

        return $s;
    }
}
