<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Rules;

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The single table behind header inspection (PLAN-WAF-HEADERS-PATHS.md §3):
 * which headers are scanned, how, and what each rule is worth by default.
 *
 * Headers with a known grammar are validated against it (an allowlist catches
 * every injection with no false positives). Free-text headers get a small set
 * of targeted rules. Secrets, tokens and structured metadata are never looked
 * at. Anything not named here is ignored unless the operator lists it.
 */
final class HeaderRules
{
    public const P_IP          = 'ip';
    public const P_FORWARDED   = 'forwarded';
    public const P_NEGOTIATION = 'negotiation';
    public const P_CONTENTTYPE = 'content_type';
    public const P_HOST        = 'host';
    public const P_FREETEXT    = 'freetext';
    public const P_NEVER       = 'never';
    public const P_UNKNOWN     = 'unknown';

    /** Longest value any scanned header may carry before it is flagged. */
    public const MAX_FREETEXT = 2048;
    public const MAX_IPLIST   = 2048;

    /** Rule id => default mode. */
    public const RULES = [
        'control_chars'          => 'block',
        'php_object_injection'   => 'block',
        'shellshock'             => 'block',
        'jndi_lookup'            => 'block',
        'php_open_tag'           => 'block',
        'malformed_ip_header'    => 'block',
        'malformed_forwarded'    => 'block',
        'malformed_negotiation'  => 'block',
        'malformed_host'         => 'block',
        'malformed_content_type' => 'log',
        'sqli_strict'            => 'log',
        'xss_strict'             => 'log',
        'traversal'              => 'log',
        'oversize'               => 'log',
    ];

    /** lower-case header name => profile */
    private const PROFILES = [
        // Carry IP addresses.
        'x-forwarded-for' => self::P_IP, 'x-real-ip' => self::P_IP, 'client-ip' => self::P_IP,
        'true-client-ip' => self::P_IP, 'x-forwarded' => self::P_IP, 'x-cluster-client-ip' => self::P_IP,
        'cf-connecting-ip' => self::P_IP, 'x-originating-ip' => self::P_IP, 'x-remote-ip' => self::P_IP,
        'x-remote-addr' => self::P_IP, 'x-client-ip' => self::P_IP,
        'forwarded' => self::P_FORWARDED,
        // Content negotiation and connection hygiene.
        'accept' => self::P_NEGOTIATION, 'accept-language' => self::P_NEGOTIATION,
        'accept-encoding' => self::P_NEGOTIATION, 'accept-charset' => self::P_NEGOTIATION,
        'content-length' => self::P_NEGOTIATION, 'connection' => self::P_NEGOTIATION,
        'cache-control' => self::P_NEGOTIATION, 'pragma' => self::P_NEGOTIATION,
        'upgrade-insecure-requests' => self::P_NEGOTIATION, 'dnt' => self::P_NEGOTIATION,
        'content-type' => self::P_CONTENTTYPE,
        // Host names.
        'host' => self::P_HOST, 'x-forwarded-host' => self::P_HOST, 'x-forwarded-server' => self::P_HOST,
        // Free text.
        'user-agent' => self::P_FREETEXT, 'referer' => self::P_FREETEXT, 'origin' => self::P_FREETEXT,
        'x-requested-with' => self::P_FREETEXT, 'from' => self::P_FREETEXT,
        // Secrets, tokens, structured metadata: never scanned, never logged.
        'authorization' => self::P_NEVER, 'proxy-authorization' => self::P_NEVER, 'cookie' => self::P_NEVER,
        'x-joomla-token' => self::P_NEVER, 'x-csrf-token' => self::P_NEVER, 'x-xsrf-token' => self::P_NEVER,
        'x-forwarded-proto' => self::P_NEVER, 'x-forwarded-port' => self::P_NEVER,
        'x-forwarded-ssl' => self::P_NEVER, 'front-end-https' => self::P_NEVER,
    ];

    /** Name prefixes that are never scanned (Cloudflare, client hints, fetch metadata, AWS). */
    private const NEVER_PREFIXES = ['cf-', 'sec-', 'x-amzn-', 'x-amz-', 'x-cloud-trace', 'x-edge-'];

    /** Cloudflare's own CF-Connecting-IP is an IP header despite the "cf-" prefix. */
    public static function profile(string $lowerName): string
    {
        if (isset(self::PROFILES[$lowerName])) {
            return self::PROFILES[$lowerName];
        }

        foreach (self::NEVER_PREFIXES as $prefix) {
            if (str_starts_with($lowerName, $prefix)) {
                return self::P_NEVER;
            }
        }

        return self::P_UNKNOWN;
    }

    /** "Valid IP list": comma-separated addresses, optional port/brackets, or the word "unknown". */
    public static function validIpList(string $value): bool
    {
        if (\strlen($value) > self::MAX_IPLIST) {
            return false;
        }

        $value = trim($value);

        if ($value === '') {
            return true;
        }

        $tokens = explode(',', $value);

        if (\count($tokens) > 50) {
            return false;
        }

        foreach ($tokens as $token) {
            $token = trim($token);

            if (strcasecmp($token, 'unknown') === 0) {
                continue;
            }

            if (ClientIpResolver::normalise($token) === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * RFC 7239 "Forwarded": elements separated by ",", pairs by ";", each
     * key=value with key in for|by|host|proto and a harmless token/quoted value.
     */
    public static function validForwarded(string $value): bool
    {
        if (\strlen($value) > self::MAX_IPLIST) {
            return false;
        }

        $value = trim($value);

        if ($value === '') {
            return true;
        }

        foreach (explode(',', $value) as $element) {
            foreach (explode(';', $element) as $pair) {
                if (!preg_match('/^\s*(?:for|by|host|proto)\s*=\s*(?:"[A-Za-z0-9._:\[\]@\-]{0,100}"|[A-Za-z0-9._:\[\]@\-]{0,100})\s*$/i', $pair)) {
                    return false;
                }
            }
        }

        return true;
    }

    public static function validNegotiation(string $lowerName, string $value): bool
    {
        if ($lowerName === 'content-length') {
            return (bool) preg_match('/^\s*\d{1,12}\s*$/', $value);
        }

        if ($lowerName === 'accept-language') {
            return (bool) preg_match('/^[A-Za-z0-9 ,;=.*\-_]{0,512}$/', $value);
        }

        return (bool) preg_match('/^[A-Za-z0-9 ,;=.*\/+\-_():"]{0,1024}$/', $value);
    }

    public static function validContentType(string $value): bool
    {
        return (bool) preg_match(
            '/^\s*[\w.+-]{1,127}\/[\w.+-]{1,127}(?:\s*;\s*[\w.-]+\s*=\s*(?:"[^"\r\n]*"|[^\s;"]+))*\s*;?\s*$/',
            $value
        );
    }

    /** One or more comma-separated host[:port] values (hostname, IPv4, or bracketed IPv6). */
    public static function validHost(string $value): bool
    {
        $value = trim($value);

        if ($value === '' || \strlen($value) > 512) {
            return false;
        }

        foreach (explode(',', $value) as $host) {
            $host = trim($host);

            if (!preg_match(
                '/^(?:[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,62})(?:\.[A-Za-z0-9_\-]{1,63})*\.?|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?$/',
                $host
            )) {
                return false;
            }
        }

        return true;
    }

    /**
     * High-confidence injection rules that make sense in ANY scanned header.
     * Order matters (first match is reported). Run on the normalised value.
     *
     * @return array<string, string>  rule => pattern
     */
    public static function injectionPatterns(): array
    {
        return [
            // PHP object injection, e.g. Joomla's session handler RCE family: }__test|O:21:"JDatabaseDriverMysqli":…{
            'php_object_injection' => '/\bo:\d{1,4}:"[^"]{1,100}":\d+:\{|\}__[a-z_]{1,20}\||\ba:\d{1,4}:\{(?:i|s):/',
            // Shellshock: () { :;};  and the follow-up variant () { _; } >_[$($())] { id; }
            'shellshock'           => '/\(\)\s*\{[^}]*\}\s*[;>]/',
            // Log4Shell-style lookups, including nested/obfuscated forms: ${jndi:…}, ${${lower:j}ndi…}, ${::-j}…
            'jndi_lookup'          => '/\$\{\s*(?:jndi|lower|upper|env|sys|java|date|ctx|main|bundle|k8s|docker|log4j|spring|sd|web|\$\{|:|-)/',
            'php_open_tag'         => '/<\?(?:php|=)/',
        ];
    }

    /**
     * Medium/low-confidence rules for free-text headers (log-only by default).
     *
     * @return array<string, string[]>  rule => patterns
     */
    public static function strictPatterns(): array
    {
        return [
            'sqli_strict' => [
                '/\bunion\b\s+(?:all\s+)?\bselect\b/',
                '/;\s*(?:select|insert|update|delete|drop|alter|create|truncate)\b/',
                '/\b(?:sleep|benchmark|pg_sleep)\s*\(/',
                '/\b(?:updatexml|extractvalue)\s*\(/',
                // quote-led tautology: ' or 1=1 (a bare "or 1=1" in free text is not flagged)
                '/[\'"]\s*(?:or|and)\b\s*[\'"]?\d{1,6}[\'"]?\s*=\s*[\'"]?\d{1,6}/',
            ],
            'xss_strict' => [
                '/<\s*script[\s>\/]/',
                '/\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|animationstart|pageshow)\s*=/',
                '/javascript\s*:/',
                '/<\s*(?:iframe|svg|object|embed)[\s>\/]/',
            ],
            'traversal' => [
                '#(?:\.\.[\/\\\\]){2,}#',
            ],
        ];
    }
}
