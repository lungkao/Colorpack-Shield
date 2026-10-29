<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Diagnostics;

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Proxy spoof self-test (AUDIT.md N1): can a client forge its IP through the
 * proxy that sits in front of this PHP process?
 *
 * The tester sends a request that carries the strongest forgery — a fake
 * Cloudflare edge in X-Forwarded-For, a made-up visitor in CF-Connecting-IP
 * and another in X-Real-IP. The plugin answers with what actually reached it
 * (report()). evaluate() then asks: if the peer that delivered this request
 * were declared a trusted proxy, would ClientIpResolver adopt one of the
 * forged values?  Yes → SPOOFABLE: do not add that proxy to "Own reverse
 * proxies" and fix the proxy first.
 */
final class ProxyProbe
{
    public const HEADER = 'X-Colorpack-Probe';

    /** Inside Cloudflare's 104.16.0.0/13: what an attacker would claim as the edge. */
    public const FAKE_EDGE = '104.16.0.1';

    /** TEST-NET-1 markers; never real visitors. */
    public const MARK_VISITOR = '192.0.2.77';
    public const MARK_REAL    = '192.0.2.78';

    public const NO_PROXY     = 'no_proxy';
    public const SAFE         = 'safe';
    public const SPOOFABLE    = 'spoofable';
    public const INCONCLUSIVE = 'inconclusive';

    /**
     * Headers the tester must send.
     *
     * @return array<string,string>
     */
    public static function requestHeaders(string $token): array
    {
        return [
            self::HEADER        => $token,
            'X-Forwarded-For'   => self::FAKE_EDGE,
            'CF-Connecting-IP'  => self::MARK_VISITOR,
            'X-Real-IP'         => self::MARK_REAL,
        ];
    }

    /**
     * What the origin saw — the plugin's reply to a valid probe.
     *
     * @param  array<string,mixed>  $server
     * @param  string[]             $trustedProxies  Currently configured.
     * @param  string               $remoteAddr      The ORIGINAL REMOTE_ADDR.
     *
     * @return array<string,mixed>
     */
    public static function report(array $server, string $remoteAddr, array $trustedProxies, ClientIp $actual): array
    {
        return [
            'probe'             => 1,
            'remote_addr'       => $remoteAddr,
            'xff'               => (string) ($server['HTTP_X_FORWARDED_FOR'] ?? ''),
            'x_real_ip'         => (string) ($server['HTTP_X_REAL_IP'] ?? ''),
            'cf_connecting_ip'  => (string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''),
            'trusted_proxies'   => array_values($trustedProxies),
            'actual'            => [
                'ip'             => $actual->ip,
                'via'            => $actual->via,
                'header_ignored' => $actual->headerIgnored,
            ],
        ];
    }

    /**
     * @param  array<string,mixed>  $report
     * @param  string[]             $cloudflareRanges
     *
     * @return array{verdict:string,reasons:string[]}
     */
    public static function evaluate(array $report, array $cloudflareRanges): array
    {
        $peer = ClientIpResolver::normalise((string) ($report['remote_addr'] ?? ''));

        if (($report['probe'] ?? null) !== 1 || $peer === '') {
            return self::result(self::INCONCLUSIVE, ['The reply was not a valid probe report.']);
        }

        if (self::isPublic($peer)) {
            return self::result(self::NO_PROXY, [
                "The web server was reached directly from public address $peer: no loopback/private proxy is in this path.",
                'Leave "Own reverse proxies" empty.',
            ]);
        }

        $server = [
            'REMOTE_ADDR'           => $peer,
            'HTTP_X_FORWARDED_FOR'  => (string) ($report['xff'] ?? ''),
            'HTTP_X_REAL_IP'        => (string) ($report['x_real_ip'] ?? ''),
            'HTTP_CF_CONNECTING_IP' => (string) ($report['cf_connecting_ip'] ?? ''),
        ];

        // What would happen if this peer were declared a trusted proxy?
        $resolved = (new ClientIpResolver($cloudflareRanges, [$peer], true))->resolve($server);
        $forged   = [self::MARK_VISITOR, self::MARK_REAL, self::FAKE_EDGE];

        // The address the proxy recorded for whoever connected to it: the last
        // X-Forwarded-For entry, else X-Real-IP.
        $chain = self::chain($server['HTTP_X_FORWARDED_FOR']);
        $seen  = $chain !== []
            ? $chain[\count($chain) - 1]
            : ClientIpResolver::normalise($server['HTTP_X_REAL_IP']);

        if ($seen === '') {
            return self::result(self::INCONCLUSIVE, [
                'No forwarding header reached the web server (the proxy strips them), so no visitor IP can be learned from it.',
            ]);
        }

        // The proxy handed our forged value straight through.
        if (\in_array($seen, $forged, true) || (\in_array($resolved->ip, $forged, true) && self::isPublic($seen))) {
            return self::result(self::SPOOFABLE, [
                "With $peer trusted, a client-supplied value ({$resolved->ip}) would be adopted as the visitor IP.",
                'The proxy forwards client-supplied X-Forwarded-For / X-Real-IP unchanged. Do NOT add it to "Own reverse proxies" until it overwrites or appends them itself.',
            ]);
        }

        // A loopback/private tester makes the proxy's appended address look
        // "trusted" too, so the result would be an artefact. Re-run from outside.
        if (!self::isPublic($seen)) {
            return self::result(self::INCONCLUSIVE, [
                "The proxy recorded the client as $seen (loopback/private), so this test came from the server side.",
                'Run the test from another machine, or connect to the server\'s public IP (--connect), then read the result again.',
            ]);
        }

        return self::result(self::SAFE, [
            "With $peer trusted, the forged values were NOT adopted (visitor resolved as {$resolved->ip}).",
            'The proxy appends/overwrites forwarding headers. It is reasonable to add it to "Own reverse proxies".',
        ]);
    }

    /**
     * @return string[]
     */
    private static function chain(string $xff): array
    {
        $out = [];

        foreach (explode(',', $xff) as $token) {
            $ip = ClientIpResolver::normalise($token);

            if ($ip !== '') {
                $out[] = $ip;
            }
        }

        return $out;
    }

    private static function isPublic(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /**
     * @param  string[]  $reasons
     *
     * @return array{verdict:string,reasons:string[]}
     */
    private static function result(string $verdict, array $reasons): array
    {
        return ['verdict' => $verdict, 'reasons' => $reasons];
    }
}
