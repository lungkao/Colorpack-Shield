<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

use Colorpack\Plugin\System\ColorpackShield\Geo\CidrMatcher;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Work out the real visitor IP, trusting a forwarding header only when the
 * hop that delivered it is one we know.
 *
 * Rules:
 *  1. Start from REMOTE_ADDR. If it is a configured trusted proxy (none by
 *     default — e.g. enter 127.0.0.1/::1 for HestiaCP's nginx in front of
 *     Apache, only after confirming that proxy appends to X-Forwarded-For;
 *     AUDIT.md C1/N1), walk the
 *     X-Forwarded-For chain right-to-left, skipping trusted proxies, to find
 *     the "edge": the first address that connected to our own infrastructure.
 *     No XFF chain? X-Real-IP is used the same way.
 *  2. If the edge is inside Cloudflare's ranges, the visitor IP is
 *     CF-Connecting-IP (must be a valid IP). Fallback: the XFF entry left of
 *     the edge, else the edge itself.
 *  3. Otherwise forwarding headers are NOT believed — a direct request to the
 *     origin can set any header. CF-Connecting-IP present in that case is
 *     reported via ClientIp::$headerIgnored.
 *
 * If the server already rewrote REMOTE_ADDR to the visitor (mod_remoteip,
 * nginx realip) the edge is not Cloudflare and REMOTE_ADDR is used as-is, which
 * is correct. Pure and Joomla-free so it is unit-testable.
 */
final class ClientIpResolver
{
    /**
     * @param  string[]  $cloudflareRanges  CIDRs of Cloudflare's edge.
     * @param  string[]  $trustedProxies    IPs/CIDRs of our own reverse proxies.
     */
    public function __construct(
        private readonly array $cloudflareRanges,
        private readonly array $trustedProxies = [],
        private readonly bool $trustCloudflare = true
    ) {
    }

    /**
     * @param  array<string, mixed>  $server  Normally $_SERVER.
     */
    public function resolve(array $server): ClientIp
    {
        $remote = self::normalise((string) ($server['REMOTE_ADDR'] ?? ''));

        if ($remote === '') {
            return new ClientIp('', '', ClientIp::VIA_DIRECT);
        }

        $cfHeader = self::normalise((string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''));
        $hasCfRaw = trim((string) ($server['HTTP_CF_CONNECTING_IP'] ?? '')) !== '';

        // Step 1: find the edge.
        $chain = $this->forwardChain($server);   // left (client side) → right (nearest hop)
        $edge  = $remote;
        $idx   = \count($chain);                 // index of the edge within [chain..., remote]
        $viaProxy = false;

        if (CidrMatcher::matchesAny($remote, $this->trustedProxies)) {
            $viaProxy = true;

            for ($i = \count($chain) - 1; $i >= 0; $i--) {
                $hop = $chain[$i];

                if (CidrMatcher::matchesAny($hop, $this->trustedProxies)) {
                    continue;
                }

                $edge = $hop;
                $idx  = $i;
                break;
            }

            if ($edge === $remote) {
                // Everything was trusted (or no chain): the edge really is the local peer.
                $idx = \count($chain);
            }
        }

        // Step 2: Cloudflare edge → believe CF-Connecting-IP.
        if ($this->trustCloudflare && CidrMatcher::matchesAny($edge, $this->cloudflareRanges)) {
            if ($cfHeader !== '') {
                return new ClientIp($cfHeader, $edge, ClientIp::VIA_CLOUDFLARE);
            }

            if ($idx > 0 && isset($chain[$idx - 1])) {
                return new ClientIp($chain[$idx - 1], $edge, ClientIp::VIA_CLOUDFLARE_NOHEADER);
            }

            return new ClientIp($edge, $edge, ClientIp::VIA_CLOUDFLARE_NOHEADER);
        }

        // Step 3: not Cloudflare.
        $ignored = $hasCfRaw;

        if ($viaProxy && $edge !== $remote) {
            return new ClientIp($edge, $edge, ClientIp::VIA_PROXY, $ignored);
        }

        return new ClientIp($edge, $edge, ClientIp::VIA_DIRECT, $ignored);
    }

    /**
     * Valid IPs from X-Forwarded-For (or X-Real-IP when XFF is absent), in
     * header order. Invalid tokens are dropped so garbage cannot become "the
     * client".
     *
     * @param  array<string, mixed>  $server
     * @return string[]
     */
    private function forwardChain(array $server): array
    {
        $out = [];
        $xff = (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '');

        if (trim($xff) !== '') {
            foreach (explode(',', $xff) as $token) {
                $ip = self::normalise($token);

                if ($ip !== '') {
                    $out[] = $ip;
                }
            }

            if ($out !== []) {
                return $out;
            }
        }

        $real = self::normalise((string) ($server['HTTP_X_REAL_IP'] ?? ''));

        return $real !== '' ? [$real] : [];
    }

    /**
     * Trim, strip brackets / ":port", reject non-IPs, and unmap IPv4-mapped
     * IPv6 (::ffff:1.2.3.4 → 1.2.3.4) so CIDR comparison is family-correct.
     * Returns '' when not a valid IP.
     */
    public static function normalise(string $raw): string
    {
        $raw = trim($raw);

        if ($raw === '' || \strlen($raw) > 64) {
            return '';
        }

        // "[2001:db8::1]:443" or "[2001:db8::1]"
        if ($raw[0] === '[') {
            $end = strpos($raw, ']');

            if ($end === false) {
                return '';
            }

            $raw = substr($raw, 1, $end - 1);
        } elseif (substr_count($raw, ':') === 1 && str_contains($raw, '.')) {
            // "1.2.3.4:5678"
            $raw = substr($raw, 0, (int) strpos($raw, ':'));
        }

        if (filter_var($raw, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        $bin = @inet_pton($raw);

        if ($bin === false) {
            return '';
        }

        if (\strlen($bin) === 16 && strncmp($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) {
            return (string) inet_ntop(substr($bin, 12));
        }

        return (string) inet_ntop($bin);
    }
}
