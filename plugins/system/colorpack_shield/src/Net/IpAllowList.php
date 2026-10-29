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
 * Trusted IPs ("never block these"): parsing, matching, and safely adding the
 * current admin's address.
 *
 * Text format: one IP or CIDR per line (commas also split). "#" starts a
 * comment. Invalid lines are ignored at match time and reported by invalid(),
 * so a typo can never widen the list. Entries broader than /8 (IPv4) or /16
 * (IPv6) are refused: a whitelist that covers a continent is a disabled
 * firewall, not a whitelist.
 */
final class IpAllowList
{
    /** Hard cap so automatic additions cannot grow the list without bound. */
    public const MAX_ENTRIES = 50;

    private const MIN_BITS_V4 = 8;
    private const MIN_BITS_V6 = 16;

    /** @var string[] */
    private array $entries = [];

    /** @var string[] */
    private array $invalid = [];

    public static function fromText(string $text): self
    {
        $list = new self();

        foreach (preg_split('/[\r\n,]+/', $text) ?: [] as $line) {
            $hash = strpos($line, '#');

            if ($hash !== false) {
                $line = substr($line, 0, $hash);
            }

            $line = trim($line);

            if ($line === '') {
                continue;
            }

            $entry = self::normaliseEntry($line);

            if ($entry === null) {
                $list->invalid[] = $line;

                continue;
            }

            $list->entries[$entry] = $entry;
        }

        $list->entries = array_values($list->entries);

        return $list;
    }

    public function matches(string $ip): bool
    {
        $ip = ClientIpResolver::normalise($ip);

        return $ip !== '' && CidrMatcher::matchesAny($ip, $this->entries);
    }

    /**
     * @return string[]
     */
    public function entries(): array
    {
        return $this->entries;
    }

    /**
     * @return string[]  Lines that could not be used.
     */
    public function invalid(): array
    {
        return $this->invalid;
    }

    /**
     * Text with $ip added on a new line — or the text unchanged when the IP is
     * invalid, already covered by an entry, or the list is at its cap. The
     * original text (comments included) is preserved.
     */
    public static function appendIp(string $text, string $ip): string
    {
        $ip = ClientIpResolver::normalise($ip);

        if ($ip === '') {
            return $text;
        }

        $list = self::fromText($text);

        if ($list->matches($ip) || \count($list->entries) >= self::MAX_ENTRIES) {
            return $text;
        }

        $text = rtrim($text);

        return ($text === '' ? '' : $text . "\n") . $ip;
    }

    /**
     * May this resolved address be added automatically?
     *
     * Refuses anything that could whitelist more than one admin: an empty IP,
     * a Cloudflare edge address (shared by every visitor routed through it),
     * our own reverse proxy (loopback / the nginx in front of Apache), or a
     * result where Cloudflare was detected but sent no visitor header.
     *
     * @param  string[]  $cloudflareRanges
     * @param  string[]  $trustedProxies
     */
    public static function isSafeToAutoAdd(ClientIp $client, array $cloudflareRanges, array $trustedProxies): bool
    {
        if ($client->ip === '' || $client->via === ClientIp::VIA_CLOUDFLARE_NOHEADER) {
            return false;
        }

        // Loopback and private/reserved addresses are refused even when no
        // proxy is configured: if our own nginx or a load balancer is
        // unconfigured, EVERY visitor looks like that address, and trusting it
        // would trust the whole internet. Add LAN admins by hand.
        if (filter_var($client->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        return !CidrMatcher::matchesAny($client->ip, $cloudflareRanges)
            && !CidrMatcher::matchesAny($client->ip, $trustedProxies);
    }

    private static function normaliseEntry(string $line): ?string
    {
        if (!str_contains($line, '/')) {
            $ip = ClientIpResolver::normalise($line);

            return $ip !== '' ? $ip : null;
        }

        if (substr_count($line, '/') !== 1) {
            return null;
        }

        [$addr, $bitsRaw] = explode('/', $line, 2);
        $addr             = trim($addr);
        $bitsRaw          = trim($bitsRaw);

        if (!ctype_digit($bitsRaw) || filter_var($addr, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $bits = (int) $bitsRaw;
        $v6   = str_contains($addr, ':');

        if ($bits > ($v6 ? 128 : 32) || $bits < ($v6 ? self::MIN_BITS_V6 : self::MIN_BITS_V4)) {
            return null;
        }

        return strtolower($addr) . '/' . $bits;
    }
}
