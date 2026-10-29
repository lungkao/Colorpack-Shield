<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Cloudflare's edge IP ranges: the bundled fallback plus a validated loader for
 * a refreshed copy.
 *
 * The list decides whom we believe about the visitor IP, so a bad list is a
 * security hole, not a nuisance: "0.0.0.0/0" would let anyone spoof
 * CF-Connecting-IP. parse() therefore refuses a whole list on any malformed
 * line, any range broader than the sanity floor, or a suspiciously small
 * list — and callers fall back to the bundled ranges.
 *
 * Bundled ranges verified against https://www.cloudflare.com/ips-v4 and
 * https://www.cloudflare.com/ips-v6 on 2026-10-28. Refresh them with each
 * release; the Scheduled Task / CLI script keeps a fresher, signed copy on disk.
 */
final class CloudflareRanges
{
    public const V4 = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
    ];

    public const V6 = [
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /**
     * Broadest acceptable range per family (shorter mask = refused). Cloudflare's
     * real prefixes are /13 and longer (IPv4) and /29 and longer (IPv6); the
     * floors leave a little slack, not a continent.
     */
    private const MIN_BITS_V4 = 12;
    private const MIN_BITS_V6 = 24;

    /** A refreshed list smaller than this is treated as truncated/corrupt. */
    private const MIN_ENTRIES = 10;

    /**
     * Where the refreshed, signed copy lives for a Joomla root. One location for
     * every application: JPATH_CACHE differs between site, administrator and api.
     */
    public static function defaultPath(string $joomlaRoot): string
    {
        return rtrim($joomlaRoot, '/\\') . '/cache/colorpack_shield/cloudflare-ips.txt';
    }

    /**
     * @return string[]
     */
    public static function bundled(): array
    {
        return array_merge(self::V4, self::V6);
    }

    /**
     * Parse a downloaded list (one CIDR per line; blank lines and "#" comments
     * ignored). Returns null when the list must not be trusted.
     *
     * @return string[]|null
     */
    public static function parse(string $text): ?array
    {
        $out = [];

        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || $line[0] === '#') {
                continue;
            }

            $cidr = self::validCidr($line);

            if ($cidr === null) {
                return null;
            }

            $out[$cidr] = true;
        }

        $out = array_keys($out);

        return \count($out) >= self::MIN_ENTRIES ? $out : null;
    }

    /**
     * Load a refreshed list from disk, or fall back to the bundled ranges.
     *
     * The refreshed file decides who may set the visitor IP, so it is only
     * believed when ALL of these hold (AUDIT.md C2): a key is supplied, the file
     * is not world-writable, a sidecar "<file>.sig" carries a valid HMAC of its
     * exact bytes, and the list passes parse(). Someone who can merely write
     * into the cache folder cannot produce the signature without the site
     * secret the key is derived from.
     *
     * @param  string  $key  See deriveKey(); '' = refuse every refreshed file.
     *
     * @return string[]
     */
    public static function load(string $path = '', string $key = ''): array
    {
        return self::loadStored($path, $key) ?? self::bundled();
    }

    /**
     * Like load(), but null (instead of the bundled list) when there is no
     * refreshed file that passes every check. Lets a caller tell "the stored copy
     * equals the bundled list" from "there is no stored copy".
     *
     * @return string[]|null
     */
    public static function loadStored(string $path, string $key): ?array
    {
        if ($path === '' || $key === '' || !is_file($path) || !is_readable($path)) {
            return null;
        }

        $perms = @fileperms($path);

        if ($perms === false || ($perms & 0002) !== 0) {
            return null;
        }

        $text = @file_get_contents($path, false, null, 0, 65536);
        $sig  = @file_get_contents($path . '.sig', false, null, 0, 128);

        if ($text === false || $sig === false || !hash_equals(self::sign($text, $key), trim($sig))) {
            return null;
        }

        return self::parse($text);
    }

    /**
     * Write a refreshed list plus its signature. For the (planned) refresh
     * task; returns false and writes nothing if the list is not acceptable.
     *
     * @param  string[]  $ranges
     */
    public static function store(string $path, array $ranges, string $key): bool
    {
        $text = implode("\n", $ranges) . "\n";

        if ($key === '' || self::parse($text) === null) {
            return false;
        }

        $dir = \dirname($path);

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }

        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';

        if (@file_put_contents($tmp, $text, LOCK_EX) === false) {
            return false;
        }

        @chmod($tmp, 0644);
        $sigTmp = $tmp . '.sig';

        if (@file_put_contents($sigTmp, self::sign($text, $key) . "\n", LOCK_EX) === false) {
            @unlink($tmp);

            return false;
        }

        @chmod($sigTmp, 0644);

        // Data first, then signature: a reader in between sees a mismatch and
        // simply uses the bundled list.
        if (!@rename($tmp, $path) || !@rename($sigTmp, $path . '.sig')) {
            @unlink($tmp);
            @unlink($sigTmp);

            return false;
        }

        return true;
    }

    public static function sign(string $text, string $key): string
    {
        return hash_hmac('sha256', 'colorpack_shield-cf-ranges|' . $text, $key);
    }

    /**
     * Signing key derived from the Joomla site secret. '' if there is no secret
     * (then refreshed files are never trusted).
     */
    public static function deriveKey(string $siteSecret): string
    {
        return $siteSecret === '' ? '' : hash_hmac('sha256', 'colorpack_shield-cf-ranges-key', $siteSecret);
    }

    /**
     * Normalised CIDR when well-formed and not too broad, else null.
     */
    public static function validCidr(string $cidr): ?string
    {
        if (substr_count($cidr, '/') !== 1) {
            return null;
        }

        [$addr, $bitsRaw] = explode('/', $cidr, 2);

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
