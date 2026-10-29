<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Keeps the signed, refreshed copy of Cloudflare's edge ranges up to date
 * (the job behind the Scheduled Task and the CLI script).
 *
 * The list decides whom the plugin believes about the visitor IP, so a fetched
 * list is distrusted until it passes every check below, and a failed refresh
 * simply leaves the previous list (or the bundled one) in place:
 *
 *   - the two URLs are fixed (no configurable address, so no SSRF), HTTPS only;
 *   - IPv4 and IPv6 lists are each parsed on their own: right family, enough entries;
 *   - every line passes {@see CloudflareRanges::validCidr()} (well-formed, nothing
 *     broader than the sanity floor), and storing re-checks the whole list;
 *   - it must still contain most of the list it replaces and may not balloon:
 *     Cloudflare changes its ranges rarely and by small steps, so a big jump is
 *     more likely a hijacked response than news — the operator updates the
 *     bundled list with a release instead;
 *   - an identical list is not rewritten.
 */
final class CloudflareRefresher
{
    public const URL_V4 = 'https://www.cloudflare.com/ips-v4';
    public const URL_V6 = 'https://www.cloudflare.com/ips-v6';

    /** Entries of the previous list that must survive in the new one. */
    public const MIN_KEPT = 0.6;

    /** The new list may have at most this many times the previous count, plus slack. */
    public const MAX_GROWTH = 2.0;

    /** A fetched body larger than this is refused. */
    public const MAX_BYTES = 32768;

    private const MIN_V4 = 8;
    private const MIN_V6 = 4;

    public const OK        = 'updated';
    public const UNCHANGED = 'unchanged';
    public const REJECTED  = 'rejected';
    public const FAILED    = 'failed';

    /**
     * @param  callable(string):(string|null)  $fetch  returns the body of a URL, or null on any failure
     * @param  string[]|null                   $previous  the list currently in force (default: the bundled one)
     *
     * @return array{status:string,reason:string,count:int}
     */
    public static function refresh(callable $fetch, string $path, string $key, ?array $previous = null): array
    {
        if ($key === '') {
            return self::result(self::FAILED, 'no site secret, so a refreshed list could not be signed', 0);
        }

        $v4 = $fetch(self::URL_V4);
        $v6 = $fetch(self::URL_V6);

        if (!\is_string($v4) || !\is_string($v6)) {
            return self::result(self::FAILED, 'could not download both lists', 0);
        }

        if (\strlen($v4) > self::MAX_BYTES || \strlen($v6) > self::MAX_BYTES) {
            return self::result(self::REJECTED, 'a downloaded list is too large', 0);
        }

        $four = self::family($v4, false, self::MIN_V4);
        $six  = self::family($v6, true, self::MIN_V6);

        if ($four === null || $six === null) {
            return self::result(self::REJECTED, 'a downloaded list is malformed, of the wrong family or too short', 0);
        }

        $new = array_merge($four, $six);

        $prev = array_map('strtolower', $previous ?? CloudflareRanges::bundled());

        if ($prev !== []) {
            $kept = \count(array_intersect($prev, $new));

            if ($kept < self::MIN_KEPT * \count($prev)) {
                return self::result(self::REJECTED, 'too different from the list in force (' . $kept . ' of ' . \count($prev) . ' entries kept); update the bundled list with a release instead', \count($new));
            }

            if (\count($new) > self::MAX_GROWTH * \count($prev) + 5) {
                return self::result(self::REJECTED, 'much longer than the list in force', \count($new));
            }
        }

        $sorted = $new;
        $old    = $prev;
        sort($sorted);
        sort($old);

        if ($sorted === $old && self::stored($path, $key) === $sorted) {
            return self::result(self::UNCHANGED, 'the stored list is already current', \count($new));
        }

        if (!CloudflareRanges::store($path, $new, $key)) {
            return self::result(self::FAILED, 'could not write the refreshed list', \count($new));
        }

        return self::result(self::OK, 'stored', \count($new));
    }

    /**
     * Fetch a URL over HTTPS with a short timeout, no redirects and a size cap.
     * Returns null on any problem. Only the two fixed Cloudflare URLs are accepted.
     */
    public static function fetch(string $url): ?string
    {
        if ($url !== self::URL_V4 && $url !== self::URL_V6) {
            return null;
        }

        if (\function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
                CURLOPT_MAXFILESIZE    => self::MAX_BYTES,
                CURLOPT_USERAGENT      => 'ColorpackShield/0.1 (+https://colorpack.co.th)',
            ]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            unset($ch);

            return \is_string($body) && $code === 200 ? $body : null;
        }

        $ctx  = stream_context_create(['http' => ['timeout' => 10, 'follow_location' => 0, 'ignore_errors' => false, 'header' => "User-Agent: ColorpackShield/0.1\r\n"], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $body = @file_get_contents($url, false, $ctx, 0, self::MAX_BYTES + 1);

        return \is_string($body) ? $body : null;
    }

    /**
     * One family's lines, validated and normalised; null if anything is off.
     *
     * @return string[]|null
     */
    private static function family(string $text, bool $v6, int $min): ?array
    {
        $out = [];

        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            $cidr = CloudflareRanges::validCidr($line);

            if ($cidr === null || str_contains($cidr, ':') !== $v6) {
                return null;
            }

            $out[$cidr] = true;
        }

        return \count($out) >= $min ? array_keys($out) : null;
    }

    /**
     * @return string[]|null  the sorted stored list when it is valid and signed, else null
     */
    private static function stored(string $path, string $key): ?array
    {
        $list = CloudflareRanges::loadStored($path, $key);

        if ($list === null) {
            return null;
        }

        sort($list);

        return $list;
    }

    /**
     * @return array{status:string,reason:string,count:int}
     */
    private static function result(string $status, string $reason, int $count): array
    {
        return ['status' => $status, 'reason' => $reason, 'count' => $count];
    }
}
