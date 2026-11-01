<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Which country an IP address comes from, for display next to the address in the admin screens.
 *
 * Two sources, cheapest first, both remembered for 30 days in small files in the cache folder:
 *  1. Cloudflare's own CF-IPCountry header, captured while the request is being handled ({@see remember()});
 *     free, exact, and the address never leaves the server;
 *  2. a lookup against ipwho.is for addresses seen only in the log: public addresses only, at most
 *     {@see MAX_LOOKUPS} per page view, 2-second timeout, and only when the setting allows it.
 *
 * Fails quiet: any problem returns null and the screen just shows the address.
 */
final class IpCountry
{
    public const MAX_LOOKUPS = 12;

    private const TTL = 30 * 86400;

    private FileStateStore $store;

    private int $lookups = 0;

    /**
     * @param  callable(string):?string|null  $fetch  returns a two-letter code for a public address (null = unknown); defaults to ipwho.is
     */
    public function __construct(string $dir, private readonly mixed $fetch = null, private readonly ?int $clock = null)
    {
        $this->store = new FileStateStore($dir, 2000, 262144, 8);
    }

    /** Keep the country Cloudflare reported for this visitor (never trust anything but two letters). */
    public function remember(string $ip, string $code): void
    {
        $code = strtoupper(trim($code));

        if (preg_match('/^[A-Z]{2}$/', $code) !== 1 || $code === 'XX' || $code === 'T1' || !self::isPublic($ip)) {
            return;
        }

        $now = $this->now();

        $this->store->mutate($this->key($ip), $now, static fn (?array $e): array => ['c' => $code, 'exp' => $now + self::TTL]);
    }

    public function lookup(string $ip, bool $allowRemote): ?string
    {
        if (!self::isPublic($ip)) {
            return null;
        }

        $now = $this->now();
        $e   = $this->store->get($this->key($ip), $now);

        if ($e !== null) {
            return ($e['c'] ?? '') === '' ? null : (string) $e['c'];
        }

        if (!$allowRemote || $this->lookups >= self::MAX_LOOKUPS) {
            return null;
        }

        $this->lookups++;
        $fetch = $this->fetch ?? [self::class, 'fetchRemote'];
        $code  = $fetch($ip);
        $code  = \is_string($code) && preg_match('/^[A-Za-z]{2}$/', $code) === 1 ? strtoupper($code) : null;

        // An unknown answer is remembered too (for a day), so a dead service is not asked again and again.
        $this->store->mutate($this->key($ip), $now, static fn (?array $old): array => ['c' => $code ?? '', 'exp' => $now + ($code === null ? 86400 : self::TTL)]);

        return $code;
    }

    /** "🇹🇭 TH": the code always shown, the flag only as decoration. */
    public static function label(string $code): string
    {
        $flag = '';

        foreach (str_split($code) as $c) {
            $flag .= mb_chr(0x1F1E6 + \ord($c) - \ord('A'), 'UTF-8');
        }

        return $flag . ' ' . $code;
    }

    public static function isPublic(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private function key(string $ip): string
    {
        return 'cc:' . substr(hash('sha256', $ip), 0, 24);
    }

    private function now(): int
    {
        return $this->clock ?? time();
    }

    public static function fetchRemote(string $ip): ?string
    {
        if (!\function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init('https://ipwho.is/' . rawurlencode($ip) . '?fields=success,country_code');

        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2, CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);

        $body = curl_exec($ch);
        $http = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if (!\is_string($body) || $http !== 200) {
            return null;
        }

        $j = json_decode($body, true);

        return \is_array($j) && ($j['success'] ?? false) === true && \is_string($j['country_code'] ?? null) ? $j['country_code'] : null;
    }
}
