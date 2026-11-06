<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Vulnerable;

use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Keeps a copy of the JED Vulnerable Extensions List on this site and refreshes it at most once a day.
 *
 * Nothing about this site is ever sent: both requests are plain GETs of a public feed. The small "verify"
 * hash is asked first, and the 300 KB feed is downloaded only when the hash changed. Fail-open: any problem
 * keeps the copy already stored. Network access is injected ($get) so it is testable.
 */
final class VelFeed
{
    public const FEED   = 'https://extensions.joomla.org/vel-feed';
    public const VERIFY = 'https://extensions.joomla.org/vel-verify';

    /** A stored copy younger than this is not even asked about. */
    public const MAX_AGE = 86400;

    public function __construct(private readonly ScanStore $store)
    {
    }

    /**
     * @return array{at:int,hash:string,rules:array<int,array<string,mixed>>}|null
     */
    public function stored(): ?array
    {
        $d = $this->store->read('feed');

        return \is_array($d) && isset($d['at'], $d['rules']) && \is_array($d['rules']) ? ['at' => (int) $d['at'], 'hash' => (string) ($d['hash'] ?? ''), 'rules' => $d['rules']] : null;
    }

    /**
     * @param  callable(string):?string  $get    returns the response body of a URL, or null on any failure
     *
     * @return string  'fresh' (not asked, copy is recent) | 'unchanged' | 'updated' | 'failed'
     */
    public function refresh(callable $get, int $now, bool $force = false): string
    {
        $have = $this->stored();

        if (!$force && $have !== null && $have['at'] > $now - self::MAX_AGE) {
            return 'fresh';
        }

        $v    = json_decode((string) $get(self::VERIFY), true);
        $hash = \is_array($v) && \is_string($v['data'] ?? null) ? $v['data'] : '';

        if (!$force && $have !== null && $hash !== '' && $hash === $have['hash']) {
            $this->store->write('feed', ['at' => $now, 'hash' => $have['hash'], 'rules' => $have['rules']]);

            return 'unchanged';
        }

        $feed  = json_decode((string) $get(self::FEED), true);
        $items = \is_array($feed) && \is_array($feed['data']['items'] ?? null) ? $feed['data']['items'] : null;

        if ($items === null) {
            return 'failed';
        }

        return $this->store->write('feed', ['at' => $now, 'hash' => $hash, 'rules' => VelRules::fromFeed($items)]) ? 'updated' : 'failed';
    }

    /** A plain GET with cURL: short timeout, no redirects to other hosts, https only. Null on any failure. */
    public static function curlGet(string $url): ?string
    {
        if (!str_starts_with($url, 'https://extensions.joomla.org/') || !\function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init($url);

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 45,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'ColorpackShield',
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        ]);

        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return \is_string($body) && $code === 200 ? $body : null;
    }
}
