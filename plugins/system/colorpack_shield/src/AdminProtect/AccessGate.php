<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The decision behind the administrator access key (A4) and address list (A5), pure.
 *
 * Access is granted when the address is on the list (and that address can be trusted as a
 * single visitor) OR the browser holds a valid access cookie. A visit with the right key
 * exchanges it for the cookie. Everything else is a plain 404.
 */
final class AccessGate
{
    public const PARAM = 'cpskey';
    public const COOKIE = 'cps_gate';

    public const ALLOW    = 'allow';
    public const DENY     = 'deny';
    public const EXCHANGE = 'exchange';
    public const OBSERVE  = 'observe';

    /**
     * @param  string|null  $cookie         value of the access cookie, if any
     * @param  string|null  $givenKey       value of ?cpskey=, if any
     * @param  bool         $ipEnforceable  the resolved address is one visitor (not a CDN edge, a private or an unlisted proxy address)
     * @param  bool         $ipListed       the address is on the administrator list
     *
     * @return array{action:string,reason:string}
     */
    public static function decide(AccessGateConfig $cfg, ?string $cookie, ?string $givenKey, bool $ipEnforceable, bool $ipListed, string $userAgent, string $siteSecret, int $now): array
    {
        if ($cfg->off()) {
            return ['action' => self::ALLOW, 'reason' => 'off'];
        }

        // A right key always wins, and then the browser gets the cookie.
        if ($cfg->gateActive && $givenKey !== null && $givenKey !== '' && hash_equals($cfg->key, $givenKey)) {
            return ['action' => self::EXCHANGE, 'reason' => 'key'];
        }

        if ($cfg->ipActive && $ipEnforceable && $ipListed) {
            return ['action' => self::ALLOW, 'reason' => 'listed_address'];
        }

        if ($cfg->gateActive && $cookie !== null && self::verifyCookie($cookie, $cfg->key, $userAgent, $siteSecret, $now, $cfg->cookieHours)) {
            return ['action' => self::ALLOW, 'reason' => 'cookie'];
        }

        // An address list alone cannot be enforced when the address is not one visitor (every
        // visitor would look the same): observe, never block.
        if ($cfg->ipActive && !$cfg->gateActive && !$ipEnforceable) {
            return ['action' => self::OBSERVE, 'reason' => 'address_not_enforceable'];
        }

        return ['action' => self::DENY, 'reason' => $cfg->gateActive ? 'no_cookie' : 'address_not_listed'];
    }

    /**
     * Cookie value: "<expiry>.<hmac>"; the hmac covers the expiry and the browser's user agent and
     * is made with a key derived from the site secret AND the access key, so changing the key
     * invalidates every cookie.
     */
    public static function cookieValue(string $siteSecret, string $key, string $userAgent, int $expiry): string
    {
        return $expiry . '.' . hash_hmac('sha256', $expiry . '|' . substr(hash('sha256', $userAgent), 0, 16), self::derive($siteSecret, $key));
    }

    public static function verifyCookie(string $cookie, string $key, string $userAgent, string $siteSecret, int $now, int $maxHours): bool
    {
        if ($siteSecret === '' || $key === '' || !preg_match('/^(\d{9,11})\.([0-9a-f]{64})$/', $cookie, $m)) {
            return false;
        }

        $expiry = (int) $m[1];

        // Expired, or an expiry further away than we would ever have issued: refused.
        if ($expiry <= $now || $expiry > $now + $maxHours * 3600 + 60) {
            return false;
        }

        return hash_equals(self::cookieValue($siteSecret, $key, $userAgent, $expiry), $cookie);
    }

    private static function derive(string $siteSecret, string $key): string
    {
        return hash_hmac('sha256', 'colorpack_shield-gate|' . $key, $siteSecret);
    }

    /**
     * The request URI without the access key parameter, for the redirect after the exchange.
     * Only a path and a query come out; anything that is not a plain local path becomes "/".
     */
    public static function cleanUri(string $uri): string
    {
        $uri = preg_replace('/[\x00-\x20\x7f]/', '', $uri) ?? '';

        if ($uri === '' || $uri[0] !== '/' || str_starts_with($uri, '//') || str_contains($uri, '\\')) {
            return '/';
        }

        $q = strpos($uri, '?');

        if ($q === false) {
            return $uri;
        }

        $path  = substr($uri, 0, $q);
        $parts = array_filter(explode('&', substr($uri, $q + 1)), static fn (string $kv): bool => $kv !== '' && !preg_match('/^' . self::PARAM . '(=|$)/i', $kv));

        return $parts === [] ? $path : $path . '?' . implode('&', $parts);
    }

    /** Remove the key (and its parameter) from text that is about to be logged. */
    public static function scrub(string $text, string $key): string
    {
        $text = preg_replace('/(' . self::PARAM . '=)[^&\s]*/i', '$1*', $text) ?? $text;

        return $key !== '' ? str_replace($key, '*', $text) : $text;
    }
}
