<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Remembers, per administrator, the addresses they have logged in from — as
 * salted hashes only — so a login from somewhere new can be reported.
 */
final class KnownIps
{
    public const LEARNING    = 'learning';
    public const KNOWN       = 'known';
    public const NEW         = 'new';
    public const UNAVAILABLE = 'unavailable';

    /** How long an administrator's list is kept without a login. */
    private const KEEP_SECONDS = 400 * 86400;

    /**
     * @param  string  $salt  must be secret and stable (derived from the site secret); empty = refuse to remember anything
     *
     * @return string  learning (first ever login: remembered, no alert) | known | new (alert) | unavailable
     */
    public static function observe(StateStore $store, int $userId, string $ip, string $salt, int $now, int $max = 10): string
    {
        $b = LockoutPolicy::bucket($ip);

        if ($b === null || $salt === '' || $userId <= 0) {
            return self::UNAVAILABLE;
        }

        $hash   = substr(hash_hmac('sha256', $b, $salt), 0, 16);
        $result = self::UNAVAILABLE;

        $store->mutate('known:' . $userId, $now, static function (?array $e) use ($hash, $now, $max, &$result): array {
            if ($e === null) {
                $result = self::LEARNING;

                return ['ips' => [$hash], 'exp' => $now + self::KEEP_SECONDS];
            }

            $ips = array_values(array_filter((array) $e['ips'], static fn ($h): bool => \is_string($h)));

            if (\in_array($hash, $ips, true)) {
                $result = self::KNOWN;
                $ips    = array_values(array_diff($ips, [$hash]));
            } else {
                $result = self::NEW;
            }

            $ips[] = $hash;

            return ['ips' => \array_slice($ips, -max(1, $max)), 'exp' => $now + self::KEEP_SECONDS];
        });

        return $store->healthy() ? $result : self::UNAVAILABLE;
    }

    /** How long an address stays "an administrator's address" after their last login from it. */
    private const ADMIN_ADDRESS_SECONDS = 30 * 86400;

    /**
     * Remember that an administrator has just logged in from this address
     * (salted hash only). Such an address is never locked out, because it may be
     * a shared office or CDN address that other visitors also use.
     */
    public static function rememberAdminAddress(StateStore $store, string $ip, string $salt, int $now): void
    {
        $key = self::adminKey($ip, $salt);

        if ($key !== null) {
            $store->mutate($key, $now, static fn (?array $e): array => ['exp' => $now + self::ADMIN_ADDRESS_SECONDS]);
        }
    }

    public static function isAdminAddress(StateStore $store, string $ip, string $salt, int $now): bool
    {
        $key = self::adminKey($ip, $salt);

        return $key !== null && $store->get($key, $now) !== null;
    }

    private static function adminKey(string $ip, string $salt): ?string
    {
        $b = LockoutPolicy::bucket($ip);

        return $b === null || $salt === '' ? null : 'adminip:' . substr(hash_hmac('sha256', $b, $salt), 0, 16);
    }
}
