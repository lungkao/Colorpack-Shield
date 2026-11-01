<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Mfa;

use Colorpack\WP\ColorpackShield\AdminProtect\StateStore;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The short-lived "username/password were right, now prove the second factor" ticket - built on
 * the same {@see StateStore} the admin-protection classes already use (`AlertThrottle`,
 * `LockoutPolicy`, ...), not a WordPress transient, so it is fail-closed and testable the same way.
 * The token itself is the only credential: whoever holds it (via the cookie `Wiring` sets) can
 * complete the login it was issued for, so it is high-entropy and single-use.
 */
final class MfaChallenge
{
    private const PREFIX = 'mfa:';
    private const TTL     = 300;

    /** `$remember` carries the login form's "remember me" choice across a wrong-code retry. */
    public static function create(StateStore $store, int $userId, int $now, bool $remember = false): string
    {
        $token = bin2hex(random_bytes(20));

        $store->mutate(self::PREFIX . $token, $now, static fn (): array => ['user_id' => $userId, 'remember' => $remember, 'exp' => $now + self::TTL]);

        return $token;
    }

    /** The pending user id for a token, or null if the token is missing, expired or malformed. */
    public static function userId(StateStore $store, string $token, int $now): ?int
    {
        $e = self::entry($store, $token, $now);

        return $e !== null ? (int) ($e['user_id'] ?? 0) : null;
    }

    public static function remember(StateStore $store, string $token, int $now): bool
    {
        return (bool) (self::entry($store, $token, $now)['remember'] ?? false);
    }

    /** @return array<string,mixed>|null */
    private static function entry(StateStore $store, string $token, int $now): ?array
    {
        if ($token === '' || !preg_match('/^[a-f0-9]{40}$/', $token)) {
            return null;
        }

        return $store->get(self::PREFIX . $token, $now);
    }

    /** Single-use: call once the code (or a backup code) has been accepted, win or lose. */
    public static function consume(StateStore $store, string $token, int $now): void
    {
        if ($token === '') {
            return;
        }

        $store->mutate(self::PREFIX . $token, $now, static fn (): ?array => null);
    }
}
