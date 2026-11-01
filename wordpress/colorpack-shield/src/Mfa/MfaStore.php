<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Mfa;

\defined('ABSPATH') || die;

/**
 * Per-user MFA state, kept in a single private usermeta row (`_cps_mfa`, underscore-prefixed so
 * it never shows in a generic meta-fields UI) rather than several rows, so a read/save is always
 * one round trip and never partially written.
 */
final class MfaStore
{
    private const META_KEY = '_cps_mfa';

    /**
     * @return array{secret:?string,confirmed:bool,backup_codes:string[],first_seen_without_mfa:?int}
     */
    public static function get(int $userId): array
    {
        $raw = get_user_meta($userId, self::META_KEY, true);
        $d   = \is_array($raw) ? $raw : [];

        return [
            'secret'                 => \is_string($d['secret'] ?? null) && $d['secret'] !== '' ? $d['secret'] : null,
            'confirmed'               => (bool) ($d['confirmed'] ?? false),
            'backup_codes'            => \is_array($d['backup_codes'] ?? null) ? array_values(array_filter($d['backup_codes'], 'is_string')) : [],
            'first_seen_without_mfa' => \is_int($d['first_seen_without_mfa'] ?? null) ? $d['first_seen_without_mfa'] : null,
        ];
    }

    public static function hasConfirmedMfa(int $userId): bool
    {
        return self::get($userId)['confirmed'];
    }

    /** Begins (or restarts) enrollment with a fresh secret - not active until confirm() is called. */
    public static function startEnrollment(int $userId, string $secret): void
    {
        $d           = self::get($userId);
        $d['secret'] = $secret;
        $d['confirmed'] = false;
        update_user_meta($userId, self::META_KEY, $d);
    }

    /**
     * @param  string[]  $hashedBackupCodes
     */
    public static function confirm(int $userId, array $hashedBackupCodes): void
    {
        $d                               = self::get($userId);
        $d['confirmed']                  = true;
        $d['backup_codes']               = array_values($hashedBackupCodes);
        $d['first_seen_without_mfa']     = null;
        update_user_meta($userId, self::META_KEY, $d);
    }

    /**
     * @param  string[]  $hashedBackupCodes
     */
    public static function setBackupCodes(int $userId, array $hashedBackupCodes): void
    {
        $d                 = self::get($userId);
        $d['backup_codes'] = array_values($hashedBackupCodes);
        update_user_meta($userId, self::META_KEY, $d);
    }

    public static function disable(int $userId): void
    {
        delete_user_meta($userId, self::META_KEY);
    }

    /** Records the first moment this user was seen without MFA while a policy applies to them - the anchor {@see \Colorpack\WP\ColorpackShield\AdminProtect\MfaPolicy}'s grace period counts from. */
    public static function markFirstSeenWithoutMfa(int $userId, int $now): int
    {
        $d = self::get($userId);

        if ($d['first_seen_without_mfa'] !== null) {
            return $d['first_seen_without_mfa'];
        }

        $d['first_seen_without_mfa'] = $now;
        update_user_meta($userId, self::META_KEY, $d);

        return $now;
    }
}
