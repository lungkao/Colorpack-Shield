<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Mfa;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * One-time recovery codes for when a user loses their authenticator - generated with enough
 * entropy (40 bits each) that a salted SHA-256 hash is a reasonable, fast way to store them (they
 * are never user-chosen or low-entropy the way a password is, so a slow KDF would protect nothing
 * a random 40-bit code doesn't already provide).
 */
final class BackupCodes
{
    private const COUNT = 8;

    /** @return string[] plain codes, "xxxx-xxxx" shaped, shown to the user exactly once */
    public static function generate(int $count = self::COUNT): array
    {
        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $n       = random_int(0, 99999999);
            $digits  = str_pad((string) $n, 8, '0', STR_PAD_LEFT);
            $codes[] = substr($digits, 0, 4) . '-' . substr($digits, 4, 4);
        }

        return $codes;
    }

    public static function hash(string $plainCode, string $pepper): string
    {
        return hash('sha256', $pepper . '|' . self::normalise($plainCode));
    }

    /**
     * @param  string[]  $hashedCodes
     *
     * @return array{ok:bool,remaining:string[]}  $remaining is $hashedCodes with the matched one removed (unchanged on failure)
     */
    public static function verifyAndConsume(array $hashedCodes, string $plainCode, string $pepper): array
    {
        $target = self::hash($plainCode, $pepper);

        foreach ($hashedCodes as $i => $h) {
            if (hash_equals($h, $target)) {
                $remaining = $hashedCodes;
                unset($remaining[$i]);

                return ['ok' => true, 'remaining' => array_values($remaining)];
            }
        }

        return ['ok' => false, 'remaining' => $hashedCodes];
    }

    private static function normalise(string $code): string
    {
        return strtolower(preg_replace('/[^0-9]/', '', $code) ?? '');
    }
}
