<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Mfa;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * A self-contained TOTP (RFC 6238, built on the HOTP core in RFC 4226) implementation - this
 * port's own second factor, not a bridge to a host CMS API the way the Joomla edition's
 * `JoomlaMfaGateway` is: WordPress core has no multi-factor authentication of its own to bridge
 * to, and the project's own convention (see `AdminProtect/`, `Scanner/`) is to ship dependency-free
 * so the zip stays self-contained on shared hosting with no `vendor/` to install. Compatible with
 * Google Authenticator / any standard TOTP app: SHA-1, 6 digits, 30-second step.
 *
 * `hotp()` is checked directly against the RFC 4226 Appendix D test vectors in `mfa_tests.php`;
 * `verify()`/`uri()` build on it, so a passing `hotp()` test is strong evidence the rest is right
 * too, without needing to trust a hand-recalled set of time-based RFC 6238 vectors.
 */
final class Totp
{
    private const DIGITS = 6;
    private const STEP   = 30;

    /** A fresh, random base32 secret (160 bits - the size RFC 4226's own test vectors use). */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    /**
     * True if `$code` matches the secret at `$now`, or at any step up to `$window` steps away
     * (clock skew - the same tolerance virtually every TOTP app/verifier allows).
     */
    public static function verify(string $base32Secret, string $code, int $now, int $window = 1): bool
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';

        if (!preg_match('/^\d{' . self::DIGITS . '}$/', $code)) {
            return false;
        }

        $key = self::base32Decode($base32Secret);

        if ($key === '') {
            return false;
        }

        $counter = intdiv($now, self::STEP);

        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals(self::hotp($key, $counter + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /** `otpauth://totp/...` provisioning URI - the manual-entry key is shown alongside it, QR-free. */
    public static function uri(string $base32Secret, string $accountName, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);

        return 'otpauth://totp/' . $label . '?' . http_build_query([
            'secret'    => $base32Secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::STEP,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /** HOTP (RFC 4226): `$key` is the raw secret bytes, not base32. */
    public static function hotp(string $key, int $counter): string
    {
        $bin  = pack('J', $counter < 0 ? 0 : $counter);
        $hash = hash_hmac('sha1', $bin, $key, true);
        $off  = \ord($hash[\strlen($hash) - 1]) & 0x0F;
        $bin4 = ((\ord($hash[$off]) & 0x7F) << 24)
            | ((\ord($hash[$off + 1]) & 0xFF) << 16)
            | ((\ord($hash[$off + 2]) & 0xFF) << 8)
            | (\ord($hash[$off + 3]) & 0xFF);

        return str_pad((string) ($bin4 % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function base32Encode(string $bytes): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits     = '';

        foreach (str_split($bytes) as $b) {
            $bits .= str_pad(decbin(\ord($b)), 8, '0', STR_PAD_LEFT);
        }

        $out = '';

        foreach (str_split($bits, 5) as $chunk) {
            if (\strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0');
            }

            $out .= $alphabet[bindec($chunk)];
        }

        return $out;
    }

    public static function base32Decode(string $b32): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32      = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $b32) ?? '');
        $bits     = '';

        foreach (str_split($b32) as $c) {
            $pos = strpos($alphabet, $c);

            if ($pos === false) {
                continue;
            }

            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';

        foreach (str_split($bits, 8) as $byte) {
            if (\strlen($byte) < 8) {
                continue;
            }

            $bytes .= \chr(bindec($byte));
        }

        return $bytes;
    }
}
