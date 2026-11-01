<?php
/**
 * This port's own TOTP second factor: the HOTP/TOTP core, backup codes, and the login-challenge
 * ticket, plus the pure grace-period policy `MfaPolicy` (ported from the Joomla edition
 * unmodified - its own assertions below are a straight port of the Joomla edition's
 * `admin_mfa_tests.php` "Admin MFA: policy" section; the Joomla gateway stand-ins the rest of
 * that file needs don't apply here, since this port never bridges a host CMS's own MFA API -
 * see `Mfa\Totp`'s docblock). Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\AdminProtect\MemoryStateStore;
use Colorpack\WP\ColorpackShield\AdminProtect\MfaPolicy;
use Colorpack\WP\ColorpackShield\Mfa\BackupCodes;
use Colorpack\WP\ColorpackShield\Mfa\MfaChallenge;
use Colorpack\WP\ColorpackShield\Mfa\Totp;

echo "== MFA: grace-period policy ==\n";

$Tn = 1_800_000_000;
$pd = static fn (string $mode, bool $applies = true, bool $has = false, int $first = 0, int $now = 0, int $grace = 7, bool $exempt = false, bool $html = true): array => MfaPolicy::decide($mode, $applies, $has, $Tn + $first, $Tn + $now, $grace, $exempt, $html);

ok('mode off or unknown -> nothing', $pd('off')['action'] === 'none' && $pd('junk')['action'] === 'none' && $pd('')['action'] === 'none');
ok('a user the policy does not apply to, or who has MFA -> nothing', $pd('enforce', false, false, 0, 99 * 86400)['action'] === 'none' && $pd('enforce', true, true, 0, 99 * 86400)['action'] === 'none' && $pd('warn', false)['action'] === 'none');
ok('warn mode inside the grace: a reminder with the days left (7 on day 0)', $pd('warn') === ['action' => 'warn', 'daysLeft' => 7, 'overdue' => false]);
ok('warn mode after the grace: still only a reminder, now "overdue"', $pd('warn', true, false, 0, 30 * 86400) === ['action' => 'warn', 'daysLeft' => 0, 'overdue' => true]);
ok('enforce inside the grace: a reminder, never a redirect', $pd('enforce', true, false, 0, 3 * 86400)['action'] === 'warn' && $pd('enforce', true, false, 0, 3 * 86400)['daysLeft'] === 4);
ok('days left are rounded up: 1 s into the grace -> 7, 1 s before the end -> 1, exactly at the end -> overdue', $pd('enforce', true, false, 0, 1)['daysLeft'] === 7 && $pd('enforce', true, false, 0, 7 * 86400 - 1)['daysLeft'] === 1 && $pd('enforce', true, false, 0, 7 * 86400)['overdue'] === true);
ok('enforce after the grace: redirect for an ordinary page, deny for ajax/json', $pd('enforce', true, false, 0, 8 * 86400)['action'] === 'redirect' && $pd('enforce', true, false, 0, 8 * 86400, 7, false, false)['action'] === 'deny');
ok('enforce after the grace: the MFA pages and logout (exempt) stay reachable, with no message', $pd('enforce', true, false, 0, 8 * 86400, 7, true)['action'] === 'none' && $pd('enforce', true, false, 0, 8 * 86400, 7, true, false)['action'] === 'none');
ok('inside the grace the exempt pages get no reminder either', $pd('enforce', true, false, 0, 86400, 7, true)['action'] === 'none' && $pd('warn', true, false, 0, 86400, 7, true)['action'] === 'none');
ok('grace 0 means enforce at once; a negative grace is overdue at once as well', $pd('enforce', true, false, 0, 0, 0)['action'] === 'redirect' && $pd('enforce', true, false, 0, 0, -5)['action'] === 'redirect');

echo "== MFA: HOTP core (RFC 4226 Appendix D test vectors) ==\n";

// The RFC's own secret: the ASCII string "12345678901234567890".
$rfcKey = '12345678901234567890';
$rfcHotp = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

ok('HOTP(secret, 0..9) matches every RFC 4226 Appendix D value', array_map(static fn (int $c): string => Totp::hotp($rfcKey, $c), range(0, 9)) === $rfcHotp);

echo "== MFA: base32 ==\n";

ok('base32 encode/decode round-trips arbitrary bytes', (static function (): bool {
    foreach (['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar', random_bytes(20)] as $b) {
        if (Totp::base32Decode(Totp::base32Encode($b)) !== $b) {
            return false;
        }
    }

    return true;
})());

ok('base32Encode("12345678901234567890") matches the well-known RFC 4648 test value', Totp::base32Encode('12345678901234567890') === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'); // trimmed of padding, which this encoder never adds

echo "== MFA: TOTP verify ==\n";

$secret = Totp::base32Encode($rfcKey);
$now    = 1_800_000_000;
$counter = intdiv($now, 30);
$validCode = Totp::hotp($rfcKey, $counter);

ok('verify() accepts the code for the current 30s step', Totp::verify($secret, $validCode, $now));
ok('verify() accepts the previous/next step within the default window, rejects two steps away', Totp::verify($secret, Totp::hotp($rfcKey, $counter - 1), $now)
    && Totp::verify($secret, Totp::hotp($rfcKey, $counter + 1), $now)
    && !Totp::verify($secret, Totp::hotp($rfcKey, $counter - 2), $now)
    && !Totp::verify($secret, Totp::hotp($rfcKey, $counter + 2), $now));
ok('verify() rejects a wrong code, a malformed code, and an empty secret', !Totp::verify($secret, '000000', $now)
    && !Totp::verify($secret, 'abcdef', $now)
    && !Totp::verify($secret, '12345', $now)
    && !Totp::verify('', $validCode, $now));
ok('verify() accepts the code with surrounding whitespace (how a phone keyboard/autofill often sends it)', Totp::verify($secret, ' ' . $validCode . ' ', $now));

echo "== MFA: provisioning URI ==\n";

$uri = Totp::uri('JBSWY3DPEHPK3PXP', 'admin', 'My Site');
ok('uri() is an otpauth://totp URI carrying the secret, label and 6-digit/30s parameters', str_starts_with($uri, 'otpauth://totp/My%20Site:admin?')
    && str_contains($uri, 'secret=JBSWY3DPEHPK3PXP')
    && str_contains($uri, 'digits=6')
    && str_contains($uri, 'period=30')
    && str_contains($uri, 'issuer=My%20Site'));

echo "== MFA: backup codes ==\n";

ok('generate() makes 8 unique "xxxx-xxxx" codes by default', (static function (): bool {
    $codes = BackupCodes::generate();

    return \count($codes) === 8 && \count(array_unique($codes)) === 8 && array_filter($codes, static fn (string $c): bool => (bool) preg_match('/^\d{4}-\d{4}$/', $c)) === $codes;
})());

ok('hash() is deterministic for the same code+pepper and differs for a different pepper', BackupCodes::hash('1234-5678', 'pepper-a') === BackupCodes::hash('1234-5678', 'pepper-a')
    && BackupCodes::hash('1234-5678', 'pepper-a') !== BackupCodes::hash('1234-5678', 'pepper-b'));

ok('verifyAndConsume(): a match removes only that one hash and reports the rest; a miss changes nothing', (static function (): bool {
    $pepper = 'pepper';
    $hashed = array_map(static fn (string $c): string => BackupCodes::hash($c, $pepper), ['1111-1111', '2222-2222', '3333-3333']);

    $hit = BackupCodes::verifyAndConsume($hashed, '2222-2222', $pepper);
    $miss = BackupCodes::verifyAndConsume($hashed, '9999-9999', $pepper);

    return $hit['ok'] === true && $hit['remaining'] === [$hashed[0], $hashed[2]]
        && $miss['ok'] === false && $miss['remaining'] === $hashed;
})());

ok('verifyAndConsume() ignores formatting (spaces/dashes) when matching a code', BackupCodes::verifyAndConsume([BackupCodes::hash('1234-5678', 'p')], '1234 5678', 'p')['ok']
    && BackupCodes::verifyAndConsume([BackupCodes::hash('1234-5678', 'p')], '12345678', 'p')['ok']);

echo "== MFA: login challenge ticket ==\n";

ok('create() then userId() returns the same user id; a wrong token returns null', (static function (): bool {
    $store = new MemoryStateStore();
    $token = MfaChallenge::create($store, 42, 1000);

    return MfaChallenge::userId($store, $token, 1000) === 42 && MfaChallenge::userId($store, 'not-a-real-token', 1000) === null;
})());

ok('a token expires after its TTL', (static function (): bool {
    $store = new MemoryStateStore();
    $token = MfaChallenge::create($store, 7, 1000);

    return MfaChallenge::userId($store, $token, 1000 + 299) === 7 && MfaChallenge::userId($store, $token, 1000 + 301) === null;
})());

ok('consume() makes the token unusable immediately, win or lose', (static function (): bool {
    $store = new MemoryStateStore();
    $token = MfaChallenge::create($store, 9, 1000);
    MfaChallenge::consume($store, $token, 1000);

    return MfaChallenge::userId($store, $token, 1000) === null;
})());

ok('remember() carries the "remember me" flag, defaulting to false', (static function (): bool {
    $store  = new MemoryStateStore();
    $plain  = MfaChallenge::create($store, 1, 1000);
    $remembered = MfaChallenge::create($store, 1, 1000, true);

    return MfaChallenge::remember($store, $plain, 1000) === false && MfaChallenge::remember($store, $remembered, 1000) === true;
})());

ok('a broken store never hands out a usable token', (static function (): bool {
    $store = new MemoryStateStore();
    $store->failing = true;
    $token = MfaChallenge::create($store, 1, 1000);

    return MfaChallenge::userId($store, $token, 1000) === null;
})());
