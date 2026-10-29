<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Login lockout rules (PLAN-ADMIN-PROTECTION.md A1), free of Joomla.
 *
 * - Failures are counted per ADDRESS (IPv4 as is, IPv6 by /64). Reaching the
 *   limit inside the window locks that address; repeated offences double the
 *   lock up to a cap. A username is never locked on its own (that would let
 *   anyone keep the real administrator out); a distributed attack on one name
 *   only raises {@see recordFailure()}'s "pressure" level, which feeds alerts.
 * - A lock is only ENFORCED for an address that stands for one visitor, when
 *   the real-IP check has passed and when no administrator has logged in from
 *   it recently ({@see decide()}); otherwise it is "observe only".
 * - Every storage problem means "no lock": nothing here throws.
 */
final class LockoutPolicy
{
    /** Most failure timestamps kept per address or name. */
    private const KEEP = 200;

    public function __construct(
        private readonly AdminProtectConfig $config,
        private readonly StateStore $store
    ) {
    }

    /**
     * The key an address is counted under, or null for text that is not an IP.
     * IPv4-mapped IPv6 collapses to IPv4; other IPv6 to its /64.
     */
    public static function bucket(string $ip): ?string
    {
        $ip = trim($ip);

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $bin = @inet_pton($ip);

        if ($bin === false) {
            return null;
        }

        if (\strlen($bin) === 16) {
            if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
                return inet_ntop(substr($bin, 12)) ?: null;
            }

            return implode(':', str_split(bin2hex(substr($bin, 0, 8)), 4)) . '::/64';
        }

        return $ip === inet_ntop($bin) ? $ip : (inet_ntop($bin) ?: null);
    }

    /**
     * Count one failed login.
     *
     * @return array{bucket:?string,failures:int,locked:bool,newLock:bool,lockUntil:int,strikes:int,pressure:int}
     */
    public function recordFailure(string $ip, string $username, int $now): array
    {
        $none = ['bucket' => null, 'failures' => 0, 'locked' => false, 'newLock' => false, 'lockUntil' => 0, 'strikes' => 0, 'pressure' => 0];
        $b    = self::bucket($ip);

        if ($b === null || !$this->config->lockoutEnabled) {
            return $none;
        }

        $c = $this->config;

        $newLock = false;
        $entry   = $this->store->mutate('ip:' . $b, $now, function (?array $e) use ($c, $now, &$newLock): array {
            $e ??= ['fails' => [], 'strikes' => 0, 'lockUntil' => 0, 'exp' => 0];

            // Already locked: attempts during the lock neither extend it nor count.
            if ((int) $e['lockUntil'] > $now) {
                return $e;
            }

            $fails   = array_values(array_filter((array) $e['fails'], static fn ($t): bool => (int) $t > $now - $c->failureWindow));
            $fails[] = $now;
            $fails   = \array_slice($fails, -self::KEEP);
            $memory  = $c->lockMaxHours * 3600;

            if (\count($fails) >= $c->maxFailures) {
                $strikes = (int) $e['strikes'] + 1;
                $seconds = min($c->lockMinutes * 60 * (2 ** min($strikes - 1, 20)), $c->lockMaxHours * 3600);
                $newLock = true;

                return ['fails' => [], 'strikes' => $strikes, 'lockUntil' => $now + $seconds, 'exp' => $now + $seconds + $memory];
            }

            return ['fails' => $fails, 'strikes' => (int) $e['strikes'], 'lockUntil' => 0, 'exp' => max((int) $e['exp'], $now + $c->failureWindow)];
        });

        $pressure = $this->userPressure($b, $username, $now);

        if ($entry === null) {
            return ['bucket' => $b, 'failures' => 0, 'locked' => false, 'newLock' => false, 'lockUntil' => 0, 'strikes' => 0, 'pressure' => $pressure];
        }

        return [
            'bucket'    => $b,
            'failures'  => \count((array) $entry['fails']),
            'locked'    => (int) $entry['lockUntil'] > $now,
            'newLock'   => $newLock,
            'lockUntil' => (int) $entry['lockUntil'],
            'strikes'   => (int) $entry['strikes'],
            'pressure'  => $pressure,
        ];
    }

    /**
     * Is this address locked, and if so may the lock be enforced?
     *
     * @param  string[]  $cloudflareRanges
     * @param  string[]  $trustedProxies
     * @param  bool|null $realIpVerified  true = the real-IP check passed; false/null = it did not or was not run
     * @param  bool      $knownAdminAddress  an administrator has logged in from this address recently: never enforced
     *                                       (behind an unrecognised CDN or a shared office address the lock would hit them)
     */
    public function decide(ClientIp $client, array $cloudflareRanges, array $trustedProxies, ?bool $realIpVerified, int $now, bool $knownAdminAddress = false): LockDecision
    {
        if (!$this->config->lockoutEnabled) {
            return new LockDecision(LockDecision::OK);
        }

        $b = self::bucket($client->ip);
        $e = $b === null ? null : $this->store->get('ip:' . $b, $now);

        if ($e === null || (int) ($e['lockUntil'] ?? 0) <= $now) {
            return new LockDecision(LockDecision::OK);
        }

        $retry = (int) $e['lockUntil'] - $now;

        if (!IpAllowList::isSafeToAutoAdd($client, $cloudflareRanges, $trustedProxies)) {
            return new LockDecision(LockDecision::OBSERVE, $retry, 'shared_address');
        }

        if ($realIpVerified !== true) {
            return new LockDecision(LockDecision::OBSERVE, $retry, 'real_ip_not_verified');
        }

        if ($knownAdminAddress) {
            return new LockDecision(LockDecision::OBSERVE, $retry, 'known_admin_address');
        }

        return new LockDecision(LockDecision::LOCKED, $retry, 'locked');
    }

    /** A successful login lifts the address's counters (unless it is locked, which cannot be undone by logging in). */
    public function recordSuccess(string $ip, int $now): void
    {
        $b = self::bucket($ip);

        if ($b === null) {
            return;
        }

        $this->store->mutate('ip:' . $b, $now, static fn (?array $e): ?array => $e !== null && (int) ($e['lockUntil'] ?? 0) > $now ? $e : null);
    }

    /**
     * Failures of one user name across all addresses: 0 = normal, 1 = suspicious
     * (many failures from several addresses), 2 = a distributed attack. Never
     * blocks; it only drives alerts and, in the plugin, a small delay.
     */
    private function userPressure(string $bucket, string $username, int $now): int
    {
        $name = strtolower(trim(substr($username, 0, 200)));

        if ($name === '') {
            return 0;
        }

        $c    = $this->config;
        $hash = substr(hash('sha256', $bucket), 0, 8);

        $e = $this->store->mutate('user:' . substr(hash('sha256', $name), 0, 24), $now, static function (?array $e) use ($c, $now, $hash): array {
            $fails   = array_values(array_filter((array) ($e['fails'] ?? []), static fn ($t): bool => (int) $t > $now - $c->failureWindow));
            $fails[] = $now;
            $ips     = array_values(array_unique(array_merge((array) ($e['ips'] ?? []), [$hash])));

            return ['fails' => \array_slice($fails, -self::KEEP), 'ips' => \array_slice($ips, -20), 'exp' => $now + $c->failureWindow];
        });

        if ($e === null) {
            return 0;
        }

        $count = \count((array) $e['fails']);
        $ips   = \count((array) $e['ips']);

        if ($count >= 5 * $c->maxFailures && $ips >= 5) {
            return 2;
        }

        return $count >= 2 * $c->maxFailures && $ips >= 3 ? 1 : 0;
    }
}
