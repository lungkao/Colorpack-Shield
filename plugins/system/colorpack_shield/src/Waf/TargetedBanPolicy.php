<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\StateStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Persists an outright ban for an address that produced a WafResult::MODE_BAN finding -
 * reserved for the "scanner_probe" rule under the path shield's "ban" probe mode, a strong
 * signal of a deliberate, tooled attacker (old-CVE paths, WordPress-on-Joomla probes,
 * well-known webshell names), never raised by ordinary visitor mistakes. Once armed, every
 * later request from that address is rejected immediately, not just the one that matched.
 *
 * Built on the same {@see StateStore} contract as the admin login lockout, so it needs no
 * APCu - this project targets shared hosting, where APCu may simply be absent (confirmed by
 * the "rate limit: bad" dashboard status, which means exactly that).
 */
final class TargetedBanPolicy
{
    public function __construct(private readonly StateStore $store)
    {
    }

    /**
     * @return array{banned:bool,until:int,reason:string}  banned=false when clean, unbucketable, or the store is empty/unhealthy
     */
    public function check(string $ip, int $now): array
    {
        $none = ['banned' => false, 'until' => 0, 'reason' => ''];
        $b    = LockoutPolicy::bucket($ip);

        if ($b === null) {
            return $none;
        }

        $e = $this->store->get('ban:' . $b, $now);

        if ($e === null || (int) ($e['until'] ?? 0) <= $now) {
            return $none;
        }

        return ['banned' => true, 'until' => (int) $e['until'], 'reason' => (string) ($e['reason'] ?? '')];
    }

    /**
     * Arm (or extend) a ban. Storage failures and unbucketable addresses are silently
     * ignored, same as every other address-keyed policy here: a storage problem must never
     * turn into an outage for everyone else.
     *
     * @return int  the ban's new expiry (unix time), or 0 when nothing was armed
     */
    public function ban(string $ip, int $now, int $durationSeconds, string $reason): int
    {
        $b = LockoutPolicy::bucket($ip);

        if ($b === null) {
            return 0;
        }

        $seconds = max(60, $durationSeconds);
        $entry   = $this->store->mutate('ban:' . $b, $now, static function (?array $e) use ($now, $seconds, $reason): array {
            $until = $now + $seconds;

            return [
                'until'   => $until,
                'reason'  => $reason,
                'strikes' => (int) ($e['strikes'] ?? 0) + 1,
                'since'   => $e['since'] ?? $now,
                'exp'     => $until,
            ];
        });

        return (int) ($entry['until'] ?? 0);
    }
}
