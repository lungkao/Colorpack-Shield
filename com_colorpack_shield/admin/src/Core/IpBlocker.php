<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\StateStore;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The owner's own "block this address" button on the Activity screen, on the same ban store the automatic attacker bans
 * use (so it is rejected before any other work, on every part of the site). A manual ban lasts a week and is marked
 * `manual`, which the request path honours whatever the other settings are - it is the owner's explicit decision.
 *
 * Refuses what would hurt the owner: an address that is not public, the visitor's own address, and any trusted address.
 */
final class IpBlocker
{
    public const HOURS  = 168;
    public const REASON = 'manual';

    public function __construct(private readonly StateStore $store)
    {
    }

    /**
     * @param  string  $ownIp     the address of the person pressing the button
     * @param  string  $allowText the "never block" list from the settings (one address or range per line)
     *
     * @return string  '' when blocked, else why not: invalid | not_public | self | trusted | failed
     */
    public function block(string $ip, int $now, string $ownIp, string $allowText): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || LockoutPolicy::bucket($ip) === null) {
            return 'invalid';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return 'not_public';
        }

        if ($ownIp !== '' && LockoutPolicy::bucket($ownIp) === LockoutPolicy::bucket($ip)) {
            return 'self';
        }

        if (trim($allowText) !== '' && IpAllowList::fromText($allowText)->matches($ip)) {
            return 'trusted';
        }

        return (new TargetedBanPolicy($this->store))->ban($ip, $now, self::HOURS * 3600, self::REASON) > 0 ? '' : 'failed';
    }

    /** Lifts any ban on the address (manual or automatic). True when there was one to lift. */
    public function unblock(string $ip, int $now): bool
    {
        $b = LockoutPolicy::bucket($ip);

        if ($b === null || !$this->isBlocked($ip, $now)) {
            return false;
        }

        $this->store->mutate('ban:' . $b, $now, static fn (?array $e): ?array => null);

        return true;
    }

    public function isBlocked(string $ip, int $now): bool
    {
        return (new TargetedBanPolicy($this->store))->check($ip, $now)['banned'];
    }
}
