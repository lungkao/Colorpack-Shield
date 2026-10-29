<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What to do with a login attempt from one address.
 *
 * "observe" means the address IS locked but must not be blocked, because it
 * cannot be told apart from many visitors (loopback, private, Cloudflare edge,
 * the site's own proxy) or because the real-IP check has not passed: the lock
 * is logged and shown on the dashboard, never enforced.
 */
final class LockDecision
{
    public const OK      = 'ok';
    public const LOCKED  = 'locked';
    public const OBSERVE = 'observe';

    public function __construct(
        public readonly string $state,
        public readonly int $retryAfter = 0,
        public readonly string $reason = ''
    ) {
    }

    public function blocks(): bool
    {
        return $this->state === self::LOCKED;
    }
}
