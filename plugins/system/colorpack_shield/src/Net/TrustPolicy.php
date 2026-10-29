<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What a "trusted IP" match is worth, given how the IP was learned.
 *
 *  - FULL: every check is skipped. Only when the address is the TCP peer
 *    itself (ClientIp::VIA_DIRECT): the connection cannot be forged.
 *  - SOFT: geo and rate limiting are skipped, but the request is still
 *    inspected by the WAF and the upload scanner. Used when the address came
 *    from a forwarding header (Cloudflare or a local proxy), because whoever
 *    can influence that header could otherwise impersonate a trusted address
 *    and walk past the WAF (AUDIT.md, C1).
 *  - NONE: not trusted.
 */
final class TrustPolicy
{
    public const NONE = 'none';
    public const SOFT = 'soft';
    public const FULL = 'full';

    public static function decide(ClientIp $client, bool $listed): string
    {
        if (!$listed || $client->ip === '') {
            return self::NONE;
        }

        return $client->via === ClientIp::VIA_DIRECT ? self::FULL : self::SOFT;
    }
}
