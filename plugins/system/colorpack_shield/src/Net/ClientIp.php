<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Net;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Immutable result of resolving the real visitor IP.
 */
final class ClientIp
{
    /** Connected straight to us (or the server already rewrote REMOTE_ADDR). */
    public const VIA_DIRECT = 'direct';

    /** Real IP taken from CF-Connecting-IP, edge verified as Cloudflare. */
    public const VIA_CLOUDFLARE = 'cloudflare';

    /** Edge is Cloudflare but sent no usable header; fell back to the edge address. */
    public const VIA_CLOUDFLARE_NOHEADER = 'cloudflare-noheader';

    /** Real IP taken from a trusted proxy chain (e.g. local nginx), not Cloudflare. */
    public const VIA_PROXY = 'proxy';

    /**
     * @param  string  $ip              The address to use ('' when REMOTE_ADDR is unusable).
     * @param  string  $edge            The connecting address after skipping trusted local proxies.
     * @param  string  $via             One of the VIA_* constants.
     * @param  bool    $headerIgnored   A CF-Connecting-IP header was present but NOT trusted
     *                                  (edge is not Cloudflare). Worth logging: either a spoof
     *                                  attempt or Cloudflare being bypassed/misconfigured.
     */
    public function __construct(
        public readonly string $ip,
        public readonly string $edge,
        public readonly string $via,
        public readonly bool $headerIgnored = false
    ) {
    }
}
