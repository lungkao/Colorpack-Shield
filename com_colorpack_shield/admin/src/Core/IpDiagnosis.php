<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Reads what reached PHP for the current request and says, in a code the screen turns into
 * words, whether the plugin sees the real visitor. It judges one request (the administrator's
 * own); it cannot prove that a proxy is unforgeable: only the proxy test can.
 */
final class IpDiagnosis
{
    public const DIRECT           = 'direct';
    public const CLOUDFLARE_OK    = 'cloudflare_ok';
    public const CLOUDFLARE_NOHDR = 'cloudflare_noheader';
    public const CF_NOT_TRUSTED   = 'cloudflare_not_trusted';
    public const PROXY_OK         = 'proxy_ok';
    public const UNLISTED_PROXY   = 'unlisted_proxy';
    public const PRIVATE_DIRECT   = 'private_direct';
    public const UNKNOWN          = 'unknown';

    /**
     * @param  array{remote:string,resolved:string,via:string,headerIgnored:bool,hasForwarding:bool,hasCfHeader:bool,trustCloudflare:bool}  $in
     *
     * @return array{code:string,level:string}  level: ok | warn | bad | info
     */
    public static function explain(array $in): array
    {
        $remote  = $in['remote'];
        $private = $remote !== '' && filter_var($remote, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;

        if ($remote === '' || $in['resolved'] === '') {
            return ['code' => self::UNKNOWN, 'level' => 'info'];
        }

        if ($in['via'] === 'cloudflare-noheader') {
            return ['code' => self::CLOUDFLARE_NOHDR, 'level' => 'bad'];
        }

        if ($in['via'] === 'cloudflare') {
            return ['code' => self::CLOUDFLARE_OK, 'level' => 'ok'];
        }

        if ($in['via'] === 'proxy') {
            return ['code' => self::PROXY_OK, 'level' => 'ok'];
        }

        // via = direct from here on.
        if ($in['hasCfHeader'] && (!$in['trustCloudflare'] || $in['headerIgnored'])) {
            return ['code' => self::CF_NOT_TRUSTED, 'level' => 'warn'];
        }

        if ($private && $in['hasForwarding']) {
            // A loopback/private peer that forwards: every visitor looks like that one address.
            return ['code' => self::UNLISTED_PROXY, 'level' => 'bad'];
        }

        if ($private) {
            return ['code' => self::PRIVATE_DIRECT, 'level' => 'warn'];
        }

        return ['code' => self::DIRECT, 'level' => 'ok'];
    }
}
