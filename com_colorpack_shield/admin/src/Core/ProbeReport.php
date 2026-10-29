<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The proxy-test report the administrator's browser brings back from the plugin's probe answer.
 * It passes through a browser, so it is read strictly: only the fields the verdict needs, each
 * of the expected type and size, nothing else kept.
 */
final class ProbeReport
{
    public const MAX_BYTES = 4000;

    /**
     * @return array{probe:int,remote_addr:string,xff:string,x_real_ip:string,cf_connecting_ip:string,trusted_proxies:string[],actual:array{ip:string,via:string,header_ignored:bool}}|null
     */
    public static function parse(string $json): ?array
    {
        if ($json === '' || \strlen($json) > self::MAX_BYTES) {
            return null;
        }

        $d = json_decode($json, true, 6);

        if (!\is_array($d) || ($d['probe'] ?? null) !== 1) {
            return null;
        }

        $remote = $d['remote_addr'] ?? null;

        if (!\is_string($remote) || filter_var($remote, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $out = ['probe' => 1, 'remote_addr' => $remote];

        foreach (['xff' => 'xff', 'x_real_ip' => 'x_real_ip', 'cf_connecting_ip' => 'cf_connecting_ip'] as $key) {
            $v = $d[$key] ?? '';

            if (!\is_string($v) || \strlen($v) > 300 || preg_match('/[\x00-\x1f\x7f]/', $v) === 1) {
                return null;
            }

            $out[$key] = $v;
        }

        $proxies = $d['trusted_proxies'] ?? [];

        if (!\is_array($proxies) || !array_is_list($proxies) || \count($proxies) > 50) {
            return null;
        }

        foreach ($proxies as $p) {
            if (!\is_string($p) || \strlen($p) > 64) {
                return null;
            }
        }

        $out['trusted_proxies'] = $proxies;
        $a = $d['actual'] ?? null;

        if (!\is_array($a) || !\is_string($a['ip'] ?? null) || ($a['ip'] !== '' && filter_var($a['ip'], FILTER_VALIDATE_IP) === false)
            || !\in_array($a['via'] ?? null, ['direct', 'cloudflare', 'cloudflare-noheader', 'proxy'], true) || !\is_bool($a['header_ignored'] ?? null)) {
            return null;
        }

        $out['actual'] = ['ip' => $a['ip'], 'via' => $a['via'], 'header_ignored' => $a['header_ignored']];

        return $out;
    }
}
