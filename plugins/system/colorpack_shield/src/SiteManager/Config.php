<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\SiteManager;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Reads the Colorpack Site Manager Agent's own config file
 * (`JPATH_PLUGINS/system/colorpack/config.php`) so Shield can push data to the same Site Manager
 * the Agent already talks to, with the same secret - no separate credential to manage.
 *
 * The file is same-filesystem, trusted content written only by the Agent plugin (`plg_system_colorpack`),
 * which already `include`s it itself; it never touches request input. Read-only, never copied
 * elsewhere, never logged.
 */
final class Config
{
    /** Hostnames exempt from the https:// requirement, for local testing only. */
    private const LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /**
     * @return array{manager_url:string,site_id:int,secret:string}|null  null when the file is
     *                                                                    missing, unreadable, or its contents are not usable
     */
    public static function load(string $jpathPlugins): ?array
    {
        $file = rtrim($jpathPlugins, '/') . '/system/colorpack/config.php';

        if (!is_file($file)) {
            return null;
        }

        try {
            $data = include $file;
        } catch (\Throwable) {
            return null;
        }

        if (!\is_array($data)) {
            return null;
        }

        $url    = trim((string) ($data['manager_url'] ?? ''));
        $siteId = (int) ($data['site_id'] ?? 0);
        $secret = (string) ($data['secret'] ?? '');

        if ($url === '' || $siteId <= 0 || $secret === '' || !self::validUrl($url)) {
            return null;
        }

        return ['manager_url' => rtrim($url, '/'), 'site_id' => $siteId, 'secret' => $secret];
    }

    /**
     * https:// always allowed; http:// only for an exact loopback host (testing). The host is
     * compared exactly (via parse_url, not a substring check) so "https://localhost.example.com"
     * is never mistaken for the real loopback host.
     */
    private static function validUrl(string $url): bool
    {
        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?: ''));
        $host   = (string) (parse_url($url, PHP_URL_HOST) ?: '');

        if ($host === '') {
            return false;
        }

        if ($scheme === 'https') {
            return true;
        }

        return $scheme === 'http' && \in_array($host, self::LOCAL_HOSTS, true);
    }
}
