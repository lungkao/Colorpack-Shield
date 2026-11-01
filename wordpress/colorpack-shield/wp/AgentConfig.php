<?php

namespace Colorpack\Shield\Wp;

defined('ABSPATH') || die;

/**
 * Reads the Colorpack Agent's own config file so Shield reports to the same Site Manager with the same
 * secret - no second credential. Read-only, never copied or logged; https only (loopback allowed for tests).
 */
final class AgentConfig
{
    /** @return array{manager_url:string,site_id:int,secret:string}|null */
    public static function load(): ?array
    {
        $file = WP_PLUGIN_DIR . '/colorpack-agent/config.php';

        if (!is_file($file)) {
            return null;
        }

        try {
            $data = include $file;
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($data)) {
            return null;
        }

        $url    = trim((string) ($data['manager_url'] ?? ''));
        $siteId = (int) ($data['site_id'] ?? 0);
        $secret = (string) ($data['secret'] ?? '');
        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?: ''));
        $host   = (string) (parse_url($url, PHP_URL_HOST) ?: '');
        $ok     = $host !== '' && ($scheme === 'https' || ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true)));

        return $ok && $siteId > 0 && $secret !== '' ? ['manager_url' => rtrim($url, '/'), 'site_id' => $siteId, 'secret' => $secret] : null;
    }
}
