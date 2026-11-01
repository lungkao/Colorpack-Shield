<?php

namespace Colorpack\WP\ColorpackShield\SiteManager;


defined('ABSPATH') || die;

/** Site Manager POSTs through WordPress's HTTP API: short timeout, no redirects, null on any failure. */
final class WpTransport implements HttpTransport
{
    public function post(string $url, array $headers, string $body, int $timeoutSeconds): ?array
    {
        $r = wp_remote_post($url, ['headers' => $headers, 'body' => $body, 'timeout' => $timeoutSeconds, 'redirection' => 0, 'blocking' => true]);

        if (is_wp_error($r)) {
            return null;
        }

        return ['status' => (int) wp_remote_retrieve_response_code($r), 'body' => (string) wp_remote_retrieve_body($r)];
    }
}
