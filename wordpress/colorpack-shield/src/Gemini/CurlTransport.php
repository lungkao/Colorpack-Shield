<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Gemini;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Real outbound POST - curl first, stream-context fallback, short timeouts, no redirects,
 * HTTPS-only, never throws. Same house style as the Joomla edition's Gemini\CurlTransport. Not
 * wired to anything yet on this side - WordPress has no Settings screen, Activity log, or file
 * scanner yet to drive it from.
 */
final class CurlTransport implements HttpTransport
{
    private const MAX_RESPONSE_BYTES = 65536;

    public function post(string $url, array $headers, string $body, int $timeoutSeconds): ?array
    {
        $lines = [];

        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        if (\function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => $timeoutSeconds,
                CURLOPT_CONNECTTIMEOUT => min(5, $timeoutSeconds),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_HTTPHEADER     => $lines,
                CURLOPT_USERAGENT      => 'ColorpackShield/0.1 (+https://colorpack.co.th)',
            ]);
            $response = curl_exec($ch);
            $status   = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            unset($ch);

            return \is_string($response) ? ['status' => $status, 'body' => substr($response, 0, self::MAX_RESPONSE_BYTES)] : null;
        }

        $ctx = stream_context_create([
            'http' => [
                'method'          => 'POST',
                'header'          => implode("\r\n", $lines),
                'content'         => $body,
                'timeout'         => $timeoutSeconds,
                'follow_location' => 0,
                'ignore_errors'   => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $response = @file_get_contents($url, false, $ctx, 0, self::MAX_RESPONSE_BYTES);

        if (!\is_string($response)) {
            return null;
        }

        $status = 0;

        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return ['status' => $status, 'body' => $response];
    }
}
