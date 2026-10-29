<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\SiteManager;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Signs and sends one `health`/`events` body to `{manager_url}/api/agent/shield`.
 * Fail-open throughout: any problem (bad config, network, a non-2xx reply) returns null and the
 * caller just tries again next time - never throws, never retries inline, never blocks anything
 * else.
 */
final class Client
{
    public function __construct(private readonly HttpTransport $transport = new CurlTransport())
    {
    }

    /**
     * @param  array{manager_url:string,site_id:int,secret:string}  $config
     * @param  array{health?:array<string,mixed>,events?:array<int,array<string,mixed>>}  $payload
     *
     * @return array{ok:bool,health:?bool,events:?int}|null  null when the request could not be
     *                                                         completed or answered 401/409/422/429/5xx
     */
    public function send(array $config, array $payload): ?array
    {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if (!\is_string($body) || \strlen($body) > 262144) {
            return null;
        }

        $time = (string) time();
        $sig  = Signer::sign($config['secret'], $time, $body);

        $headers = [
            'Content-Type' => 'application/json',
            'X-CP-Site'    => (string) $config['site_id'],
            'X-CP-Time'    => $time,
            'X-CP-Sig'     => $sig,
        ];

        $resp = $this->transport->post($config['manager_url'] . '/api/agent/shield', $headers, $body, 5);

        if ($resp === null || $resp['status'] !== 200) {
            return null;
        }

        $decoded = json_decode($resp['body'], true, 8);

        if (!\is_array($decoded) || ($decoded['ok'] ?? null) !== true) {
            return null;
        }

        return [
            'ok'     => true,
            'health' => \is_bool($decoded['health'] ?? null) ? $decoded['health'] : null,
            'events' => \is_int($decoded['events'] ?? null) ? $decoded['events'] : null,
        ];
    }
}
