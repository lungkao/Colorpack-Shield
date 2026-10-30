<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Gemini;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Sends one prompt to the Gemini API and returns its plain-text reply.
 * Fail-open throughout: any problem (network, a non-2xx reply, an unexpected
 * JSON shape) returns null - never throws. Only ever called from an
 * admin-triggered controller action or the scheduled digest task.
 */
final class Client
{
    private const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s';

    public function __construct(private readonly HttpTransport $transport = new CurlTransport())
    {
    }

    /**
     * @return string|null  the model's plain-text reply, or null on any failure
     */
    public function ask(Config $config, string $prompt): ?string
    {
        $body = json_encode(
            ['contents' => [['parts' => [['text' => $prompt]]]]],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        if (!\is_string($body)) {
            return null;
        }

        $url = sprintf(self::ENDPOINT, rawurlencode($config->model), rawurlencode($config->apiKey));

        $resp = $this->transport->post($url, ['Content-Type' => 'application/json'], $body, 20);

        if ($resp === null || $resp['status'] !== 200) {
            return null;
        }

        $decoded = json_decode($resp['body'], true, 16);

        if (!\is_array($decoded)) {
            return null;
        }

        $text = $decoded['candidates'][0]['content']['parts'][0]['text'] ?? null;

        return \is_string($text) && $text !== '' ? $text : null;
    }
}
