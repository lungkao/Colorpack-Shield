<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Gemini;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Sends one prompt to the Gemini API and returns its plain-text reply. Fail-open throughout: any
 * problem returns null - never throws. Same contract as the Joomla edition's Gemini\Client.
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
        // JSON_INVALID_UTF8_SUBSTITUTE is a second line of defence: PromptBuilder::clean()
        // already keeps its own output valid UTF-8, but json_encode() otherwise fails *silently*
        // (returns false) on the first invalid byte anywhere in the structure. Matches the
        // Joomla edition's 0.10.2 fix.
        $body = json_encode(
            ['contents' => [['parts' => [['text' => $prompt]]]]],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
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
