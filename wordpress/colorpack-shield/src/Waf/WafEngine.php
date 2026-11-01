<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

use Colorpack\WP\ColorpackShield\Waf\Shield\MultiResultShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\ShieldInterface;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Orchestrates the shield set over one request for a given client
 * ("site" | "admin"). Each shield declares which clients it covers, so the
 * same generic shields can run on both the public front end and wp-admin.
 *
 * WordPress-free by design so the whole request→verdict path is unit-testable.
 */
final class WafEngine
{
    /**
     * @param  ShieldInterface[]        $shields  registered shields
     * @param  array<string, string[]>  $scopes   shieldId => list of covered clients
     */
    public function __construct(
        private readonly array $shields,
        private readonly array $scopes
    ) {
    }

    /**
     * Run every shield that covers $client against the request.
     * Returns the first BLOCKING hit, or a clean result. Detect-only (log)
     * hits are ignored here — use inspectAll() to see them.
     */
    public function inspect(string $client, RequestData $data): WafResult
    {
        return $this->inspectAll($client, $data)['block'] ?? WafResult::clean();
    }

    /**
     * Like inspect(), but also returns the detect-only hits.
     *
     * @return array{block:?WafResult,logged:WafResult[]}
     */
    public function inspectAll(string $client, RequestData $data): array
    {
        $logged = [];

        foreach ($this->shields as $shield) {
            $covered = $this->scopes[$shield->id()] ?? ['site'];

            if (!\in_array($client, $covered, true)) {
                continue;
            }

            $results = $shield instanceof MultiResultShield
                ? $shield->inspectAll($data)
                : [$shield->inspect($data)];

            foreach ($results as $result) {
                if (!$result->matched) {
                    continue;
                }

                if ($result->mode === WafResult::MODE_BLOCK || $result->mode === WafResult::MODE_BAN) {
                    return ['block' => $result, 'logged' => $logged];
                }

                $logged[] = $result;
            }
        }

        return ['block' => null, 'logged' => $logged];
    }
}
