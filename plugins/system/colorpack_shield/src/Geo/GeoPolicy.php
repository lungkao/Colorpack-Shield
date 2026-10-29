<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Geo;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * P1.2: decide whether a request is allowed on the basis of its source IP and
 * resolved country. Pure and Joomla-free — the country string is supplied by a
 * separate resolver ({@see CountryLookup}) so the whole decision is testable.
 *
 * Precedence (first match wins):
 *   1. IP allowlist  — an explicit trusted CIDR ALWAYS passes (office IPs, the
 *      monitoring probe) even from an otherwise-denied country.
 *   2. IP denylist   — an explicit banned CIDR is blocked outright.
 *   3. Country rule  — deny-mode blocks listed countries; allow-mode blocks
 *      everything NOT listed.
 *
 * An unknown country (no DB, private IP, gap in the DB) fails OPEN in deny-mode
 * (can't be on a denylist) and, in allow-mode, follows $allowUnknown so an
 * operator can choose fail-open or fail-closed.
 */
final class GeoPolicy
{
    /** @var string[] uppercased ISO-3166-1 alpha-2 codes */
    private array $countries;

    /**
     * @param  string    $mode         'deny' | 'allow'
     * @param  string[]  $countries    ISO country codes the rule applies to
     * @param  string[]  $allowIps     CIDRs that always pass
     * @param  string[]  $denyIps      CIDRs that are always blocked
     * @param  bool      $allowUnknown allow requests with no resolved country (allow-mode only)
     */
    public function __construct(
        private readonly string $mode,
        array $countries,
        private readonly array $allowIps = [],
        private readonly array $denyIps = [],
        private readonly bool $allowUnknown = true
    ) {
        $this->countries = array_map('strtoupper', $countries);
    }

    /**
     * Does a verdict require the (potentially expensive) country lookup? Lets
     * the caller skip the DB read when only IP rules are configured.
     */
    public function needsCountry(): bool
    {
        return $this->countries !== [];
    }

    /**
     * @param  string       $ip       the client IP
     * @param  string|null   $country resolved ISO code, or null if unknown
     *
     * @return string|null  a stable block-reason token, or null to allow
     */
    public function decide(string $ip, ?string $country): ?string
    {
        if (CidrMatcher::matchesAny($ip, $this->allowIps)) {
            return null;
        }

        if (CidrMatcher::matchesAny($ip, $this->denyIps)) {
            return 'ip_denylist';
        }

        if ($this->countries === []) {
            return null;
        }

        $iso = $country === null ? null : strtoupper($country);

        if ($this->mode === 'allow') {
            if ($iso === null) {
                return $this->allowUnknown ? null : 'geo_unknown';
            }

            return \in_array($iso, $this->countries, true) ? null : 'geo_not_allowed';
        }

        // deny-mode: an unknown country can't be on the denylist → allow.
        if ($iso === null) {
            return null;
        }

        return \in_array($iso, $this->countries, true) ? 'geo_denied' : null;
    }
}
