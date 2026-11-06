<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\WafResult;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Names the attack and scanning tools that announce themselves in the User-Agent header.
 *
 * This is a courtesy filter, not a security boundary: the header is chosen by the sender, so a
 * careful attacker simply changes it. It still removes the large volume of unmodified tool traffic
 * (sqlmap, nikto, nuclei ...) from the logs and from the sites' load. An empty User-Agent is left
 * alone, and ordinary HTTP libraries (curl, python-requests ...) are deliberately not listed because
 * legitimate integrations use them.
 *
 * Reads the "UA" source only (see Bootstrap), so it never sees the other request values.
 */
final class UserAgentShield implements ShieldInterface
{
    /** Lowercase fragments; a User-Agent containing any of them is a known tool. */
    public const SCANNERS = [
        'sqlmap', 'nikto', 'nuclei', 'acunetix', 'nessus', 'openvas', 'wpscan', 'masscan', 'zgrab',
        'nmap scripting engine', 'dirbuster', 'gobuster', 'feroxbuster', 'wfuzz', 'ffuf', 'havij',
        'netsparker', 'appscan', 'w3af', 'arachni', 'skipfish', 'jaeles', 'commix', 'fimap',
        'joomscan', 'droopescan', 'cmsmap', 'whatweb', 'rmut-cert-toolkit',
    ];

    /**
     * @param  string    $mode   WafResult::MODE_BLOCK or WafResult::MODE_LOG
     * @param  string[]  $extra  extra lowercase fragments added by the site owner
     */
    public function __construct(private readonly string $mode = WafResult::MODE_BLOCK, private readonly array $extra = [])
    {
    }

    public function id(): string
    {
        return 'ua';
    }

    public function inspect(RequestData $data): WafResult
    {
        foreach ($data->items() as $item) {
            if ($item['source'] !== 'UA' || $item['value'] === '') {
                continue;
            }

            $ua = strtolower($item['value']);

            foreach (self::SCANNERS as $needle) {
                if (str_contains($ua, $needle)) {
                    return WafResult::hit($this->id(), 'known_scanner', 'UA', $item['key'], $item['value'], $this->mode);
                }
            }

            foreach ($this->extra as $needle) {
                if ($needle !== '' && str_contains($ua, $needle)) {
                    return WafResult::hit($this->id(), 'custom_user_agent', 'UA', $item['key'], $item['value'], $this->mode);
                }
            }
        }

        return WafResult::clean();
    }
}
