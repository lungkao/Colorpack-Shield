<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Colorpack\Plugin\System\ColorpackShield\Net\IpCountry;
use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;

\defined('_JEXEC') || die;

/**
 * The little "🇹🇭 TH" that goes next to an IP address in the Activity and Login screens.
 * Never throws: when anything is wrong the address is simply shown without a country.
 */
final class CountryLabel
{
    private ?IpCountry $country = null;

    private bool $allowRemote = true;

    public function __construct()
    {
        try {
            $params            = (new ShieldPlugin(Factory::getContainer()->get(DatabaseInterface::class)))->params();
            $this->allowRemote = filter_var($params['ip_country_lookup'] ?? true, FILTER_VALIDATE_BOOLEAN);
            $this->country     = new IpCountry(JPATH_ROOT . '/cache/colorpack_shield/country');
        } catch (\Throwable) {
            $this->country = null;
        }
    }

    /**
     * @param  bool  $masked  the screen hides addresses: a masked address is never sent to an outside service
     *
     * @return string  ready-to-print HTML (empty when the country is unknown)
     */
    public function html(string $ip, bool $masked = false): string
    {
        if ($this->country === null || $ip === '') {
            return '';
        }

        try {
            $code = $this->country->lookup($ip, $this->allowRemote && !$masked);
        } catch (\Throwable) {
            return '';
        }

        return $code === null ? '' : ' <span class="cps-muted" title="' . htmlspecialchars($code, ENT_QUOTES) . '">' . htmlspecialchars(IpCountry::label($code), ENT_QUOTES, 'UTF-8') . '</span>';
    }
}
