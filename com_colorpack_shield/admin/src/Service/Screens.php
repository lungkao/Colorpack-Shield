<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

\defined('_JEXEC') || die;

/**
 * The screens, in tab order: view name => language key. One list for the tabs and for the
 * controller's whitelist, so a view that is not here cannot be asked for.
 */
final class Screens
{
    public const ALL = [
        'dashboard' => 'COM_COLORPACK_SHIELD_NAV_DASHBOARD',
        'setup'     => 'COM_COLORPACK_SHIELD_NAV_SETUP',
        'settings'  => 'COM_COLORPACK_SHIELD_NAV_SETTINGS',
        'scan'      => 'COM_COLORPACK_SHIELD_NAV_SCAN',
        'activity'  => 'COM_COLORPACK_SHIELD_NAV_ACTIVITY',
        'login'     => 'COM_COLORPACK_SHIELD_NAV_LOGIN',
        'rules'     => 'COM_COLORPACK_SHIELD_NAV_RULES',
        'network'   => 'COM_COLORPACK_SHIELD_NAV_NETWORK',
        'server'    => 'COM_COLORPACK_SHIELD_NAV_SERVER',
        'tools'     => 'COM_COLORPACK_SHIELD_NAV_TOOLS',
    ];
}
