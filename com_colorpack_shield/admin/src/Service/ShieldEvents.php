<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\Event;

\defined('_JEXEC') || die;

/**
 * Extension point for add-ons. When the Dashboard (or a Settings save) works out the security score it is announced
 * to every system plugin as "onColorpackShieldScore" with the arguments `score` (ScoreCalculator::calculate()'s
 * output) and `version` (this package's version). Shield itself does nothing with it; an add-on may.
 *
 * Never throws: a missing add-on, or one that fails, must not break the Dashboard or a Settings save.
 */
final class ShieldEvents
{
    /**
     * @param  array{score:?int,items:array<int,array{id:string,weight:int,status:string}>}  $score
     */
    public static function scoreComputed(array $score, string $version): void
    {
        try {
            PluginHelper::importPlugin('system');
            Factory::getApplication()->getDispatcher()->dispatch('onColorpackShieldScore', new Event('onColorpackShieldScore', ['score' => $score, 'version' => $version]));
        } catch (\Throwable) {
            // Nobody listening, or a listener failed.
        }
    }
}
