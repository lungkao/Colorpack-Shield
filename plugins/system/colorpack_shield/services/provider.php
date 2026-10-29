<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;
use Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                $config  = (array) PluginHelper::getPlugin('system', 'colorpack_shield');
                $subject = $container->get(DispatcherInterface::class);

                $plugin = new ColorpackShield($subject, $config);
                $plugin->setApplication(Factory::getApplication());

                return $plugin;
            }
        );
    }
};
