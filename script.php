<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\CMS\Language\Text;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;

return new class () implements InstallerScriptInterface, ContainerAwareInterface {
    use ContainerAwareTrait;

    private string $minimumPhp    = '8.1.0';
    private string $minimumJoomla = '4.0.0';

    public function install($adapter): bool
    {
        return true;
    }

    public function update($adapter): bool
    {
        return true;
    }

    public function uninstall($adapter): bool
    {
        return true;
    }

    public function preflight(string $type, $adapter): bool
    {
        if (version_compare(PHP_VERSION, $this->minimumPhp, '<')) {
            Factory::getApplication()->enqueueMessage(
                sprintf('Colorpack Shield requires PHP %s or newer. You have %s.', $this->minimumPhp, PHP_VERSION),
                'error'
            );

            return false;
        }

        if (version_compare(JVERSION, $this->minimumJoomla, '<')) {
            Factory::getApplication()->enqueueMessage(
                sprintf('Colorpack Shield requires Joomla %s or newer. You have %s.', $this->minimumJoomla, JVERSION),
                'error'
            );

            return false;
        }

        return true;
    }

    public function postflight(string $type, $adapter): bool
    {
        // Auto-enable the WAF plugin on first install so protection is on by default.
        if ($type === 'install') {
            $db    = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
            $query = $db->getQuery(true)
                ->update($db->quoteName('#__extensions'))
                ->set($db->quoteName('enabled') . ' = 1')
                ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
                ->where($db->quoteName('element') . ' = ' . $db->quote('colorpack_shield'))
                ->where($db->quoteName('folder') . ' = ' . $db->quote('system'));
            $db->setQuery($query)->execute();
        }

        return true;
    }
};
