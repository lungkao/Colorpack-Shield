<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\View;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Toolbar\ToolbarHelper;

\defined('_JEXEC') || die;

/**
 * What every screen shares: the stylesheet, the page title and who may change things.
 */
trait ScreenTrait
{
    /** The screen being shown: dashboard | settings | setup. */
    public string $screen = 'dashboard';

    /** True for people who may change settings (core.admin); everyone else only looks. */
    public bool $canChange = false;

    protected function prepare(string $screen): void
    {
        $app = Factory::getApplication();

        \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::apply();

        $this->screen    = $screen;
        $this->canChange = $app->getIdentity()->authorise('core.admin', 'com_colorpack_shield');

        $this->getDocument()->getWebAssetManager()
            ->useStyle('com_colorpack_shield.admin')
            ->useScript('com_colorpack_shield.admin');

        ToolbarHelper::title(Text::_('COM_COLORPACK_SHIELD'), 'shield');
    }
}
