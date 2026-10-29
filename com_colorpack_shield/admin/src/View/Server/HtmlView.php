<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\View\Server;

use Colorpack\Component\ColorpackShield\Administrator\View\ScreenTrait;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;

\defined('_JEXEC') || die;

class HtmlView extends BaseHtmlView
{
    use ScreenTrait;

    /** @var array<string,mixed> */
    public array $server = [];

    public function display($tpl = null): void
    {
        $this->prepare('server');
        $this->server = $this->getModel()->getServer(Factory::getApplication()->getInput()->get->getArray());

        parent::display($tpl);
    }
}
