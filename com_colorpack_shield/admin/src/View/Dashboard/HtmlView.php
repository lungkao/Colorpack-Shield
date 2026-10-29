<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\View\Dashboard;

use Colorpack\Component\ColorpackShield\Administrator\View\ScreenTrait;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;

\defined('_JEXEC') || die;

class HtmlView extends BaseHtmlView
{
    use ScreenTrait;

    /** @var array<string,mixed> */
    public array $summary = [];

    public function display($tpl = null): void
    {
        $this->prepare('dashboard');
        $this->summary = $this->getModel()->getSummary();

        parent::display($tpl);
    }
}
