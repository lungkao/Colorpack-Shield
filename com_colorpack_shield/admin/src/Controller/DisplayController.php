<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Service\Screens;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

/**
 * Screens only; a GET never changes anything. Viewing needs core.manage, which Joomla's
 * dispatcher already checks before this class runs.
 */
class DisplayController extends BaseController
{
    protected $default_view = 'dashboard';

    public function display($cachable = false, $urlparams = [])
    {
        // Our own view names only: nothing from the request names a file.
        $view = $this->input->getCmd('view', $this->default_view);

        if (!isset(Screens::ALL[$view])) {
            $this->input->set('view', $this->default_view);
        }

        return parent::display(false, $urlparams);
    }

    /**
     * The language buttons: remember the choice in a cookie and go back to the same screen. Only
     * our two languages (or "follow the administrator language") are accepted.
     */
    public function language(): void
    {
        $this->checkToken();

        $return = $this->input->post->getCmd('return', 'dashboard');
        $this->setRedirect('index.php?option=com_colorpack_shield&view=' . (isset(Screens::ALL[$return]) ? $return : 'dashboard'));

        \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::remember((string) $this->input->post->getString('lang', ''));
    }
}
