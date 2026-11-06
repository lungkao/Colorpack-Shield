<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;
use Colorpack\Plugin\System\ColorpackShield\Vulnerable\VelFeed;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class DashboardController extends BaseController
{
    protected $default_view = 'dashboard';

    /** "Check now": downloads the JED Vulnerable Extensions List again (a plain public GET, nothing about this site is sent). */
    public function checkVulnerable(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=dashboard');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        $dir    = JPATH_ROOT . '/cache/colorpack_shield/vel';

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $result = (new VelFeed(new ScanStore($dir)))->refresh([VelFeed::class, 'curlGet'], time(), true);

        $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_VEL_RESULT_' . strtoupper($result)), $result === 'failed' ? 'warning' : 'message');
    }
}
