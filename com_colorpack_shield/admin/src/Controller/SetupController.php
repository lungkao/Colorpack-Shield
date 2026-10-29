<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Model\SetupModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class SetupController extends BaseController
{
    protected $default_view = 'setup';

    public function apply(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=setup');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        $step = $this->input->post->getInt('step', 0);

        if (!\in_array($step, SetupModel::STEPS, true)) {
            return;
        }

        /** @var SetupModel $model */
        $model  = $this->getModel('Setup', 'Administrator', ['ignore_request' => true]);
        $result = $model->apply($step);

        if ($result['errors'] !== []) {
            foreach ($result['errors'] as $e) {
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_ERR_' . strtoupper($e['code']), $e['key'], $e['detail']), 'error');
            }

            return;
        }

        if ($result['nothing']) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_SETUP_NOTHING'), 'notice');

            return;
        }

        $this->app->enqueueMessage(Text::_($result['applied'] ? 'COM_COLORPACK_SHIELD_SETUP_APPLIED' : 'COM_COLORPACK_SHIELD_ERR_SAVE_FAILED'), $result['applied'] ? 'message' : 'error');
    }
}
