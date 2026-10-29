<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Model\SettingsModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class SettingsController extends BaseController
{
    protected $default_view = 'settings';

    public function save(): void
    {
        // POST only, with the form token, and only for people who may change settings.
        $this->checkToken();

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');
            $this->setRedirect('index.php?option=com_colorpack_shield&view=dashboard');

            return;
        }

        /** @var SettingsModel $model */
        $model     = $this->getModel('Settings', 'Administrator', ['ignore_request' => true]);
        $posted    = $this->input->post->get('jform', [], 'raw');
        $submitted = \is_array($posted) && \is_array($posted['params'] ?? null) ? $posted['params'] : [];
        $result    = $model->saveSettings($submitted);

        // Whatever the person typed comes back on the form if the save was refused.
        $this->app->setUserState('com_colorpack_shield.settings', ['params' => $submitted, 'errors' => $result['errors'], 'warnings' => $result['warnings']]);

        foreach ($result['warnings'] as $w) {
            $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_WARN_' . strtoupper($w['code']), $w['key'], $w['detail']), 'warning');
        }

        if ($result['saved']) {
            $this->app->setUserState('com_colorpack_shield.settings', null);
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_SAVED'), 'message');
        } elseif ($result['errors'] === []) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_ERR_SAVE_FAILED'), 'error');
        } else {
            foreach ($result['errors'] as $e) {
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_ERR_' . strtoupper($e['code']), $e['key'], $e['detail']), 'error');
            }
        }

        $this->setRedirect('index.php?option=com_colorpack_shield&view=settings');
    }
}
