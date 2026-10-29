<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Model\ServerModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class ServerController extends BaseController
{
    protected $default_view = 'server';

    /** The generated text as a file. Read-only. */
    public function download(): void
    {
        /** @var ServerModel $model */
        $model  = $this->getModel('Server', 'Administrator', ['ignore_request' => true]);
        $target = $this->input->get->getCmd('target', '');
        $allow  = $this->input->get->getString('allow', '');
        $text   = $model->render($target, $allow, $this->input->get->getInt('codedirs', 0) === 1);

        if ($text === null) {
            $this->setRedirect('index.php?option=com_colorpack_shield&view=server');

            return;
        }

        $name = $target === 'nginx' ? 'colorpack-shield-nginx.conf' : 'colorpack-shield-htaccess.txt';
        $this->app->setHeader('Content-Type', 'text/plain; charset=utf-8', true);
        $this->app->setHeader('Content-Disposition', 'attachment; filename="' . $name . '"', true);
        $this->app->setHeader('X-Content-Type-Options', 'nosniff', true);
        $this->app->sendHeaders();
        echo $text;
        $this->app->close();
    }

    public function verify(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=server');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        /** @var ServerModel $model */
        $model  = $this->getModel('Server', 'Administrator', ['ignore_request' => true]);
        $result = $model->verify();
        $type   = ['refused' => 'message', 'open' => 'error', 'unknown' => 'notice'][$result['result']] ?? 'notice';
        $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_VERIFY_' . strtoupper($result['result'])), $type);
    }

    /** Optional: put the block into this site's .htaccess for the person (Super User, token, checked live, undone on any change in the answers). */
    public function htaccess(): void
    {
        $this->changeHtaccess(false);
    }

    /** Take our block out again. */
    public function unhtaccess(): void
    {
        $this->changeHtaccess(true);
    }

    private function changeHtaccess(bool $remove): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=server');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        /** @var ServerModel $model */
        $model = $this->getModel('Server', 'Administrator', ['ignore_request' => true]);

        try {
            $r = $model->changeHtaccess($remove, $this->input->post->getArray());
        } catch (\InvalidArgumentException) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_HTA_BAD_ENTRY'), 'error');

            return;
        }

        $type = ['applied' => 'message', 'reverted' => 'error', 'cannot_verify' => 'warning'][$r['result']] ?? 'error';
        $key  = 'COM_COLORPACK_SHIELD_HTA_' . strtoupper($r['result']) . ($r['result'] === 'applied' && $remove ? '_REMOVED' : '');

        // Kept, but the host ignores .htaccess: say so instead of claiming protection.
        if ($r['result'] === 'applied' && !$remove && ($r['effective'] ?? true) === false) {
            $key  = 'COM_COLORPACK_SHIELD_HTA_APPLIED_INACTIVE';
            $type = 'warning';
        }

        $this->app->enqueueMessage(Text::_($key), $type);
    }
}
