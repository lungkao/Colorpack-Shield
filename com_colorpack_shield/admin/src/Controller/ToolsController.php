<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Model\ToolsModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class ToolsController extends BaseController
{
    protected $default_view = 'tools';

    private function model(): ToolsModel
    {
        /** @var ToolsModel $m */
        $m = $this->getModel('Tools', 'Administrator', ['ignore_request' => true]);

        return $m;
    }

    private function allowed(): bool
    {
        if ($this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            return true;
        }

        $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

        return false;
    }

    /** Settings as a file. It holds addresses and an e-mail, so Super Users only; no secret is in it. */
    public function export(): void
    {
        $this->setRedirect('index.php?option=com_colorpack_shield&view=tools');

        if (!$this->allowed()) {
            return;
        }

        $this->app->setHeader('Content-Type', 'application/json; charset=utf-8', true);
        $this->app->setHeader('Content-Disposition', 'attachment; filename="colorpack-shield-settings.json"', true);
        $this->app->setHeader('X-Content-Type-Options', 'nosniff', true);
        $this->app->setHeader('Cache-Control', 'no-store', true);
        $this->app->sendHeaders();
        echo $this->model()->exportJson();
        $this->app->close();
    }

    public function preview(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=tools');

        if (!$this->allowed()) {
            return;
        }

        $json = '';
        $file = $this->input->files->get('settings_file', null, 'raw');

        if (\is_array($file) && ($file['error'] ?? 1) === UPLOAD_ERR_OK && ($file['size'] ?? 0) > 0 && ($file['size'] ?? 0) <= 65536 && is_uploaded_file((string) ($file['tmp_name'] ?? ''))) {
            $json = (string) file_get_contents($file['tmp_name'], false, null, 0, 65537);
        } elseif ($this->input->post->getString('settings_text', '') !== '') {
            $json = (string) $this->input->post->get('settings_text', '', 'raw');
        }

        $error = $json === '' ? 'empty' : $this->model()->preview($json);

        if ($error !== '') {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_IMPORT_ERR_' . strtoupper($error)), 'error');
        }
    }

    public function apply(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=tools');

        if (!$this->allowed()) {
            return;
        }

        $r = $this->model()->apply();

        if ($r['none']) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_IMPORT_NONE'), 'notice');
        } elseif ($r['errors'] !== []) {
            foreach ($r['errors'] as $e) {
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_ERR_' . strtoupper($e['code']), $e['key'], $e['detail']), 'error');
            }
        } else {
            $this->app->enqueueMessage(Text::_($r['applied'] ? 'COM_COLORPACK_SHIELD_IMPORT_DONE' : 'COM_COLORPACK_SHIELD_ERR_SAVE_FAILED'), $r['applied'] ? 'message' : 'error');
        }
    }

    public function discard(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=tools');

        if ($this->allowed()) {
            $this->model()->discard();
        }
    }
}
