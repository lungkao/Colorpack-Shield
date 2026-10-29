<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Core\ProbeReport;
use Colorpack\Component\ColorpackShield\Administrator\Model\NetworkModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

\defined('_JEXEC') || die;

class NetworkController extends BaseController
{
    protected $default_view = 'network';

    public function refresh(): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=network');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        /** @var NetworkModel $model */
        $model  = $this->getModel('Network', 'Administrator', ['ignore_request' => true]);
        $result = $model->refreshRanges();

        switch ($result['status']) {
            case 'updated':
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_CF_UPDATED', (int) $result['count']), 'message');
                break;
            case 'unchanged':
                $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_CF_UNCHANGED'), 'message');
                break;
            case 'cooldown':
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_CF_COOLDOWN', NetworkModel::COOLDOWN), 'notice');
                break;
            default:
                // The reason text comes from our own refresher code, never from the download.
                $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_CF_FAILED', htmlspecialchars($result['reason'], ENT_QUOTES, 'UTF-8')), 'error');
        }
    }

    /**
     * The browser's proxy test came back: judge it and remember the verdict. The report is read
     * strictly (ProbeReport) and nothing from it is ever shown or stored except the verdict.
     */
    public function probe(): void
    {
        $this->checkToken();
        $back = $this->input->post->getCmd('return', '') === 'setup' ? 'setup' : 'network';
        $this->setRedirect('index.php?option=com_colorpack_shield&view=' . $back);

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        $report = ProbeReport::parse((string) $this->input->post->get('report', '', 'raw'));

        if ($report === null) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_PROBE_BAD_REPORT'), 'error');

            return;
        }

        /** @var NetworkModel $model */
        $model  = $this->getModel('Network', 'Administrator', ['ignore_request' => true]);
        $result = $model->judgeProbe($report);
        $type   = ['safe' => 'message', 'no_proxy' => 'message', 'spoofable' => 'error', 'inconclusive' => 'notice'][$result['verdict']] ?? 'notice';
        $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_PROBE_DONE_' . strtoupper($result['verdict'])), $type);
    }
}
