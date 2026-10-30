<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Core\CsvExporter;
use Colorpack\Component\ColorpackShield\Administrator\Model\ActivityModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

\defined('_JEXEC') || die;

class ActivityController extends BaseController
{
    protected $default_view = 'activity';

    /**
     * CSV of what the Activity screen currently shows. Read-only, so a GET is fine. Addresses are
     * masked unless the person may change settings AND asks for them in full.
     */
    public function export(): void
    {
        /** @var ActivityModel $model */
        $model = $this->getModel('Activity', 'Administrator', ['ignore_request' => true]);
        $get   = $this->input->get->getArray();
        $data  = $model->getActivity($get);
        $full  = $this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield') && $this->input->get->getInt('mask', 1) === 0;
        $csv   = CsvExporter::build($data['all'], !$full);

        $this->app->setHeader('Content-Type', 'text/csv; charset=utf-8', true);
        $this->app->setHeader('Content-Disposition', 'attachment; filename="colorpack-shield-activity.csv"', true);
        $this->app->setHeader('X-Content-Type-Options', 'nosniff', true);
        $this->app->setHeader('Cache-Control', 'no-store', true);
        $this->app->sendHeaders();
        echo "\xEF\xBB\xBF" . $csv;
        $this->app->close();
    }

    /**
     * On-demand "analyse with AI" button: POST only, with the form token, and only for people who
     * may change settings - this spends the admin's own, billable Gemini API key, so it gets the
     * same guard as the Settings screen's save(), not the lighter read-only guard export() uses.
     */
    public function analyze(): void
    {
        $this->checkToken();

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');
            $this->setRedirect(Route::_('index.php?option=com_colorpack_shield&view=activity', false));

            return;
        }

        /** @var ActivityModel $model */
        $model  = $this->getModel('Activity', 'Administrator', ['ignore_request' => true]);
        $get    = $this->input->get->getArray();
        $result = $model->analyzeWithAi($get);

        $this->app->enqueueMessage(Text::_($result['message']), $result['ok'] ? 'message' : 'warning');
        $this->setRedirect(Route::_('index.php?option=com_colorpack_shield&view=activity&' . http_build_query($get), false));
    }
}
