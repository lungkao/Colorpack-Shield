<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Core\CsvExporter;
use Colorpack\Component\ColorpackShield\Administrator\Core\ExceptionLine;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Component\ColorpackShield\Administrator\Model\ActivityModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

\defined('_JEXEC') || die;

class ActivityController extends BaseController
{
    protected $default_view = 'activity';

    /**
     * Allow one blocked field. Posted with the form token by a person who may change settings; it only takes the
     * reference code and rebuilds the exception from the log row on the server, so nothing typed in the browser
     * can widen it. Not tied to any IP address.
     */
    public function allow(): void
    {
        $this->checkToken();
        $back = 'index.php?option=com_colorpack_shield&view=activity';

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');
            $this->setRedirect($back);

            return;
        }

        $ref    = strtoupper(trim((string) $this->input->post->getString('ref', '')));
        $plugin = new ShieldPlugin(\Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class));
        $line   = null;

        if (preg_match('/^[0-9A-F]{8}$/', $ref) === 1) {
            foreach ((new LogReader($plugin->logFile()))->read()['entries'] as $entry) {
                $watched = $entry['type'] === 'DETECT' && ($entry['f']['note'] ?? '') === 'watch';

                if (($entry['type'] === 'BLOCK' || $watched) && ($entry['f']['ref'] ?? '') === $ref) {
                    $line = ExceptionLine::fromRow($entry['f']);

                    break;
                }
            }
        }

        if ($line === null) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_ALLOW_NOT_POSSIBLE'), 'warning');
            $this->setRedirect($back);

            return;
        }

        $current = ExceptionLine::withoutWatch((string) ($plugin->params()['waf_exceptions'] ?? ''), $line);

        if (!ExceptionLine::contains($current, $line)) {
            $current = ExceptionLine::append($current, $line);
        }

        if (!$plugin->save(['waf_exceptions' => $current])) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_ERR_SAVE_FAILED'), 'error');
            $this->setRedirect($back);

            return;
        }

        $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_ALLOWED', $line), 'message');
        $this->setRedirect($back);
    }

    /**
     * Watch one blocked field for a week instead of allowing it: its low and medium rules are logged but no longer block,
     * real attack patterns still block, and the watch ends by itself. Takes only the reference code; the line is
     * rebuilt from the log row here.
     */
    public function watch(): void
    {
        $this->checkToken();
        $back = 'index.php?option=com_colorpack_shield&view=activity';

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');
            $this->setRedirect($back);

            return;
        }

        $ref    = strtoupper(trim((string) $this->input->post->getString('ref', '')));
        $plugin = new ShieldPlugin(\Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class));
        $line   = null;

        if (preg_match('/^[0-9A-F]{8}$/', $ref) === 1) {
            foreach ((new LogReader($plugin->logFile()))->read()['entries'] as $entry) {
                if ($entry['type'] === 'BLOCK' && ($entry['f']['ref'] ?? '') === $ref && ExceptionLine::isWatchable($entry['f']['rule'] ?? '')) {
                    $line = ExceptionLine::fromRow($entry['f']);

                    break;
                }
            }
        }

        if ($line === null) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_WATCH_NOT_POSSIBLE'), 'warning');
            $this->setRedirect($back);

            return;
        }

        $now   = time();
        $until = $now + ExceptionLine::WATCH_SECONDS;

        if (!$plugin->save(['waf_exceptions' => ExceptionLine::withWatch((string) ($plugin->params()['waf_exceptions'] ?? ''), $line, $until, $now)])) {
            $this->app->enqueueMessage(Text::_('COM_COLORPACK_SHIELD_ERR_SAVE_FAILED'), 'error');
            $this->setRedirect($back);

            return;
        }

        $this->app->enqueueMessage(Text::sprintf('COM_COLORPACK_SHIELD_WATCHING', $line, gmdate('Y-m-d H:i', $until) . ' UTC'), 'message');
        $this->setRedirect($back);
    }

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
}
