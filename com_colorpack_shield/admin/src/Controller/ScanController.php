<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Controller;

use Colorpack\Component\ColorpackShield\Administrator\Model\ScanModel;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Session\Session;

\defined('_JEXEC') || die;

class ScanController extends BaseController
{
    protected $default_view = 'scan';

    private function model(): ScanModel
    {
        /** @var ScanModel $m */
        $m = $this->getModel('Scan', 'Administrator', ['ignore_request' => true]);

        return $m;
    }

    /** JSON answer for the progress script; refuses anything but a Super User with a valid token. */
    private function json(callable $work): void
    {
        $allowed = Session::checkToken('post') && $this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield');

        $this->app->setHeader('Content-Type', 'application/json; charset=utf-8', true);
        $this->app->setHeader('Cache-Control', 'no-store', true);

        if (!$allowed) {
            $this->app->setHeader('status', '403 Forbidden', true);
            $this->app->sendHeaders();
            echo json_encode(['ok' => false]);
            $this->app->close();

            return;
        }

        $out = $work();
        $this->app->sendHeaders();
        echo json_encode($out);
        $this->app->close();
    }

    public function start(): void
    {
        $this->json(fn (): array => ['ok' => $this->model()->start()]);
    }

    public function step(): void
    {
        $this->json(fn (): array => $this->model()->step());
    }

    private function act(callable $work, string $okKey, string $failKey = 'COM_COLORPACK_SHIELD_SCAN_FAILED'): void
    {
        $this->checkToken();
        $this->setRedirect('index.php?option=com_colorpack_shield&view=scan');

        if (!$this->app->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $this->app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');

            return;
        }

        $ok = $work();
        $this->app->enqueueMessage(Text::_($ok ? $okKey : $failKey), $ok ? 'message' : 'error');
    }

    public function accept(): void
    {
        $this->act(fn (): bool => $this->model()->acceptBaseline(), 'COM_COLORPACK_SHIELD_SCAN_ACCEPTED');
    }

    public function safe(): void
    {
        $path = (string) $this->input->post->get('path', '', 'raw');
        $hash = $this->input->post->getCmd('hash', '');
        $this->act(fn (): bool => $this->model()->markSafe($path, strtolower($hash)), 'COM_COLORPACK_SHIELD_SCAN_MARKED');
    }

    public function clearsafe(): void
    {
        $this->act(function (): bool {
            $this->model()->clearSafe();

            return true;
        }, 'COM_COLORPACK_SHIELD_SCAN_CLEARED');
    }

    /** A file's text and its suspicious lines, for the code dialog. */
    public function view(): void
    {
        $path = (string) $this->input->post->get('path', '', 'raw');
        $this->json(fn (): array => $this->model()->view($path));
    }

    public function save(): void
    {
        $path    = (string) $this->input->post->get('path', '', 'raw');
        $content = (string) $this->input->post->get('content', '', 'raw');
        $base    = $this->input->post->getCmd('base', '');
        $force   = $this->input->post->getInt('force', 0) === 1;
        $this->json(fn (): array => $this->model()->save($path, $content, strtolower($base), $force));
    }

    public function delete(): void
    {
        $path    = (string) $this->input->post->get('path', '', 'raw');
        $confirm = (string) $this->input->post->get('confirm', '', 'raw');
        $this->json(fn (): array => $this->model()->delete($path, $confirm));
    }

    public function bulkdelete(): void
    {
        $paths = $this->input->post->get('paths', [], 'array');
        $this->json(fn (): array => $this->model()->bulkDelete(\is_array($paths) ? array_map('strval', $paths) : []));
    }

    public function bulksafe(): void
    {
        $paths = $this->input->post->get('paths', [], 'array');
        $this->json(fn (): array => $this->model()->bulkSafe(\is_array($paths) ? array_map('strval', $paths) : []));
    }

    public function bulkbyfilter(): void
    {
        $action = $this->input->post->getCmd('action', '');
        $sev    = $this->input->post->getCmd('sev', '');
        $text   = (string) $this->input->post->get('q', '', 'raw');
        $this->json(fn (): array => $this->model()->bulkByFilter($action, ['sev' => $sev, 'q' => $text]));
    }

    public function restore(): void
    {
        $id        = $this->input->post->getCmd('id', '');
        $overwrite = $this->input->post->getInt('overwrite', 0) === 1;
        $this->json(fn (): array => $this->model()->restore($id, $overwrite));
    }

    public function dropcopy(): void
    {
        $id = $this->input->post->getCmd('id', '');
        $this->json(fn (): array => ['ok' => $this->model()->dropCopy($id)]);
    }

    /** On-demand "analyse with AI" button for the scan findings - same AJAX pattern as the other actions here. */
    public function analyze(): void
    {
        $this->json(function (): array {
            $r = $this->model()->analyzeWithAi();

            return ['ok' => $r['ok'], 'message' => Text::_($r['message'])];
        });
    }
}
