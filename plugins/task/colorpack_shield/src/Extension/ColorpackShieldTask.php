<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\Task\ColorpackShield\Extension;

use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Component\Scheduler\Administrator\Event\ExecuteTaskEvent;
use Joomla\Component\Scheduler\Administrator\Task\Status;
use Joomla\Component\Scheduler\Administrator\Traits\TaskPluginTrait;
use Joomla\Event\SubscriberInterface;

\defined('_JEXEC') || die;

/**
 * Scheduled Task: keeps the signed copy of Cloudflare's edge IP ranges fresh.
 *
 * The job itself lives in the system plugin (Net\CloudflareRefresher) so the CLI
 * script and this task run exactly the same code and checks. A failed or
 * suspicious download changes nothing; the task then reports a failure so it
 * shows up in the scheduler's log.
 */
class ColorpackShieldTask extends CMSPlugin implements SubscriberInterface
{
    use TaskPluginTrait;

    /** @var array<string,array<string,string>> */
    private const TASKS_MAP = [
        'colorpack_shield.cloudflare_ranges' => [
            'langConstPrefix' => 'PLG_TASK_COLORPACK_SHIELD_CFRANGES',
            'method'          => 'refreshCloudflareRanges',
        ],
        'colorpack_shield.file_scan' => [
            'langConstPrefix' => 'PLG_TASK_COLORPACK_SHIELD_FILESCAN',
            'method'          => 'scanFiles',
        ],
        'colorpack_shield.site_manager_sync' => [
            'langConstPrefix' => 'PLG_TASK_COLORPACK_SHIELD_SITEMANAGER',
            'method'          => 'syncSiteManager',
        ],
    ];

    /** @var bool */
    protected $autoloadLanguage = true;

    public static function getSubscribedEvents(): array
    {
        return [
            'onTaskOptionsList'    => 'advertiseRoutines',
            'onExecuteTask'        => 'standardRoutineHandler',
            'onContentPrepareForm' => 'enhanceTaskItemForm',
        ];
    }

    /** The download function; only tests replace it. */
    protected function fetcher(): callable
    {
        return ['Colorpack\\Plugin\\System\\ColorpackShield\\Net\\CloudflareRefresher', 'fetch'];
    }

    private function refreshCloudflareRanges(ExecuteTaskEvent $event): int
    {
        // The job classes belong to the system plugin; load them by path in case its namespace is not mapped yet.
        $base = JPATH_PLUGINS . '/system/colorpack_shield/src/Net';

        foreach (['CloudflareRanges', 'CloudflareRefresher'] as $class) {
            $fqcn = 'Colorpack\\Plugin\\System\\ColorpackShield\\Net\\' . $class;

            if (!class_exists($fqcn, false) && is_file($base . '/' . $class . '.php')) {
                require_once $base . '/' . $class . '.php';
            }
        }

        $ranges    = 'Colorpack\\Plugin\\System\\ColorpackShield\\Net\\CloudflareRanges';
        $refresher = 'Colorpack\\Plugin\\System\\ColorpackShield\\Net\\CloudflareRefresher';

        if (!class_exists($ranges) || !class_exists($refresher)) {
            $this->logTask('Cloudflare ranges: the Colorpack Shield system plugin is not installed', 'error');

            return Status::KNOCKOUT;
        }

        $key  = $ranges::deriveKey((string) $this->getApplication()->get('secret', ''));
        $path = $ranges::defaultPath(JPATH_ROOT);

        $result = $refresher::refresh($this->fetcher(), $path, $key, $ranges::load($path, $key));

        $ok = \in_array($result['status'], [$refresher::OK, $refresher::UNCHANGED], true);
        $this->logTask(sprintf('Cloudflare ranges: %s — %s (%d entries)', $result['status'], $result['reason'], $result['count']), $ok ? 'info' : 'error');

        return $ok ? Status::OK : Status::KNOCKOUT;
    }

    /**
     * The file scan as a scheduled task: works in short runs (it continues what the File scan page
     * started, or what the last run left), and e-mails once when a finished scan has serious findings.
     */
    private function scanFiles(ExecuteTaskEvent $event): int
    {
        $base = JPATH_PLUGINS . '/system/colorpack_shield/src';

        foreach (['Scanner/SignatureRules', 'Scanner/LocationRules', 'Scanner/FileScanner', 'Scanner/ScanStore', 'Safety/KillSwitchAlert'] as $file) {
            $fqcn = 'Colorpack\\Plugin\\System\\ColorpackShield\\' . str_replace('/', '\\', $file);

            if (!class_exists($fqcn, false) && is_file($base . '/' . $file . '.php')) {
                require_once $base . '/' . $file . '.php';
            }
        }

        $scanner = 'Colorpack\\Plugin\\System\\ColorpackShield\\Scanner\\FileScanner';
        $store   = 'Colorpack\\Plugin\\System\\ColorpackShield\\Scanner\\ScanStore';

        if (!class_exists($scanner) || !class_exists($store)) {
            $this->logTask('File scan: the Colorpack Shield system plugin is not installed', 'error');

            return Status::KNOCKOUT;
        }

        $s   = new $store(JPATH_ROOT . '/cache/colorpack_shield/scan');
        $max = (int) ini_get('max_execution_time');
        $sec = $max > 0 ? max(2.0, min(20.0, $max * 0.4)) : 20.0;
        $st  = $s->read('state') ?? $scanner::newState(time());
        $ign = $s->read('ignore');
        $st  = $scanner::step($st, JPATH_ROOT, microtime(true) + $sec, \is_array($ign) ? array_map('strval', $ign) : []);

        if (!$st['done']) {
            $s->write('state', $st);
            $this->logTask(sprintf('File scan: %d files so far, continues at the next run', $st['seen']), 'info');

            return Status::OK;
        }

        $now = time();
        $res = $scanner::result($st, $s->read('baseline'), $now);
        $s->write('result', $res);
        $s->write('lastfiles', ['at' => $now, 'files' => $st['tracked'] ? $st['files'] : null]);
        $s->delete('state');
        $this->logTask(sprintf('File scan: %d files, %d serious, %d medium', $res['seen'], $res['count']['high'], $res['count']['medium']), 'info');

        if ($res['count']['high'] > 0) {
            $to = '';

            try {
                $sys = \Joomla\CMS\Plugin\PluginHelper::getPlugin('system', 'colorpack_shield');
                $to  = trim((string) (new \Joomla\Registry\Registry($sys->params ?? '{}'))->get('alert_email', ''));
            } catch (\Throwable) {
                $to = '';
            }

            $to = $to !== '' ? $to : trim((string) $this->getApplication()->get('mailfrom', ''));

            if ($to !== '') {
                $clean = static fn (string $v): string => substr(preg_replace('/[^\P{C}\t]|[\r\n]+/u', ' ', $v) ?? '', 0, 200);
                $list  = [];

                foreach (array_slice(array_filter($res['findings'], static fn (array $f): bool => $f['sev'] === 'high'), 0, 10) as $f) {
                    $list[] = '- ' . $clean((string) $f['path']);
                }

                \Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitchAlert::send(
                    $to,
                    Text::sprintf('PLG_TASK_COLORPACK_SHIELD_FILESCAN_MAIL_SUBJECT', $clean((string) $this->getApplication()->get('sitename', ''))),
                    Text::sprintf('PLG_TASK_COLORPACK_SHIELD_FILESCAN_MAIL_BODY', $clean((string) $this->getApplication()->get('sitename', '')), (string) $res['count']['high'], implode("\n", $list))
                );
            }
        }

        return Status::OK;
    }

    /**
     * Pushes the Colorpack Site Manager integration's queued events (P3/P4) and, at most once a
     * day, the cached health report (P6) - see `docs/shield-integration.md` in the Site Manager
     * project. Reads what the system plugin and the admin component already prepared; computes
     * nothing itself. Off by default (the system plugin's own switch), and silent - not even a
     * log line beyond this task's own run - when the Agent plugin's config is absent or invalid,
     * per the spec.
     */
    private function syncSiteManager(ExecuteTaskEvent $event): int
    {
        $base = JPATH_PLUGINS . '/system/colorpack_shield/src';

        foreach (['AdminProtect/StateStore', 'AdminProtect/FileStateStore', 'AdminProtect/AlertThrottle', 'SiteManager/HttpTransport', 'SiteManager/CurlTransport', 'SiteManager/Config', 'SiteManager/Signer', 'SiteManager/Client', 'SiteManager/EventQueue', 'SiteManager/HealthCache'] as $file) {
            $fqcn = 'Colorpack\\Plugin\\System\\ColorpackShield\\' . str_replace('/', '\\', $file);

            if (!class_exists($fqcn, false) && is_file($base . '/' . $file . '.php')) {
                require_once $base . '/' . $file . '.php';
            }
        }

        $store = 'Colorpack\\Plugin\\System\\ColorpackShield\\AdminProtect\\FileStateStore';
        $cfg   = 'Colorpack\\Plugin\\System\\ColorpackShield\\SiteManager\\Config';

        if (!class_exists($store) || !class_exists($cfg)) {
            $this->logTask('Site Manager sync: the Colorpack Shield system plugin is not installed', 'error');

            return Status::KNOCKOUT;
        }

        $enabled = false;

        try {
            $sys     = \Joomla\CMS\Plugin\PluginHelper::getPlugin('system', 'colorpack_shield');
            $enabled = filter_var((new \Joomla\Registry\Registry($sys->params ?? '{}'))->get('site_manager_enabled', 0), FILTER_VALIDATE_BOOLEAN);
        } catch (\Throwable) {
            $enabled = false;
        }

        if (!$enabled) {
            $this->logTask('Site Manager sync: switched off, nothing to do', 'info');

            return Status::OK;
        }

        $config = $cfg::load(JPATH_PLUGINS);

        if ($config === null) {
            // Per the spec: quiet, no error - the Agent plugin may simply not be installed yet.
            $this->logTask('Site Manager sync: no usable Agent configuration, nothing sent', 'info');

            return Status::OK;
        }

        $now       = time();
        $queueCls  = 'Colorpack\\Plugin\\System\\ColorpackShield\\SiteManager\\EventQueue';
        $healthCls = 'Colorpack\\Plugin\\System\\ColorpackShield\\SiteManager\\HealthCache';
        $fs        = new $store(JPATH_ROOT . '/cache/colorpack_shield/sitemanager');
        $queue     = new $queueCls($fs);
        $health    = new $healthCls($fs);

        $events  = $queue->drain(100, $now);
        $sendHealth = $health->dueToday($now);
        $payload = [];

        if ($events !== []) {
            $payload['events'] = $events;
        }

        if ($sendHealth) {
            $h = $health->peek($now);

            if ($h !== null) {
                $payload['health'] = $h;
            } else {
                $sendHealth = false;
            }
        }

        if ($payload === []) {
            $this->logTask('Site Manager sync: nothing queued, nothing sent', 'info');

            return Status::OK;
        }

        $clientCls = 'Colorpack\\Plugin\\System\\ColorpackShield\\SiteManager\\Client';
        $result    = (new $clientCls())->send($config, $payload);

        if ($result === null) {
            $this->logTask('Site Manager sync: send failed (will retry next run)', 'error');

            return Status::KNOCKOUT;
        }

        if (isset($payload['events'])) {
            $queue->ack(array_map(static fn (array $e): string => (string) ($e['id'] ?? ''), $payload['events']), $now);
        }

        if ($sendHealth) {
            $health->markSent($now);
        }

        $this->logTask(sprintf('Site Manager sync: sent (%d event(s), health %s)', \count($payload['events'] ?? []), $sendHealth ? 'sent' : 'not due'), 'info');

        return Status::OK;
    }
}
