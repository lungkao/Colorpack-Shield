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
        'colorpack_shield.vulnerable_extensions' => [
            'langConstPrefix' => 'PLG_TASK_COLORPACK_SHIELD_VEL',
            'method'          => 'refreshVulnerableList',
        ],
        'colorpack_shield.gemini_digest' => [
            'langConstPrefix' => 'PLG_TASK_COLORPACK_SHIELD_GEMINI',
            'method'          => 'sendGeminiDigest',
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
     * Keeps a copy of the JED Vulnerable Extensions List up to date (a plain GET of a public feed; nothing about this
     * site is sent). A failed download keeps the copy already stored. The Dashboard reads that copy.
     */
    private function refreshVulnerableList(ExecuteTaskEvent $event): int
    {
        $base = JPATH_PLUGINS . '/system/colorpack_shield/src';

        foreach (['Scanner/ScanStore', 'Vulnerable/VelRules', 'Vulnerable/VelFeed'] as $file) {
            $fqcn = 'Colorpack\\Plugin\\System\\ColorpackShield\\' . str_replace('/', '\\', $file);

            if (!class_exists($fqcn, false) && is_file($base . '/' . $file . '.php')) {
                require_once $base . '/' . $file . '.php';
            }
        }

        $feed = 'Colorpack\\Plugin\\System\\ColorpackShield\\Vulnerable\\VelFeed';
        $scan = 'Colorpack\\Plugin\\System\\ColorpackShield\\Scanner\\ScanStore';

        if (!class_exists($feed) || !class_exists($scan)) {
            $this->logTask('Vulnerable extensions list: the Colorpack Shield system plugin is not installed', 'error');

            return Status::KNOCKOUT;
        }

        $dir = JPATH_ROOT . '/cache/colorpack_shield/vel';

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $result = (new $feed(new $scan($dir)))->refresh([$feed, 'curlGet'], time());
        $this->logTask('Vulnerable extensions list: ' . $result, $result === 'failed' ? 'error' : 'info');

        return $result === 'failed' ? Status::KNOCKOUT : Status::OK;
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
     * The scheduled half of the Gemini advisor: an automatic digest of recent WAF activity, in
     * addition to the on-demand button on the Activity screen. Off by default (both the master
     * Gemini toggle and this schedule toggle must be on); throttled to at most once per the
     * admin-configured interval via AlertThrottle, so a short Task Scheduler interval cannot call
     * a billable API more often than the admin asked for. Silent when either toggle is off or no
     * key is configured - same "quiet, no error" convention as the other routines.
     */
    private function sendGeminiDigest(ExecuteTaskEvent $event): int
    {
        $base = JPATH_PLUGINS . '/system/colorpack_shield/src';

        foreach (['AdminProtect/StateStore', 'AdminProtect/FileStateStore', 'AdminProtect/AlertThrottle', 'Gemini/HttpTransport', 'Gemini/CurlTransport', 'Gemini/Config', 'Gemini/PromptBuilder', 'Gemini/Client', 'Gemini/AnalysisHistory'] as $file) {
            $fqcn = 'Colorpack\\Plugin\\System\\ColorpackShield\\' . str_replace('/', '\\', $file);

            if (!class_exists($fqcn, false) && is_file($base . '/' . $file . '.php')) {
                require_once $base . '/' . $file . '.php';
            }
        }

        $logReaderFile = JPATH_ADMINISTRATOR . '/components/com_colorpack_shield/src/Core/LogReader.php';

        if (!class_exists('Colorpack\\Component\\ColorpackShield\\Administrator\\Core\\LogReader', false) && is_file($logReaderFile)) {
            require_once $logReaderFile;
        }

        $store     = 'Colorpack\\Plugin\\System\\ColorpackShield\\AdminProtect\\FileStateStore';
        $cfg       = 'Colorpack\\Plugin\\System\\ColorpackShield\\Gemini\\Config';
        $reader    = 'Colorpack\\Component\\ColorpackShield\\Administrator\\Core\\LogReader';

        if (!class_exists($store) || !class_exists($cfg) || !class_exists($reader)) {
            $this->logTask('Gemini digest: the Colorpack Shield system plugin is not installed', 'error');

            return Status::KNOCKOUT;
        }

        $enabled         = false;
        $scheduleEnabled = false;
        $params          = [];

        try {
            $sys             = \Joomla\CMS\Plugin\PluginHelper::getPlugin('system', 'colorpack_shield');
            $registry        = new \Joomla\Registry\Registry($sys->params ?? '{}');
            $enabled         = filter_var($registry->get('gemini_enabled', 0), FILTER_VALIDATE_BOOLEAN);
            $scheduleEnabled = filter_var($registry->get('gemini_schedule_enabled', 0), FILTER_VALIDATE_BOOLEAN);
            $params          = [
                'api_key'        => (string) $registry->get('gemini_api_key', ''),
                'model'          => (string) $registry->get('gemini_model', ''),
                'schedule_hours' => (int) $registry->get('gemini_schedule_hours', 24),
            ];
        } catch (\Throwable) {
            $enabled = false;
        }

        if (!$enabled || !$scheduleEnabled) {
            $this->logTask('Gemini digest: switched off, nothing to do', 'info');

            return Status::OK;
        }

        $config = $cfg::fromParams($params['api_key'], true, $params['model'], true, $params['schedule_hours']);

        if ($config === null) {
            $this->logTask('Gemini digest: no API key configured, nothing sent', 'info');

            return Status::OK;
        }

        $now        = time();
        $throttleFs = new $store(JPATH_ROOT . '/cache/colorpack_shield/gemini');
        $throttle   = 'Colorpack\\Plugin\\System\\ColorpackShield\\AdminProtect\\AlertThrottle';
        $claim      = $throttle::claim($throttleFs, 'gemini_digest', $now, $config->scheduleIntervalHours * 3600);

        if (!$claim['send']) {
            $this->logTask('Gemini digest: within the configured interval, nothing sent', 'info');

            return Status::OK;
        }

        $logFile = rtrim((string) $this->getApplication()->get('log_path', JPATH_ADMINISTRATOR . '/logs'), '/\\') . '/colorpack_shield.php';
        $entries = (new $reader($logFile))->read()['entries'] ?? [];
        $recent  = array_values(array_filter($entries, static fn (array $e): bool => ($e['time'] ?? 0) >= $now - 86400));

        if ($recent === []) {
            $this->logTask('Gemini digest: no recent WAF activity, nothing sent', 'info');

            return Status::OK;
        }

        $builderCls = 'Colorpack\\Plugin\\System\\ColorpackShield\\Gemini\\PromptBuilder';
        $prompt     = (new $builderCls())->forWafActivity($recent);
        $client     = 'Colorpack\\Plugin\\System\\ColorpackShield\\Gemini\\Client';
        $answer     = (new $client())->ask($config, $prompt);

        $history = 'Colorpack\\Plugin\\System\\ColorpackShield\\Gemini\\AnalysisHistory';
        (new $history($throttleFs))->record('waf_digest', $prompt, $answer, $now);

        $this->logTask(sprintf('Gemini digest: %s (%d log entries considered)', $answer === null ? 'call failed, will retry next eligible run' : 'recorded', \count($recent)), $answer === null ? 'error' : 'info');

        return $answer === null ? Status::KNOCKOUT : Status::OK;
    }
}
