<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\LogFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Service\Locale;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\Gemini\AnalysisHistory;
use Colorpack\Plugin\System\ColorpackShield\Gemini\Client;
use Colorpack\Plugin\System\ColorpackShield\Gemini\Config;
use Colorpack\Plugin\System\ColorpackShield\Gemini\PromptBuilder;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Read-only: the log, filtered. The file is always the plugin's own log; nothing in the request
 * names a file.
 */
class ActivityModel extends BaseDatabaseModel
{
    public const PER_PAGE = 50;

    /**
     * @param  array<string,mixed>  $request  GET values
     *
     * @return array{criteria:array<string,mixed>,readable:bool,truncated:bool,list:array{rows:array<int,mixed>,total:int,page:int,pages:int},all:array<int,mixed>}
     */
    public function getActivity(array $request): array
    {
        $plugin   = new ShieldPlugin($this->getDatabase());
        $criteria = LogFilter::criteria($request);
        $log      = (new LogReader($plugin->logFile()))->read();
        $rows     = LogFilter::apply($log['entries'], $criteria, time());

        return [
            'criteria'  => $criteria,
            'readable'  => $log['readable'],
            'truncated' => $log['truncated'],
            'list'      => LogFilter::page($rows, (int) ($request['page'] ?? 1), self::PER_PAGE),
            'all'       => $rows,
            'report'    => $log['readable'] ? $this->report($log['entries'], time()) : null,
        ];
    }

    /**
     * The numbers above the filter: the last 7 days against the 7 before, and 14 days of bars. Always
     * the whole log, whatever the filter below is set to.
     *
     * @param  array<int,array{time:int,type:string,f:array<string,string>}>  $entries
     *
     * @return array<string,mixed>
     */
    private function report(array $entries, int $now): array
    {
        $week = LogStats::window($entries, $now, 86400 * 7);
        $prev = LogStats::window($entries, $now - 86400 * 7, 86400 * 7);

        return [
            'week'    => $week,
            'blocked' => LogStats::change($week['blocked'], $prev['blocked']),
            'logged'  => LogStats::change($week['detected'], $prev['detected']),
            'unique'  => LogStats::uniqueBlockedIps($entries, $now, 86400 * 7),
            'daily'   => LogStats::daily($entries, $now, 14),
        ];
    }

    /** Whether the on-demand "analyse with AI" button should show at all. */
    public function geminiAvailable(): bool
    {
        return $this->geminiConfig() !== null;
    }

    /**
     * @return array{kind:string,prompt:string,answer:?string,when:int}|null  the most recent
     *                                                                          analysis of any kind, or null if none yet
     */
    public function latestAiAnalysis(): ?array
    {
        return (new AnalysisHistory(new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/gemini')))->recent(time(), 1, ['waf_ondemand', 'waf_digest'])[0] ?? null;
    }

    /**
     * Builds a prompt from the currently filtered WAF activity, asks Gemini, and records the
     * result - the on-demand half of the Gemini advisor (the other half is the scheduled digest
     * task). Fails soft: any problem (feature off, no key, the call itself failing) is reported
     * back as a message, never an exception.
     *
     * @param  array<string,mixed>  $request  GET values (same filter criteria as getActivity())
     *
     * @return array{ok:bool,message:string}
     */
    public function analyzeWithAi(array $request): array
    {
        $config = $this->geminiConfig();

        if ($config === null) {
            return ['ok' => false, 'message' => 'COM_COLORPACK_SHIELD_AI_OFF'];
        }

        $plugin   = new ShieldPlugin($this->getDatabase());
        $criteria = LogFilter::criteria($request);
        $log      = (new LogReader($plugin->logFile()))->read();
        $rows     = LogFilter::apply($log['entries'], $criteria, time());

        if ($rows === []) {
            return ['ok' => false, 'message' => 'COM_COLORPACK_SHIELD_AI_NO_DATA'];
        }

        // Locale::tag() is this plugin's OWN language-switcher cookie (cps_lang), which can
        // differ from the administrator's own interface language by design - falls back to the
        // admin language when no cookie choice was made. That's "our" language button, not
        // Joomla's.
        $lang    = substr(Locale::tag(), 0, 2);
        $prompt  = (new PromptBuilder())->forWafActivity($rows, $lang);
        $answer  = (new Client())->ask($config, $prompt);
        $history = new AnalysisHistory(new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/gemini'));
        $history->record('waf_ondemand', $prompt, $answer, time());

        return $answer === null
            ? ['ok' => false, 'message' => 'COM_COLORPACK_SHIELD_AI_FAILED']
            : ['ok' => true, 'message' => 'COM_COLORPACK_SHIELD_AI_DONE'];
    }

    private function geminiConfig(): ?Config
    {
        try {
            $plugin   = \Joomla\CMS\Plugin\PluginHelper::getPlugin('system', 'colorpack_shield');
            $registry = new \Joomla\Registry\Registry($plugin->params ?? '{}');

            return Config::fromParams(
                (string) $registry->get('gemini_api_key', ''),
                filter_var($registry->get('gemini_enabled', 0), FILTER_VALIDATE_BOOLEAN),
                (string) $registry->get('gemini_model', ''),
                filter_var($registry->get('gemini_schedule_enabled', 0), FILTER_VALIDATE_BOOLEAN),
                (int) $registry->get('gemini_schedule_hours', 24)
            );
        } catch (\Throwable) {
            return null;
        }
    }
}
