<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsGuard;
use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsPorter;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;
use Joomla\CMS\Version;

\defined('_JEXEC') || die;

/**
 * Reports & tools: settings export / import (with a preview step), the replay command with this
 * site's log path filled in, kill-switch help and version information.
 */
class ToolsModel extends BaseDatabaseModel
{
    private const STATE   = 'com_colorpack_shield.import';
    private const KEEP    = 900;

    public function plugin(): ShieldPlugin
    {
        return new ShieldPlugin($this->getDatabase());
    }

    /**
     * @return array<string,mixed>
     */
    public function getTools(): array
    {
        $plugin = $this->plugin();
        $out    = [
            'installed' => $plugin->installed(),
            'versions'  => ['plugin' => $plugin->version(), 'component' => $this->componentVersion(), 'php' => PHP_VERSION, 'joomla' => (new Version())->getShortVersion()],
            'logFile'   => $plugin->logFile(),
            'root'      => JPATH_ROOT,
            'pending'   => null,
        ];

        if (!$plugin->installed()) {
            return $out;
        }

        $pending = $this->pending();

        if ($pending !== null) {
            $current        = $plugin->params();
            $diff           = [];

            foreach ($pending['params'] as $k => $v) {
                if ($this->str($current[$k] ?? null) !== $this->str($v)) {
                    $diff[$k] = ['old' => $this->str($current[$k] ?? null), 'new' => $this->str($v)];
                }
            }

            $out['pending'] = ['diff' => $diff, 'ignored' => $pending['ignored'], 'count' => \count($pending['params'])];
        }

        return $out;
    }

    /**
     * @return string[]  names of the plugin's settings
     */
    public function known(): array
    {
        return array_keys($this->plugin()->defaults());
    }

    public function exportJson(): string
    {
        $plugin = $this->plugin();

        return SettingsPorter::export($plugin->params(), $this->known(), $plugin->version(), time());
    }

    /**
     * Read and check a file; keep the result for the apply step. Nothing is saved yet.
     *
     * @return string  '' on success, else an error code from SettingsPorter
     */
    public function preview(string $json): string
    {
        $r = SettingsPorter::import($json, $this->known());

        if ($r['error'] !== '') {
            return $r['error'];
        }

        Factory::getApplication()->setUserState(self::STATE, ['params' => $r['params'], 'ignored' => $r['ignored'], 'time' => time()]);

        return '';
    }

    public function discard(): void
    {
        Factory::getApplication()->setUserState(self::STATE, null);
    }

    /**
     * @return array{applied:bool,errors:array<int,array{key:string,code:string,detail:string}>,none:bool}
     */
    public function apply(): array
    {
        $pending = $this->pending();

        if ($pending === null) {
            return ['applied' => false, 'errors' => [], 'none' => true];
        }

        $plugin = $this->plugin();
        $res    = SettingsGuard::check($pending['params'], fn (array $p): bool => $plugin->wouldBlockSelf($p + $plugin->params()));

        if ($res['errors'] !== []) {
            return ['applied' => false, 'errors' => $res['errors'], 'none' => false];
        }

        $ok = $plugin->save($res['params']);
        $this->discard();

        return ['applied' => $ok, 'errors' => [], 'none' => false];
    }

    /**
     * @return array{params:array<string,mixed>,ignored:string[]}|null
     */
    private function pending(): ?array
    {
        $s = Factory::getApplication()->getUserState(self::STATE);

        if (!\is_array($s) || !\is_array($s['params'] ?? null) || !\is_int($s['time'] ?? null) || time() - $s['time'] > self::KEEP) {
            return null;
        }

        return ['params' => $s['params'], 'ignored' => (array) ($s['ignored'] ?? [])];
    }

    private function str(mixed $v): string
    {
        return \is_array($v) ? implode(',', array_map('strval', $v)) : (string) $v;
    }

    private function componentVersion(): string
    {
        $db = $this->getDatabase();
        $db->setQuery($db->getQuery(true)->select($db->quoteName('manifest_cache'))->from($db->quoteName('#__extensions'))->where($db->quoteName('element') . ' = ' . $db->quote('com_colorpack_shield'))->where($db->quoteName('type') . ' = ' . $db->quote('component')));
        $m = json_decode((string) $db->loadResult(), true);

        return \is_array($m) && \is_string($m['version'] ?? null) ? $m['version'] : '';
    }
}
