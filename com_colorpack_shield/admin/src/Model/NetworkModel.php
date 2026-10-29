<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\IpDiagnosis;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRefresher;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Network & IP: what the plugin sees for this request, the state of the Cloudflare address list,
 * and the lists of trusted addresses. The only write is "refresh the Cloudflare list", which
 * downloads two fixed URLs and stores a signed copy.
 */
class NetworkModel extends BaseDatabaseModel
{
    /** Seconds between two refreshes; a click storm must not hammer Cloudflare. */
    public const COOLDOWN = 60;

    private function rangesPath(): string
    {
        return CloudflareRanges::defaultPath(JPATH_ROOT);
    }

    private function key(): string
    {
        $secret = (string) Factory::getApplication()->get('secret', '');

        return $secret === '' ? '' : CloudflareRanges::deriveKey($secret);
    }

    /**
     * @return array<string,mixed>
     */
    public function getNetwork(): array
    {
        $plugin = new ShieldPlugin($this->getDatabase());

        if (!$plugin->installed()) {
            return ['installed' => false];
        }

        $p      = $plugin->params();
        $path   = $this->rangesPath();
        $key    = $this->key();
        $stored = $key !== '' ? CloudflareRanges::loadStored($path, $key) : null;
        $ranges = $key !== '' ? CloudflareRanges::load($path, $key) : CloudflareRanges::bundled();
        $proxy  = IpAllowList::fromText((string) ($p['trusted_proxies'] ?? ''));
        $trust  = filter_var($p['trust_cloudflare'] ?? true, FILTER_VALIDATE_BOOLEAN);
        $client = (new ClientIpResolver($ranges, $proxy->entries(), $trust))->resolve($_SERVER);
        $mtime  = $stored !== null ? @filemtime($path) : false;

        $diag = IpDiagnosis::explain([
            'remote'          => ClientIpResolver::normalise((string) ($_SERVER['REMOTE_ADDR'] ?? '')),
            'resolved'        => $client->ip,
            'via'             => $client->via,
            'headerIgnored'   => $client->headerIgnored,
            'hasForwarding'   => !empty($_SERVER['HTTP_X_FORWARDED_FOR']) || !empty($_SERVER['HTTP_X_REAL_IP']) || !empty($_SERVER['HTTP_FORWARDED']),
            'hasCfHeader'     => !empty($_SERVER['HTTP_CF_CONNECTING_IP']),
            'trustCloudflare' => $trust,
        ]);

        return [
            'installed' => true,
            'diag'      => $diag,
            'seen'      => ['remote' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''), 'resolved' => $client->ip, 'edge' => $client->edge, 'via' => $client->via],
            'trustCloudflare' => $trust,
            'ranges'    => [
                'source'  => $stored !== null ? 'refreshed' : 'bundled',
                'count'   => \count($ranges),
                'ageDays' => $mtime !== false ? max(0, (int) floor((time() - $mtime) / 86400)) : null,
                'date'    => $mtime !== false ? gmdate('Y-m-d', $mtime) : null,
                'canSign' => $key !== '',
            ],
            'proxies'   => ['entries' => $proxy->entries(), 'invalid' => \count($proxy->invalid())],
            'allow'     => ['entries' => IpAllowList::fromText((string) ($p['allow_ips'] ?? ''))->entries()],
            'probe'     => $plugin->storedProbe(),
            'probeUi'   => $plugin->probeUi(),
            'scheduled' => $this->taskScheduled(),
        ];
    }

    /**
     * Judge the report the browser brought back and remember the verdict.
     *
     * @param  array<string,mixed>  $report  already checked by ProbeReport::parse
     *
     * @return array{verdict:string,reasons:string[]}
     */
    public function judgeProbe(array $report): array
    {
        $key    = $this->key();
        $ranges = $key !== '' ? CloudflareRanges::load($this->rangesPath(), $key) : CloudflareRanges::bundled();
        $result = ProxyProbe::evaluate($report, $ranges);

        (new ShieldPlugin($this->getDatabase()))->saveProbe($result['verdict']);

        return $result;
    }

    /**
     * @return array{status:string,reason:string,count:int}
     */
    public function refreshRanges(): array
    {
        $path = $this->rangesPath();
        $key  = $this->key();

        // The time of the last attempt (not of the last change): an "unchanged" answer must hold back clicks too.
        $stamp = JPATH_ROOT . '/cache/colorpack_shield/cf_refresh.stamp';

        if (is_file($stamp) && (time() - (int) @filemtime($stamp)) < self::COOLDOWN) {
            return ['status' => 'cooldown', 'reason' => '', 'count' => 0];
        }

        if (is_dir(\dirname($stamp)) || @mkdir(\dirname($stamp), 0755, true)) {
            @touch($stamp);
        }

        return CloudflareRefresher::refresh([CloudflareRefresher::class, 'fetch'], $path, $key, $key !== '' ? CloudflareRanges::load($path, $key) : null);
    }

    /**
     * Whether a Scheduler task for the Cloudflare refresh exists and is enabled. Null when the
     * Scheduler is not there (Joomla 4.0) or cannot be read.
     */
    private function taskScheduled(): ?bool
    {
        try {
            $db = $this->getDatabase();
            $db->setQuery(
                $db->getQuery(true)->select('COUNT(*)')->from($db->quoteName('#__scheduler_tasks'))
                    ->where($db->quoteName('type') . ' = ' . $db->quote('colorpack_shield.cloudflare_ranges'))
                    ->where($db->quoteName('state') . ' = 1')
            );

            return (int) $db->loadResult() > 0;
        } catch (\Throwable) {
            return null;
        }
    }
}
