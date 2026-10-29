<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGate;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProbeToken;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitch;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;
use Joomla\CMS\Factory;
use Joomla\CMS\Table\Extension;
use Joomla\Database\DatabaseInterface;

\defined('_JEXEC') || die;

/**
 * The thin Joomla side: finds the system plugin, reads and writes ITS parameters (the single
 * source of truth), and gathers the facts the pure classes score. No decisions live here.
 */
final class ShieldPlugin
{
    private ?object $row = null;

    private bool $rowLoaded = false;

    public function __construct(private readonly DatabaseInterface $db)
    {
    }

    public function row(): ?object
    {
        if (!$this->rowLoaded) {
            $this->rowLoaded = true;
            $query           = $this->db->getQuery(true)
                ->select($this->db->quoteName(['extension_id', 'enabled', 'params', 'manifest_cache']))
                ->from($this->db->quoteName('#__extensions'))
                ->where($this->db->quoteName('type') . ' = ' . $this->db->quote('plugin'))
                ->where($this->db->quoteName('folder') . ' = ' . $this->db->quote('system'))
                ->where($this->db->quoteName('element') . ' = ' . $this->db->quote('colorpack_shield'));
            $this->db->setQuery($query);
            $this->row = $this->db->loadObject() ?: null;
        }

        return $this->row;
    }

    public function installed(): bool
    {
        return $this->row() !== null && is_file($this->pluginDir() . '/colorpack_shield.xml');
    }

    public function enabled(): bool
    {
        return $this->row() !== null && (int) $this->row()->enabled === 1;
    }

    public function version(): string
    {
        $m = json_decode((string) ($this->row()->manifest_cache ?? ''), true);

        return \is_array($m) && \is_string($m['version'] ?? null) ? $m['version'] : '';
    }

    public function pluginDir(): string
    {
        return JPATH_PLUGINS . '/system/colorpack_shield';
    }

    public function formFile(): string
    {
        return $this->pluginDir() . '/colorpack_shield.xml';
    }

    /**
     * Defaults straight from the plugin's own form, so they can never drift from the plugin.
     *
     * @return array<string,string>
     */
    public function defaults(): array
    {
        $out = [];
        $xml = @simplexml_load_file($this->formFile());

        if ($xml === false) {
            return $out;
        }

        foreach ($xml->xpath('//config//field') ?: [] as $field) {
            $name = (string) $field['name'];

            if ($name !== '' && isset($field['default'])) {
                $out[$name] = html_entity_decode((string) $field['default'], ENT_QUOTES | ENT_XML1);
            }
        }

        return $out;
    }

    /**
     * Stored parameters over the plugin's defaults.
     *
     * @return array<string,mixed>
     */
    public function params(): array
    {
        $stored = json_decode((string) ($this->row()->params ?? ''), true);

        return (\is_array($stored) ? $stored : []) + $this->defaults();
    }

    /**
     * Save through Joomla's extension table; keys the component does not know are kept.
     *
     * @param  array<string,mixed>  $params
     */
    public function save(array $params): bool
    {
        $row = $this->row();

        if ($row === null) {
            return false;
        }

        $table = new Extension($this->db);

        if (!$table->load((int) $row->extension_id)) {
            return false;
        }

        $current = json_decode((string) $table->params, true);
        $merged  = array_merge(\is_array($current) ? $current : [], $params);
        $table->params = json_encode($merged, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if (!$table->store()) {
            return false;
        }

        $this->rowLoaded = false;

        try {
            Factory::getContainer()->get(\Joomla\CMS\Cache\CacheControllerFactoryInterface::class)
                ->createCacheController('callback', ['defaultgroup' => 'com_plugins', 'cachebase' => JPATH_CACHE])
                ->clean();
        } catch (\Throwable) {
            // A stale plugin cache only delays the new value; the save itself succeeded.
        }

        return true;
    }

    public function logFile(): string
    {
        $dir = (string) Factory::getApplication()->get('log_path', JPATH_ADMINISTRATOR . '/logs');

        return rtrim($dir, '/\\') . '/colorpack_shield.php';
    }

    /**
     * @param  array<string,mixed>  $p  parameters (with defaults)
     *
     * @return array<string,mixed>
     */
    public function facts(array $p): array
    {
        $flag  = static fn (string $k): bool => filter_var($p[$k] ?? false, FILTER_VALIDATE_BOOLEAN);
        $token = trim((string) ($p['killswitch_token'] ?? ''));
        $kill  = KillSwitch::locate([JPATH_ROOT, JPATH_ADMINISTRATOR], $token)['active'] !== null;
        $list  = IpAllowList::fromText((string) ($p['allow_ips'] ?? ''));
        $facts = [
            'plugin_installed'     => $this->installed(),
            'plugin_enabled'       => $this->enabled(),
            'kill_switch'          => $kill,
            'probe'                => null,
            'probe_age_days'       => null,
            'trust_cloudflare'     => $flag('trust_cloudflare'),
            'cf_age_days'          => $this->cloudflareAgeDays(),
            'allow_ips_count'      => \count($list->entries()),
            'auto_allow_admin'     => $flag('auto_allow_admin'),
            'killswitch_token_set' => $token !== '',
            'apcu'                 => \function_exists('apcu_fetch') && filter_var(ini_get('apc.enabled'), FILTER_VALIDATE_BOOLEAN),
            'server_rules'         => null,
            'mfa_enforce'          => (string) ($p['mfa_enforce'] ?? 'off'),
            'admin_door'           => !AccessGateConfig::fromArray($p)->off(),
        ];

        foreach (['cover_site', 'cover_admin', 'cover_api', 'shield_sqli', 'shield_xss', 'shield_lfi', 'shield_rfi', 'header_scan', 'path_scan', 'scan_body', 'scan_uploads', 'rate_enabled', 'login_lockout'] as $k) {
            $facts[$k] = $flag($k);
        }

        $scan = (new \Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore(JPATH_ROOT . '/cache/colorpack_shield/scan'))->read('result');

        if (\is_array($scan) && isset($scan['finished'], $scan['count']['high'])) {
            $facts['file_scan'] = ['age' => max(0, (int) floor((time() - (int) $scan['finished']) / 86400)), 'high' => (int) $scan['count']['high']];
        }

        $verify = $this->storedVerify();

        // A result older than 90 days is not evidence about today.
        if ($verify !== null && $verify['age'] <= 90 && $verify['result'] !== 'unknown') {
            $facts['server_rules'] = $verify['result'];
        }

        $stored = $this->storedProbe();

        if ($stored !== null) {
            $facts['probe']          = $stored['verdict'];
            $facts['probe_age_days'] = $stored['age'];
        }

        return $facts;
    }

    /**
     * Last proxy-probe verdict, written by the command-line probe or (later) the Network screen.
     *
     * @return array{verdict:string,age:int}|null
     */
    public function storedProbe(): ?array
    {
        $file = JPATH_ROOT . '/cache/colorpack_shield/probe.json';

        if (!is_file($file) || !is_readable($file)) {
            return null;
        }

        $data = json_decode((string) @file_get_contents($file, false, null, 0, 4096), true);

        if (!\is_array($data) || !\in_array($data['verdict'] ?? null, ['safe', 'no_proxy', 'spoofable', 'inconclusive'], true) || !is_int($data['time'] ?? null)) {
            return null;
        }

        return ['verdict' => $data['verdict'], 'age' => max(0, (int) floor((time() - $data['time']) / 86400))];
    }

    private function cacheFile(string $name): string
    {
        return JPATH_ROOT . '/cache/colorpack_shield/' . $name;
    }

    /**
     * The last "Verify server rules" result: open | refused | unknown, and how old it is.
     *
     * @return array{result:string,age:int}|null
     */
    public function storedVerify(): ?array
    {
        $file = $this->cacheFile('server_verify.json');
        $data = is_file($file) && is_readable($file) ? json_decode((string) @file_get_contents($file, false, null, 0, 2048), true) : null;

        if (!\is_array($data) || !\in_array($data['result'] ?? null, ['open', 'refused', 'unknown'], true) || !\is_int($data['time'] ?? null)) {
            return null;
        }

        return ['result' => $data['result'], 'age' => max(0, (int) floor((time() - $data['time']) / 86400))];
    }

    public function saveVerify(string $result): bool
    {
        $dir = $this->cacheFile('');

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }

        return @file_put_contents($this->cacheFile('server_verify.json'), json_encode(['result' => $result, 'time' => time()]), LOCK_EX) !== false;
    }

    private function cloudflareAgeDays(): ?int
    {
        $secret = (string) Factory::getApplication()->get('secret', '');
        $path   = CloudflareRanges::defaultPath(JPATH_ROOT);

        if ($secret === '' || CloudflareRanges::loadStored($path, CloudflareRanges::deriveKey($secret)) === null) {
            return null;
        }

        $mtime = @filemtime($path);

        return $mtime === false ? null : max(0, (int) floor((time() - $mtime) / 86400));
    }

    /**
     * Would these settings block the administrator's own request to this component?
     *
     * @param  array<string,mixed>  $p
     */
    public function wouldBlockSelf(array $p): bool
    {
        $lines = static fn (string $v): array => array_values(array_filter(array_map('trim', preg_split('/\R/', $v) ?: [])));
        $tools = $lines((string) ($p['path_tools_exempt'] ?? implode("\n", PathRules::DEFAULT_TOOLS_EXEMPT)));
        $mode  = (string) ($p['path_mode'] ?? 'recommended');
        $probe = (string) ($p['path_probe_mode'] ?? 'log');

        $shield = new PathShield(
            \in_array($mode, ['recommended', 'log', 'block'], true) ? $mode : 'recommended',
            \in_array($probe, ['off', 'log', 'block'], true) ? $probe : 'log',
            $lines((string) ($p['path_allow'] ?? '')),
            $lines((string) ($p['path_extra_deny'] ?? '')),
            $tools
        );

        foreach (['/administrator/index.php', '/administrator/index.php?option=com_colorpack_shield&view=settings'] as $uri) {
            foreach ($shield->inspectAll(new RequestData(['PATH' => ['path' => $uri]])) as $result) {
                if ($result->mode === WafResult::MODE_BLOCK) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The saving administrator's own address as the plugin would see it, and whether it is one
     * single visitor (a CDN edge or a private proxy address would make every visitor look alike).
     *
     * @param  array<string,mixed>  $p
     *
     * @return array{ip:string,enforceable:bool}
     */
    public function visitor(array $p): array
    {
        $secret = (string) Factory::getApplication()->get('secret', '');
        $path   = CloudflareRanges::defaultPath(JPATH_ROOT);
        $ranges = $secret !== '' ? CloudflareRanges::load($path, CloudflareRanges::deriveKey($secret)) : CloudflareRanges::bundled();
        $prox   = IpAllowList::fromText((string) ($p['trusted_proxies'] ?? ''))->entries();
        $client = (new ClientIpResolver($ranges, $prox, filter_var($p['trust_cloudflare'] ?? true, FILTER_VALIDATE_BOOLEAN)))->resolve($_SERVER);

        return ['ip' => $client->ip, 'enforceable' => IpAllowList::isSafeToAutoAdd($client, $ranges, $prox)];
    }

    /**
     * Give THIS browser the access cookie when the access key is in force, so that switching the
     * gate on does not shut out the person who switched it on. Same cookie the plugin issues.
     *
     * @param  array<string,mixed>  $p  parameters as saved
     */
    public function issueGateCookie(array $p): bool
    {
        $cfg    = AccessGateConfig::fromArray($p);
        $secret = (string) Factory::getApplication()->get('secret', '');

        if (!$cfg->gateActive || $secret === '' || headers_sent()) {
            return false;
        }

        $expiry = time() + $cfg->cookieHours * 3600;
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/administrator/index.php');
        $path   = str_starts_with($script, '/') ? rtrim(\dirname($script), '/\\') : '';

        return setcookie(AccessGate::COOKIE, AccessGate::cookieValue($secret, $cfg->key, (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), $expiry), [
            'expires'  => $expiry,
            'path'     => $path === '' ? '/' : $path,
            'secure'   => Factory::getApplication()->isSSLConnection(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * What the "Test now" button needs: this site's own address, the headers of the forged
     * request (with a token that only lives about ten minutes), and the same test as a command
     * with this site's real values filled in.
     *
     * @return array{url:string,headers:array<string,string>,command:string}|null
     */
    public function probeUi(): ?array
    {
        $secret = (string) Factory::getApplication()->get('secret', '');

        if ($secret === '') {
            return null;
        }

        $url = rtrim(\Joomla\CMS\Uri\Uri::root(), '/') . '/';

        return [
            'url'     => $url,
            'headers' => ProxyProbe::requestHeaders(ProbeToken::make($secret, time())),
            'command' => 'php ' . $this->pluginDir() . '/cli/proxy_probe.php --url=' . $url . ' --config=' . JPATH_ROOT . '/configuration.php',
        ];
    }

    /**
     * Remember a verdict (and nothing else) for the dashboard.
     */
    public function saveProbe(string $verdict): bool
    {
        $dir = $this->cacheFile('');

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }

        return @file_put_contents($this->cacheFile('probe.json'), json_encode(['verdict' => $verdict, 'time' => time()]), LOCK_EX) !== false;
    }
}
