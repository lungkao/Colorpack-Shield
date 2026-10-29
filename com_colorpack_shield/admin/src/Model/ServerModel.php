<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\HtaccessManager;
use Colorpack\Component\ColorpackShield\Administrator\Core\ServerDetector;
use Colorpack\Component\ColorpackShield\Administrator\Core\ServerVerify;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\Export\AdminAllowSnippet;
use Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy;
use Colorpack\Plugin\System\ColorpackShield\Export\HtaccessBlock;
use Colorpack\Plugin\System\ColorpackShield\Export\NginxPathPolicy;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;
use Joomla\CMS\Uri\Uri;

\defined('_JEXEC') || die;

/**
 * Server rules: the same generators as the command-line exporter, shown for review. Nothing is
 * ever written to the server; the person pastes the text where it belongs.
 */
class ServerModel extends BaseDatabaseModel
{
    /**
     * @param  array<string,mixed>  $request  GET values
     *
     * @return array<string,mixed>
     */
    public function getServer(array $request): array
    {
        $plugin = new ShieldPlugin($this->getDatabase());

        if (!$plugin->installed()) {
            return ['installed' => false];
        }

        $params = $plugin->params();
        $typed  = \is_string($request['allow'] ?? null) ? $request['allow'] : '';
        // Start from the plugin's own path allow-list: its plain "/path" lines are legitimate direct requests too.
        $base   = ServerDetector::parseAllow((string) ($params['path_allow'] ?? ''), [ApachePathPolicy::class, 'validate']);
        $own    = ServerDetector::parseAllow($typed, [ApachePathPolicy::class, 'validate']);
        $allow  = array_values(array_unique(array_merge($base['ok'], $own['ok'])));
        $code   = !empty($request['codedirs']);

        return [
            'installed' => true,
            'guess'     => ServerDetector::guess((string) ($_SERVER['SERVER_SOFTWARE'] ?? '')),
            'allowText' => $typed,
            'bad'       => $own['bad'],
            'codedirs'  => $code,
            'apache'    => ApachePathPolicy::render($allow, $code),
            'nginx'     => NginxPathPolicy::render($allow, $code),
            'verify'    => $plugin->storedVerify(),
            'htaccess'  => $this->manager()->state() + ['canAsk' => $this->canAsk()],
            'adminList' => [
                'apache' => AdminAllowSnippet::render('apache', preg_split('/\R/', (string) ($params['admin_ip_list'] ?? '')) ?: []),
                'nginx'  => AdminAllowSnippet::render('nginx', preg_split('/\R/', (string) ($params['admin_ip_list'] ?? '')) ?: []),
            ],
        ];
    }

    /**
     * Text of one generator, for download.
     */
    public function render(string $target, string $allowText, bool $code): ?string
    {
        $allow = ServerDetector::parseAllow($allowText, [ApachePathPolicy::class, 'validate'])['ok'];

        return match ($target) {
            'apache' => ApachePathPolicy::render($allow, $code),
            'nginx'  => NginxPathPolicy::render($allow, $code),
            default  => null,
        };
    }

    /**
     * Ask this site, at its own address, for the fixed list of files. HEAD requests, no redirects,
     * short timeouts, certificate checked. Stores the result for the dashboard.
     *
     * @return array{result:string,statuses:array<string,int>}
     */
    public function verify(): array
    {
        $origin   = rtrim(Uri::root(), '/');
        $statuses = [];

        foreach (ServerVerify::PATHS as $path) {
            $statuses[$path] = $this->head($origin . $path);
        }

        $result = ServerVerify::summarize($statuses);
        (new ShieldPlugin($this->getDatabase()))->saveVerify($result);

        return ['result' => $result, 'statuses' => $statuses];
    }

    private function manager(): HtaccessManager
    {
        $origin = rtrim(Uri::root(), '/');

        return new HtaccessManager(JPATH_ROOT, fn (string $path): int => $this->head($origin . $path));
    }

    /** Can this host ask its own site at all (curl, or PHP's own http wrapper)? Without it nothing is applied. */
    private function canAsk(): bool
    {
        return \function_exists('curl_init') || filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Put the block into this site's .htaccess (or take it out), checking the live site before and
     * after and undoing the change if any answer differs.
     *
     * @param  array<string,mixed>  $request  POST values
     *
     * @return array{result:string,before:array<string,int>,after:array<string,int>,effective?:?bool}
     */
    public function changeHtaccess(bool $remove, array $request): array
    {
        if ($remove) {
            return $this->manager()->remove();
        }

        $params = (new ShieldPlugin($this->getDatabase()))->params();
        $base   = ServerDetector::parseAllow((string) ($params['path_allow'] ?? ''), [ApachePathPolicy::class, 'validate'])['ok'];
        $own    = ServerDetector::parseAllow(\is_string($request['allow'] ?? null) ? $request['allow'] : '', [ApachePathPolicy::class, 'validate'])['ok'];
        $block  = HtaccessBlock::render(array_values(array_unique(array_merge($base, $own))), [
            'headers'   => !empty($request['headers']),
            'hsts'      => !empty($request['hsts']),
            'code_dirs' => !empty($request['codedirs']),
        ]);

        $r = $this->manager()->apply($block);

        // Kept does not mean working: some hosts ignore .htaccess. Look for one of our headers.
        if ($r['result'] === 'applied' && !empty($request['headers'])) {
            $r['effective'] = $this->hasHeader(rtrim(Uri::root(), '/') . '/', 'x-content-type-options');
        }

        return $r;
    }

    /** Does the live site send this response header? null when it cannot be asked. */
    private function hasHeader(string $url, string $name): ?bool
    {
        if (\function_exists('curl_init')) {
            $seen = false;
            $ch   = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_NOBODY => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'ColorpackShield-verify',
                CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$seen, $name): int {
                    if (stripos($line, $name . ':') === 0) {
                        $seen = true;
                    }

                    return \strlen($line);
                },
            ]);
            $ok = curl_exec($ch);
            unset($ch);

            return $ok === false ? null : $seen;
        }

        if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            return null;
        }

        $h = @get_headers($url, false, stream_context_create(['http' => ['method' => 'HEAD', 'timeout' => 6, 'follow_location' => 0, 'ignore_errors' => true]]));

        if (!\is_array($h)) {
            return null;
        }

        foreach ($h as $line) {
            if (stripos((string) $line, $name . ':') === 0) {
                return true;
            }
        }

        return false;
    }

    private function head(string $url): int
    {
        if (!preg_match('~^https?://~i', $url)) {
            return 0;
        }

        if (!\function_exists('curl_init')) {
            // No curl on this host: PHP's own http wrapper, HEAD only, no redirects, short timeout.
            if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
                return 0;
            }

            $ctx = stream_context_create(['http' => ['method' => 'HEAD', 'timeout' => 6, 'follow_location' => 0, 'ignore_errors' => true, 'user_agent' => 'ColorpackShield-verify']]);
            $h   = @get_headers($url, false, $ctx);

            return \is_array($h) && isset($h[0]) && preg_match('~^HTTP/\S+ (\d{3})~', $h[0], $m) ? (int) $m[1] : 0;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 6,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'ColorpackShield-verify',
        ]);
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch);

        return $code;
    }
}
