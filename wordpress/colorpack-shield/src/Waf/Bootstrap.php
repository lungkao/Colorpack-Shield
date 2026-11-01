<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

use Colorpack\WP\ColorpackShield\Admin\ActivityLog;
use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\Net\ClientIpResolver;
use Colorpack\WP\ColorpackShield\SiteManager\Reporter;
use Colorpack\WP\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XssShield;

defined('ABSPATH') || die;

/**
 * Wires the WAF engine into WordPress's own request lifecycle.
 *
 * Off by default: activating this plugin runs nothing (see README "Status").
 * An admin turns protection on from the Colorpack Shield > Settings screen
 * (`Admin\Settings`). The `colorpack_shield_waf_enabled` filter still works
 * as a wp-config.php/mu-plugin override on top of the stored setting:
 *
 *     add_filter('colorpack_shield_waf_enabled', '__return_true');
 *
 * This matches the Joomla edition's own philosophy: every server-facing
 * feature is opt-in, never on just because the plugin is installed.
 */
final class Bootstrap
{
    public static function boot(): void
    {
        add_action('plugins_loaded', [self::class, 'maybeInspect'], 0);
    }

    public static function maybeInspect(): void
    {
        if (!apply_filters('colorpack_shield_waf_enabled', Settings::get()['waf_enabled'])) {
            return;
        }

        self::refuseBannedAddress();

        $client = is_admin() ? 'admin' : 'site';
        $data   = self::buildRequestData();
        $engine = self::engine();

        $result = $engine->inspect($client, $data);

        if ($result->matched) {
            self::block($result);
        }
    }

    /** Addresses the fleet feed banned (see SiteManager\Reporter) get a plain 403 before anything else runs. */
    private static function refuseBannedAddress(): void
    {
        try {
            if (!Settings::get()['fleet_ban']) {
                return;
            }

            $ip = ClientIpResolver::normalise((string) ($_SERVER['REMOTE_ADDR'] ?? ''));

            if ($ip === '' || !(new TargetedBanPolicy(Reporter::banStore()))->check($ip, time())['banned']) {
                return;
            }
        } catch (\Throwable) {
            return; // A storage problem must never turn into an outage.
        }

        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=utf-8', true, 403);
        }

        exit('Forbidden');
    }

    private static function engine(): WafEngine
    {
        $shields = [
            new SqliShield(),
            new XssShield(),
            new LfiShield(),
            new RfiShield(),
            new HeaderShield(),
            new PathShield(),
        ];

        // Every shield covers both clients: WordPress's own admin screens get
        // the same generic protection as the public front end.
        $scopes = [
            'sqli'   => ['site', 'admin'],
            'xss'    => ['site', 'admin'],
            'lfi'    => ['site', 'admin'],
            'rfi'    => ['site', 'admin'],
            'header' => ['site', 'admin'],
            'path'   => ['site', 'admin'],
        ];

        return new WafEngine($shields, $scopes);
    }

    private static function buildRequestData(): RequestData
    {
        $sources = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => [], // Cookies carry session identity, not attacker payloads worth scanning here.
            'PATH'   => [
                'path'      => (string) ($_SERVER['REQUEST_URI'] ?? ''),
                'php_self'  => (string) ($_SERVER['PHP_SELF'] ?? ''),
                'path_info' => (string) ($_SERVER['PATH_INFO'] ?? ''),
            ],
            'HEADER' => RequestMeta::headers($_SERVER),
        ];

        $body = (string) file_get_contents('php://input');

        if ($body !== '') {
            $parser  = new BodyParser();
            $sources = array_merge($sources, $parser->parse($body, (string) ($_SERVER['CONTENT_TYPE'] ?? '')));
        }

        return new RequestData($sources);
    }

    /**
     * Refuse the request. A blocking WAF hit never reaches WordPress's own
     * routing, so no theme/plugin code runs on attacker-controlled input.
     */
    private static function block(WafResult $result): void
    {
        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=utf-8', true, 403);
        }

        $ip = ClientIpResolver::normalise((string) ($_SERVER['REMOTE_ADDR'] ?? ''));

        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY']) && \is_string($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            \Colorpack\WP\ColorpackShield\Net\IpCountry::remember($ip, $_SERVER['HTTP_CF_IPCOUNTRY']); // free, exact, never leaves the server
        }

        // "sample" goes last: LogReader::parseLine() treats it as taking the rest of the line.
        (new ActivityLog(ActivityLog::defaultPath()))->write('BLOCK', [
            'client' => is_admin() ? 'administrator' : 'site',
            'shield' => $result->shield,
            'rule'   => $result->rule,
            'src'    => $result->source,
            'key'    => $result->key,
            'uri'    => (string) ($_SERVER['REQUEST_URI'] ?? ''),
            'sample' => $result->sample,
        ], $ip);

        exit('Forbidden');
    }
}
