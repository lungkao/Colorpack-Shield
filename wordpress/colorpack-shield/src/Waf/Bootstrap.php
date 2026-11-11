<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

use Colorpack\WP\ColorpackShield\Admin\ActivityLog;
use Colorpack\WP\ColorpackShield\Admin\Lang;
use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\WP\ColorpackShield\Geo\CountryLookup;
use Colorpack\WP\ColorpackShield\Geo\GeoPolicy;
use Colorpack\WP\ColorpackShield\Net\ClientIp;
use Colorpack\WP\ColorpackShield\Net\ClientIpResolver;
use Colorpack\WP\ColorpackShield\Net\CloudflareRanges;
use Colorpack\WP\ColorpackShield\Net\IpAllowList;
use Colorpack\WP\ColorpackShield\Net\TrustPolicy;
use Colorpack\WP\ColorpackShield\RateLimit\ApcuRateStore;
use Colorpack\WP\ColorpackShield\RateLimit\RateLimiter;
use Colorpack\WP\ColorpackShield\RateLimit\RateStores;
use Colorpack\WP\ColorpackShield\Safety\KillSwitch;
use Colorpack\WP\ColorpackShield\Safety\KillSwitchAlert;
use Colorpack\WP\ColorpackShield\Waf\Shield\CmdiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SsrfShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SstiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\UserAgentShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XxeShield;
use Colorpack\WP\ColorpackShield\Waf\Rules\PathRules;

defined('ABSPATH') || die;

/**
 * Wires the WAF engine into WordPress's own request lifecycle, step for step like the Joomla
 * edition's guard(): kill switch, real visitor address, trusted addresses, bans, address-country
 * rule, request-rate limit, URL path, uploaded files, request body and headers, then the payload
 * shields. Every step reads its own setting from {@see Settings}.
 *
 * Off until an administrator turns "Firewall on" in Colorpack Shield > Settings. The
 * `colorpack_shield_waf_enabled` filter still works as a wp-config.php/mu-plugin override.
 */
final class Bootstrap
{
    /** @var array<string,mixed> */
    private static array $cfg = [];

    private static ?ClientIp $client = null;

    public static function boot(): void
    {
        add_action('plugins_loaded', [self::class, 'maybeInspect'], 0);
    }

    public static function maybeInspect(): void
    {
        self::$cfg    = Settings::get();
        self::$client = null;

        if (!apply_filters('colorpack_shield_waf_enabled', self::$cfg['waf_enabled'])) {
            return;
        }

        // Emergency switch first: nothing below may run while it is in place.
        if (self::killSwitchActive()) {
            return;
        }

        $client = self::clientName();

        if (!self::covers($client)) {
            return;
        }

        $ip = self::clientIp()->ip;

        // Trusted addresses: a real TCP peer on the list skips everything; an address learned from a
        // forwarding header skips only the country rule and the rate limit.
        $trust = TrustPolicy::decide(self::clientIp(), self::isTrustedIp());

        if ($trust === TrustPolicy::FULL) {
            return;
        }

        $soft = $trust === TrustPolicy::SOFT;

        $banUntil = self::bannedUntil($ip);

        if ($banUntil !== null) {
            $ref = BlockPage::newRef();
            self::log('BLOCK', ['client' => $client, 'ref' => $ref, 'shield' => 'path', 'rule' => 'ip_banned', 'until' => (string) $banUntil, 'uri' => self::uri()]);
            self::forbid($ref);
        }

        if ($client === 'administrator' && self::adminScreenAllowlisted()) {
            return;
        }

        if (!$soft && self::$cfg['geo_enabled']) {
            $reason = self::geoDecision($ip);

            if ($reason !== null) {
                $ref = BlockPage::newRef();
                self::log('BLOCK', ['client' => $client, 'ref' => $ref, 'kind' => 'geo', 'reason' => $reason, 'uri' => self::uri()]);
                self::forbid($ref);
            }
        }

        if (!$soft && self::$cfg['rate_enabled']) {
            self::rateStep($client, $ip);
        }

        if (self::$cfg['path_scan'] && self::pathStep($client)) {
            return;
        }

        if (self::$cfg['ua_mode'] !== 'off') {
            self::userAgentStep($client);
        }

        if (self::$cfg['scan_uploads'] && !empty($_FILES)) {
            $scanner = new \Colorpack\WP\ColorpackShield\Waf\UploadScanner(
                (int) self::$cfg['upload_max_bytes'],
                self::parseList((string) self::$cfg['upload_allowlist'])
            );
            $threat = $scanner->scan(\Colorpack\WP\ColorpackShield\Waf\UploadScanner::normalize($_FILES));

            if ($threat !== null) {
                $ref = BlockPage::newRef();
                self::log('BLOCK', ['client' => $client, 'ref' => $ref, 'kind' => 'upload', 'reason' => $threat->reason, 'uri' => self::uri(), 'file' => $threat->file . ' detail=' . $threat->detail]);
                self::forbid($ref);
            }
        }

        $sources = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => [], // Cookies carry session identity, not attacker payloads worth scanning here.
            'PATH'   => [
                'path'      => (string) ($_SERVER['REQUEST_URI'] ?? ''),
                'php_self'  => (string) ($_SERVER['PHP_SELF'] ?? ''),
                'path_info' => (string) ($_SERVER['PATH_INFO'] ?? ''),
            ],
        ];

        if (self::$cfg['scan_body']) {
            $raw = file_get_contents('php://input', false, null, 0, BodyParser::MAX_BODY_BYTES + 1);

            if (\is_string($raw) && $raw !== '') {
                $sources = array_merge($sources, (new BodyParser())->parse($raw, (string) ($_SERVER['CONTENT_TYPE'] ?? '')));
            }
        }

        if (self::$cfg['header_scan']) {
            $headers = RequestMeta::headers($_SERVER, self::parseList((string) self::$cfg['extra_scan_headers']), self::parseList((string) self::$cfg['ignored_headers']));

            if ($headers !== []) {
                $sources['HEADER'] = $headers;
            }
        }

        $found = self::engine($client)->inspectAll($client, new RequestData($sources));

        self::logDetections($client, $found['logged']);

        if ($found['block'] !== null) {
            self::block($client, $found['block']);
        }
    }

    // ---------------------------------------------------------------- who is asking

    private static function clientName(): string
    {
        $uri  = (string) ($_SERVER['REQUEST_URI'] ?? '');
        $path = (string) parse_url($uri, PHP_URL_PATH);
        $file = basename($path);

        if ($file === 'xmlrpc.php' || str_contains($path, '/wp-json/') || isset($_GET['rest_route'])) {
            return 'api';
        }

        // admin-ajax.php and admin-post.php are public entry points that live in wp-admin: they are the front end's.
        if (\in_array($file, ['admin-ajax.php', 'admin-post.php'], true)) {
            return 'site';
        }

        return $file === 'wp-login.php' || is_admin() || str_contains($path, '/wp-admin/') ? 'administrator' : 'site';
    }

    private static function covers(string $client): bool
    {
        return (bool) self::$cfg[['site' => 'cover_site', 'administrator' => 'cover_admin', 'api' => 'cover_api'][$client]];
    }

    private static function clientIp(): ClientIp
    {
        if (self::$client !== null) {
            return self::$client;
        }

        $resolver = new ClientIpResolver(
            CloudflareRanges::bundled(),
            self::parseList((string) self::$cfg['trusted_proxies']),
            (bool) self::$cfg['trust_cloudflare']
        );

        self::$client = $resolver->resolve($_SERVER);

        if (
            self::$cfg['override_remote_addr']
            && self::$client->ip !== ''
            && self::$client->ip !== ($_SERVER['REMOTE_ADDR'] ?? '')
        ) {
            $_SERVER['COLORPACK_SHIELD_ORIGINAL_REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SERVER['REMOTE_ADDR']                          = self::$client->ip;
        }

        return self::$client;
    }

    private static function isTrustedIp(): bool
    {
        $raw = (string) self::$cfg['allow_ips'];

        return trim($raw) !== '' && IpAllowList::fromText($raw)->matches(self::clientIp()->ip);
    }

    private static function adminScreenAllowlisted(): bool
    {
        $page = isset($_GET['page']) && \is_string($_GET['page']) ? strtolower(trim($_GET['page'])) : '';

        if ($page === '') {
            return false;
        }

        // This plugin's own screens (they hold rule text that looks like an attack) are always exempt.
        return str_starts_with($page, 'colorpack-shield') || \in_array($page, self::parseList((string) self::$cfg['admin_allowlist']), true);
    }

    // ---------------------------------------------------------------- kill switch

    private static function killSwitchActive(): bool
    {
        $hit = KillSwitch::locate([ABSPATH, \defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ''], trim((string) self::$cfg['killswitch_token']));

        if ($hit['present'] !== null) {
            self::alertKillSwitch($hit['present'], $hit['active'] !== null);
        }

        return $hit['active'] !== null;
    }

    /** Mail the admin that the switch file exists: once when it appears, then a daily reminder. Never throws. */
    private static function alertKillSwitch(string $path, bool $active): void
    {
        try {
            $mtime = (int) @filemtime($path);
            $state = trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/killswitch-alert.json';

            if (!KillSwitchAlert::claim($state, $path, $mtime, $active ? 'active' : 'ignored', time())) {
                return;
            }

            $to = trim((string) self::$cfg['alert_email']);
            $to = $to !== '' ? $to : (string) get_option('admin_email', '');

            if ($to === '') {
                return;
            }

            $site = (string) get_option('blogname', '');
            $when = gmdate('Y-m-d H:i:s', $mtime) . ' UTC';

            KillSwitchAlert::send(
                $to,
                Lang::t($active ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_SUBJECT_ACTIVE' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_SUBJECT_IGNORED', $site),
                Lang::t($active ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_BODY_ACTIVE' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_BODY_IGNORED', $site, $path, $when, (string) ($_SERVER['REMOTE_ADDR'] ?? '-'))
            );
        } catch (\Throwable) {
            // An alert must never take the site down.
        }
    }

    // ---------------------------------------------------------------- bans

    /** Targeted-attack bans (the "ban" path mode) and bans an add-on feeds in share one store. */
    private static function bannedUntil(string $ip): ?int
    {
        if ($ip === '') {
            return null;
        }

        $local = self::$cfg['path_scan'] && self::$cfg['path_probe_mode'] === 'ban';

        // An add-on that feeds a shared attacker list switches the check on (filter); alone, only the "ban" path mode does.
        if (!$local && !apply_filters('colorpack_shield_use_ban_store', false)) {
            return null;
        }

        try {
            $check = (new TargetedBanPolicy(BanStore::get()))->check($ip, time());
        } catch (\Throwable) {
            return null; // A storage problem must never turn into an outage.
        }

        return $check['banned'] ? $check['until'] : null;
    }

    private static function armBan(string $reason): void
    {
        $ip = self::clientIp()->ip;

        if ($ip === '') {
            return;
        }

        $hours = max(1, (int) self::$cfg['path_probe_ban_hours']);
        $until = (new TargetedBanPolicy(BanStore::get()))->ban($ip, time(), $hours * 3600, $reason);

        if ($until > 0) {
            self::log('LOCK', ['client' => 'site', 'kind' => 'ip_ban', 'until' => (string) $until, 'reason' => $reason]);

            // Public event: add-ons (such as Colorpack Shield Fleet) may report it. Nothing is sent from here.
            do_action('colorpack_shield_ban', $ip, $reason);
        }
    }

    // ---------------------------------------------------------------- country and rate

    private static function geoDecision(string $ip): ?string
    {
        if ($ip === '') {
            return null;
        }

        $policy = new GeoPolicy(
            (string) self::$cfg['geo_mode'],
            self::parseList((string) self::$cfg['geo_countries']),
            self::parseList((string) self::$cfg['geo_allow_ips']),
            self::parseList((string) self::$cfg['geo_deny_ips']),
            (bool) self::$cfg['geo_unknown_allow']
        );

        $country = $policy->needsCountry() ? (new CountryLookup((string) self::$cfg['geo_db_path']))->country($ip) : null;

        return $policy->decide($ip, $country);
    }

    private static function rateStep(string $client, string $ip): void
    {
        // APCu when the server has it, otherwise small files in uploads/colorpack-shield/rate (see RateStores).
        $store = $ip === '' ? null : RateStores::pick(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/rate');

        if ($store === null) {
            return;
        }

        $limiter = new RateLimiter(
            $store,
            (int) self::$cfg['rate_window'],
            (int) self::$cfg['rate_limit'],
            (int) self::$cfg['rate_ban_threshold'],
            (int) self::$cfg['rate_ban_window'],
            (int) self::$cfg['rate_ban_duration']
        );

        $page    = isset($_GET['page']) && \is_string($_GET['page']) ? $_GET['page'] : '';
        $verdict = $limiter->decide(time(), $ip, $client . ':' . $page);

        if ($verdict->allowed) {
            return;
        }

        self::log('BLOCK', ['client' => $client, 'kind' => 'rate', 'reason' => $verdict->reason, 'retry' => (string) $verdict->retryAfter, 'uri' => self::uri()]);

        if (self::$cfg['block_silent']) {
            exit;
        }

        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=utf-8', true, 429);
            header('Retry-After: ' . $verdict->retryAfter);
        }

        exit('Too Many Requests');
    }

    // ---------------------------------------------------------------- path and payload shields

    private static function pathStep(string $client): bool
    {
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');

        if ($uri === '') {
            return false;
        }

        $sources = ['PATH' => ['path' => $uri]];

        foreach (['PHP_SELF' => 'php_self', 'PATH_INFO' => 'path_info'] as $var => $key) {
            if (isset($_SERVER[$var]) && \is_string($_SERVER[$var]) && $_SERVER[$var] !== '') {
                $sources['PATH'][$key] = $_SERVER[$var];
            }
        }

        $mode  = \in_array(self::$cfg['path_mode'], ['recommended', 'log', 'block'], true) ? self::$cfg['path_mode'] : 'recommended';
        $probe = \in_array(self::$cfg['path_probe_mode'], ['off', 'log', 'block', 'ban'], true) ? self::$cfg['path_probe_mode'] : 'log';
        $tools = self::parseList((string) self::$cfg['path_tools_exempt']);

        $shield = new PathShield(
            $mode,
            $probe,
            self::parseLines((string) self::$cfg['path_allow']),
            self::parseLines((string) self::$cfg['path_extra_deny']),
            $tools === [] ? PathRules::DEFAULT_TOOLS_EXEMPT : $tools
        );

        $engine = new WafEngine([$shield], [$shield->id() => [$client]]);
        $found  = $engine->inspectAll($client, new RequestData($sources));
        $shown  = self::pathForLog($uri);

        self::logDetections($client, $found['logged'], $shown);

        if ($found['block'] === null) {
            return false;
        }

        self::block($client, $found['block'], $shown);

        return true;
    }

    /** Known attack tools named in the User-Agent: own engine so no other shield ever reads the header as a parameter. */
    private static function userAgentStep(string $client): void
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if (!\is_string($ua) || $ua === '') {
            return;
        }

        $shield = new UserAgentShield(
            self::$cfg['ua_mode'] === 'log' ? WafResult::MODE_LOG : WafResult::MODE_BLOCK,
            self::parseList((string) self::$cfg['ua_extra_deny'])
        );
        $found = (new WafEngine([$shield], [$shield->id() => [$client]]))->inspectAll($client, new RequestData(['UA' => ['user-agent' => $ua]]));

        self::logDetections($client, $found['logged']);

        if ($found['block'] !== null) {
            self::block($client, $found['block']);
        }
    }

    private static function engine(string $client): WafEngine
    {
        $shields = [];
        $scopes  = [];

        foreach ([new SqliShield(), new XssShield(), new LfiShield(), new RfiShield()] as $shield) {
            if (self::$cfg['shield_' . $shield->id()]) {
                $shields[]             = $shield;
                $scopes[$shield->id()] = [$client];
            }
        }

        // Injection classes that look like ordinary text more often: they start in log mode (see shield_inject_mode),
        // and the two that match code-like content stay out of wp-admin, where editors paste snippets.
        $mode = self::$cfg['shield_inject_mode'] === 'block' ? WafResult::MODE_BLOCK : WafResult::MODE_LOG;

        foreach ([new CmdiShield($mode), new SsrfShield($mode), new XxeShield($mode), new SstiShield($mode)] as $shield) {
            if (!self::$cfg['shield_' . $shield->id()]) {
                continue;
            }

            if ($client === 'administrator' && \in_array($shield->id(), ['cmdi', 'ssrf', 'ssti'], true)) {
                continue;
            }

            $shields[]             = $shield;
            $scopes[$shield->id()] = [$client];
        }

        if (self::$cfg['header_scan']) {
            $head = new HeaderShield(\in_array(self::$cfg['header_mode'], ['default', 'log', 'block'], true) ? self::$cfg['header_mode'] : 'default');

            $shields[]           = $head;
            $scopes[$head->id()] = [$client];
        }

        $path       = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
        $pick       = $_GET['page'] ?? $_GET['action'] ?? '';
        $option     = \is_string($pick) ? (preg_replace('/[^a-z0-9_\-]/', '', strtolower($pick)) ?? '') : '';
        $exceptions = ExceptionRules::forRequest(ExceptionRules::parse((string) (self::$cfg['waf_exceptions'] ?? '')), $path, $option);

        return new WafEngine($shields, $scopes, $exceptions);
    }

    // ---------------------------------------------------------------- answering and logging

    /**
     * @param  WafResult[]  $logged
     */
    private static function logDetections(string $client, array $logged, ?string $uri = null): void
    {
        $written = 0;

        foreach ($logged as $hit) {
            if ($written >= 3) {
                break;
            }

            if (ApcuRateStore::isAvailable() && !apcu_add('cps_dl_' . md5($hit->rule . '|' . $hit->key . '|' . self::clientIp()->ip), 1, 60)) {
                continue;
            }

            self::log('DETECT', ['client' => $client, 'shield' => $hit->shield, 'rule' => $hit->rule, 'src' => $hit->source, 'key' => $hit->key, 'uri' => $uri ?? self::uri(), 'sample' => $hit->sample]);
            $written++;
        }
    }

    private static function block(string $client, WafResult $result, ?string $uri = null): void
    {
        $ip = self::clientIp()->ip;

        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY']) && \is_string($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            \Colorpack\WP\ColorpackShield\Net\IpCountry::remember($ip, $_SERVER['HTTP_CF_IPCOUNTRY']); // free, exact, never leaves the server
        }

        $ref = BlockPage::newRef();

        // "sample" goes last: LogReader::parseLine() treats it as taking the rest of the line.
        self::log('BLOCK', ['client' => $client, 'ref' => $ref, 'shield' => $result->shield, 'rule' => $result->rule, 'src' => $result->source, 'key' => $result->key, 'uri' => $uri ?? self::uri(), 'sample' => $result->sample]);

        if ($result->mode === WafResult::MODE_BAN) {
            self::armBan($result->rule);
        }

        self::forbid($ref);
    }

    /**
     * @param  array<string,string>  $fields
     */
    private static function log(string $type, array $fields): void
    {
        try {
            (new ActivityLog(ActivityLog::defaultPath()))->write($type, $fields, self::clientIp()->ip);
        } catch (\Throwable) {
            // A log problem must never turn into an outage.
        }
    }

    private static function forbid(string $ref = ''): never
    {
        // "Block silent" hides that a firewall is present (recon-resistance).
        if (self::$cfg['block_silent']) {
            exit('');
        }

        $html = $ref !== '' && BlockPage::wantsHtml((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));

        if (!headers_sent()) {
            header('Content-Type: ' . ($html ? 'text/html' : 'text/plain') . '; charset=utf-8', true, 403);
            header('Cache-Control: no-store, private');
            header('X-Robots-Tag: noindex');

            if ($ref !== '') {
                header('X-Block-Ref: ' . $ref);
            }
        }

        // The product name, the rule and the field are NOT shown: only a short reference. What matched is in
        // the Activity log under that reference, where the administrator can allow it.
        exit($ref === '' ? 'Forbidden' : ($html ? BlockPage::html($ref) : BlockPage::text($ref)));
    }

    private static function uri(): string
    {
        return (string) ($_SERVER['REQUEST_URI'] ?? '-');
    }

    private static function pathForLog(string $uri): string
    {
        $path = substr($uri, 0, strcspn($uri, '?#'));

        return \strlen($path) > 200 ? substr($path, 0, 200) . '…' : $path;
    }

    /**
     * Comma/newline list into trimmed, lowercased, non-empty tokens.
     *
     * @return string[]
     */
    private static function parseList(string $raw): array
    {
        $out = [];

        foreach (preg_split('/[\r\n,]+/', $raw) ?: [] as $entry) {
            $entry = strtolower(trim($entry));

            if ($entry !== '') {
                $out[] = $entry;
            }
        }

        return $out;
    }

    /**
     * One entry per line, kept as typed (regular expressions may contain commas).
     *
     * @return string[]
     */
    private static function parseLines(string $raw): array
    {
        $out = [];

        foreach (preg_split('/\r\n|\r|\n/', $raw) ?: [] as $line) {
            $line = trim($line);

            if ($line !== '') {
                $out[] = $line;
            }
        }

        return $out;
    }
}
