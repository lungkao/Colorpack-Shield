<?php

namespace Colorpack\Shield\Wp;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Net\TrustPolicy;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\EventQueue;
use Colorpack\Plugin\System\ColorpackShield\Waf\BodyParser;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestMeta;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;
use Colorpack\Plugin\System\ColorpackShield\Waf\UploadScanner;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafEngine;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

defined('ABSPATH') || die;

/**
 * The request firewall: runs once per request, very early, before WordPress routes anything.
 * Order: kill switch, real visitor address, trusted addresses, banned addresses, URL path, uploads,
 * then the request payload and headers. Detect-only until the owner turns on enforcement.
 */
final class Guard
{
    private static ?ClientIp $ip = null;

    public static function run(): void
    {
        if ((defined('WP_CLI') && WP_CLI) || self::killSwitch()) {
            return;
        }

        try {
            $client = self::client();
            $trust  = TrustPolicy::decide(self::ip(), self::isListed());

            if ($trust === TrustPolicy::FULL) {
                return;
            }

            $until = self::bannedUntil(self::ip()->ip);

            if ($until !== null) {
                Logger::add(sprintf('BLOCK client=%s shield=path rule=ip_banned ip=%s until=%d uri=%s', $client, self::logIp(), $until, self::uri()));
                self::forbid();
            }

            if (Settings::get('path_scan') && self::pathStep($client)) {
                return;
            }

            if (Settings::get('scan_uploads') && !empty($_FILES)) {
                $threat = (new UploadScanner((int) Settings::get('upload_max_bytes'), []))->scan(UploadScanner::normalize($_FILES));

                if ($threat !== null) {
                    Logger::add(sprintf('%s client=%s kind=upload reason=%s file=%s detail=%s ip=%s uri=%s', self::enforce() ? 'BLOCK' : 'DETECT', $client, $threat->reason, $threat->file, $threat->detail, self::logIp(), self::uri()));

                    if (self::enforce()) {
                        self::forbid();
                    }
                }
            }

            self::payloadStep($client);
        } catch (\Throwable $e) {
            // A bug in the firewall must never take the site down.
            Logger::add('ERROR guard ' . get_class($e) . ': ' . $e->getMessage());
        }
    }

    public static function ip(): ClientIp
    {
        if (self::$ip === null) {
            $proxies = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string) Settings::get('trusted_proxies')) ?: [])));
            $ranges  = CloudflareRanges::bundled();
            self::$ip = (new ClientIpResolver($ranges, $proxies, (bool) Settings::get('trust_cloudflare')))->resolve($_SERVER);
        }

        return self::$ip;
    }

    public static function isListed(): bool
    {
        $raw = (string) Settings::get('allow_ips');

        return trim($raw) !== '' && IpAllowList::fromText($raw)->matches(self::ip()->ip);
    }

    public static function logIp(): string
    {
        $c = self::ip();

        return $c->ip === '' ? '-' : $c->ip . ($c->via !== ClientIp::VIA_DIRECT ? ' via=' . $c->via : '');
    }

    public static function banStore(): FileStateStore
    {
        return new FileStateStore(Settings::stateDir('bans'));
    }

    public static function bannedUntil(string $ip): ?int
    {
        if ((string) Settings::get('path_probe_mode') !== 'ban' || $ip === '') {
            return null;
        }

        $check = (new TargetedBanPolicy(self::banStore()))->check($ip, time());

        return $check['banned'] ? $check['until'] : null;
    }

    /** Where the emergency off-switch is checked: a file the owner can create over FTP, or a constant in wp-config.php. */
    private static function killSwitch(): bool
    {
        return (defined('COLORPACK_SHIELD_DISABLED') && COLORPACK_SHIELD_DISABLED)
            || is_file(ABSPATH . 'colorpack_shield.disable') || is_file(WP_CONTENT_DIR . '/colorpack_shield.disable');
    }

    private static function enforce(): bool
    {
        return (bool) Settings::get('waf_enforce');
    }

    /** "administrator" for wp-admin / wp-login, "api" for the REST API, otherwise "site" (the Joomla package's three areas). */
    private static function client(): string
    {
        $path = strtolower((string) parse_url(self::uri(), PHP_URL_PATH));

        if (str_contains($path, '/wp-admin') || str_contains($path, 'wp-login.php')) {
            return 'administrator';
        }

        return str_contains($path, '/wp-json') || isset($_GET['rest_route']) ? 'api' : 'site';
    }

    private static function covered(): array
    {
        return array_keys(array_filter(['site' => Settings::get('cover_site'), 'administrator' => Settings::get('cover_admin'), 'api' => Settings::get('cover_api')]));
    }

    private static function uri(): string
    {
        return (string) ($_SERVER['REQUEST_URI'] ?? '');
    }

    private static function pathStep(string $client): bool
    {
        $uri = self::uri();

        if ($uri === '') {
            return false;
        }

        $mode  = (string) Settings::get('path_mode');
        $probe = (string) Settings::get('path_probe_mode');
        $shield = new PathShield($mode, $probe, [], []);
        $engine = new WafEngine([$shield], [$shield->id() => self::covered()]);
        $found = $engine->inspectAll($client, new RequestData(['PATH' => ['path' => $uri]]));
        $shown = substr($uri, 0, strcspn($uri, '?#'));

        self::logDetections($client, $found['logged'], $shown);

        if ($found['block'] === null) {
            return false;
        }

        return self::act($client, $found['block'], $shown);
    }

    private static function payloadStep(string $client): void
    {
        // Editors legitimately post HTML, scripts and SQL snippets from wp-admin and the REST API; a
        // request carrying a WordPress login cookie is judged on path and uploads only (WordPress itself
        // checks that cookie). Everything unauthenticated, and the whole public site, gets the full check.
        if ($client !== 'site' && self::hasLoginCookie()) {
            return;
        }

        $sources = ['GET' => $_GET, 'POST' => $_POST, 'COOKIE' => $_COOKIE];

        if (Settings::get('scan_body')) {
            $raw = file_get_contents('php://input', false, null, 0, BodyParser::MAX_BODY_BYTES + 1);
            $sources += (new BodyParser())->parse($raw === false ? '' : $raw, $_SERVER['CONTENT_TYPE'] ?? '');
        }

        if (Settings::get('header_scan')) {
            $headers = RequestMeta::headers($_SERVER, [], []);

            if ($headers !== []) {
                $sources['HEADER'] = $headers;
            }
        }

        $shields = [];
        $scopes  = [];

        foreach ([new SqliShield(), new XssShield(), new LfiShield(), new RfiShield()] as $shield) {
            if (Settings::get('shield_' . $shield->id())) {
                $shields[]             = $shield;
                $scopes[$shield->id()] = self::covered();
            }
        }

        if (Settings::get('header_scan')) {
            $mode                 = (string) Settings::get('header_mode');
            $head                 = new HeaderShield($mode);
            $shields[]            = $head;
            $scopes[$head->id()]  = self::covered();
        }

        $found = (new WafEngine($shields, $scopes))->inspectAll($client, new RequestData($sources));

        self::logDetections($client, $found['logged'], null);

        if ($found['block'] !== null) {
            self::act($client, $found['block'], null);
        }
    }

    private static function hasLoginCookie(): bool
    {
        foreach (array_keys($_COOKIE) as $name) {
            if (str_starts_with((string) $name, 'wordpress_logged_in_')) {
                return true;
            }
        }

        return false;
    }

    /**
     * A blocking finding: refused only when enforcement is on (otherwise logged as DETECT). A ban-mode finding
     * (scanner probes) only exists when the owner chose the "ban" probe mode, which is itself the opt-in.
     */
    private static function act(string $client, WafResult $r, ?string $uri): bool
    {
        $enforce = self::enforce() || $r->mode === WafResult::MODE_BAN && (string) Settings::get('path_probe_mode') === 'ban';

        Logger::add(sprintf('%s client=%s shield=%s rule=%s src=%s key=%s ip=%s uri=%s sample=%s', $enforce ? 'BLOCK' : 'DETECT', $client, $r->shield, $r->rule, $r->source, $r->key, self::logIp(), $uri ?? self::uri(), $r->sample));

        if (!$enforce) {
            return false;
        }

        if ($r->mode === WafResult::MODE_BAN) {
            self::ban($r->rule);
        }

        self::forbid();

        return true;
    }

    private static function ban(string $reason): void
    {
        $ip = self::ip()->ip;

        if ($ip === '') {
            return;
        }

        $hours = max(1, (int) Settings::get('path_probe_ban_hours'));
        $until = (new TargetedBanPolicy(self::banStore()))->ban($ip, time(), $hours * 3600, $reason);

        if ($until > 0) {
            Logger::add(sprintf('LOCK kind=ip_ban ip=%s until=%d reason=%s', self::logIp(), $until, $reason));
            self::reportThreat($ip, $reason, time());
        }
    }

    /** Tell the Site Manager about a deliberately banned attacker (never a visitor), once per address per day. */
    private static function reportThreat(string $ip, string $reason, int $now): void
    {
        try {
            if (!Settings::get('site_manager_enabled') || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return;
            }

            (new EventQueue(Reporter::store(), 'threats'))->enqueue([
                'id'     => substr(hash('sha256', $ip), 0, 16) . '-' . gmdate('Ymd', $now),
                'at'     => gmdate('Y-m-d\TH:i:s\Z', $now),
                'ip'     => $ip,
                'reason' => substr($reason, 0, 60),
            ], $now);
        } catch (\Throwable) {
            // Best effort.
        }
    }

    private static function logDetections(string $client, array $logged, ?string $uri): void
    {
        foreach (array_slice($logged, 0, 3) as $hit) {
            Logger::add(sprintf('DETECT client=%s shield=%s rule=%s src=%s key=%s ip=%s uri=%s sample=%s', $client, $hit->shield, $hit->rule, $hit->source, $hit->key, self::logIp(), $uri ?? self::uri(), $hit->sample));
        }
    }

    private static function forbid(): never
    {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=utf-8');
        }

        echo 'Forbidden';
        exit;
    }
}
