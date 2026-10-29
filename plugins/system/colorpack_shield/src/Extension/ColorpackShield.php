<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Extension;

use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Event\Event;
use Joomla\Event\SubscriberInterface;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminChangeDetector;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGate;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminProtectConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AlertThrottle;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\JoomlaMfaGateway;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\KnownIps;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockDecision;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LoginRateLimit;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\MfaPolicy;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProbeToken;
use Colorpack\Plugin\System\ColorpackShield\Diagnostics\ProxyProbe;
use Colorpack\Plugin\System\ColorpackShield\Geo\CidrMatcher;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Net\TrustPolicy;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitch;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitchAlert;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Geo\CountryLookup;
use Colorpack\Plugin\System\ColorpackShield\Geo\GeoPolicy;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\ApcuRateStore;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateLimiter;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateVerdict;
use Colorpack\Plugin\System\ColorpackShield\Waf\BodyParser;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestMeta;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;
use Colorpack\Plugin\System\ColorpackShield\Waf\UploadScanner;
use Colorpack\Plugin\System\ColorpackShield\Waf\UploadThreat;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafEngine;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

\defined('_JEXEC') || die;

/**
 * Colorpack Shield system plugin — the generic request WAF.
 *
 * P0.1: unlike the site-only shields in comparable extensions, Colorpack Shield runs
 * the same SQLi/XSS/LFI/RFI signatures on the site, administrator, AND api
 * applications. Front-end + admin are inspected at onAfterInitialise (payload
 * already present, admin `option` known for allowlisting); the api app is
 * inspected at onAfterApiRoute.
 */
final class ColorpackShield extends CMSPlugin implements SubscriberInterface
{
    /** Only tests replace this: they cannot read a Set-Cookie header in a command-line run. */
    public static ?\Closure $cookieSender = null;

    protected $autoloadLanguage = true;

    private ?WafEngine $engine = null;

    private ?WafEngine $pathEngine = null;

    private ?FileStateStore $adminStore = null;

    private ?FileStateStore $banStore = null;

    /** @var array<int,int[]> user id => group ids before the save in progress */
    private array $groupsBefore = [];

    private bool $handled = false;

    private bool $logReady = false;

    private ?string $rawBody = null;

    private ?ClientIp $clientIp = null;

    /** @var string[]|null */
    private ?array $cfRanges = null;

    private bool $killSwitchChecked = false;

    private ?string $killSwitchFile = null;

    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterInitialise' => 'onAfterInitialise',
            'onAfterApiRoute'   => 'onAfterApiRoute',
            'onAfterRoute'      => 'onAfterRoute',
            'onExtensionBeforeSave' => 'onExtensionBeforeSave',
            'onUserLoginFailure' => 'onUserLoginFailure',
            'onUserAfterLogin'   => 'onUserAfterLogin',
            'onUserBeforeSave'   => 'onUserBeforeSave',
            'onUserAfterSave'    => 'onUserAfterSave',
        ];
    }

    /**
     * Keep the emergency switch visible: while the kill-switch file exists the
     * plugin protects nothing, so every administrator page says so.
     */
    public function onAfterRoute(Event $event): void
    {
        $app = $this->getApplication();

        if ($app === null || !$app->isClient('administrator')) {
            return;
        }

        $path = $this->killSwitchPath();

        if ($path !== null) {
            $app->enqueueMessage(Text::sprintf('PLG_SYSTEM_COLORPACK_SHIELD_KILLSWITCH_ACTIVE', $path), 'warning');

            return;
        }

        $this->mfaStep($app);
    }

    /**
     * Multi-factor authentication for administrators (PLAN-ADMIN-PROTECTION.md A3):
     * a reminder, and after the grace period a redirect to Joomla's own setup page.
     * Joomla's list of MFA pages decides what stays reachable, so no loop can arise;
     * any problem reading Joomla's MFA state means "do nothing".
     */
    private function mfaStep($app): void
    {
        $action = MfaPolicy::NONE;
        $info   = ['daysLeft' => 0, 'overdue' => false];
        $url    = '';

        try {
            $cfg = AdminProtectConfig::fromArray($this->params->toArray());

            if ($cfg->mfaEnforce === AdminProtectConfig::MFA_OFF || !JoomlaMfaGateway::available()) {
                return;
            }

            $user = $app->getIdentity();
            $id   = (int) ($user->id ?? 0);

            if ($user === null || $id <= 0 || !empty($user->guest)) {
                return;
            }

            $groups  = JoomlaMfaGateway::userGroups($user);
            $applies = array_intersect($cfg->mfaGroups, $groups) !== [] && array_intersect(JoomlaMfaGateway::neverGroups(), $groups) === [];

            if (!$applies || JoomlaMfaGateway::userHasMfa($id)) {
                return;
            }

            $now    = time();
            $first  = $this->mfaFirstSeen($id, $now, $cfg->mfaGraceDays);
            $isHtml = (string) $app->getInput()->getCmd('format', 'html') === 'html';
            $d      = MfaPolicy::decide($cfg->mfaEnforce, true, false, $first, $now, $cfg->mfaGraceDays, JoomlaMfaGateway::isExemptPage($app), $isHtml);
            $action = $d['action'];
            $info   = $d;
            $url    = JoomlaMfaGateway::setupUrl();

            if ($action === MfaPolicy::REDIRECT || $action === MfaPolicy::DENY) {
                $this->logAdminEvent('NOTE', 'mfa', $action === MfaPolicy::REDIRECT ? 'redirect_to_setup' : 'denied_until_setup', 0, $now);
            }
        } catch (\Throwable) {
            return;
        }

        if ($action === MfaPolicy::WARN) {
            $app->enqueueMessage(
                $info['overdue']
                    ? Text::sprintf('PLG_SYSTEM_COLORPACK_SHIELD_MFA_MSG_OVERDUE', htmlspecialchars($url, ENT_QUOTES))
                    : Text::sprintf('PLG_SYSTEM_COLORPACK_SHIELD_MFA_MSG_GRACE', (string) $info['daysLeft'], htmlspecialchars($url, ENT_QUOTES)),
                'warning'
            );
        } elseif ($action === MfaPolicy::REDIRECT) {
            $app->enqueueMessage(Text::_('PLG_SYSTEM_COLORPACK_SHIELD_MFA_MSG_REQUIRED'), 'warning');
            $app->redirect($url, 307);
        } elseif ($action === MfaPolicy::DENY) {
            throw new \RuntimeException(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }
    }

    /**
     * When this user was first seen without multi-factor authentication: the
     * start of the grace period. Remembered in the state store (it is never
     * reset by a request, only extended so the entry outlives the grace).
     */
    private function mfaFirstSeen(int $userId, int $now, int $graceDays): int
    {
        $keep  = ($graceDays + 120) * 86400;
        $store = $this->adminStore();
        $e     = $store->get('mfa:' . $userId, $now);

        if ($e !== null && (int) ($e['exp'] ?? 0) - $now > 60 * 86400) {
            return (int) $e['first'];
        }

        $e = $store->mutate('mfa:' . $userId, $now, static fn (?array $e): array => ['first' => (int) ($e['first'] ?? $now), 'exp' => $now + $keep]);

        // An unusable store means no grace tracking: treat the user as just seen (a reminder, never a redirect).
        return $e === null ? $now : (int) $e['first'];
    }

    /**
     * When a Super User saves this plugin's settings, add their current IP to
     * the trusted list so a stricter setting cannot lock out the person who
     * just applied it. Never throws: a failure here must not block saving.
     */
    public function onExtensionBeforeSave(Event $event): void
    {
        try {
            $subject = $event->getArgument('subject') ?? $event->getArgument(1);

            if (
                !\is_object($subject)
                || ($subject->element ?? '') !== 'colorpack_shield'
                || ($subject->folder ?? '') !== 'system'
            ) {
                return;
            }

            $app      = $this->getApplication();
            $identity = $app?->getIdentity();

            if ($identity === null || !$identity->authorise('core.admin')) {
                return;
            }

            // Read the values being saved, not the stored ones.
            $params = new Registry($subject->params ?? '');

            if ((int) $params->get('auto_allow_admin', 1) !== 1) {
                return;
            }

            $client = $this->clientIp();

            if (!IpAllowList::isSafeToAutoAdd($client, $this->cloudflareRanges(), $this->trustedProxies())) {
                $app->enqueueMessage(Text::_('PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_NOT_ADDED'), 'warning');

                return;
            }

            $current = (string) $params->get('allow_ips', '');
            $updated = IpAllowList::appendIp($current, $client->ip);

            if ($updated !== $current) {
                $params->set('allow_ips', $updated);
                $subject->params = $params->toString();
                $app->enqueueMessage(Text::sprintf('PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_ADDED', $client->ip), 'message');
            }
        } catch (\Throwable $e) {
            // Saving settings must never fail because of this convenience.
        }
    }

    /**
     * Guards the site and administrator applications.
     */
    public function onAfterInitialise(Event $event): void
    {
        $app = $this->getApplication();

        if ($app === null || $app->isClient('api')) {
            return;
        }

        $this->handleProbe($app);

        $client = $app->isClient('administrator') ? 'administrator' : 'site';
        $this->guard($client);
    }

    /**
     * Guards the api application (Joomla web-services app).
     */
    public function onAfterApiRoute(Event $event): void
    {
        $this->guard('api');
    }

    /**
     * Build the request view, run the covering shields, block on a hit.
     */
    private function guard(string $client): void
    {
        if ($this->handled) {
            return;
        }

        // Emergency switch first: nothing below may run while it is in place.
        if ($this->killSwitchPath() !== null) {
            $this->handled = true;

            return;
        }

        $app = $this->getApplication();

        if ($app === null) {
            return;
        }

        // Resolve the real visitor IP first: geo, rate limit and every log line
        // below depend on it, and it may rewrite REMOTE_ADDR for later plugins.
        $this->clientIp();

        // Trusted IPs (admin lock-out protection). FULL trust (skip everything)
        // only when the address is the real TCP peer; an address learned from a
        // forwarding header gets SOFT trust — geo and rate limit are skipped,
        // the WAF and upload scan still run (AUDIT.md C1).
        $trust = TrustPolicy::decide($this->clientIp(), $this->isTrustedIp());

        if ($trust === TrustPolicy::FULL) {
            $this->handled = true;

            return;
        }

        $soft = $trust === TrustPolicy::SOFT;

        // An address already banned by an earlier deliberate-attacker hit (WafResult::MODE_BAN,
        // armed in block()) is rejected before any other work - that is the whole point of a
        // ban over a per-request block. Trusted IPs never reach here (FULL trust returns above).
        $banUntil = $this->bannedUntil($this->clientIp()->ip);

        if ($banUntil !== null) {
            $this->handled = true;
            $this->blockBanned($client, $banUntil);

            return;
        }

        // Administrator login protection (PLAN-ADMIN-PROTECTION.md A1): a locked
        // address and the login speed limit come before any other work. Fully
        // trusted addresses never get here; soft-trusted ones are exempt.
        // Access key and address list (A4/A5) come first: a request that may not even see the
        // administrator gets a plain 404 before any other work or log line about it.
        if ($client === 'administrator') {
            $this->adminAccessGate($app, $soft);
        }

        if ($client === 'administrator' && !$soft) {
            $this->adminLoginGate($app);
        }

        // Admin allowlist: never risk locking a Super User out of a trusted
        // component whose params legitimately contain regex-like values.
        if ($client === 'administrator') {
            $option = (string) $app->getInput()->getCmd('option', '');

            if ($option !== '' && $this->isAllowlisted($option)) {
                return;
            }
        }

        // P1.2: GeoIP is the cheapest gate — a denied country never reaches the
        // upload scan or the payload WAF.
        if (!$soft && (int) $this->params->get('geo_enabled', 0)) {
            $reason = $this->geoDecision();

            if ($reason !== null) {
                $this->handled = true;
                $this->blockGeo($client, $reason);

                return;
            }
        }

        // P1.3: rate limit early — a flood is cheapest to shed before any scan.
        if (!$soft && (int) $this->params->get('rate_enabled', 0)) {
            $verdict = $this->rateDecision($app, $client);

            if ($verdict !== null && !$verdict->allowed) {
                $this->handled = true;
                $this->blockRate($client, $verdict);

                return;
            }
        }

        // URL path: judged before the body is read or any parameter is parsed.
        if ((int) $this->params->get('path_scan', 1) && $this->pathStep($client)) {
            $this->handled = true;

            return;
        }

        // P1.1: inspect uploaded files before the payload WAF — a malicious
        // upload is a threat regardless of its form-field values.
        if ((int) $this->params->get('scan_uploads', 1) && !empty($_FILES)) {
            $scanner = new UploadScanner(
                (int) $this->params->get('upload_max_bytes', 10485760),
                $this->parseList((string) $this->params->get('upload_allowlist', ''))
            );

            $threat = $scanner->scan(UploadScanner::normalize($_FILES));

            if ($threat !== null) {
                $this->handled = true;
                $this->blockUpload($client, $threat);

                return;
            }
        }

        // The WAF must see the RAW request, not Joomla's filtered input.
        $sources = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => $_COOKIE,
        ];

        // P0.2: $_GET/$_POST miss application/json and raw bodies. Read
        // php://input once, content-type aware, and fold it into the scan.
        if ((int) $this->params->get('scan_body', 1)) {
            $parser  = new BodyParser();
            $sources += $parser->parse($this->readRawBody(), $_SERVER['CONTENT_TYPE'] ?? '');

            if ($parser->oversize) {
                $this->writeLog(sprintf(
                    'NOTE client=%s body oversize (>%d bytes) — partial scan only ip=%s uri=%s',
                    $client,
                    BodyParser::MAX_BODY_BYTES,
                    $this->logIp(),
                    $_SERVER['REQUEST_URI'] ?? '-'
                ));
            }
        }

        // Request headers: a named set, never secrets (RequestMeta / HeaderRules).
        if ((int) $this->params->get('header_scan', 1)) {
            $headers = RequestMeta::headers(
                $_SERVER,
                $this->parseList((string) $this->params->get('extra_scan_headers', '')),
                $this->parseList((string) $this->params->get('ignored_headers', ''))
            );

            if ($headers !== []) {
                $sources['HEADER'] = $headers;
            }
        }

        $data = new RequestData($sources);

        $found         = $this->getEngine()->inspectAll($client, $data);
        $this->handled = true;

        // Detect-only findings are written to the log; the request goes on.
        $this->logDetections($client, $found['logged']);

        if ($found['block'] === null) {
            return;
        }

        $this->block($client, $found['block']);
    }

    /**
     * A failed administrator login: count it against the visitor's address and
     * lock the address when it has failed too often (see {@see LockoutPolicy}).
     * Trusted addresses are never counted; any storage problem means "do nothing".
     */
    public function onUserLoginFailure(Event $event): void
    {
        try {
            $app = $this->getApplication();

            if ($app === null || !$app->isClient('administrator') || $this->killSwitchPath() !== null) {
                return;
            }

            $cfg = AdminProtectConfig::fromArray($this->params->toArray());

            if (!$cfg->lockoutEnabled || TrustPolicy::decide($this->clientIp(), $this->isTrustedIp()) !== TrustPolicy::NONE) {
                return;
            }

            $response = $event->getArgument('subject') ?? $event->getArgument(0);
            $username = \is_array($response) ? (string) ($response['username'] ?? '') : '';
            $now      = time();
            $result   = (new LockoutPolicy($cfg, $this->adminStore()))->recordFailure($this->clientIp()->ip, $username, $now);

            if ($result['newLock']) {
                $this->writeLog(sprintf(
                    'LOCK client=administrator ip=%s until=%d strikes=%d seconds=%d',
                    $this->logIp(),
                    $result['lockUntil'],
                    $result['strikes'],
                    $result['lockUntil'] - $now
                ));
            }

            if ($result['pressure'] >= 1) {
                $this->logAdminEvent('NOTE', 'name_pressure', 'level' . $result['pressure'], 0, $now);
            }

            if ($result['newLock'] && $cfg->alertLockouts) {
                $enforced = IpAllowList::isSafeToAutoAdd($this->clientIp(), $this->cloudflareRanges(), $this->trustedProxies())
                    && !KnownIps::isAdminAddress($this->adminStore(), $this->clientIp()->ip, $this->adminSalt(), $now);

                $this->sendAdminAlert(
                    'lockout',
                    3600,
                    'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_SUBJECT',
                    'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_BODY',
                    [],
                    [
                        (string) $result['bucket'],
                        (string) ($result['lockUntil'] - $now),
                        (string) $result['strikes'],
                        Text::_($enforced ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_ENFORCED' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_LOCKOUT_OBSERVED'),
                        '{held}',
                        '{when}',
                    ]
                );
            }
        } catch (\Throwable) {
            // Never let the protection break a login.
        }
    }

    /**
     * A successful administrator login lifts the address's counters and marks
     * the address as one an administrator uses (it is then never locked out).
     */
    public function onUserAfterLogin(Event $event): void
    {
        try {
            $app = $this->getApplication();

            if ($app === null || !$app->isClient('administrator')) {
                return;
            }

            $ip    = $this->clientIp()->ip;
            $now   = time();
            $store = $this->adminStore();

            $cfg = AdminProtectConfig::fromArray($this->params->toArray());

            (new LockoutPolicy($cfg, $store))->recordSuccess($ip, $now);
            KnownIps::rememberAdminAddress($store, $ip, $this->adminSalt(), $now);

            // A login from an address this administrator has not used before.
            $options = $event->getArgument('options') ?? $event->getArgument(0);
            $user    = \is_array($options) ? ($options['user'] ?? null) : null;
            $userId  = (int) (\is_object($user) ? ($user->id ?? 0) : (\is_array($user) ? ($user['id'] ?? 0) : 0));
            $name    = (string) (\is_object($user) ? ($user->username ?? '') : (\is_array($user) ? ($user['username'] ?? '') : ''));
            $seen    = KnownIps::observe($store, $userId, $ip, $this->adminSalt(), $now);

            if ($seen === KnownIps::NEW && $cfg->alertNewIp && IpAllowList::isSafeToAutoAdd($this->clientIp(), $this->cloudflareRanges(), $this->trustedProxies())) {
                $this->sendAdminAlert(
                    'newip:' . $userId,
                    3600,
                    'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_NEWIP_SUBJECT',
                    'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_NEWIP_BODY',
                    [],
                    [$name, $ip, '{when}']
                );
            }
        } catch (\Throwable) {
            // Never let the protection break a login.
        }
    }

    /**
     * Before the administrator application does any work: refuse a locked
     * address and enforce the login speed limit. A storage or logic problem
     * never blocks (fail open); the blocking itself happens outside the try.
     */
    private function adminLoginGate($app): void
    {
        $retry = 0;

        try {
            $cfg = AdminProtectConfig::fromArray($this->params->toArray());

            if (!$cfg->lockoutEnabled && $cfg->ratePerMinute <= 0) {
                return;
            }

            $client = $this->clientIp();
            $now    = time();
            $store  = $this->adminStore();
            $known  = KnownIps::isAdminAddress($store, $client->ip, $this->adminSalt(), $now);
            $ranges = $this->cloudflareRanges();
            $prox   = $this->trustedProxies();
            $ok     = true;   // reserved for the stored real-IP verdict of the component (C4); shared and proxy addresses are already handled by the policy

            $decision = (new LockoutPolicy($cfg, $store))->decide($client, $ranges, $prox, $ok, $now, $known);

            if ($decision->state === LockDecision::OBSERVE) {
                $this->logAdminEvent('OBSERVE', 'lockout', $decision->reason, $decision->retryAfter, $now);
            }

            if ($decision->blocks()) {
                $this->logAdminEvent('BLOCK', 'lockout', 'locked', $decision->retryAfter, $now);
                $retry = max(1, $decision->retryAfter);
            } elseif ($cfg->ratePerMinute > 0 && $this->isLoginAttempt($app)) {
                $rate = LoginRateLimit::hit($store, $client->ip, $cfg->ratePerMinute, $now);

                if ($rate['over'] && (!IpAllowList::isSafeToAutoAdd($client, $ranges, $prox) || !$ok)) {
                    $this->logAdminEvent('OBSERVE', 'login_rate', 'not_enforceable', $rate['retryAfter'], $now);
                } elseif ($rate['over']) {
                    $this->logAdminEvent('BLOCK', 'login_rate', 'too_many', $rate['retryAfter'], $now);
                    $retry = max(1, $rate['retryAfter']);
                }
            }
        } catch (\Throwable) {
            return;
        }

        if ($retry > 0) {
            $this->handled = true;
            $this->blockAdminAccess($retry);
        }
    }

    /**
     * Administrator access key (A4) and address list (A5). Fails open on any problem; the
     * blocking itself happens outside the try. A fully trusted address never gets here; a
     * soft-trusted one (the administrator's own trusted address, seen through Cloudflare or a
     * listed proxy) passes when it is one single visitor.
     */
    private function adminAccessGate($app, bool $soft): void
    {
        $action = AccessGate::ALLOW;
        $reason = '';
        $cfg    = null;
        $now    = time();

        try {
            $cfg = AccessGateConfig::fromArray($this->params->toArray());

            if ($cfg->off()) {
                return;
            }

            // Rescue switch for someone with shell access (cli/admin_unlock.php --gate-off).
            if (is_file(JPATH_ROOT . '/cache/colorpack_shield/gate.off')) {
                return;
            }

            $client      = $this->clientIp();
            $ranges      = $this->cloudflareRanges();
            $prox        = $this->trustedProxies();
            $enforceable = IpAllowList::isSafeToAutoAdd($client, $ranges, $prox);

            if ($soft && $enforceable) {
                return;
            }

            $listed = $cfg->ipActive && $enforceable && CidrMatcher::matchesAny($client->ip, $cfg->ipList);
            $cookie = $_COOKIE[AccessGate::COOKIE] ?? null;
            $given  = $_GET[AccessGate::PARAM] ?? null;
            $d      = AccessGate::decide(
                $cfg,
                \is_string($cookie) ? $cookie : null,
                \is_string($given) ? $given : null,
                $enforceable,
                $listed,
                (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''),
                (string) $app->get('secret', ''),
                $now
            );
            $action = $d['action'];
            $reason = $d['reason'];
        } catch (\Throwable) {
            return;
        }

        if ($action === AccessGate::OBSERVE) {
            $this->logGate('OBSERVE', $reason, $now);

            return;
        }

        if ($action === AccessGate::EXCHANGE) {
            $this->handled = true;
            $this->issueGateCookie($app, $cfg, $now);
            $this->redirectCleanly($app);
        }

        if ($action === AccessGate::DENY) {
            $this->handled = true;
            $this->logGate('BLOCK', $reason, $now);
            $this->respondNotFound($app);
        }
    }

    /** One log line per minute for the whole gate, however many scanners knock. */
    private function logGate(string $level, string $reason, int $now): void
    {
        try {
            if (!AlertThrottle::claim($this->adminStore(), 'log:gate:' . $level . ':' . $reason, $now, 60)['send']) {
                return;
            }

            $this->writeLog(sprintf('%s client=administrator kind=gate reason=%s ip=%s uri=%s', $level, $reason, $this->logIp(), $this->pathForLog((string) ($_SERVER['REQUEST_URI'] ?? '-'))));
        } catch (\Throwable) {
            // Logging problems never decide anything.
        }
    }

    /** The access cookie: signed, HttpOnly, Secure on HTTPS, SameSite=Lax, limited to the administrator path. */
    private function issueGateCookie($app, AccessGateConfig $cfg, int $now): void
    {
        $expiry = $now + $cfg->cookieHours * 3600;
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/administrator/index.php');
        $path   = str_starts_with($script, '/') ? rtrim(\dirname($script), '/\\') : '';

        $this->sendGateCookie(AccessGate::cookieValue((string) $app->get('secret', ''), $cfg->key, (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), $expiry), [
            'expires'  => $expiry,
            'path'     => $path === '' ? '/' : $path,
            'secure'   => $app->isSSLConnection(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * @param  array<string,mixed>  $options
     */
    private function sendGateCookie(string $value, array $options): void
    {
        if (self::$cookieSender !== null) {
            (self::$cookieSender)($value, $options);

            return;
        }

        setcookie(AccessGate::COOKIE, $value, $options);
    }

    /** Back to the same page without the key, so it does not stay in the address bar, the history or a Referer. */
    private function redirectCleanly($app): void
    {
        $app->setHeader('status', '303 See Other', true);
        $app->setHeader('Location', AccessGate::cleanUri((string) ($_SERVER['REQUEST_URI'] ?? '/')), true);
        $app->setHeader('Cache-Control', 'no-store', true);
        $app->setHeader('Referrer-Policy', 'no-referrer', true);
        $app->sendHeaders();
        $app->close();
    }

    /** As if there were nothing at this address. */
    private function respondNotFound($app): void
    {
        $app->setHeader('status', '404 Not Found', true);
        $app->setHeader('Content-Type', 'text/html; charset=utf-8', true);
        $app->setHeader('Cache-Control', 'no-store', true);
        $app->sendHeaders();

        echo "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";
        $app->close();
    }

    /** Is this request an attempt to log in to the administrator (a POST of the login form)? */
    private function isLoginAttempt($app): bool
    {
        return ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
            && $this->isLoginTask((string) $app->getInput()->getCmd('task', ''));
    }

    /**
     * Joomla lower-cases the task and takes the part after the last dot, so "LOGIN", "Login" and
     * "display.login" all run the login: compare the same way.
     */
    private function isLoginTask(string $task): bool
    {
        $task = strtolower($task);
        $pos  = strrpos($task, '.');

        return ($pos === false ? $task : substr($task, $pos + 1)) === 'login';
    }

    private function adminStore(): FileStateStore
    {
        return $this->adminStore ??= new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/admin');
    }

    /** A stable secret salt for the stored address fingerprints; '' (nothing remembered) without a site secret. */
    private function adminSalt(): string
    {
        $secret = (string) ($this->getApplication()?->get('secret', '') ?? '');

        return $secret === '' ? '' : hash_hmac('sha256', 'colorpack_shield-admin-salt', $secret);
    }

    /**
     * One log line per kind and reason per address per minute, so a hammering
     * attacker cannot flood the log through the protection itself.
     */
    private function logAdminEvent(string $level, string $kind, string $reason, int $retry, int $now): void
    {
        $bucket = LockoutPolicy::bucket($this->clientIp()->ip) ?? 'unknown';

        if (!AlertThrottle::claim($this->adminStore(), 'log:' . $kind . ':' . $reason . ':' . $bucket, $now, 60)['send']) {
            return;
        }

        $this->writeLog(sprintf(
            '%s client=administrator kind=%s reason=%s retry=%d ip=%s uri=%s',
            $level,
            $kind,
            $reason,
            $retry,
            $this->logIp(),
            $this->pathForLog((string) ($_SERVER['REQUEST_URI'] ?? '-'))
        ));
    }

    /** Refuse a locked address: 429 with Retry-After and a neutral message (no hint about user names). */
    private function blockAdminAccess(int $retryAfter): void
    {
        $app = $this->getApplication();

        $app->setHeader('status', '429 Too Many Requests', true);
        $app->setHeader('Retry-After', (string) $retryAfter, true);
        $app->setHeader('Content-Type', 'text/plain; charset=utf-8', true);
        $app->sendHeaders();

        echo 'Too many attempts. Please try again later.';
        $app->close();
    }

    /**
     * Remember the groups a user has before a save, so that {@see onUserAfterSave()}
     * can tell whether somebody was just given Super User powers.
     */
    public function onUserBeforeSave(Event $event): void
    {
        try {
            $old = $event->getArgument('subject') ?? $event->getArgument(0);

            if (\is_array($old) && (int) ($old['id'] ?? 0) > 0) {
                $this->groupsBefore[(int) $old['id']] = array_values(array_map('intval', array_values((array) ($old['groups'] ?? []))));
            }
        } catch (\Throwable) {
            // Never let an alert break a save.
        }
    }

    /** A user was saved: a new Super User, or an existing user promoted to one, is reported at once. */
    public function onUserAfterSave(Event $event): void
    {
        try {
            $cfg = AdminProtectConfig::fromArray($this->params->toArray());

            if (!$cfg->alertNewAdmin || $this->killSwitchPath() !== null) {
                return;
            }

            $user   = $event->getArgument('subject') ?? $event->getArgument(0);
            $isNew  = (bool) ($event->getArgument('isNew') ?? $event->getArgument(1));
            $result = $event->getArgument('savingResult') ?? $event->getArgument(2);

            if (!\is_array($user) || $result === false) {
                return;
            }

            $id     = (int) ($user['id'] ?? 0);
            $groups = isset($user['groups']) && \is_array($user['groups']) ? $user['groups'] : null;
            // An existing user whose groups before the save are unknown (the before-event did not reach us) is skipped: guessing would report every ordinary save of a Super User.
            $known  = $isNew || \array_key_exists($id, $this->groupsBefore);
            $before = $isNew ? null : ($this->groupsBefore[$id] ?? null);
            unset($this->groupsBefore[$id]);

            if (!$known) {
                return;
            }

            $kind = AdminChangeDetector::change($before, $groups, $isNew, fn (int $g): bool => $this->isSuperGroup($g));

            if ($kind === null) {
                return;
            }

            $actor = $this->getApplication()?->getIdentity();

            $this->sendAdminAlert(
                'newadmin:' . $id,
                300,
                'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_NEWADMIN_SUBJECT',
                $kind === AdminChangeDetector::CREATED ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_NEWADMIN_BODY_CREATED' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_NEWADMIN_BODY_PROMOTED',
                [],
                [
                    (string) ($user['username'] ?? ''),
                    (string) $id,
                    implode(', ', array_map('intval', array_values($groups ?? []))),
                    (string) ($actor !== null && (int) ($actor->id ?? 0) > 0 ? ($actor->username ?? '') . ' (#' . (int) $actor->id . ')' : '-'),
                    $this->clientIp()->ip !== '' ? $this->clientIp()->ip : '-',
                    '{when}',
                ]
            );
        } catch (\Throwable) {
            // Never let an alert break a save.
        }
    }

    /** A group gives Super User powers when it is allowed core.admin; group 8 is always one. */
    private function isSuperGroup(int $groupId): bool
    {
        if ($groupId === 8) {
            return true;
        }

        try {
            return class_exists(\Joomla\CMS\Access\Access::class) && (bool) \Joomla\CMS\Access\Access::checkGroup($groupId, 'core.admin');
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Mail one administrator alert, at most once per $key per $interval seconds
     * (fail-closed: when the throttle cannot be used nothing is sent), to the alert
     * address or, failing that, the site's mail-from address. Everything that comes
     * from a request is cut to one short printable line first. Never throws.
     *
     * @param  string[]  $subjectArgs  after the site name
     * @param  string[]  $bodyArgs     after the site name; '{held}' = alerts held back since the last mail, '{when}' = now (UTC)
     */
    private function sendAdminAlert(string $key, int $interval, string $subjectKey, string $bodyKey, array $subjectArgs, array $bodyArgs): void
    {
        try {
            $now   = time();
            $claim = AlertThrottle::claim($this->adminStore(), $key, $now, $interval);

            if (!$claim['send']) {
                return;
            }

            $app = $this->getApplication();
            $to  = trim((string) $this->params->get('alert_email', ''));

            if ($to === '') {
                $to = trim((string) ($app?->get('mailfrom', '') ?? ''));
            }

            if ($to === '') {
                return;
            }

            $clean = static fn (string $v): string => substr(preg_replace('/[^\P{C}\t]|[\r\n]+/u', ' ', $v) ?? '', 0, 200);
            $site  = $clean((string) ($app?->get('sitename', '') ?? ''));
            $fill  = static fn (string $v): string => $v === '{held}' ? (string) $claim['suppressed'] : ($v === '{when}' ? gmdate('Y-m-d H:i:s', $now) . ' UTC' : $v);
            $args  = array_map($clean, array_map($fill, $bodyArgs));

            $sent = KillSwitchAlert::send(
                $to,
                Text::sprintf($subjectKey, $site, ...array_map($clean, $subjectArgs)),
                Text::sprintf($bodyKey, $site, ...$args)
            );

            $this->writeLog(sprintf('ALERT client=administrator kind=%s sent=%d', explode(':', $key)[0], $sent ? 1 : 0));
        } catch (\Throwable) {
            // An alert must never take the site down.
        }
    }

    /**
     * Log detect-only hits: at most three per request, and (with APCu) each
     * rule+header+IP at most once a minute, so a scanner cannot flood the log.
     *
     * @param  WafResult[]  $logged
     */
    private function logDetections(string $client, array $logged, ?string $uri = null): void
    {
        $written = 0;

        foreach ($logged as $hit) {
            if ($written >= 3) {
                break;
            }

            if (ApcuRateStore::isAvailable()) {
                $key = 'cps_dl_' . md5($hit->rule . '|' . $hit->key . '|' . $this->clientIp()->ip);

                if (!apcu_add($key, 1, 60)) {
                    continue;
                }
            }

            $this->writeLog(sprintf(
                'DETECT client=%s shield=%s rule=%s src=%s key=%s ip=%s uri=%s sample=%s',
                $client,
                $hit->shield,
                $hit->rule,
                $hit->source,
                $hit->key,
                $this->logIp(),
                $uri ?? $_SERVER['REQUEST_URI'] ?? '-',
                $hit->sample
            ));

            $written++;
        }
    }

    /**
     * The visitor IP, resolved once per request. A forwarding header such as
     * CF-Connecting-IP is believed only when the connecting hop is Cloudflare
     * (see ClientIpResolver), so a direct hit on the origin cannot spoof it.
     */
    private function clientIp(): ClientIp
    {
        if ($this->clientIp !== null) {
            return $this->clientIp;
        }

        $resolver = new ClientIpResolver(
            $this->cloudflareRanges(),
            $this->trustedProxies(),
            (int) $this->params->get('trust_cloudflare', 1) === 1
        );

        $this->clientIp = $resolver->resolve($_SERVER);

        // Optional: make the resolved IP visible to Joomla core and other
        // extensions too. Off by default; the original is kept for diagnostics.
        if (
            (int) $this->params->get('override_remote_addr', 0) === 1
            && $this->clientIp->ip !== ''
            && $this->clientIp->ip !== ($_SERVER['REMOTE_ADDR'] ?? '')
        ) {
            $_SERVER['COLORPACK_SHIELD_ORIGINAL_REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SERVER['REMOTE_ADDR']                          = $this->clientIp->ip;
        }

        return $this->clientIp;
    }

    /**
     * Proxy self-test endpoint (AUDIT.md N1). A request carrying a valid,
     * short-lived probe token (see ProbeToken; only someone who can read the
     * site secret can make one) gets a JSON report of what actually reached
     * PHP, and the request ends. Anything else falls through untouched.
     */
    private function handleProbe($app): void
    {
        $token = (string) ($_SERVER['HTTP_X_COLORPACK_PROBE'] ?? '');

        if ($token === '' || !ProbeToken::verify((string) $app->get('secret', ''), $token, time())) {
            return;
        }

        $client = $this->clientIp();
        $report = ProxyProbe::report(
            $_SERVER,
            (string) ($_SERVER['COLORPACK_SHIELD_ORIGINAL_REMOTE_ADDR'] ?? $_SERVER['REMOTE_ADDR'] ?? ''),
            $this->trustedProxies(),
            $client
        );

        $app->setHeader('status', '200 OK', true);
        $app->setHeader('Content-Type', 'application/json; charset=utf-8', true);
        $app->setHeader('Cache-Control', 'no-store', true);
        $app->sendHeaders();

        echo json_encode($report);
        $app->close();
    }

    /**
     * @return string[]
     */
    private function cloudflareRanges(): array
    {
        if ($this->cfRanges === null) {
            // A refreshed list is believed only with a valid signature made
            // under a key derived from the site secret (AUDIT.md C2).
            $secret = (string) ($this->getApplication()?->get('secret', '') ?? '');

            $this->cfRanges = CloudflareRanges::load(
                CloudflareRanges::defaultPath(JPATH_ROOT),
                CloudflareRanges::deriveKey($secret)
            );
        }

        return $this->cfRanges;
    }

    /**
     * @return string[]
     */
    private function trustedProxies(): array
    {
        return $this->parseList((string) $this->params->get('trusted_proxies', ''));
    }

    /**
     * Path of the emergency kill-switch file, or null. Checked once per request.
     */
    private function killSwitchPath(): ?string
    {
        if (!$this->killSwitchChecked) {
            $this->killSwitchChecked = true;

            $hit = KillSwitch::locate(
                [JPATH_ROOT, JPATH_ADMINISTRATOR],
                trim((string) $this->params->get('killswitch_token', ''))
            );

            $this->killSwitchFile = $hit['active'];

            // A switch file the admin did not expect is exactly what an
            // attacker with file-write access would create: say so (C4).
            if ($hit['present'] !== null) {
                $this->alertKillSwitch($hit['present'], $hit['active'] !== null);
            }
        }

        return $this->killSwitchFile;
    }

    /**
     * Mail the admin that the kill-switch file exists — once when it appears
     * (or changes), then as a daily reminder. Never throws, never blocks.
     */
    private function alertKillSwitch(string $path, bool $active): void
    {
        try {
            $mtime = (int) @filemtime($path);

            if (!KillSwitchAlert::claim(JPATH_CACHE . '/colorpack_shield/killswitch-alert.json', $path, $mtime, $active ? 'active' : 'ignored', time())) {
                return;
            }

            $app = $this->getApplication();
            $to  = trim((string) $this->params->get('alert_email', ''));

            if ($to === '') {
                $to = trim((string) ($app?->get('mailfrom', '') ?? ''));
            }

            if ($to === '') {
                return;
            }

            $site = (string) ($app?->get('sitename', '') ?? '');
            $when = gmdate('Y-m-d H:i:s', $mtime) . ' UTC';

            KillSwitchAlert::send(
                $to,
                Text::sprintf($active ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_SUBJECT_ACTIVE' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_SUBJECT_IGNORED', $site),
                Text::sprintf($active ? 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_BODY_ACTIVE' : 'PLG_SYSTEM_COLORPACK_SHIELD_MAIL_KS_BODY_IGNORED', $site, $path, $when, (string) ($_SERVER['REMOTE_ADDR'] ?? '-'))
            );
        } catch (\Throwable $e) {
            // An alert must never take the site down.
        }
    }

    /**
     * Is the visitor on the trusted-IP list?
     */
    private function isTrustedIp(): bool
    {
        $raw = (string) $this->params->get('allow_ips', '');

        if (trim($raw) === '') {
            return false;
        }

        return IpAllowList::fromText($raw)->matches($this->clientIp()->ip);
    }

    /**
     * IP text for log lines, with a hint when it did not come straight from
     * REMOTE_ADDR or when a CF-Connecting-IP header was refused.
     */
    private function logIp(): string
    {
        $c = $this->clientIp();

        if ($c->ip === '') {
            return '-';
        }

        $out = $c->ip;

        if ($c->via !== ClientIp::VIA_DIRECT) {
            $out .= ' via=' . $c->via;
        }

        if ($c->headerIgnored) {
            $out .= ' cfheader=ignored';
        }

        return $out;
    }

    /**
     * Inspect the URL path (PLAN-WAF-PATH-P2.md). Writes detect-only findings to
     * the log and ends the request on a blocking one.
     *
     * @return bool  true when the request was blocked
     */
    private function pathStep(string $client): bool
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

        $found = $this->getPathEngine()->inspectAll($client, new RequestData($sources));
        $shown = $this->pathForLog($uri);

        $this->logDetections($client, $found['logged'], $shown);

        if ($found['block'] === null) {
            return false;
        }

        $this->block($client, $found['block'], $shown);

        return true;
    }

    /** The request path for the log: never the query string, bounded, one line. */
    private function pathForLog(string $uri): string
    {
        $path = substr($uri, 0, strcspn($uri, '?#'));

        return \strlen($path) > 200 ? substr($path, 0, 200) . '…' : $path;
    }

    private function getPathEngine(): WafEngine
    {
        if ($this->pathEngine !== null) {
            return $this->pathEngine;
        }

        $covered = [];

        foreach (['site' => 'cover_site', 'administrator' => 'cover_admin', 'api' => 'cover_api'] as $client => $param) {
            if ((int) $this->params->get($param, 1)) {
                $covered[] = $client;
            }
        }

        $mode  = (string) $this->params->get('path_mode', 'recommended');
        $probe = (string) $this->params->get('path_probe_mode', 'log');
        $tools = $this->parseList((string) $this->params->get('path_tools_exempt', implode("\n", PathRules::DEFAULT_TOOLS_EXEMPT)));

        $shield = new PathShield(
            \in_array($mode, ['recommended', 'log', 'block'], true) ? $mode : 'recommended',
            \in_array($probe, ['off', 'log', 'block', 'ban'], true) ? $probe : 'log',
            $this->parseLines((string) $this->params->get('path_allow', '')),
            $this->parseLines((string) $this->params->get('path_extra_deny', '')),
            $tools
        );

        return $this->pathEngine = new WafEngine([$shield], [$shield->id() => $covered]);
    }

    /**
     * Lazily assemble the engine from plugin params.
     */
    private function getEngine(): WafEngine
    {
        if ($this->engine !== null) {
            return $this->engine;
        }

        $covered = [];

        if ((int) $this->params->get('cover_site', 1)) {
            $covered[] = 'site';
        }

        if ((int) $this->params->get('cover_admin', 1)) {
            $covered[] = 'administrator';
        }

        if ((int) $this->params->get('cover_api', 1)) {
            $covered[] = 'api';
        }

        $shields = [];
        $scopes  = [];

        foreach ([new SqliShield(), new XssShield(), new LfiShield(), new RfiShield()] as $shield) {
            if ((int) $this->params->get('shield_' . $shield->id(), 1)) {
                $shields[]              = $shield;
                $scopes[$shield->id()]  = $covered;
            }
        }

        // Header inspection is independent of the four parameter shields.
        if ((int) $this->params->get('header_scan', 1)) {
            $mode = (string) $this->params->get('header_mode', 'default');
            $head = new HeaderShield(\in_array($mode, ['default', 'log', 'block'], true) ? $mode : 'default');

            $shields[]            = $head;
            $scopes[$head->id()]  = $covered;
        }

        return $this->engine = new WafEngine($shields, $scopes);
    }

    /**
     * Read php://input once and cache it. Bounded up front so a huge body can
     * never be pulled fully into memory — BodyParser only ever needs the head.
     */
    private function readRawBody(): string
    {
        if ($this->rawBody !== null) {
            return $this->rawBody;
        }

        $raw = file_get_contents('php://input', false, null, 0, BodyParser::MAX_BODY_BYTES + 1);

        return $this->rawBody = ($raw === false ? '' : $raw);
    }

    /**
     * One entry per line, kept as typed (regular expressions may contain commas).
     *
     * @return string[]
     */
    private function parseLines(string $raw): array
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

    /**
     * Split a comma/newline list into trimmed, lowercased, non-empty tokens.
     *
     * @return string[]
     */
    private function parseList(string $raw): array
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

    private function isAllowlisted(string $option): bool
    {
        $raw = (string) $this->params->get('admin_allowlist', 'com_colorpack_shield');

        foreach (preg_split('/[\r\n,]+/', $raw) ?: [] as $entry) {
            $entry = trim($entry);

            if ($entry !== '' && strcasecmp($entry, $option) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Log the hit and terminate the request with 403.
     */
    private function block(string $client, WafResult $result, ?string $uri = null): void
    {
        $ip = $this->logIp();

        $this->writeLog(sprintf(
            'BLOCK client=%s shield=%s rule=%s src=%s key=%s ip=%s uri=%s sample=%s',
            $client,
            $result->shield,
            $result->rule,
            $result->source,
            $result->key,
            $ip,
            $uri ?? $_SERVER['REQUEST_URI'] ?? '-',
            $result->sample
        ));

        if ($result->mode === WafResult::MODE_BAN) {
            $this->armBan($result->rule);
        }

        $this->sendForbidden();
    }

    /**
     * A MODE_BAN finding does not just end this one request - the address itself is
     * persisted as banned (see {@see TargetedBanPolicy}) for {@see bannedUntil()} to
     * reject on every later request, until the ban expires.
     */
    private function armBan(string $reason): void
    {
        $ip = $this->clientIp()->ip;

        if ($ip === '') {
            return;
        }

        $hours = max(1, (int) $this->params->get('path_probe_ban_hours', 24));
        $until = (new TargetedBanPolicy($this->banStore()))->ban($ip, time(), $hours * 3600, $reason);

        if ($until > 0) {
            $this->writeLog(sprintf('LOCK client=site kind=ip_ban ip=%s until=%d reason=%s', $this->logIp(), $until, $reason));
        }
    }

    /**
     * @return int|null  unix time the ban lifts, or null when this address is not banned
     *                    (including when the "ban" probe mode is not the one currently in effect)
     */
    private function bannedUntil(string $ip): ?int
    {
        if ($ip === '' || !(int) $this->params->get('path_scan', 1)) {
            return null;
        }

        if ((string) $this->params->get('path_probe_mode', 'log') !== 'ban') {
            return null;
        }

        $check = (new TargetedBanPolicy($this->banStore()))->check($ip, time());

        return $check['banned'] ? $check['until'] : null;
    }

    /** Log and reject a request from an address already under a targeted-attack ban. */
    private function blockBanned(string $client, int $until): void
    {
        $this->writeLog(sprintf(
            'BLOCK client=%s shield=path rule=ip_banned ip=%s until=%d uri=%s',
            $client,
            $this->logIp(),
            $until,
            $_SERVER['REQUEST_URI'] ?? '-'
        ));

        $this->sendForbidden();
    }

    private function banStore(): FileStateStore
    {
        return $this->banStore ??= new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/bans');
    }

    /**
     * Log a blocked upload and terminate the request with 403.
     */
    private function blockUpload(string $client, UploadThreat $threat): void
    {
        $this->writeLog(sprintf(
            'BLOCK client=%s kind=upload reason=%s file=%s detail=%s ip=%s uri=%s',
            $client,
            $threat->reason,
            $threat->file,
            $threat->detail,
            $this->logIp(),
            $_SERVER['REQUEST_URI'] ?? '-'
        ));

        $this->sendForbidden();
    }

    /**
     * Apply the GeoIP allow/deny policy to the client IP.
     *
     * @return string|null  block-reason token, or null to allow
     */
    private function geoDecision(): ?string
    {
        $ip = $this->clientIp()->ip;

        if ($ip === '') {
            return null;
        }

        $policy = new GeoPolicy(
            (string) $this->params->get('geo_mode', 'deny'),
            $this->parseList((string) $this->params->get('geo_countries', '')),
            $this->parseList((string) $this->params->get('geo_allow_ips', '')),
            $this->parseList((string) $this->params->get('geo_deny_ips', '')),
            (int) $this->params->get('geo_unknown_allow', 1) === 1
        );

        $country = null;

        if ($policy->needsCountry()) {
            $lookup  = new CountryLookup((string) $this->params->get('geo_db_path', ''));
            $country = $lookup->country($ip);
        }

        return $policy->decide($ip, $country);
    }

    /**
     * Log a GeoIP block and terminate the request with 403.
     */
    private function blockGeo(string $client, string $reason): void
    {
        $this->writeLog(sprintf(
            'BLOCK client=%s kind=geo reason=%s ip=%s uri=%s',
            $client,
            $reason,
            $this->logIp(),
            $_SERVER['REQUEST_URI'] ?? '-'
        ));

        $this->sendForbidden();
    }

    /**
     * Run the per-IP rate limiter. Returns null when no usable counter store is
     * available (fail-open) so a flood is never worsened by a broken limiter.
     */
    private function rateDecision($app, string $client): ?RateVerdict
    {
        $ip = $this->clientIp()->ip;

        if ($ip === '' || !ApcuRateStore::isAvailable()) {
            return null;
        }

        $limiter = new RateLimiter(
            new ApcuRateStore(),
            (int) $this->params->get('rate_window', 60),
            (int) $this->params->get('rate_limit', 120),
            (int) $this->params->get('rate_ban_threshold', 5),
            (int) $this->params->get('rate_ban_window', 300),
            (int) $this->params->get('rate_ban_duration', 3600)
        );

        // Bucket per IP + app + component so one noisy endpoint can't exhaust
        // another's budget.
        $route = $client . ':' . (string) $app->getInput()->getCmd('option', '');

        return $limiter->decide(time(), $ip, $route);
    }

    /**
     * Log a rate-limit hit and terminate the request with 429 + Retry-After.
     */
    private function blockRate(string $client, RateVerdict $verdict): void
    {
        $this->writeLog(sprintf(
            'BLOCK client=%s kind=rate reason=%s retry=%d ip=%s uri=%s',
            $client,
            $verdict->reason,
            $verdict->retryAfter,
            $this->logIp(),
            $_SERVER['REQUEST_URI'] ?? '-'
        ));

        $app = $this->getApplication();

        if ((int) $this->params->get('block_silent', 0)) {
            $app->close();
        }

        $app->setHeader('status', '429 Too Many Requests', true);
        $app->setHeader('Retry-After', (string) $verdict->retryAfter, true);
        $app->setHeader('Content-Type', 'text/plain; charset=utf-8', true);
        $app->sendHeaders();

        echo 'Too Many Requests';
        $app->close();
    }

    /**
     * Emit the 403 response (or a silent close) and end the request.
     */
    private function sendForbidden(): void
    {
        $app = $this->getApplication();

        // "Block silent" hides that a WAF is present (recon-resistance).
        if ((int) $this->params->get('block_silent', 0)) {
            $app->close();
        }

        $app->setHeader('status', '403 Forbidden', true);
        $app->setHeader('Content-Type', 'text/plain; charset=utf-8', true);
        $app->sendHeaders();

        // Generic on purpose: the product name is not revealed to scanners.
        // What blocked the request is in the log (AUDIT.md C5).
        echo 'Forbidden';
        $app->close();
    }

    private function writeLog(string $message): void
    {
        if (!$this->logReady) {
            Log::addLogger(['text_file' => 'colorpack_shield.php'], Log::ALL, ['colorpack_shield']);
            $this->logReady = true;
        }

        // The access key must never reach a log, whatever line it would have been part of.
        $message = AccessGate::scrub($message, AccessGateConfig::fromArray($this->params->toArray())->key);

        // One event, one line: a hostile value must not be able to forge log lines.
        Log::add(preg_replace('/[\\x00-\\x1f\\x7f]/', '?', $message) ?? '', Log::WARNING, 'colorpack_shield');
    }
}
