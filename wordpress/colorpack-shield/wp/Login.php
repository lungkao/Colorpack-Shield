<?php

namespace Colorpack\Shield\Wp;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminProtectConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AlertThrottle;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockoutPolicy;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LockDecision;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\LoginRateLimit;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\TrustPolicy;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\BurstWindow;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\EventQueue;

defined('ABSPATH') || die;

/** Login lock-out and speed limit on wp-login.php and XML-RPC, counted per visitor address. */
final class Login
{
    public static function hooks(): void
    {
        add_filter('authenticate', [self::class, 'gate'], 1, 3);
        add_action('wp_login_failed', [self::class, 'failed'], 10, 1);
        add_action('wp_login', [self::class, 'succeeded'], 10, 0);
    }

    private static function config(): AdminProtectConfig
    {
        return AdminProtectConfig::fromArray(Settings::all());
    }

    private static function store(): \Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore
    {
        return new \Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore(Settings::stateDir('admin'));
    }

    private static function exempt(): bool
    {
        return TrustPolicy::decide(Guard::ip(), Guard::isListed()) !== TrustPolicy::NONE;
    }

    /** Refuse a locked or too-fast address before the password is even looked at. */
    public static function gate(mixed $user, mixed $username = '', mixed $password = ''): mixed
    {
        try {
            $cfg = self::config();

            if (!$cfg->lockoutEnabled || $username === '' || self::exempt()) {
                return $user;
            }

            $ip   = Guard::ip();
            $now  = time();
            $lock = (new LockoutPolicy($cfg, self::store()))->decide($ip, [], [], $ip->via === ClientIp::VIA_DIRECT || $ip->via === ClientIp::VIA_CLOUDFLARE, $now);

            if ($lock->state === LockDecision::LOCKED) {
                Logger::add(sprintf('BLOCK client=administrator kind=login_locked ip=%s retry=%d', Guard::logIp(), $lock->retryAfter));

                return new \WP_Error('colorpack_locked', __('Too many failed attempts. Try again later.', 'colorpack-shield'));
            }

            $rate = LoginRateLimit::hit(self::store(), $ip->ip, $cfg->ratePerMinute, $now);

            if ($rate['over']) {
                Logger::add(sprintf('BLOCK client=administrator kind=login_rate ip=%s', Guard::logIp()));

                return new \WP_Error('colorpack_rate', __('Too many attempts. Wait a minute and try again.', 'colorpack-shield'));
            }
        } catch (\Throwable) {
            // The protection must never break a login.
        }

        return $user;
    }

    public static function failed(string $username): void
    {
        try {
            $cfg = self::config();

            if (!$cfg->lockoutEnabled || self::exempt()) {
                return;
            }

            $now    = time();
            $result = (new LockoutPolicy($cfg, self::store()))->recordFailure(Guard::ip()->ip, $username, $now);

            if (!$result['newLock']) {
                return;
            }

            Logger::add(sprintf('LOCK client=administrator ip=%s until=%d strikes=%d seconds=%d', Guard::logIp(), $result['lockUntil'], $result['strikes'], $result['lockUntil'] - $now));
            self::queueEvents($now);
        } catch (\Throwable) {
        }
    }

    public static function succeeded(): void
    {
        try {
            if (Guard::ip()->ip !== '') {
                (new LockoutPolicy(self::config(), self::store()))->recordSuccess(Guard::ip()->ip, time());
            }
        } catch (\Throwable) {
        }
    }

    /**
     * Every new lock-out is a `lockout` event; 3 or more inside 10 minutes also raises one `login_burst`
     * (the only severity that alerts the team). Counts and fixed Thai sentences only - never a username or address.
     */
    private static function queueEvents(int $now): void
    {
        if (!Settings::get('site_manager_enabled')) {
            return;
        }

        $store = Reporter::store();
        $queue = new EventQueue($store);
        $queue->enqueue(['id' => gmdate('Y-m-d\TH:i:s\Z', $now) . '-lockout-' . bin2hex(random_bytes(4)), 'at' => gmdate('Y-m-d\TH:i:s\Z', $now), 'type' => 'lockout', 'severity' => 'warning', 'count' => 1, 'detail' => 'ล็อกบัญชีแล้ว 1 บัญชี'], $now);

        $burst = (new BurstWindow($store))->recordLock($now);

        if ($burst >= 3 && AlertThrottle::claim($store, 'site_manager_login_burst', $now, 600)['send']) {
            $queue->enqueue(['id' => gmdate('Y-m-d\TH:i:s\Z', $now) . '-login_burst-' . bin2hex(random_bytes(4)), 'at' => gmdate('Y-m-d\TH:i:s\Z', $now), 'type' => 'login_burst', 'severity' => 'high', 'count' => $burst, 'detail' => sprintf('มีบัญชีถูกล็อกแล้ว %d บัญชีใน 10 นาที', $burst)], $now);
        }
    }
}
