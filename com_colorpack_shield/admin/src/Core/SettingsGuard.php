<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AdminProtectConfig;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Checks a settings change before it is saved, with the plugin's own rules (so the screen
 * says "this line is ignored" before saving, not after) and refuses what would lock the
 * saving administrator out (PLAN-ADMIN-COMPONENT.md §2, §7).
 *
 * Returns the cleaned parameters plus messages; the caller shows them and saves only when
 * there are no errors. Keys the component does not know are passed through untouched, so
 * nothing the plugin stores is lost by a save.
 */
final class SettingsGuard
{
    /** Text areas holding one address or range per line. */
    private const IP_LISTS = ['allow_ips', 'trusted_proxies', 'geo_allow_ips', 'geo_deny_ips', 'admin_ip_list'];

    /** Keys with a number range; the plugin clamps the same way. */
    private const RANGES = [
        'login_max_failures'   => [1, 100],
        'login_failure_window' => [60, 86400],
        'login_lock_minutes'   => [1, 1440],
        'login_lock_max_hours' => [1, 168],
        'login_rate_per_minute' => [0, 600],
        'mfa_grace_days'       => [0, 90],
        'gate_cookie_hours'    => [1, 168],
    ];

    public const MIN_TOKEN = 12;

    /**
     * @param  array<string,mixed>        $params       submitted plugin parameters
     * @param  (callable(array):bool)|null $wouldBlock  true when these settings would block the
     *                                                  saving administrator's own request
     * @param  array{ip:string,enforceable:bool}|null $visitor  the saving administrator's address and
     *                                                  whether it is one single visitor (not a CDN edge or private proxy)
     *
     * @return array{params:array<string,mixed>,errors:array<int,array{key:string,code:string,detail:string}>,warnings:array<int,array{key:string,code:string,detail:string}>}
     */
    public static function check(array $params, ?callable $wouldBlock = null, ?array $visitor = null): array
    {
        $errors   = [];
        $warnings = [];

        foreach (self::IP_LISTS as $key) {
            if (!isset($params[$key]) || !\is_string($params[$key]) || $params[$key] === '') {
                continue;
            }

            $list = IpAllowList::fromText($params[$key]);

            foreach ($list->invalid() as $line) {
                $errors[] = ['key' => $key, 'code' => 'invalid_line', 'detail' => self::shorten($line)];
            }

            if (\count($list->entries()) > IpAllowList::MAX_ENTRIES) {
                $errors[] = ['key' => $key, 'code' => 'too_many', 'detail' => (string) IpAllowList::MAX_ENTRIES];
            }
        }

        $token = $params['killswitch_token'] ?? '';

        if (\is_string($token) && $token !== '' && mb_strlen($token) < self::MIN_TOKEN) {
            $errors[] = ['key' => 'killswitch_token', 'code' => 'token_short', 'detail' => (string) self::MIN_TOKEN];
        }

        $email = $params['alert_email'] ?? '';

        if (\is_string($email) && $email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = ['key' => 'alert_email', 'code' => 'email_invalid', 'detail' => ''];
        }

        foreach (self::RANGES as $key => [$min, $max]) {
            if (!isset($params[$key]) || $params[$key] === '') {
                continue;
            }

            if (!is_numeric($params[$key])) {
                $errors[] = ['key' => $key, 'code' => 'not_number', 'detail' => ''];

                continue;
            }

            $n = (int) $params[$key];

            if ($n < $min || $n > $max) {
                $warnings[] = ['key' => $key, 'code' => 'adjusted', 'detail' => $min . '–' . $max];
                $params[$key] = max($min, min($max, $n));
            }
        }

        if (($params['mfa_enforce'] ?? 'off') === AdminProtectConfig::MFA_ENFORCE && trim((string) ($params['alert_email'] ?? '')) === '') {
            $warnings[] = ['key' => 'alert_email', 'code' => 'enforce_without_email', 'detail' => ''];
        }

        $key = $params['gate_key'] ?? '';

        if (\is_string($key) && $key !== '' && !AccessGateConfig::fromArray(['gate_enabled' => '1', 'gate_key' => $key])->gateActive) {
            $errors[] = ['key' => 'gate_key', 'code' => 'gate_key_invalid', 'detail' => (string) AccessGateConfig::MIN_KEY];
        }

        $cfg = AccessGateConfig::fromArray($params);

        if ($cfg->keyMissing) {
            $errors[] = ['key' => 'gate_key', 'code' => 'gate_key_invalid', 'detail' => (string) AccessGateConfig::MIN_KEY];
        }

        if ($cfg->listEmpty) {
            $errors[] = ['key' => 'admin_ip_list', 'code' => 'admin_list_empty', 'detail' => ''];
        }

        if ($cfg->ipActive && $visitor !== null && $visitor['ip'] !== '') {
            $listed = IpAllowList::fromText((string) ($params['admin_ip_list'] ?? ''))->matches($visitor['ip']);

            if (!$visitor['enforceable']) {
                // Every visitor would look the same to the plugin: the list will only be observed.
                $warnings[] = ['key' => 'admin_ip_list', 'code' => 'admin_ip_unenforceable', 'detail' => ''];
            } elseif (!$listed && !$cfg->gateActive) {
                $errors[] = ['key' => 'admin_ip_list', 'code' => 'admin_not_in_list', 'detail' => ''];
            }
        }

        if ($wouldBlock !== null && $errors === [] && $wouldBlock($params)) {
            $errors[] = ['key' => 'path_extra_deny', 'code' => 'self_lockout', 'detail' => ''];
        }

        return ['params' => $params, 'errors' => $errors, 'warnings' => $warnings];
    }

    private static function shorten(string $s): string
    {
        $s = preg_replace('/[\x00-\x1f\x7f]/', '?', $s) ?? '';

        return mb_substr($s, 0, 60);
    }
}
