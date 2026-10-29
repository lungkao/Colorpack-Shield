<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What each Quick-setup step would change, as a plain patch of plugin parameters plus the
 * reason. Pure: it decides nothing by itself, the wizard shows the patch (old → new) and
 * saves it only when the administrator confirms the step.
 */
final class SetupAdvisor
{
    /**
     * Step 1 — real visitor IP. The probe verdict decides; without a usable verdict the step
     * changes nothing and says to run the test first.
     *
     * @param  array<string,mixed>  $current
     *
     * @return array{patch:array<string,mixed>,advice:string}
     */
    public static function realIp(?string $verdict, bool $behindCloudflare, array $current): array
    {
        $patch = [];

        switch ($verdict) {
            case 'safe':
            case 'no_proxy':
                if ($behindCloudflare && !self::on($current['trust_cloudflare'] ?? 1)) {
                    $patch['trust_cloudflare'] = 1;
                }

                return ['patch' => $patch, 'advice' => $verdict];

            case 'spoofable':
                // The visitor address can be forged. Which setting fixes that depends on the
                // server in front (not guessable here), so nothing is changed: the wizard
                // shows the advice and the Network screen explains the options.
                return ['patch' => [], 'advice' => 'spoofable'];

            default:
                return ['patch' => [], 'advice' => 'untested'];
        }
    }

    /**
     * Step 2 — do not lock me out. Adds nothing about IPs (the plugin's own safe auto-add
     * handles the administrator's address); this step turns the safety features on.
     *
     * @param  array<string,mixed>  $current
     *
     * @return array{patch:array<string,mixed>,advice:string}
     */
    public static function safety(array $current, string $email): array
    {
        $patch = [];

        if (!self::on($current['auto_allow_admin'] ?? 1)) {
            $patch['auto_allow_admin'] = 1;
        }

        if (trim((string) ($current['alert_email'] ?? '')) === '' && $email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) !== false) {
            $patch['alert_email'] = $email;
        }

        if (!self::on($current['login_lockout'] ?? 1)) {
            $patch['login_lockout'] = 1;
        }

        return ['patch' => $patch, 'advice' => $patch === [] ? 'already' : 'changed'];
    }

    /**
     * Step 3 — start in log mode. Only ever lowers a block to log; never the other way.
     *
     * @param  array<string,mixed>  $current
     *
     * @return array{patch:array<string,mixed>,advice:string}
     */
    public static function logMode(array $current): array
    {
        $patch = [];

        if (($current['header_mode'] ?? 'default') === 'block') {
            $patch['header_mode'] = 'log';
        }

        if (($current['path_mode'] ?? 'recommended') === 'block') {
            $patch['path_mode'] = 'log';
        }

        if (($current['path_probe_mode'] ?? 'log') === 'block') {
            $patch['path_probe_mode'] = 'log';
        }

        return ['patch' => $patch, 'advice' => $patch === [] ? 'already' : 'changed'];
    }

    /**
     * Step 4 — the administrator access key (recommended for every site). Turns it on with a fresh
     * key; nothing when a key or an address list is already in force.
     *
     * @param  array<string,mixed>  $current
     *
     * @return array{patch:array<string,mixed>,advice:string}
     */
    public static function accessKey(array $current, string $newKey): array
    {
        if (AccessGateConfig::fromArray($current)->off() === false) {
            return ['patch' => [], 'advice' => 'already'];
        }

        // A key that is stored but switched off is reused (the person may already hold the link).
        $key = AccessGateConfig::fromArray(['gate_enabled' => '1', 'gate_key' => $current['gate_key'] ?? ''])->key;

        return ['patch' => ['gate_enabled' => 1, 'gate_key' => $key !== '' ? $key : $newKey], 'advice' => 'changed'];
    }

    private static function on(mixed $v): bool
    {
        return $v === true || $v === 1 || $v === '1' || $v === 'true';
    }
}
