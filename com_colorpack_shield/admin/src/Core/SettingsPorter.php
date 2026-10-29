<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Settings as a JSON file, and the strict reading of one. A secret never leaves in an export and
 * never comes in through an import; unknown keys, other products' files, odd shapes and big files
 * are refused with a reason code.
 */
final class SettingsPorter
{
    public const FORMAT    = 'colorpack-shield-settings';
    public const VERSION   = 1;
    public const MAX_BYTES = 65536;
    public const MAX_VALUE = 4000;

    /**
     * Never exported, never imported: the two secrets, and the settings that can lock people out
     * of a site (an address list or a gate belongs to ONE site and its administrators).
     */
    public const SECRET = ['killswitch_token', 'gate_key', 'gate_enabled', 'admin_ip_enforce', 'admin_ip_list'];

    /**
     * @param  array<string,mixed>  $params
     * @param  string[]             $known   names of the plugin's settings
     */
    public static function export(array $params, array $known, string $pluginVersion, int $now): string
    {
        $out = [];

        foreach ($known as $k) {
            if (\in_array($k, self::SECRET, true) || !\array_key_exists($k, $params)) {
                continue;
            }

            $out[$k] = $params[$k];
        }

        ksort($out);

        return (string) json_encode([
            'format'         => self::FORMAT,
            'version'        => self::VERSION,
            'plugin_version' => $pluginVersion,
            'exported_utc'   => gmdate('Y-m-d\TH:i:s\Z', $now),
            'not_included'   => self::SECRET,
            'params'         => $out,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }

    /**
     * @param  string[]  $known
     *
     * @return array{params:array<string,mixed>,error:string,ignored:string[]}
     *         error: '' | too_big | not_json | wrong_format | newer_version | no_params | bad_value
     */
    public static function import(string $json, array $known): array
    {
        $fail = static fn (string $code): array => ['params' => [], 'error' => $code, 'ignored' => []];

        if (\strlen($json) > self::MAX_BYTES) {
            return $fail('too_big');
        }

        $data = json_decode($json, true, 8);

        if (!\is_array($data)) {
            return $fail('not_json');
        }

        if (($data['format'] ?? null) !== self::FORMAT) {
            return $fail('wrong_format');
        }

        if (!\is_int($data['version'] ?? null) || $data['version'] > self::VERSION || $data['version'] < 1) {
            return $fail('newer_version');
        }

        if (!\is_array($data['params'] ?? null) || array_is_list($data['params']) && $data['params'] !== []) {
            return $fail('no_params');
        }

        $params  = [];
        $ignored = [];

        foreach ($data['params'] as $k => $v) {
            if (!\is_string($k) || !\in_array($k, $known, true) || \in_array($k, self::SECRET, true)) {
                $ignored[] = \is_string($k) ? mb_substr(preg_replace('/[^\x20-\x7e]/', '?', $k) ?? '', 0, 40) : '?';

                continue;
            }

            $clean = self::value($v);

            if ($clean === null) {
                return $fail('bad_value');
            }

            $params[$k] = $clean;
        }

        return ['params' => $params, 'error' => '', 'ignored' => $ignored];
    }

    /**
     * A setting is a short string, a number, a boolean (stored as "1"/"0") or a short list of those.
     *
     * @return string|int|string[]|null
     */
    private static function value(mixed $v): string|int|array|null
    {
        if (\is_bool($v)) {
            return $v ? '1' : '0';
        }

        if (\is_int($v)) {
            return $v;
        }

        if (\is_string($v)) {
            return mb_strlen($v) <= self::MAX_VALUE && preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $v) !== 1 ? $v : null;
        }

        if (\is_array($v) && array_is_list($v) && \count($v) <= 50) {
            $out = [];

            foreach ($v as $item) {
                if (!\is_string($item) && !\is_int($item) || \is_string($item) && mb_strlen($item) > 100) {
                    return null;
                }

                $out[] = (string) $item;
            }

            return $out;
        }

        return null;
    }
}
