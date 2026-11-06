<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Vulnerable;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns the Joomla Extensions Directory's Vulnerable Extensions List (the official VEL API feed, GPL) into
 * compact rules, and matches them against the extensions installed on this site. Pure: no Joomla, no network.
 *
 * The feed carries no exact extension identifier. A rule is keyed either by the element from the feed's
 * install_data (com_x, mod_x, or a plugin's element) or, failing that, by the normalised name from the title,
 * written "~name" (at least 5 characters, so a short name can never match something unrelated).
 * A "Live" item with no versions at all is reported for every installed version: the list says it is vulnerable.
 */
final class VelRules
{
    private const SEVERITY_RANK = ['critical' => 3, 'high' => 2, 'medium' => 1];

    /**
     * @param  array<int,array<string,mixed>>  $items  the feed's data.items
     *
     * @return array<int,array<string,mixed>>  id, title, key, intro, last, fixed, sev, url, live
     */
    public static function fromFeed(array $items): array
    {
        $rules = [];

        foreach ($items as $item) {
            $rule = \is_array($item) ? self::convert($item) : null;

            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    /**
     * @param  array<string,mixed>  $i
     *
     * @return array<string,mixed>|null  null when the item cannot be judged (resolved, but no fixed or affected version)
     */
    public static function convert(array $i): ?array
    {
        $id    = (string) ($i['id'] ?? '');
        $title = trim((string) ($i['title'] ?? ''));

        if ($id === '' || $title === '') {
            return null;
        }

        $parts   = array_map('trim', explode(',', $title));
        $name    = trim((string) preg_replace('/\s+v?\d+(?:\.\d+)+\s*$/', '', $parts[0]));
        $install = \is_array($i['install_data'] ?? null) ? $i['install_data'] : [];
        $norm    = self::normName($name);
        $key     = self::elementKey((string) ($install['name'] ?? '')) ?? (\strlen($norm) >= 5 ? '~' . $norm : null);

        if ($key === null) {
            return null;
        }

        $titleVersion = null;

        foreach (\array_slice($parts, 1, 2) as $p) {
            if (preg_match('/^v?(\d+(?:\.\d+){0,3})$/i', $p, $m)) {
                $titleVersion = $m[1];
                break;
            }
        }

        if ($titleVersion === null && preg_match('/\b(\d+\.\d+(?:\.\d+){0,2})\b/', $parts[0], $m)) {
            $titleVersion = $m[1];
        }

        $fixed = self::version($i['patch_version'] ?? null);
        $last  = self::version($i['vulnerable_version'] ?? null) ?? $titleVersion;
        $live  = (string) ($i['status'] ?? '') === '1';

        if (!$live && $fixed === null && $last === null) {
            return null;
        }

        $url = (string) ($i['update_notice'] ?? '') !== '' ? (string) $i['update_notice'] : ((string) ($i['jed'] ?? '') !== '' ? (string) $i['jed'] : 'https://extensions.joomla.org/vulnerable-extensions/');

        return [
            'id'    => $id,
            'title' => mb_substr((string) preg_replace('/\s+/', ' ', $title), 0, 200),
            'key'   => $key,
            'intro' => self::version($i['start_version'] ?? null),
            'last'  => $fixed === null ? $last : null,
            'fixed' => $fixed,
            'sev'   => self::severity(strtolower($title . ' ' . (string) ($i['risk level'] ?? '')), isset($i['cvss30_base_score']) && is_numeric($i['cvss30_base_score']) ? (float) $i['cvss30_base_score'] : null),
            'url'   => str_starts_with($url, 'https://') ? $url : 'https://extensions.joomla.org/vulnerable-extensions/',
            'live'  => $live,
        ];
    }

    /**
     * @param  array<int,array<string,mixed>>                                          $rules
     * @param  array<int,array{name:string,element:string,type:string,version:string}>  $installed
     *
     * @return array<int,array<string,mixed>>  rule fields plus name/version of the installed extension; most severe first
     */
    public static function match(array $rules, array $installed): array
    {
        $byKey = [];

        foreach ($rules as $r) {
            $byKey[$r['key']][] = $r;
        }

        $found = [];

        foreach ($installed as $e) {
            if ($e['version'] === '') {
                continue;
            }

            foreach (self::keys($e) as $k) {
                foreach ($byKey[$k] ?? [] as $r) {
                    if (self::affects($r, $e['version'])) {
                        $found[$r['id'] . '|' . $e['type'] . '|' . $e['element']] = $r + ['name' => $e['name'], 'installed' => $e['version'], 'element' => $e['element']];
                    }
                }
            }
        }

        $found = array_values($found);
        usort($found, static fn (array $a, array $b): int => [self::SEVERITY_RANK[$b['sev']] ?? 0, $a['name']] <=> [self::SEVERITY_RANK[$a['sev']] ?? 0, $b['name']]);

        return $found;
    }

    /** Lower-case, no spaces or marks, version and a trailing " by author" removed: "EasyDiscuss by Stackideas" -> "easydiscuss". */
    public static function normName(string $name): string
    {
        $n = strtolower((string) preg_replace('/\s+by\s+.*$/i', '', $name));
        $n = (string) preg_replace('/\([^)]*\)|\bv?\d+(?:\.\d+)+\b/', ' ', $n);

        return (string) preg_replace('/[^a-z0-9]+/', '', $n);
    }

    /**
     * @param  array<string,mixed>  $r
     */
    public static function affects(array $r, string $version): bool
    {
        $v = self::cleanVersion($version);

        if ($r['intro'] !== null && version_compare($v, $r['intro'], '<')) {
            return false;
        }

        if ($r['last'] !== null && version_compare($v, $r['last'], '>')) {
            return false;
        }

        return $r['fixed'] === null || version_compare($v, $r['fixed'], '<');
    }

    /**
     * @param  array{name:string,element:string,type:string}  $e
     *
     * @return string[]
     */
    private static function keys(array $e): array
    {
        $el   = strtolower($e['element']);
        $bare = (string) preg_replace('/^(?:com|mod|plg|tpl|lib|pkg)_/', '', $el);
        $keys = [$el, $bare];

        foreach ([$bare, (string) preg_replace('/^(?:com|mod|plg|tpl|lib|pkg)_/i', '', $e['name'])] as $n) {
            $norm = self::normName($n);

            if (\strlen($norm) >= 5) {
                $keys[] = '~' . $norm;
            }
        }

        return array_values(array_unique($keys));
    }

    /** com_x / mod_x / plg_group_x from the feed's install_data -> the element key an installed extension is looked up by. */
    private static function elementKey(string $name): ?string
    {
        $n = strtolower(trim($name));

        if (preg_match('/^plg_[a-z0-9]+_([a-z0-9_]+)$/', $n, $m)) {
            return $m[1];
        }

        return preg_match('/^(?:com|mod|tpl|lib|pkg)_[a-z0-9_]+$/', $n) ? $n : null;
    }

    private static function version(mixed $v): ?string
    {
        return preg_match('/^v?(\d+(?:\.\d+){0,3})/i', trim((string) $v), $m) ? $m[1] : null;
    }

    private static function cleanVersion(string $v): string
    {
        return preg_match('/^v?(\d+(?:\.\d+)*)/i', trim($v), $m) ? $m[1] : '0';
    }

    private static function severity(string $hay, ?float $cvss): string
    {
        if ($cvss !== null) {
            return $cvss >= 9 ? 'critical' : ($cvss >= 7 ? 'high' : 'medium');
        }

        if (preg_match('/back ?door|remote code|rce|critical|file upload/', $hay) === 1) {
            return 'critical';
        }

        return preg_match('/sql|rfi|lfi|inclusion|high/', $hay) === 1 ? 'high' : 'medium';
    }
}
