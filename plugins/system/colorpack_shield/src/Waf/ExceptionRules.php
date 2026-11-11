<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Narrow, per-field exceptions: "this rule group may skip THIS field on THIS page".
 *
 * They are not tied to an IP address (addresses change), only to what the request is: the rule group, the
 * kind of field, the field name and the page. One line per exception:
 *
 *     shield | source | key | path | option
 *
 *  - shield  sqli, xss, lfi, rfi, cmdi, ssrf, xxe or ssti. Never "*".
 *  - source  GET, POST, COOKIE, JSON or XML ("*" = any of these).
 *  - key     the field name as the Activity log shows it (nested fields are joined with dots). A trailing * matches a prefix.
 *  - path    the request path. Exact, or a prefix when it ends with *.
 *  - option  optional (Joomla): the component the page belongs to, e.g. com_rsform. Empty = any.
 *
 * Headers, the URL path and upload checks have their own controls and can never be excepted here.
 */
final class ExceptionRules
{
    public const SHIELDS = ['sqli', 'xss', 'lfi', 'rfi', 'cmdi', 'ssrf', 'xxe', 'ssti'];

    public const SOURCES = ['GET', 'POST', 'COOKIE', 'JSON', 'XML'];

    public const MAX_RULES = 200;

    /**
     * @return array<int,array{shield:string,source:string,key:string,path:string,option:string,watch:bool,until:int}>
     */
    public static function parse(string $raw): array
    {
        $rules = [];

        foreach (preg_split('/\R/', $raw) ?: [] as $line) {
            $rule = self::parseLine($line);

            if ($rule !== null) {
                $rules[] = $rule;
            }

            if (\count($rules) >= self::MAX_RULES) {
                break;
            }
        }

        return $rules;
    }

    /**
     * @return array{shield:string,source:string,key:string,path:string,option:string,watch:bool,until:int}|null
     */
    public static function parseLine(string $line): ?array
    {
        $line = trim($line);

        if ($line === '' || $line[0] === '#') {
            return null;
        }

        $p = array_map('trim', explode('|', $line));

        if (\count($p) < 4 || \count($p) > 6) {
            return null;
        }

        [$shield, $source, $key, $path] = $p;
        $option = $p[4] ?? '';
        $until  = 0;

        // Sixth column: "watch:<unix time>" = observe this field until then (hits are logged, not blocked, and only
        // for low/medium rules), after which the line does nothing and the field is checked normally again.
        if (isset($p[5])) {
            if (preg_match('/^watch:(\d{9,11})$/', $p[5], $m) !== 1) {
                return null;
            }

            $until = (int) $m[1];
        }
        $shield = strtolower($shield);
        $source = strtoupper($source);

        if (!\in_array($shield, self::SHIELDS, true)
            || ($source !== '*' && !\in_array($source, self::SOURCES, true))
            || $key === '' || $key === '*' || \strlen($key) > 200 || preg_match('/[\x00-\x1f\x7f|]/', $key)
            || $path === '' || $path[0] !== '/' || $path === '/*' || \strlen($path) > 200 || preg_match('/[\x00-\x1f\x7f|]/', $path)
            || ($option !== '' && preg_match('/^[a-z0-9_]{1,60}$/', $option) !== 1)) {
            return null;
        }

        return ['shield' => $shield, 'source' => $source, 'key' => $key, 'path' => $path, 'option' => $option, 'watch' => $until > 0, 'until' => $until];
    }

    /**
     * The exceptions that apply to this request.
     *
     * @param  array<int,array{shield:string,source:string,key:string,path:string,option:string,watch:bool,until:int}>  $rules
     *
     * @return array<int,array{shield:string,source:string,key:string,path:string,option:string,watch:bool,until:int}>
     */
    public static function forRequest(array $rules, string $path, string $option = '', ?int $now = null): array
    {
        $now ??= time();

        return array_values(array_filter($rules, static function (array $r) use ($path, $option, $now): bool {
            if (($r['watch'] ?? false) && ($r['until'] ?? 0) <= $now) {
                return false;
            }

            $pathOk = str_ends_with($r['path'], '*') ? str_starts_with($path, substr($r['path'], 0, -1)) : $path === $r['path'];

            return $pathOk && ($r['option'] === '' || $r['option'] === $option);
        }));
    }

    /** One exception line from what a BLOCK log row recorded; null when that kind of hit cannot be excepted. */
    public static function lineFor(string $shield, string $source, string $key, string $uri): ?string
    {
        $path   = (string) (parse_url($uri, PHP_URL_PATH) ?? '');
        $query  = (string) (parse_url($uri, PHP_URL_QUERY) ?? '');
        $option = '';

        if ($query !== '') {
            parse_str($query, $q);
            $option = isset($q['option']) && \is_string($q['option']) && preg_match('/^[a-z0-9_]{1,60}$/', $q['option']) ? $q['option'] : '';
        }

        $line = implode('|', [strtolower($shield), strtoupper($source), $key, $path, $option]);

        return self::parseLine($line) === null ? null : rtrim($line, '|');
    }
}
