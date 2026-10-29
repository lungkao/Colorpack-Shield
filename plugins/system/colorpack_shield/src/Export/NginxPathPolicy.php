<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Export;

use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The nginx counterpart of {@see ApachePathPolicy}: a block for the domain's
 * `server { }` that refuses the same paths from the same shared lists.
 *
 * Why it exists: with nginx in front of Apache, nginx answers requests for
 * files whose extension is on its "static" list (json, xml, txt, zip ...)
 * itself, so an Apache `.htaccess` never sees them. These rules run in nginx's
 * server rewrite phase, i.e. BEFORE any `location` is chosen, which makes the
 * result independent of where the block is placed and of the template's
 * static-file locations. They match `$uri`, which nginx has already decoded and
 * normalised (so `%2e`, `/a/../x` and `//` are resolved before our regexes run).
 *
 * Only text is returned; nothing is written. Entries for $allow are validated
 * exactly as in the Apache exporter.
 */
final class NginxPathPolicy
{
    /**
     * @param  string[]  $allow         extra legitimate direct requests ("/file.php" or "/folder/")
     * @param  bool      $withCodeDirs  also refuse direct PHP requests in code folders (class D)
     *
     * @throws \InvalidArgumentException
     */
    public static function render(array $allow = [], bool $withCodeDirs = false): string
    {
        $exceptions = [];

        foreach (PathRules::ENTRY_POINT_FILES as $file) {
            $exceptions[] = '/' . $file;
        }

        foreach ($allow as $entry) {
            $exceptions[] = ApachePathPolicy::validate($entry);
        }

        $exceptions = array_values(array_unique($exceptions));
        $ext        = PathRules::PHP_EXT;

        $out   = [];
        $out[] = '# Colorpack Shield — nginx path policy (generated; review before use)';
        $out[] = '# 1. Put this inside the domain\'s server { } block (or in a file that block includes); the position does not matter.';
        $out[] = '# 2. Run "nginx -t" and test on a staging copy before reloading; keep a backup of the file you change.';
        $out[] = '# 3. These rules run before nginx picks a location, so they also cover files nginx would serve itself (json, xml, txt, zip ...).';
        $out[] = '## ---- Colorpack Shield path policy ----';
        $out[] = '# Dot-files and dot-folders are never served; ACME challenges at the site root stay open';
        $out[] = 'set $cps_dot 0;';
        $out[] = 'if ($uri ~ "(?:^|/)\.[^/]*") { set $cps_dot 1; }';
        $out[] = 'if ($uri ~* "^/\.well-known/") { set $cps_dot 0; }';
        $out[] = 'if ($cps_dot) { return 403; }';
        $out[] = '';
        $out[] = '# PHP-type files in data folders never execute (uploaded web shells, double extensions like x.php.jpg)';
        $out[] = 'if ($uri ~* "^/(?:' . PathRules::DATA_DIRS . ')/.*\.(?:' . $ext . ')(?:\.[a-z0-9]{1,6})?[.\s]*(?:/|$)") { return 403; }';
        $out[] = '';

        if ($withCodeDirs) {
            $out[] = '# Direct requests to PHP files in code folders are refused, except the legitimate endpoints below';
            $out[] = 'set $cps_code 0;';
            $out[] = 'if ($uri ~* "^/(?:' . PathRules::CODE_DIRS . ')/.*\.php\d*[.\s]*(?:/|$)") { set $cps_code 1; }';

            foreach ($exceptions as $path) {
                $out[] = 'if ($uri ~* "^' . str_replace('.', '\.', $path) . (str_ends_with($path, '/') ? '' : '$') . '") { set $cps_code 0; }';
            }

            $out[] = 'if ($cps_code) { return 403; }';
            $out[] = '';
        }

        $out[] = '# Leftovers and backups at the web root, Joomla internals, logs';
        $out[] = 'if ($uri ~* "^/(?:' . PathRules::LEFTOVER_ROOT_FILES . ')$") { return 403; }';
        $out[] = 'if ($uri ~* "^/[^/]+\.(?:' . PathRules::LEFTOVER_ROOT_EXT . ')$") { return 403; }';
        $out[] = 'if ($uri ~* "^/administrator/manifests/") { return 403; }';
        $out[] = 'if ($uri ~* "(?:^|/)(?:' . PathRules::LOG_FILES . ')$") { return 403; }';
        $out[] = '## ---- end path policy ----';

        return implode("\n", $out) . "\n";
    }
}
