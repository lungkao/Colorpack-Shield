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
 * Renders the server-level half of the path policy (PLAN-WAF-PATH-P2.md, layer 2)
 * as an Apache / LiteSpeed `.htaccess` block, from the same folder lists and
 * entry points the plugin's {@see PathRules} use.
 *
 * It only returns text. Nothing is ever written to the server: the operator
 * pastes the block into a staging copy first. Exceptions are validated
 * strictly (letters, digits and `_ - . /` only) so that a mistyped or hostile
 * list line can never inject a directive.
 */
final class ApachePathPolicy
{
    /**
     * @param  string[]  $allow         extra legitimate direct requests: "/exact/file.php" or "/folder/" (prefix)
     * @param  bool      $withCodeDirs  also refuse direct PHP requests in code folders (class D)
     *
     * @throws \InvalidArgumentException  when an $allow entry is not a plain path
     */
    public static function render(array $allow = [], bool $withCodeDirs = false): string
    {
        $exceptions = [];

        foreach (PathRules::ENTRY_POINT_FILES as $file) {
            $exceptions[] = '/' . $file;
        }

        foreach ($allow as $entry) {
            $exceptions[] = self::validate($entry);
        }

        $exceptions = array_values(array_unique($exceptions));
        $ext        = PathRules::PHP_EXT;

        $out   = [];
        $out[] = '# Colorpack Shield — server-level path policy (generated; review before use)';
        $out[] = '# 1. Try it on a staging copy first and keep a backup of the current .htaccess.';
        $out[] = '# 2. Paste this block ABOVE the CMS rewrite rules (above the Joomla "RewriteCond %{REQUEST_FILENAME}" lines).';
        $out[] = '# 3. Joomla installed in a sub-folder: put it in that folder\'s .htaccess instead.';
        $out[] = '<IfModule mod_rewrite.c>';
        $out[] = 'RewriteEngine On';
        $out[] = '';
        $out[] = '## ---- Colorpack Shield path policy ----';
        $out[] = '# Dot-files and dot-folders (.env, .git, .htaccess ...) are never served; ACME challenges stay open';
        $out[] = 'RewriteCond %{REQUEST_URI} !^/\.well-known/ [NC]';
        $out[] = 'RewriteRule (?:^|/)\.[^/]* - [F,L]';
        $out[] = '';
        $out[] = '# PHP-type files in data folders never execute (uploaded web shells, double extensions like x.php.jpg)';
        $out[] = 'RewriteRule ^(?:' . PathRules::DATA_DIRS . ')/.*\.(?:' . $ext . ')(?:\.[a-z0-9]{1,6})?[.\\s]*(?:/|$) - [F,L,NC]';
        $out[] = '';

        if ($withCodeDirs) {
            $out[] = '# Direct requests to PHP files in code folders are refused, except the legitimate endpoints below';
            $out[] = '# (Joomla Update / Akeeba, plus the ones you listed). Everything else is reached through index.php.';

            foreach ($exceptions as $path) {
                $out[] = 'RewriteCond %{REQUEST_URI} !^' . self::apacheRegex($path) . (str_ends_with($path, '/') ? '' : '$') . ' [NC]';
            }

            $out[] = 'RewriteRule ^(?:' . PathRules::CODE_DIRS . ')/.*\.php\d*[.\\s]*(?:/|$) - [F,L,NC]';
            $out[] = '';
        }

        $out[] = '# Leftovers and backups at the web root, Joomla internals, logs';
        $out[] = 'RewriteRule ^(?:' . PathRules::LEFTOVER_ROOT_FILES . ')$ - [F,L,NC]';
        $out[] = 'RewriteRule ^[^/]+\.(?:' . PathRules::LEFTOVER_ROOT_EXT . ')$ - [F,L,NC]';
        $out[] = 'RewriteRule ^administrator/manifests/ - [F,L,NC]';
        $out[] = 'RewriteRule (?:^|/)(?:' . PathRules::LOG_FILES . ')$ - [F,L,NC]';
        $out[] = '## ---- end path policy ----';
        $out[] = '</IfModule>';

        return implode("\n", $out) . "\n";
    }

    /**
     * @throws \InvalidArgumentException
     */
    public static function validate(string $entry): string
    {
        $entry = trim($entry);

        if ($entry === '' || $entry[0] !== '/' || preg_match('~^/[A-Za-z0-9_./-]*$~', $entry) !== 1 || str_contains($entry, '..') || str_contains($entry, '//') || preg_match('~[A-Za-z0-9_.-]~', $entry) !== 1) {
            // A bare "/" would be an exception covering the whole site, which switches the rule off.
            throw new \InvalidArgumentException('Not a plain path starting with "/" (letters, digits and _ - . / only): ' . substr(preg_replace('/[^\x20-\x7e]/', '?', $entry) ?? '', 0, 60));
        }

        return $entry;
    }

    /** Escape a validated path for use inside an Apache regular expression. */
    private static function apacheRegex(string $path): string
    {
        return str_replace('.', '\.', $path);
    }
}
