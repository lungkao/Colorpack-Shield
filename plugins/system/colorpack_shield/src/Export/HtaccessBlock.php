<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Export;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The block Colorpack Shield keeps in the site's .htaccess, and the text surgery around it.
 *
 * Only directives that need the same permission Joomla's own rewrite rules need (FileInfo) are
 * used: rewrite rules and mod_headers. (No TRACE refusal: tested on a real Apache, TRACE is answered
 * before .htaccess rewrite rules run, so such a rule would only look like protection.) Directives that need more (Options, ServerSignature)
 * are left out on purpose, because on a restricted host they turn the whole site into a
 * "500 Internal Server Error". The block sits between two marker lines at the TOP of the file, so
 * it can be replaced or removed exactly, and everything outside the markers is never touched.
 */
final class HtaccessBlock
{
    public const BEGIN = '# BEGIN Colorpack Shield (do not edit between these lines: the plugin replaces them)';
    public const END   = '# END Colorpack Shield';

    /**
     * @param  string[]  $allow         legitimate direct PHP requests ("/exact/file.php" or "/folder/")
     * @param  array{headers?:bool,hsts?:bool,code_dirs?:bool}  $options
     *
     * @throws \InvalidArgumentException  when an $allow entry is not a plain path
     */
    public static function render(array $allow = [], array $options = []): string
    {
        $headers = $options['headers'] ?? true;
        $hsts    = $options['hsts'] ?? false;
        $policy  = ApachePathPolicy::render($allow, $options['code_dirs'] ?? false);

        // The policy text carries "paste it yourself" notes for the manual route: not useful in the file.
        $lines = array_values(array_filter(explode("\n", rtrim($policy)), static fn (string $l): bool => preg_match('/^# [123]\. /', $l) !== 1));
        $out   = [self::BEGIN];

        foreach ($lines as $l) {
            $out[] = $l;
        }

        if ($headers) {
            $out[] = '';
            $out[] = '# Browser-side hardening headers (no content-security-policy: it needs to be fitted to each site)';
            $out[] = '<IfModule mod_headers.c>';
            $out[] = '    Header always set X-Content-Type-Options "nosniff"';
            $out[] = '    Header always set X-Frame-Options "SAMEORIGIN"';
            $out[] = '    Header always set Referrer-Policy "strict-origin-when-cross-origin"';
            $out[] = '    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"';
            $out[] = '    Header always unset X-Powered-By';
            $out[] = '    Header unset X-Powered-By';

            if ($hsts) {
                $out[] = '    # Browsers will insist on https for 180 days: only when the whole site works over https';
                $out[] = '    Header always set Strict-Transport-Security "max-age=15552000" "expr=%{HTTPS} == \'on\'"';
            }

            $out[] = '</IfModule>';
        }

        $out[] = self::END;

        return implode("\n", $out) . "\n";
    }

    /** True when the file already holds our block. */
    public static function has(string $file): bool
    {
        return str_contains($file, self::BEGIN) && str_contains($file, self::END);
    }

    /**
     * The file with our block put at the top (replacing an earlier copy of it). Line endings of the
     * file are kept; nothing outside the block is changed.
     */
    public static function insert(string $file, string $block): string
    {
        $eol   = str_contains($file, "\r\n") ? "\r\n" : "\n";
        $block = str_replace("\n", $eol, rtrim($block, "\n")) . $eol;
        $file  = self::remove($file);

        return $block . ($file === '' ? '' : $eol . $file);
    }

    /**
     * The file without our block (and without the one blank line that separated it).
     * Exact inverse of {@see insert()}: insert then remove gives back the original bytes.
     */
    public static function remove(string $file): string
    {
        $pattern = '/' . preg_quote(self::BEGIN, '/') . '.*?' . preg_quote(self::END, '/') . '(?:\r?\n){1,2}/s';

        // Collapses any number of old copies; one blank line after the end marker belongs to the block.
        $out = preg_replace($pattern, '', $file);

        return $out ?? $file;
    }
}
