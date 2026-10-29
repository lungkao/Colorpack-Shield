<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Export;

use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Print-only server-level version of the administrator address list (A5): text to review and
 * paste, never written to the server. Only entries that pass the plugin's own parsing (and its
 * floors) are printed, so a hostile or mistyped line cannot inject a directive.
 */
final class AdminAllowSnippet
{
    /**
     * @param  string[]  $entries  lines as typed
     *
     * @return array{text:string,count:int}
     */
    public static function render(string $target, array $entries): array
    {
        $list = IpAllowList::fromText(implode("\n", $entries))->entries();
        $out  = [
            '# Colorpack Shield — administrator address list at server level (generated; review before use)',
            '# WARNING: the web server must see the REAL visitor address. Behind Cloudflare or a proxy it sees the',
            '# proxy instead, and this list would then refuse everybody (or nobody). Set up real-IP handling first',
            '# (mod_remoteip / nginx realip), try it on a staging copy, and keep FTP access to remove it again.',
        ];

        if ($list === []) {
            $out[] = '# (no valid address in the list: nothing to print)';

            return ['text' => implode("\n", $out) . "\n", 'count' => 0];
        }

        if ($target === 'nginx') {
            $out[] = '# Put these lines inside the location block that serves /administrator (the one with your PHP handling):';

            foreach ($list as $e) {
                $out[] = 'allow ' . $e . ';';
            }

            $out[] = 'deny all;';
        } else {
            $out[] = '# Put this in administrator/.htaccess (Apache 2.4 / LiteSpeed):';
            $out[] = '<IfModule mod_authz_core.c>';
            $out[] = '    Require ip ' . implode(' ', $list);
            $out[] = '</IfModule>';
        }

        return ['text' => implode("\n", $out) . "\n", 'count' => \count($list)];
    }
}
