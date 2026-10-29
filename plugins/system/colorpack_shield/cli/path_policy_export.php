<?php
/**
 * Prints the server-level path policy (Apache / LiteSpeed .htaccess block) to
 * standard output. It never writes to the server: you review it, try it on a
 * staging copy and paste it yourself.
 *
 *   php path_policy_export.php [--target=apache|litespeed|nginx] [--allow-file=FILE]
 *                              [--allow=/path]... [--with-code-dirs]
 *
 *   --allow-file   file with one legitimate direct request per line ("/folder/file.php"
 *                  or "/folder/" as a prefix; "#" comments); the output of
 *                  php_endpoints_scan.php --allow-list is a good start
 *   --with-code-dirs   also refuse direct PHP requests in code folders (class D).
 *                  Off by default: enable it per site after the inventory.
 *
 * apache / litespeed: an .htaccess block (tested on Apache 2.4; LiteSpeed untested).
 * nginx: a block for the domain's server { } (tested on nginx 1.29 in front of Apache).
 * With nginx in front of Apache, use BOTH: nginx answers static files (json, xml, zip ...)
 * itself, Apache answers the rest.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

\define('_JEXEC', 1);

$src = \dirname(__DIR__) . '/src';
require_once $src . '/Waf/Rules/PathRules.php';
require_once $src . '/Export/ApachePathPolicy.php';
require_once $src . '/Export/NginxPathPolicy.php';

use Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy;
use Colorpack\Plugin\System\ColorpackShield\Export\NginxPathPolicy;

$opt = getopt('', ['target:', 'allow-file:', 'allow:', 'with-code-dirs', 'help']);

if (isset($opt['help'])) {
    fwrite(STDOUT, "Usage: php path_policy_export.php [--target=apache|litespeed|nginx] [--allow-file=FILE] [--allow=/path]... [--with-code-dirs]\n");
    exit(0);
}

$target = (string) ($opt['target'] ?? 'apache');

if (!\in_array($target, ['apache', 'litespeed', 'nginx'], true)) {
    fwrite(STDERR, "ERROR: --target must be apache, litespeed or nginx\n");
    exit(1);
}

$allow = isset($opt['allow']) ? (array) $opt['allow'] : [];

if (isset($opt['allow-file'])) {
    $file = (string) $opt['allow-file'];
    $text = is_file($file) && is_readable($file) ? file_get_contents($file) : false;

    if ($text === false) {
        fwrite(STDERR, "ERROR: cannot read the --allow-file you gave\n");
        exit(1);
    }

    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        $line = trim($line);

        if ($line !== '' && $line[0] !== '#') {
            $allow[] = $line;
        }
    }
}

try {
    $text = $target === 'nginx'
        ? NginxPathPolicy::render($allow, isset($opt['with-code-dirs']))
        : ApachePathPolicy::render($allow, isset($opt['with-code-dirs']));
} catch (InvalidArgumentException $e) {
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . "\n");
    exit(1);
}

if ($target === 'litespeed') {
    $text = "# LiteSpeed / OpenLiteSpeed: .htaccess rewrite rules are supported, but this output has not been tested there yet.\n" . $text;
}

echo $text;
exit(0);
