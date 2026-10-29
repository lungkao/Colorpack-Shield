<?php
/**
 * Refreshes the signed copy of Cloudflare's edge IP ranges that the plugin uses
 * to decide whom to believe about the visitor IP. The same job runs from the
 * Joomla Scheduled Task (plugin "Task - Colorpack Shield"); use this script from
 * cron when the scheduler is not available.
 *
 *   php cloudflare_ranges_refresh.php --root=/path/to/joomla [--dry-run] [--from-dir=DIR]
 *
 *   --root       the Joomla root (reads the site secret from configuration.php to sign the file)
 *   --dry-run    download and validate, write nothing
 *   --from-dir   take "ips-v4" and "ips-v6" from this folder instead of the network
 *                (air-gapped servers; the same checks apply)
 *
 * A failed or suspicious download never changes anything: the previous list (or
 * the bundled one) stays in force. Exit code 0 = updated or unchanged, 1 = failed
 * or rejected. The secret is never printed.
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
require_once $src . '/Net/CloudflareRanges.php';
require_once $src . '/Net/CloudflareRefresher.php';

use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRefresher;

$opt = getopt('', ['root:', 'dry-run', 'from-dir:', 'help']);

if (isset($opt['help']) || !isset($opt['root'])) {
    fwrite(isset($opt['help']) ? STDOUT : STDERR, "Usage: php cloudflare_ranges_refresh.php --root=/path/to/joomla [--dry-run] [--from-dir=DIR]\n");
    exit(isset($opt['help']) ? 0 : 1);
}

$root = rtrim((string) $opt['root'], '/');
$conf = $root . '/configuration.php';
$text = is_file($conf) && is_readable($conf) ? (string) file_get_contents($conf) : '';

// The configuration file is read as text, never executed.
if (preg_match('/public\s+\$secret\s*=\s*\'((?:[^\'\\\\]|\\\\.)*)\'/', $text, $m) !== 1 || $m[1] === '') {
    fwrite(STDERR, "ERROR: no site secret found in {root}/configuration.php\n");
    exit(1);
}

$key  = CloudflareRanges::deriveKey(stripcslashes($m[1]));
$path = CloudflareRanges::defaultPath($root);

if (isset($opt['from-dir'])) {
    $dir   = rtrim((string) $opt['from-dir'], '/');
    $fetch = static function (string $url) use ($dir): ?string {
        $file = $dir . '/' . basename($url);
        $body = is_file($file) && is_readable($file) ? file_get_contents($file, false, null, 0, CloudflareRefresher::MAX_BYTES + 1) : false;

        return \is_string($body) ? $body : null;
    };
} else {
    $fetch = [CloudflareRefresher::class, 'fetch'];
}

$previous = CloudflareRanges::load($path, $key);

if (isset($opt['dry-run'])) {
    $tmp    = sys_get_temp_dir() . '/cps-cf-dry-' . bin2hex(random_bytes(4)) . '/cloudflare-ips.txt';
    $result = CloudflareRefresher::refresh($fetch, $tmp, $key, $previous);
    array_map('unlink', glob(\dirname($tmp) . '/*') ?: []);
    @rmdir(\dirname($tmp));
    $result['reason'] .= ' (dry run: nothing written to the site)';
} else {
    $result = CloudflareRefresher::refresh($fetch, $path, $key, $previous);
}

printf("Cloudflare ranges: %s — %s (%d entries)\n", $result['status'], $result['reason'], $result['count']);
exit(\in_array($result['status'], [CloudflareRefresher::OK, CloudflareRefresher::UNCHANGED], true) ? 0 : 1);
