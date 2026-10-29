<?php
/**
 * Endpoint inventory: which PHP files under a Joomla root could a browser
 * request directly, and which of them are legitimate?
 *
 * Read-only. Prints PATHS ONLY (never file contents), grouped:
 *
 *   BOOTSTRAP   starts Joomla itself (payment callbacks, restore scripts ...): likely real endpoints
 *   REVIEW      top-level executable code that reads request input, no "defined('_JEXEC') or die" guard
 *   SUSPECT     unguarded executable PHP in a data folder (images/ tmp/ cache/ logs/ ...): possible web shell
 *   NOTE        any PHP file in images/ or at the web root besides index.php / configuration.php
 *
 * Library folders (vendor/, node_modules/) are only counted. Joomla's own guarded
 * cache and log files are ignored.
 *
 *   php php_endpoints_scan.php [--root=DIR] [--allow-list] [--max-list=200]
 *
 *   --allow-list   print only the BOOTSTRAP and REVIEW paths of code folders, one per line,
 *                  ready for `path_policy_export.php --allow-file=` (review it first!)
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
require_once $src . '/Inventory/EndpointClassifier.php';

use Colorpack\Plugin\System\ColorpackShield\Inventory\EndpointClassifier as C;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;

$opt = getopt('', ['root:', 'allow-list', 'max-list:', 'help']);

if (isset($opt['help'])) {
    fwrite(STDOUT, "Usage: php php_endpoints_scan.php [--root=DIR] [--allow-list] [--max-list=200]\n");
    exit(0);
}

$root = rtrim((string) ($opt['root'] ?? getcwd()), '/');

if (!is_dir($root) || !is_readable($root)) {
    fwrite(STDERR, "ERROR: --root is not a readable directory\n");
    exit(1);
}

$maxList   = max(1, (int) ($opt['max-list'] ?? 200));
$codeRe    = '~^(?:' . PathRules::CODE_DIRS . ')/~';
$dataRe    = '~^(?:' . PathRules::DATA_DIRS . ')/~';
$libRe     = '~(?:^|/)(?:vendor|node_modules)/~';
$found     = ['bootstrap' => [], 'review' => [], 'suspect' => [], 'note' => []];
$counts    = ['files' => 0, 'library' => 0, 'guarded' => 0, 'inert' => 0, 'noinput' => 0, 'error' => 0, 'large' => 0, 'symlink' => 0];
$libReview = 0;

$it = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        static function (SplFileInfo $f) use (&$counts): bool {
            if ($f->isLink()) {
                $counts['symlink']++;

                return false;
            }

            return true;
        }
    )
);

foreach ($it as $file) {
    /** @var SplFileInfo $file */
    if (!$file->isFile() || !preg_match('/\.(?:php\d*|phtml|phar|pht|phps|inc)$/i', $file->getFilename())) {
        continue;
    }

    $rel = ltrim(substr($file->getPathname(), \strlen($root)), '/');
    $counts['files']++;

    if ($file->getSize() > 2 * 1024 * 1024) {
        $counts['large']++;
        continue;
    }

    $verdict = C::classify((string) @file_get_contents($file->getPathname()));
    $isLib   = preg_match($libRe, $rel) === 1;
    $inImg   = str_starts_with($rel, 'images/');
    $rootPhp = !str_contains($rel, '/') && !\in_array($rel, ['index.php', 'configuration.php'], true);

    if ($inImg || $rootPhp) {
        $found['note'][] = $rel;
    }

    if ($verdict === C::ERROR) {
        $counts['error']++;
        continue;
    }

    if ($verdict === C::GUARDED) {
        $counts['guarded']++;
        continue;
    }

    if ($verdict === C::INERT) {
        $counts['inert']++;
        continue;
    }

    if ($verdict === C::NO_INPUT && preg_match($dataRe, $rel) !== 1) {
        $counts['noinput']++;
        continue;
    }

    if (preg_match($dataRe, $rel) === 1) {
        $found['suspect'][] = $rel;
    } elseif ($isLib) {
        $counts['library']++;
        $libReview++;
    } elseif (preg_match($codeRe, $rel) === 1) {
        $found[$verdict === C::BOOTSTRAP ? 'bootstrap' : 'review'][] = $rel;
    }
}

foreach ($found as &$list) {
    sort($list);
}

unset($list);

if (isset($opt['allow-list'])) {
    echo "# Candidate legitimate direct endpoints found under the scanned root.\n";
    echo "# REVIEW this list: delete every line you do not recognise, then use it with path_policy_export.php --allow-file=\n";

    foreach (array_merge($found['bootstrap'], $found['review']) as $rel) {
        echo '/' . $rel . "\n";
    }

    exit(0);
}

echo "Colorpack Shield — PHP endpoint inventory (paths only)\n";
echo "======================================================\n";
printf("PHP files: %d   guarded (ignored): %d   declarations only (ignored): %d   no request input (ignored): %d   libraries with top-level code (counted): %d   unparsable: %d   larger than 2 MB (skipped): %d   symlinks (not followed): %d\n\n",
    $counts['files'], $counts['guarded'], $counts['inert'], $counts['noinput'], $libReview, $counts['error'], $counts['large'], $counts['symlink']);

$section = static function (string $title, string $hint, array $paths) use ($maxList): void {
    echo $title . ' (' . \count($paths) . ")\n";
    echo '  ' . $hint . "\n";

    foreach (\array_slice($paths, 0, $maxList) as $p) {
        echo "    /$p\n";
    }

    if (\count($paths) > $maxList) {
        echo '    … ' . (\count($paths) - $maxList) . " more (raise --max-list)\n";
    }

    echo "\n";
};

$section('BOOTSTRAP', 'Start Joomla themselves: probably legitimate direct endpoints. Keep reachable (add to the exporter allow list).', $found['bootstrap']);
$section('REVIEW', 'Executable code without a _JEXEC-style guard. Often helper scripts; decide one by one.', $found['review']);
$section('SUSPECT', 'Unguarded executable PHP inside a data folder: nothing legitimate lives here. Inspect each file now.', $found['suspect']);
$section('NOTE', 'PHP in images/ or at the web root (besides index.php and configuration.php).', $found['note']);
echo "Paths only; file contents are never printed.\n";
exit(0);
