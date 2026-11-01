<?php
/**
 * What the scan screen may do to a file: show the suspicious lines, decide whether a file may be
 * viewed / edited / deleted, keep a copy before any change (and give it back), check PHP syntax
 * before saving. Pure PHP on temporary folders. Ported from the Joomla edition's
 * tests/scanner_actions_tests.php with paths adjusted for WordPress's layout (wp-content/uploads
 * instead of images/, wp-admin/index.php instead of administrator/index.php, wp-config.php
 * instead of configuration.php, wp-content/plugins/colorpack-shield instead of
 * plugins/system/colorpack_shield). Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Scanner\FileGuard;
use Colorpack\WP\ColorpackShield\Scanner\FileScanner;
use Colorpack\WP\ColorpackShield\Scanner\LineMarker;
use Colorpack\WP\ColorpackShield\Scanner\PhpSyntax;
use Colorpack\WP\ColorpackShield\Scanner\Quarantine;

echo "== Scan actions: suspicious lines ==\n";

$lmCode = "<?php\n// harmless\n\$a = 1;\n@eval(base64_decode(\$_POST['z']));\n\n\$f = 'x';\n\$f(\$_GET['c']);\n";
$lm     = LineMarker::marks($lmCode);
ok('marks come sorted by line', array_column($lm, 'line') === (static function (array $l): array { sort($l); return $l; })(array_column($lm, 'line')) && count($lm) >= 2);
ok('eval(base64_decode…) is on line 4 and the callback with request data on line 7', in_array(['line' => 4, 'rule' => 'eval_decode'], $lm, true) && in_array(['line' => 7, 'rule' => 'callback_request'], $lm, true)
   );
ok('clean code gives no marks; marks are capped; a multi-line match is placed at its start', LineMarker::marks("<?php echo 1;\n") === [] && count(LineMarker::marks(str_repeat("<?php eval(\$x);\n", 400))) <= LineMarker::MAX_MARKS
    && LineMarker::marks("<?php\n\n\neval(\n  base64_decode(\$x)\n);")[0]['line'] === 4);
ok('kinds: .htaccess in an upload folder, PHP in an image, ordinary PHP', LineMarker::marks("AddHandler application/x-httpd-php .jpg\n", 'htaccess', true)[0]['rule'] === 'htaccess_php_handler' && LineMarker::marks("AddHandler application/x-httpd-php .jpg\n", 'htaccess', false) === []
    && LineMarker::marks("JFIF\n<?php system(\$_GET['c']);", 'image')[0]['line'] === 2 && LineMarker::kindOf('a/b/.htaccess') === 'htaccess' && LineMarker::kindOf('x/y.PHP') === 'php' && LineMarker::kindOf('wp-content/uploads/a.jpg') === 'image');

echo "== Scan actions: who may be touched ==\n";

$fgRoot = sys_get_temp_dir() . '/cps-wp-fg-' . bin2hex(random_bytes(4));
mkdir($fgRoot . '/wp-content/uploads', 0777, true);
mkdir($fgRoot . '/wp-admin', 0777, true);
mkdir($fgRoot . '/wp-content/plugins/colorpack-shield/src', 0777, true);
mkdir($fgRoot . '/wp-content/uploads/colorpack-shield/scan', 0777, true);
mkdir($fgRoot . '/outside_target');
file_put_contents($fgRoot . '/wp-content/uploads/shell.php', '<?php system($_GET["c"]);');
file_put_contents($fgRoot . '/index.php', '<?php // front');
file_put_contents($fgRoot . '/wp-admin/index.php', '<?php // admin');
file_put_contents($fgRoot . '/wp-config.php', "<?php define('DB_NAME', 'x');");
file_put_contents($fgRoot . '/wp-content/plugins/colorpack-shield/src/X.php', '<?php // ours');
file_put_contents($fgRoot . '/wp-content/uploads/colorpack-shield/scan/result.json.php', 'x');
file_put_contents($fgRoot . '/outside_target/real.php', '<?php // x');
@symlink($fgRoot . '/outside_target', $fgRoot . '/wp-content/uploads/linked');
@symlink($fgRoot . '/outside_target/real.php', $fgRoot . '/wp-content/uploads/link.php');
$fgAllow = array_fill_keys(['wp-content/uploads/shell.php', 'index.php', 'wp-admin/index.php', 'wp-config.php', 'wp-content/plugins/colorpack-shield/src/X.php', 'wp-content/uploads/colorpack-shield/scan/result.json.php', 'wp-content/uploads/linked/real.php', 'wp-content/uploads/link.php', 'wp-content/uploads', 'gone.php'], 1);
$fg = static fn (string $rel, string $act = 'view', ?array $allow = null): string => FileGuard::check($fgRoot, $rel, $allow ?? $fgAllow, $act)['code'];

ok('a reported file may be viewed, edited and deleted; the answer carries its real path', $fg('wp-content/uploads/shell.php') === 'ok' && $fg('wp-content/uploads/shell.php', 'edit') === 'ok' && $fg('wp-content/uploads/shell.php', 'delete') === 'ok' && FileGuard::check($fgRoot, 'wp-content/uploads/shell.php', $fgAllow, 'view')['real'] === realpath($fgRoot) . '/wp-content/uploads/shell.php');
ok('a file the scan did not report is refused, even if it exists', $fg('wp-content/plugins/x.php', 'view', ['wp-content/uploads/shell.php' => 1]) === 'not_in_scan' && $fg('index.php', 'view', []) === 'not_in_scan');
ok('odd paths are refused before anything touches the disk', $fg('') === 'bad_path' && $fg('../etc/passwd') === 'bad_path' && $fg('wp-content/uploads/../index.php') === 'bad_path' && $fg('/wp-content/uploads/shell.php') === 'bad_path' && $fg("wp-content/uploads/shell.php\0.jpg") === 'bad_path' && $fg('wp-content\\uploads\\shell.php') === 'bad_path' && $fg(str_repeat('a/', 300)) === 'bad_path' && $fg('./index.php') === 'bad_path');
ok('a symbolic link, a file reached through a linked folder, a folder and a vanished file are refused', $fg('wp-content/uploads/link.php') === 'outside' && $fg('wp-content/uploads/linked/real.php') === 'outside' && $fg('wp-content/uploads') === 'not_a_file' && $fg('gone.php') === 'outside');
ok('the site configuration and the scanner\'s own files are never shown, edited or deleted from here', $fg('wp-config.php') === 'protected' && $fg('wp-config.php', 'edit') === 'protected' && $fg('wp-config.php', 'delete') === 'protected'
    && $fg('wp-content/plugins/colorpack-shield/src/X.php') === 'protected' && $fg('wp-content/uploads/colorpack-shield/scan/result.json.php', 'view') === 'protected');
ok('WordPress\'s entry points can be viewed and edited (they get infected) but not deleted (the site would go down)', $fg('index.php', 'view') === 'ok' && $fg('index.php', 'edit') === 'ok' && $fg('index.php', 'delete') === 'entry_point' && $fg('wp-admin/index.php', 'delete') === 'entry_point' && $fg('wp-admin/index.php', 'edit') === 'ok');
ok('a differently-cased name is not the same entry (it must be reported by the scan exactly)', $fg('WP-CONFIG.PHP') === 'not_in_scan' && $fg('Index.php') === 'not_in_scan');

echo "== Scan actions: copies kept before a change ==\n";

$qDir = $fgRoot . '/wp-content/uploads/colorpack-shield/quarantine';
$q    = new Quarantine($qDir);
$real = realpath($fgRoot . '/wp-content/uploads/shell.php');
$id   = $q->store($real, 'wp-content/uploads/shell.php', 'delete');
ok('a copy is made, read back and checked; its id has a fixed shape', is_string($id) && preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $id) === 1 && $q->bytes($id) === '<?php system($_GET["c"]);');
ok('the stored file cannot run (it stops itself), holds no readable code, and the folder is closed to the web', str_starts_with((string) file_get_contents("$qDir/$id.php"), Quarantine::HEADER) && !str_contains((string) file_get_contents("$qDir/$id.php"), 'system(')
    && in_array(trim((string) shell_exec('php ' . escapeshellarg("$qDir/$id.php"))), ['Forbidden', 'Forbidden.'], true));
ok('the folder carries a deny-all .htaccess and an index.html; stored files are private', str_contains((string) file_get_contents("$qDir/.htaccess"), 'Deny from all') && is_file("$qDir/index.html") && (fileperms("$qDir/$id.php") & 0077) === 0);
$it = $q->items();
ok('the list says what was kept, newest first', count($it) === 1 && $it[0]['path'] === 'wp-content/uploads/shell.php' && $it[0]['action'] === 'delete' && $it[0]['size'] === 25 && $it[0]['time'] > 0);
$bin = random_bytes(3000) . "\0\xff";
file_put_contents($fgRoot . '/wp-content/uploads/bin.dat', $bin);
$idb = $q->store($fgRoot . '/wp-content/uploads/bin.dat', 'wp-content/uploads/bin.dat', 'edit');
ok('binary and odd bytes survive the round trip exactly', $idb !== null && $q->bytes($idb) === $bin);
ok('a missing file, a folder and a file over the size limit are refused (and nothing is half-stored)', $q->store($fgRoot . '/nope', 'nope', 'x') === null && $q->store($fgRoot . '/wp-content/uploads', 'wp-content/uploads', 'x') === null && (function () use ($q, $fgRoot): bool {
    file_put_contents($fgRoot . '/wp-content/uploads/big.bin', str_repeat('A', Quarantine::MAX_SIZE + 1));
    $r = $q->store($fgRoot . '/wp-content/uploads/big.bin', 'wp-content/uploads/big.bin', 'x');
    unlink($fgRoot . '/wp-content/uploads/big.bin');

    return $r === null;
})() && glob("$qDir/*.tmp") === []);

unlink($fgRoot . '/wp-content/uploads/shell.php');
ok('restore puts the file back where it was, with its permissions', $q->restore($id, $fgRoot, false) === 'ok' && file_get_contents($fgRoot . '/wp-content/uploads/shell.php') === '<?php system($_GET["c"]);' && (fileperms($fgRoot . '/wp-content/uploads/shell.php') & 0777) !== 0);
ok('restore never overwrites unless told to; an overwrite first keeps what is there as a new copy', $q->restore($id, $fgRoot, false) === 'exists' && (function () use ($q, $fgRoot, $id): bool {
    file_put_contents($fgRoot . '/wp-content/uploads/shell.php', 'changed since');
    $n = count($q->ids());

    return $q->restore($id, $fgRoot, true) === 'ok' && count($q->ids()) === $n + 1 && file_get_contents($fgRoot . '/wp-content/uploads/shell.php') === '<?php system($_GET["c"]);';
})());
ok('a forged copy cannot be restored onto the site configuration or this package\'s own files, and a forged mode is not applied', (function () use ($fgRoot, $qDir): bool {
    $q2   = new Quarantine($qDir);
    $evil = gmdate('Ymd-His') . '-cafebabe';
    @mkdir($fgRoot . '/wp-content/plugins/colorpack-shield', 0777, true);
    file_put_contents($fgRoot . '/wp-config.php', 'ORIGINAL');
    file_put_contents($fgRoot . '/wp-content/plugins/colorpack-shield/x.php', 'ORIGINAL');
    foreach (['wp-config.php', 'Wp-Config.PHP', 'wp-content/plugins/colorpack-shield/x.php', 'wp-content/uploads/colorpack-shield/x.php'] as $p) {
        file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => $p, 'action' => 'delete', 'time' => 1, 'size' => 1, 'mode' => 0666]) . "\n" . base64_encode('EVIL'));
        if ($q2->restore($evil, $fgRoot, true) !== 'protected') {
            return false;
        }
    }
    $same = file_get_contents($fgRoot . '/wp-config.php') === 'ORIGINAL' && file_get_contents($fgRoot . '/wp-content/plugins/colorpack-shield/x.php') === 'ORIGINAL';
    file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => 'wp-content/uploads/modetest.php', 'action' => 'delete', 'time' => 1, 'size' => 1, 'mode' => 0666]) . "\n" . base64_encode('x'));
    $ok = $q2->restore($evil, $fgRoot, true) === 'ok' && (fileperms($fgRoot . '/wp-content/uploads/modetest.php') & 0777) === 0644;
    @unlink("$qDir/$evil.php");

    return $same && $ok;
})());
ok('a copy cannot be restored outside the site, through a link or into a folder that does not exist; unknown ids are "not found"', (function () use ($fgRoot, $qDir): bool {
    $q2  = new Quarantine($qDir);
    $evil = gmdate('Ymd-His') . '-deadbeef';
    foreach (['../../escape.php', 'wp-content/uploads/linked/x.php', 'nodir/x.php', '/abs.php'] as $p) {
        file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => $p, 'action' => 'x', 'time' => 1, 'size' => 1, 'mode' => 0644]) . "\n" . base64_encode('x'));
        $r = $q2->restore($evil, $fgRoot, true);

        if ($r === 'ok' || is_file($fgRoot . '/../escape.php') || is_file($fgRoot . '/outside_target/x.php')) {
            return false;
        }
    }

    unlink("$qDir/$evil.php");

    return $q2->restore('nonsense', $fgRoot, true) === 'not_found' && $q2->restore('20260101-000000-aaaaaaaa', $fgRoot, true) === 'not_found';
})());
ok('a file in the folder that is not ours (no header) or an id with path characters is ignored', (function () use ($q, $qDir): bool {
    file_put_contents("$qDir/20260101-000000-bbbbbbbb.php", '<?php echo "x";');

    $ok = $q->bytes('20260101-000000-bbbbbbbb') === null && $q->bytes('../../etc/passwd') === null && $q->drop('../x') === true;
    unlink("$qDir/20260101-000000-bbbbbbbb.php");

    return $ok;
})());
ok('drop removes one copy; a full store refuses the next change instead of dropping old copies', (function () use ($q, $qDir, $fgRoot): bool {
    $before = count($q->ids());
    $q->drop($q->ids()[0]);
    $dropped = count($q->ids()) === $before - 1;

    for ($i = 0; count($q->ids()) < Quarantine::MAX_ITEMS; $i++) {
        file_put_contents("$qDir/20260102-" . sprintf('%06d', $i) . '-aaaaaaaa.php', Quarantine::HEADER . '{"path":"x","action":"x","time":1,"size":1}' . "\nWA==");
    }

    $refused = $q->store($fgRoot . '/index.php', 'index.php', 'edit') === null && count($q->ids()) === Quarantine::MAX_ITEMS;
    array_map('unlink', glob("$qDir/20260102-*.php") ?: []);

    return $dropped && $refused;
})());

echo "== Scan actions: PHP syntax before saving ==\n";

ok('good PHP parses; a missing semicolon and an unclosed brace are caught with a line number', PhpSyntax::error("<?php\n\$a = 1;\necho \$a;\n") === null && PhpSyntax::error("<?php\n\$a = 1\necho \$a;\n")['line'] === 3 && PhpSyntax::error("<?php\nfunction f() {\n  return 1;\n") !== null);
ok('plain HTML, an empty file and PHP 8 syntax pass; the message is one printable line', PhpSyntax::error('<html>no php</html>') === null && PhpSyntax::error('') === null && PhpSyntax::error('<?php enum S: string { case A = "a"; } echo S::A->value;') === null
    && !preg_match('/[\x00-\x1f]/', PhpSyntax::error("<?php \$a = ;\n")['message']));
ok('checking never runs anything', (function (): bool {
    $marker = sys_get_temp_dir() . '/cps-wp-syntax-' . bin2hex(random_bytes(3));
    PhpSyntax::error('<?php file_put_contents(' . var_export($marker, true) . ', "ran");');

    return !is_file($marker);
})());

echo "== Scan actions: one file again ==\n";

file_put_contents($fgRoot . '/wp-content/uploads/shell.php', '<?php @eval(base64_decode($_POST["z"]));');
$one = FileScanner::inspectFile($fgRoot, 'wp-content/uploads/shell.php');
ok('a bad file gives its finding again; once cleaned it gives none; a missing file or a link gives none', $one !== null && $one['sev'] === 'high' && FileScanner::inspectFile($fgRoot, 'index.php') === null && FileScanner::inspectFile($fgRoot, 'nope.php') === null && FileScanner::inspectFile($fgRoot, 'wp-content/uploads/link.php') === null);
file_put_contents($fgRoot . '/wp-content/uploads/shell.php', '<?php // cleaned');
ok('…and a cleaned file keeps only the place and name rules (no code signature left)', (FileScanner::inspectFile($fgRoot, 'wp-content/uploads/shell.php')['rules'] ?? []) === ['php_in_uploads', 'shell_name']);
exec('rm -rf ' . escapeshellarg($fgRoot));
