<?php
/**
 * What the scan screen may do to a file: show the suspicious lines, decide whether a file may be
 * viewed / edited / deleted, keep a copy before any change (and give it back), check PHP syntax
 * before saving. Pure PHP on temporary folders. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Scanner\FileGuard;
use Colorpack\Plugin\System\ColorpackShield\Scanner\FileScanner;
use Colorpack\Plugin\System\ColorpackShield\Scanner\LineMarker;
use Colorpack\Plugin\System\ColorpackShield\Scanner\PhpSyntax;
use Colorpack\Plugin\System\ColorpackShield\Scanner\Quarantine;

echo "== Scan actions: suspicious lines ==\n";

$lmCode = "<?php\n// harmless\n\$a = 1;\n@eval(base64_decode(\$_POST['z']));\n\n\$f = 'x';\n\$f(\$_GET['c']);\n";
$lm     = LineMarker::marks($lmCode);
ipCheck('marks come sorted by line', array_column($lm, 'line') === (static function (array $l): array { sort($l); return $l; })(array_column($lm, 'line')) && count($lm) >= 2);
ipCheck('eval(base64_decode…) is on line 4 and the callback with request data on line 7', in_array(['line' => 4, 'rule' => 'eval_decode'], $lm, true) && in_array(['line' => 7, 'rule' => 'callback_request'], $lm, true)
   );
ipCheck('clean code gives no marks; marks are capped; a multi-line match is placed at its start', LineMarker::marks("<?php echo 1;\n") === [] && count(LineMarker::marks(str_repeat("<?php eval(\$x);\n", 400))) <= LineMarker::MAX_MARKS
    && LineMarker::marks("<?php\n\n\neval(\n  base64_decode(\$x)\n);")[0]['line'] === 4);
ipCheck('kinds: .htaccess in an upload folder, PHP in an image, ordinary PHP', LineMarker::marks("AddHandler application/x-httpd-php .jpg\n", 'htaccess', true)[0]['rule'] === 'htaccess_php_handler' && LineMarker::marks("AddHandler application/x-httpd-php .jpg\n", 'htaccess', false) === []
    && LineMarker::marks("JFIF\n<?php system(\$_GET['c']);", 'image')[0]['line'] === 2 && LineMarker::kindOf('a/b/.htaccess') === 'htaccess' && LineMarker::kindOf('x/y.PHP') === 'php' && LineMarker::kindOf('images/a.jpg') === 'image');

echo "== Scan actions: who may be touched ==\n";

$fgRoot = sys_get_temp_dir() . '/cps-fg-' . bin2hex(random_bytes(4));
mkdir($fgRoot . '/images', 0777, true);
mkdir($fgRoot . '/administrator', 0777, true);
mkdir($fgRoot . '/plugins/system/colorpack_shield/src', 0777, true);
mkdir($fgRoot . '/cache/colorpack_shield/scan', 0777, true);
mkdir($fgRoot . '/outside_target');
file_put_contents($fgRoot . '/images/shell.php', '<?php system($_GET["c"]);');
file_put_contents($fgRoot . '/index.php', '<?php // front');
file_put_contents($fgRoot . '/administrator/index.php', '<?php // admin');
file_put_contents($fgRoot . '/configuration.php', '<?php class JConfig {}');
file_put_contents($fgRoot . '/plugins/system/colorpack_shield/src/X.php', '<?php // ours');
file_put_contents($fgRoot . '/cache/colorpack_shield/scan/result.json.php', 'x');
file_put_contents($fgRoot . '/outside_target/real.php', '<?php // x');
@symlink($fgRoot . '/outside_target', $fgRoot . '/images/linked');
@symlink($fgRoot . '/outside_target/real.php', $fgRoot . '/images/link.php');
$fgAllow = array_fill_keys(['images/shell.php', 'index.php', 'administrator/index.php', 'configuration.php', 'plugins/system/colorpack_shield/src/X.php', 'cache/colorpack_shield/scan/result.json.php', 'images/linked/real.php', 'images/link.php', 'images', 'gone.php'], 1);
$fg = static fn (string $rel, string $act = 'view', ?array $allow = null): string => FileGuard::check($fgRoot, $rel, $allow ?? $fgAllow, $act)['code'];

ipCheck('a reported file may be viewed, edited and deleted; the answer carries its real path', $fg('images/shell.php') === 'ok' && $fg('images/shell.php', 'edit') === 'ok' && $fg('images/shell.php', 'delete') === 'ok' && FileGuard::check($fgRoot, 'images/shell.php', $fgAllow, 'view')['real'] === realpath($fgRoot) . '/images/shell.php');
ipCheck('a file the scan did not report is refused, even if it exists', $fg('plugins/x.php', 'view', ['images/shell.php' => 1]) === 'not_in_scan' && $fg('index.php', 'view', []) === 'not_in_scan');
ipCheck('odd paths are refused before anything touches the disk', $fg('') === 'bad_path' && $fg('../etc/passwd') === 'bad_path' && $fg('images/../index.php') === 'bad_path' && $fg('/images/shell.php') === 'bad_path' && $fg("images/shell.php\0.jpg") === 'bad_path' && $fg('images\\shell.php') === 'bad_path' && $fg(str_repeat('a/', 300)) === 'bad_path' && $fg('./index.php') === 'bad_path');
ipCheck('a symbolic link, a file reached through a linked folder, a folder and a vanished file are refused', $fg('images/link.php') === 'outside' && $fg('images/linked/real.php') === 'outside' && $fg('images') === 'not_a_file' && $fg('gone.php') === 'outside');
ipCheck('the site configuration and the scanner\'s own files are never shown, edited or deleted from here', $fg('configuration.php') === 'protected' && $fg('configuration.php', 'edit') === 'protected' && $fg('configuration.php', 'delete') === 'protected'
    && $fg('plugins/system/colorpack_shield/src/X.php') === 'protected' && $fg('cache/colorpack_shield/scan/result.json.php', 'view') === 'protected');
ipCheck('Joomla\'s entry points can be viewed and edited (they get infected) but not deleted (the site would go down)', $fg('index.php', 'view') === 'ok' && $fg('index.php', 'edit') === 'ok' && $fg('index.php', 'delete') === 'entry_point' && $fg('administrator/index.php', 'delete') === 'entry_point' && $fg('administrator/index.php', 'edit') === 'ok');
ipCheck('a differently-cased name is not the same entry (it must be reported by the scan exactly)', $fg('CONFIGURATION.PHP') === 'not_in_scan' && $fg('Index.php') === 'not_in_scan');

echo "== Scan actions: copies kept before a change ==\n";

$qDir = $fgRoot . '/cache/colorpack_shield/quarantine';
$q    = new Quarantine($qDir);
$real = realpath($fgRoot . '/images/shell.php');
$id   = $q->store($real, 'images/shell.php', 'delete');
ipCheck('a copy is made, read back and checked; its id has a fixed shape', is_string($id) && preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $id) === 1 && $q->bytes($id) === '<?php system($_GET["c"]);');
ipCheck('the stored file cannot run (it stops itself), holds no readable code, and the folder is closed to the web', str_starts_with((string) file_get_contents("$qDir/$id.php"), Quarantine::HEADER) && !str_contains((string) file_get_contents("$qDir/$id.php"), 'system(')
    && in_array(trim((string) shell_exec('php ' . escapeshellarg("$qDir/$id.php"))), ['Forbidden', 'Forbidden.'], true));
ipCheck('the folder carries a deny-all .htaccess and an index.html; stored files are private', str_contains((string) file_get_contents("$qDir/.htaccess"), 'Deny from all') && is_file("$qDir/index.html") && (fileperms("$qDir/$id.php") & 0077) === 0);
$it = $q->items();
ipCheck('the list says what was kept, newest first', count($it) === 1 && $it[0]['path'] === 'images/shell.php' && $it[0]['action'] === 'delete' && $it[0]['size'] === 25 && $it[0]['time'] > 0);
$bin = random_bytes(3000) . "\0\xff";
file_put_contents($fgRoot . '/images/bin.dat', $bin);
$idb = $q->store($fgRoot . '/images/bin.dat', 'images/bin.dat', 'edit');
ipCheck('binary and odd bytes survive the round trip exactly', $idb !== null && $q->bytes($idb) === $bin);
ipCheck('a missing file, a folder and a file over the size limit are refused (and nothing is half-stored)', $q->store($fgRoot . '/nope', 'nope', 'x') === null && $q->store($fgRoot . '/images', 'images', 'x') === null && (function () use ($q, $fgRoot): bool {
    file_put_contents($fgRoot . '/images/big.bin', str_repeat('A', Quarantine::MAX_SIZE + 1));
    $r = $q->store($fgRoot . '/images/big.bin', 'images/big.bin', 'x');
    unlink($fgRoot . '/images/big.bin');

    return $r === null;
})() && glob("$qDir/*.tmp") === []);

unlink($fgRoot . '/images/shell.php');
ipCheck('restore puts the file back where it was, with its permissions', $q->restore($id, $fgRoot, false) === 'ok' && file_get_contents($fgRoot . '/images/shell.php') === '<?php system($_GET["c"]);' && (fileperms($fgRoot . '/images/shell.php') & 0777) !== 0);
ipCheck('restore never overwrites unless told to; an overwrite first keeps what is there as a new copy', $q->restore($id, $fgRoot, false) === 'exists' && (function () use ($q, $fgRoot, $id): bool {
    file_put_contents($fgRoot . '/images/shell.php', 'changed since');
    $n = count($q->ids());

    return $q->restore($id, $fgRoot, true) === 'ok' && count($q->ids()) === $n + 1 && file_get_contents($fgRoot . '/images/shell.php') === '<?php system($_GET["c"]);';
})());
ipCheck('a forged copy cannot be restored onto the site configuration or this package\'s own files, and a forged mode is not applied', (function () use ($fgRoot, $qDir): bool {
    $q2   = new Quarantine($qDir);
    $evil = gmdate('Ymd-His') . '-cafebabe';
    @mkdir($fgRoot . '/plugins/system/colorpack_shield', 0777, true);
    file_put_contents($fgRoot . '/configuration.php', 'ORIGINAL');
    file_put_contents($fgRoot . '/plugins/system/colorpack_shield/x.php', 'ORIGINAL');
    foreach (['configuration.php', 'Configuration.PHP', 'plugins/system/colorpack_shield/x.php', 'administrator/components/com_colorpack_shield/x.php'] as $p) {
        file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => $p, 'action' => 'delete', 'time' => 1, 'size' => 1, 'mode' => 0666]) . "\n" . base64_encode('EVIL'));
        if ($q2->restore($evil, $fgRoot, true) !== 'protected') {
            return false;
        }
    }
    $same = file_get_contents($fgRoot . '/configuration.php') === 'ORIGINAL' && file_get_contents($fgRoot . '/plugins/system/colorpack_shield/x.php') === 'ORIGINAL';
    file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => 'images/modetest.php', 'action' => 'delete', 'time' => 1, 'size' => 1, 'mode' => 0666]) . "\n" . base64_encode('x'));
    $ok = $q2->restore($evil, $fgRoot, true) === 'ok' && (fileperms($fgRoot . '/images/modetest.php') & 0777) === 0644;
    @unlink("$qDir/$evil.php");

    return $same && $ok;
})());
ipCheck('a copy cannot be restored outside the site, through a link or into a folder that does not exist; unknown ids are "not found"', (function () use ($fgRoot, $qDir): bool {
    $q2  = new Quarantine($qDir);
    $evil = gmdate('Ymd-His') . '-deadbeef';
    foreach (['../../escape.php', 'images/linked/x.php', 'nodir/x.php', '/abs.php'] as $p) {
        file_put_contents("$qDir/$evil.php", Quarantine::HEADER . json_encode(['path' => $p, 'action' => 'x', 'time' => 1, 'size' => 1, 'mode' => 0644]) . "\n" . base64_encode('x'));
        $r = $q2->restore($evil, $fgRoot, true);

        if ($r === 'ok' || is_file($fgRoot . '/../escape.php') || is_file($fgRoot . '/outside_target/x.php')) {
            return false;
        }
    }

    unlink("$qDir/$evil.php");

    return $q2->restore('nonsense', $fgRoot, true) === 'not_found' && $q2->restore('20260101-000000-aaaaaaaa', $fgRoot, true) === 'not_found';
})());
ipCheck('a file in the folder that is not ours (no header) or an id with path characters is ignored', (function () use ($q, $qDir): bool {
    file_put_contents("$qDir/20260101-000000-bbbbbbbb.php", '<?php echo "x";');

    $ok = $q->bytes('20260101-000000-bbbbbbbb') === null && $q->bytes('../../etc/passwd') === null && $q->drop('../x') === true;
    unlink("$qDir/20260101-000000-bbbbbbbb.php");

    return $ok;
})());
ipCheck('drop removes one copy; a full store refuses the next change instead of dropping old copies', (function () use ($q, $qDir, $fgRoot): bool {
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

ipCheck('good PHP parses; a missing semicolon and an unclosed brace are caught with a line number', PhpSyntax::error("<?php\n\$a = 1;\necho \$a;\n") === null && PhpSyntax::error("<?php\n\$a = 1\necho \$a;\n")['line'] === 3 && PhpSyntax::error("<?php\nfunction f() {\n  return 1;\n") !== null);
ipCheck('plain HTML, an empty file and PHP 8 syntax pass; the message is one printable line', PhpSyntax::error('<html>no php</html>') === null && PhpSyntax::error('') === null && PhpSyntax::error('<?php enum S: string { case A = "a"; } echo S::A->value;') === null
    && !preg_match('/[\x00-\x1f]/', PhpSyntax::error("<?php \$a = ;\n")['message']));
ipCheck('checking never runs anything', (function (): bool {
    $marker = sys_get_temp_dir() . '/cps-syntax-' . bin2hex(random_bytes(3));
    PhpSyntax::error('<?php file_put_contents(' . var_export($marker, true) . ', "ran");');

    return !is_file($marker);
})());

echo "== Scan actions: one file again ==\n";

file_put_contents($fgRoot . '/images/shell.php', '<?php @eval(base64_decode($_POST["z"]));');
$one = FileScanner::inspectFile($fgRoot, 'images/shell.php');
ipCheck('a bad file gives its finding again; once cleaned it gives none; a missing file or a link gives none', $one !== null && $one['sev'] === 'high' && FileScanner::inspectFile($fgRoot, 'index.php') === null && FileScanner::inspectFile($fgRoot, 'nope.php') === null && FileScanner::inspectFile($fgRoot, 'images/link.php') === null);
file_put_contents($fgRoot . '/images/shell.php', '<?php // cleaned');
ipCheck('…and a cleaned file keeps only the place and name rules (no code signature left)', (FileScanner::inspectFile($fgRoot, 'images/shell.php')['rules'] ?? []) === ['php_in_uploads', 'shell_name']);
exec('rm -rf ' . escapeshellarg($fgRoot));
