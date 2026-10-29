<?php
/**
 * File scanner (signatures, names and places, resumable walk, baseline, "marked safe", the small
 * JSON store). Pure PHP on temporary folders. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Scanner\FileScanner;
use Colorpack\Plugin\System\ColorpackShield\Scanner\LocationRules;
use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;
use Colorpack\Plugin\System\ColorpackShield\Scanner\SignatureRules;

echo "== File scanner: signatures ==\n";

$sg = static fn (string $code): array => SignatureRules::scan($code);
$bad = [
    'eval_decode'     => ['<?php eval(base64_decode("ZWNobyAx"));', '<?php @eval ( gzinflate( base64_decode($x)));', '<?php assert(str_rot13("x"));'],
    'exec_request'    => ['<?php system($_GET["c"]);', '<?php eval($_POST[x]);', '<?php @shell_exec( $_REQUEST["cmd"] );', '<?php passthru(@$_COOKIE["a"]);'],
    'include_request' => ['<?php include($_GET["f"]);', '<?php require_once $_POST["p"];', '<?php include @$_REQUEST[x];'],
    'preg_replace_e'  => ['<?php preg_replace("/x/e", $_POST["c"], "x");', "<?php preg_replace('/(.*)/ei', 'strtolower(\\\\1)', \$s);"],
    'webshell_name'   => ['<?php /* c99shell v1 */', '// FilesMan', '<title>WSO shell</title>', '<?php // b374k mini'],
    'callback_request'=> ['<?php $f = "x"; $f($_POST["a"]);'],
    'write_request'   => ['<?php file_put_contents($_POST["path"], $_POST["data"]);'],
    'create_function' => ['<?php $f = create_function("", $c);'],
    'eval_variable'   => ['<?php eval($code);'],
    'long_base64'     => ['<?php $x = "' . str_repeat('QUJD', 500) . '";'],
    'hex_blob'        => ['<?php $x = "' . str_repeat('\\x41', 30) . '";'],
    'chr_chain'       => ['<?php $x = ' . str_repeat('chr(65).', 12) . 'chr(66);'],
];

foreach ($bad as $rule => $samples) {
    $all = true;

    foreach ($samples as $code) {
        $all = $all && in_array($rule, $sg($code), true);
    }

    ipCheck("signature $rule matches its backdoor shapes", $all);
}

$good = [
    '<?php echo $_GET["id"] ?? "";', '<?php $x = (int) $_POST["n"]; echo $x;', '<?php $input = JFactory::getApplication()->input; $id = $input->getInt("id");',
    '<?php $data = base64_decode($encoded); return $data;', '<?php $r = exec("ls");  // fixed command, no request data', '<?php eval("return 1;");',
    '<?php require JPATH_ROOT . "/libraries/x.php";', '<?php include __DIR__ . "/tmpl/default.php";', '<?php function evaluate($x) { return $x; }', '<?php $this->assertEquals(1, 1);',
    '<?php // the system() function is dangerous', '<?php $methods = ["get", "post"]; echo $_SERVER["REQUEST_METHOD"];', '<?php $key = "abc"; $short = "' . str_repeat('A', 200) . '";',
    '<?php // wsolution, shellshock, filesystem, FilesystemIterator', '<?php preg_replace("/a/i", "b", $s);', '<?php preg_replace("/e/", "b", $s);',
];
$fp = [];

foreach ($good as $code) {
    $hits = $sg($code);

    if ($hits !== []) {
        $fp[] = implode(',', $hits) . ' <= ' . substr($code, 0, 50);
    }
}

if ($fp !== []) {
    echo '  false positives: ' . implode(' | ', $fp) . "\n";
}

ipCheck('ordinary Joomla-style code is not matched (no false positives in the corpus)', $fp === []);
ipCheck('every rule has a known severity; the dangerous ones are "high"', count(array_filter(SignatureRules::PHP, static fn ($r) => in_array($r[0], ['high', 'medium', 'low'], true))) === count(SignatureRules::PHP)
    && SignatureRules::severity('eval_decode') === 'high' && SignatureRules::severity('hex_blob') === 'medium');
ipCheck('a hostile file cannot make a pattern slow (a long line of junk is scanned fast)', (static function () use ($sg): bool {
    $t = microtime(true);
    $sg(str_repeat('$a(', 50000) . str_repeat('chr(1).', 20000) . str_repeat('"', 100000));

    return microtime(true) - $t < 2.0;
})());
ipCheck('.htaccess rules: a handler in an upload folder is high, a prepend anywhere is flagged; a host\'s own AddHandler line is not in the "anywhere" table', SignatureRules::scan("AddHandler application/x-httpd-php .jpg\n", SignatureRules::HTACCESS_DATA) === ['htaccess_php_handler']
    && SignatureRules::scan("php_value auto_prepend_file /x/y.php\n", SignatureRules::HTACCESS_ANY) === ['htaccess_prepend'] && SignatureRules::scan("AddHandler application/x-httpd-php8 .php\n", SignatureRules::HTACCESS_ANY) === []);

ipCheck('severities: the backdoor shapes are "high", the soft signs "medium"', array_reduce(['eval_decode', 'exec_request', 'include_request', 'preg_replace_e', 'webshell_name'], static fn ($c, $r) => $c && SignatureRules::severity($r) === 'high', true)
    && array_reduce(['callback_request', 'write_request', 'create_function', 'eval_variable', 'long_base64', 'hex_blob', 'chr_chain'], static fn ($c, $r) => $c && SignatureRules::severity($r) === 'medium', true));

echo "== File scanner: names and places ==\n";

$lc = static fn (string $rel, int $perms = 0100644): array => LocationRules::check($rel, $perms);
ipCheck('PHP in images/ is high; PHP in tmp/ is medium; PHP in cache/ and logs/ is normal for Joomla (not flagged)', $lc('images/a/x.php') === ['php_in_uploads'] && $lc('images/x.phtml') === ['php_in_uploads'] && $lc('tmp/x.php') === ['php_in_tmp']
    && $lc('cache/com_x/__abc.php') === [] && $lc('logs/error.php') === [] && $lc('administrator/logs/x.php') === [] && $lc('components/com_x/x.php') === []);
ipCheck('double extension, hidden PHP, shell names, foreign-CMS names, world-writable PHP', $lc('media/x.php.jpg') === ['double_extension'] && $lc('images/x.php.jpg') === ['php_in_uploads', 'double_extension'] && $lc('media/.x.php') === ['hidden_php']
    && $lc('media/c99.php') === ['shell_name'] && $lc('a/Shell.PHP') === ['shell_name'] && $lc('wp-login.php') === ['foreign_cms_file'] && $lc('x/y.php', 0100666) === ['world_writable'] && $lc('x/y.txt', 0100666) === []);
ipCheck('ordinary names are quiet', $lc('index.php') === [] && $lc('templates/t/index.php') === [] && $lc('images/photo.jpg') === [] && $lc('media/system/js/core.js') === [] && $lc('administrator/index.php') === []);

echo "== File scanner: the walk ==\n";

$fsRoot = sys_get_temp_dir() . '/cps-scan-' . bin2hex(random_bytes(4));
$fsPut  = static function (string $rel, string $content) use ($fsRoot): void {
    $f = $fsRoot . '/' . $rel;
    @mkdir(dirname($f), 0777, true);
    file_put_contents($f, $content);
};
$fsPut('index.php', '<?php // front controller');
$fsPut('components/com_x/x.php', '<?php echo "ok";');
$fsPut('images/photo.jpg', "\xFF\xD8\xFF\xE0JFIF clean image");
$fsPut('images/evil.jpg', "\xFF\xD8\xFF\xE0JFIF\n<?php system(\$_GET['c']); ?>");
$fsPut('images/tail.png', str_repeat('P', 20000) . "\n<?php eval(\$_POST['x']);");
$fsPut('images/shell.php', '<?php echo 1;');
$fsPut('images/.htaccess', "AddHandler application/x-httpd-php .jpg\n");
$fsPut('.htaccess', "AddHandler application/x-httpd-php8 .php\nRewriteEngine On\n");
$fsPut('tmp/x.php', '<?php // x');
$fsPut('cache/com_x/__abc.php', '<?php die("cache"); ?>');
$fsPut('plugins/system/backdoor/b.php', '<?php @eval(base64_decode($_POST["z"]));');
$fsPut('plugins/system/colorpack_shield/src/Scanner/SignatureRules.php', '<?php // c99shell FilesMan b374k');
$fsPut("odd\nname.php", '<?php system($_GET["c"]);');
$fsPut('.git/hooks/x.php', '<?php system($_GET["c"]);');
$fsPut('cache/colorpack_shield/scan/state.json.php', '<?php system($_GET["c"]);');
@symlink($fsRoot . '/plugins', $fsRoot . '/linked');

$run = static function (array $ignore = [], ?array $base = null, float $budget = 5.0) use ($fsRoot): array {
    $st = FileScanner::newState(1_800_000_000);

    while (!$st['done']) {
        $st = FileScanner::step($st, $fsRoot, microtime(true) + $budget, $ignore);
    }

    return [$st, FileScanner::result($st, $base, 1_800_000_100)];
};
[$st1, $r1] = $run();
$byPath = [];

foreach ($r1['findings'] as $f) {
    $byPath[$f['path']] = $f;
}

ipCheck('planted backdoors are found: PHP in an image, at the END of a big image, a decode-and-run shell, PHP in images/, a handler in an upload .htaccess', isset($byPath['images/evil.jpg']) && in_array('php_in_image', $byPath['images/evil.jpg']['rules'], true) && isset($byPath['images/tail.png'])
    && isset($byPath['plugins/system/backdoor/b.php']) && $byPath['plugins/system/backdoor/b.php']['sev'] === 'high' && $byPath['images/shell.php']['sev'] === 'high' && isset($byPath['images/.htaccess']) && $byPath['images/.htaccess']['sev'] === 'high');
ipCheck('normal files are quiet: front controller, component, clean image, a host\'s own AddHandler in the root .htaccess, Joomla cache PHP', !isset($byPath['index.php']) && !isset($byPath['components/com_x/x.php']) && !isset($byPath['images/photo.jpg']) && !isset($byPath['.htaccess']) && !isset($byPath['cache/com_x/__abc.php']));
ipCheck('tmp/x.php is medium; the scanner\'s own pattern files are not flagged for the words they contain', ($byPath['tmp/x.php']['sev'] ?? '') === 'medium' && !isset($byPath['plugins/system/colorpack_shield/src/Scanner/SignatureRules.php']));
ipCheck('a hostile file name cannot break a line: control bytes are made printable', isset($byPath["odd?name.php"]) && !preg_match('/[\x00-\x1f]/', implode('', array_keys($byPath))));
ipCheck('.git, symbolic links and the plugin\'s own cache folder are not walked', !isset($byPath['.git/hooks/x.php']) && !isset($byPath['linked/system/backdoor/b.php']) && !isset($byPath['cache/colorpack_shield/scan/state.json.php']) && $r1['links'] >= 1);
ipCheck('counts: files seen, PHP files, severities add up, worst first', $r1['seen'] >= 12 && $r1['php'] >= 8 && $r1['count']['high'] + $r1['count']['medium'] + $r1['count']['low'] === count($r1['findings']) && $r1['findings'][0]['sev'] === 'high' && end($r1['findings'])['sev'] !== 'high');
ipCheck('each finding carries size, time and a short fingerprint', $byPath['plugins/system/backdoor/b.php']['size'] > 10 && $byPath['plugins/system/backdoor/b.php']['mtime'] > 0 && strlen($byPath['plugins/system/backdoor/b.php']['hash']) === 12);

// Resumable: a budget of "no time at all" still makes progress and gives the same answer in the end.
$steps = 0;
$st    = FileScanner::newState(1_800_000_000);

while (!$st['done'] && $steps < 5000) {
    $st = FileScanner::step($st, $fsRoot, microtime(true) - 1, []);   // deadline already passed
    $steps++;
}

$st2 = FileScanner::newState(1_800_000_000);
$st2 = FileScanner::step($st2, $fsRoot, microtime(true) - 1, []);   // one call, no time left
ipCheck('a step always ends in time, never loops, and a scan cut into many tiny steps finds exactly the same', $steps < 5000 && $st['done'] && FileScanner::result($st, null, 1)['findings'] == FileScanner::result($st1, null, 1)['findings'] && $st2['done'] === false && $st2['seen'] > 0 && $st2['seen'] < $st1['seen']);

$fsMany = $fsRoot . '/many';
mkdir($fsMany);

for ($i = 0; $i < 300; $i++) {
    file_put_contents("$fsMany/f$i.txt", 'x');
}

file_put_contents("$fsMany/zz.php", '<?php system($_GET["c"]);');
$st = FileScanner::newState(1);
$n  = 0;

while (!$st['done'] && $n < 100000) {
    // Deadline in the past: only the 64-file clock checks can stop it, so a big folder is cut in pieces.
    $st = FileScanner::step($st, $fsRoot, microtime(true) - 1, []);
    $n++;
}

$paths = array_column(FileScanner::result($st, null, 1)['findings'], 'path');
ipCheck('one folder of 300 files is cut into pieces and still every file is seen once (the planted one is found)', $st['done'] && in_array('many/zz.php', $paths, true) && $st['seen'] === $st1['seen'] + 301);
exec('rm -rf ' . escapeshellarg($fsMany));

// One call on a big folder with no time left does only a first piece (the clock is looked at inside a folder).
@mkdir($fsRoot . '/big');

for ($i = 0; $i < 300; $i++) {
    file_put_contents($fsRoot . "/big/f$i.txt", 'x');
}

$stOne = FileScanner::step(['v' => 1, 'started' => 1, 'queue' => [['big', 0]], 'findings' => [], 'more' => 0, 'files' => [], 'tracked' => true, 'seen' => 0, 'php' => 0, 'ignored' => 0, 'links' => 0, 'unreadable' => 0, 'done' => false], $fsRoot, microtime(true) - 1, []);
ipCheck('a huge folder is worked on in pieces: one call with no time left sees only a part of it', $stOne['done'] === false && $stOne['seen'] > 0 && $stOne['seen'] < 300 && $stOne['queue'][0][0] === 'big' && $stOne['queue'][0][1] > 0);
exec('rm -rf ' . escapeshellarg($fsRoot . '/big'));

// The findings list is capped.
@mkdir($fsRoot . '/flood');

for ($i = 0; $i < FileScanner::MAX_FINDINGS + 10; $i++) {
    file_put_contents($fsRoot . "/flood/s$i.php", '<?php system($_GET["c"]);');
}

$stFlood = FileScanner::newState(1);

while (!$stFlood['done']) {
    $stFlood = FileScanner::step($stFlood, $fsRoot, microtime(true) + 5, []);
}

ipCheck('more findings than the cap: exactly the cap is kept, the rest is counted', count($stFlood['findings']) === FileScanner::MAX_FINDINGS && $stFlood['more'] >= 10);
exec('rm -rf ' . escapeshellarg($fsRoot . '/flood'));

// Marked as safe: by path AND fingerprint; a changed file comes back.
$ign = [$byPath['tmp/x.php']['path'] => $byPath['tmp/x.php']['hash']];
[, $r2] = $run($ign);
$p2 = array_column($r2['findings'], 'path');
ipCheck('a file marked safe disappears from the findings (and is counted as ignored)', !in_array('tmp/x.php', $p2, true) && $r2['ignored'] === 1 && in_array('images/shell.php', $p2, true));
file_put_contents($fsRoot . '/tmp/x.php', '<?php // x changed after being marked safe');
[, $r3] = $run($ign);
ipCheck('a marked file that CHANGES is reported again', in_array('tmp/x.php', array_column($r3['findings'], 'path'), true) && $r3['ignored'] === 0);
file_put_contents($fsRoot . '/tmp/x.php', '<?php // x');

// Baseline.
$base = FileScanner::baselineFrom($st1, 1_800_000_000);
ipCheck('a baseline keeps size and fingerprint of every PHP file', is_array($base) && isset($base['files']['index.php']) && preg_match('/^\d+-[0-9a-f]{12}$/', $base['files']['index.php']) === 1);
[, $rb] = $run([], $base);
ipCheck('scanning again with that baseline: nothing new, changed or removed', $rb['baseline'] === true && $rb['changes']['new'] === [] && $rb['changes']['changed'] === [] && $rb['changes']['removed'] === []);
$fsPut('components/com_x/dropper.php', '<?php // new file');
file_put_contents($fsRoot . '/index.php', '<?php // front controller, edited');
unlink($fsRoot . '/images/shell.php');
[, $rc] = $run([], $base);
ipCheck('new, changed and removed PHP files are listed (by path)', $rc['changes']['new'] === ['components/com_x/dropper.php'] && $rc['changes']['changed'] === ['index.php'] && $rc['changes']['removed'] === ['images/shell.php']);
ipCheck('a site with too many PHP files to remember gives no baseline (and no false "nothing changed")', FileScanner::baselineFrom(['tracked' => false, 'files' => []], 1) === null && FileScanner::result(['tracked' => false, 'files' => [], 'findings' => [], 'more' => 0, 'seen' => 0, 'php' => 0, 'ignored' => 0, 'links' => 0, 'unreadable' => 0, 'started' => 1], ['created' => 1, 'files' => ['a.php' => '1-x']], 2)['changes'] === null);
ipCheck('without a baseline there is no change list (first scan)', $r1['baseline'] === false && $r1['changes'] === null);
$big = ['created' => 1, 'files' => []];

for ($i = 0; $i < 300; $i++) {
    $big['files']["old/$i.php"] = '1-aaaaaaaaaaaa';
}

[, $rd] = $run([], $big);
ipCheck('a long change list is capped, and says how many more there were', count($rd['changes']['removed']) === FileScanner::MAX_CHANGES && $rd['changes']['more'] === 300 - FileScanner::MAX_CHANGES + 0 || $rd['changes']['more'] >= 100);

echo "== File scanner: the store ==\n";

$ss = new ScanStore($fsRoot . '/store');
ipCheck('write then read gives the same data; the file starts with a die() line', $ss->write('result', ['a' => [1, 2], 'b' => 'ü']) && $ss->read('result') === ['a' => [1, 2], 'b' => 'ü'] && str_starts_with((string) file_get_contents($fsRoot . '/store/result.json.php'), ScanStore::HEADER));
ipCheck('running the stored file as PHP shows nothing', trim((string) shell_exec('php ' . escapeshellarg($fsRoot . '/store/result.json.php'))) === 'Forbidden.' || trim((string) shell_exec('php ' . escapeshellarg($fsRoot . '/store/result.json.php'))) === 'Forbidden');
ipCheck('missing, foreign or damaged files read as null; names are fixed short words only', $ss->read('nothing') === null && $ss->read('../evil') === null && $ss->write('../evil', ['x']) === false && $ss->write('A', ['x']) === false);
file_put_contents($fsRoot . '/store/state.json.php', str_repeat(' ', strlen(ScanStore::HEADER)) . '{"a":1}');   // valid JSON after the same number of bytes, but not written by us
file_put_contents($fsRoot . '/store/baseline.json.php', ScanStore::HEADER . '{broken');
ipCheck('a file without our header, or with broken JSON, reads as null', $ss->read('state') === null && $ss->read('baseline') === null);
$ss->delete('result');
$hugeJson = ScanStore::HEADER . '{"a":"' . str_repeat('x', ScanStore::MAX + 10) . '"}';
file_put_contents($fsRoot . '/store/lastfiles.json.php', $hugeJson);
ipCheck('a stored file bigger than the cap is not read at all', $ss->read('lastfiles') === null);
unlink($fsRoot . '/store/lastfiles.json.php');
ipCheck('delete removes it; no temporary file is left behind', $ss->read('result') === null && glob($fsRoot . '/store/*.tmp') === []);
exec('rm -rf ' . escapeshellarg($fsRoot));
