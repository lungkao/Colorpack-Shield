<?php
/**
 * File scanner (signatures, names and places, resumable walk, baseline, "marked safe", the small
 * JSON store). Pure PHP on temporary folders. Ported from the Joomla edition's
 * tests/file_scanner_tests.php - `SignatureRules`/`FileScanner`'s walk/store logic are an
 * unchanged port (content-based, no path assumptions); `LocationRules`/`FileScanner`'s own-path
 * skips were rewritten for WordPress's real folder layout (wp-content/uploads instead of
 * images/, wp-content/plugins/colorpack-shield instead of plugins/system/colorpack_shield, the
 * Joomla edition's "wp-login.php is foreign" check replaced with "configuration.php is foreign" -
 * the inverse is true here). Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Scanner\FileScanner;
use Colorpack\WP\ColorpackShield\Scanner\LocationRules;
use Colorpack\WP\ColorpackShield\Scanner\ScanStore;
use Colorpack\WP\ColorpackShield\Scanner\SignatureRules;

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
    // Mined from PHP Malware Finder (jvoisin/php-malware-finder, data/php.yar); each was re-checked
    // by hand (on the Joomla edition, where these signatures were first written) against real CMS
    // core + extension code for zero false positives before being added.
    'extract_request'   => ['<?php extract($_POST); echo $cmd;', '<?php extract(@$_REQUEST);'],
    'callback_decode'   => ['<?php array_walk($x, "base64_decode");', '<?php usort($a, \'gzinflate\');', '<?php preg_replace_callback($p, "str_rot13", $s);'],
    'unsafe_ini_tamper' => ['<?php ini_set("disable_functions", "");', '<?php ini_restore("open_basedir");'],
    'ld_preload'        => ['<?php putenv("LD_PRELOAD=/tmp/x.so");'],
    'exploit_site_ref'  => ['<?php // downloaded from milw0rm.com', '<?php $u = "http://pentestmonkey.net/x";'],
    // From a real incident (asianpa.org, 2026-10-30, originally found on the Joomla edition):
    // every sample below is a redacted shape of an actual malicious file that evaded every rule
    // above by never spelling out a dangerous name as a plain substring.
    'cookie_superglobal_octal' => ["<?php \$jg = \${\"\\137\".\"\\103\".\"\\117\".\"\\117\".\"\\113\".\"\\111\".\"\\105\"};"],
    'xor_string_obfuscation'   => ["<?php \$a='aaaaaa'^\$k; \$b='bbbbbb'^\$k; \$c='cccccc'^\$k;"],
    'concat_func_name_exec'    => ['<?php $a="sys"."tem";$a($_GET[x]);'],
    'chr_built_eval'            => ['<?php $f = "" . chr(101) . "val(g" . chr(122) . "inflate(base64_decode(";'],
    'charmap_index_obfuscation' => ['<?php $x[a] = $m[f][0].$m[f][1].$m[f][2].$m[f][3].$m[f][4].$m[f][5].$m[f][6];'],
    'split_base64_decode'       => ["<?php \$f='base'.(128/2).'_de'.'code';"],
    'upload_probe'              => ['<?php echo "jm"."te"."st";'],
];

foreach ($bad as $rule => $samples) {
    $all = true;

    foreach ($samples as $code) {
        $all = $all && in_array($rule, $sg($code), true);
    }

    ok("signature $rule matches its backdoor shapes", $all);
}

$good = [
    '<?php echo $_GET["id"] ?? "";', '<?php $x = (int) $_POST["n"]; echo $x;', '<?php $id = absint($_GET["id"] ?? 0);',
    '<?php $data = base64_decode($encoded); return $data;', '<?php $r = exec("ls");  // fixed command, no request data', '<?php eval("return 1;");',
    '<?php require ABSPATH . "wp-includes/x.php";', '<?php include __DIR__ . "/tmpl/default.php";', '<?php function evaluate($x) { return $x; }', '<?php $this->assertEquals(1, 1);',
    '<?php // the system() function is dangerous', '<?php $methods = ["get", "post"]; echo $_SERVER["REQUEST_METHOD"];', '<?php $key = "abc"; $short = "' . str_repeat('A', 200) . '";',
    '<?php // wsolution, shellshock, filesystem, FilesystemIterator', '<?php preg_replace("/a/i", "b", $s);', '<?php preg_replace("/e/", "b", $s);',
    '<?php extract($data);', '<?php extract($this->getFields());', '<?php array_map("strtoupper", $words);', '<?php usort($list, fn ($a, $b) => $a <=> $b);',
    '<?php if (ini_get("disable_functions")) { echo "restricted"; }', '<?php echo ini_get("open_basedir");', '<?php $allowed = !ini_get("safe_mode");',
    '<?php // see https://www.exploit-db.com for CVE details', '<?php // explains webshell/backdoor detection in this very scanner',
    '<?php $name = $_COOKIE["name"] ?? "";', '<?php class Foo { public function __get($name) { return $this->$name; } }',
    '<?php $colour = "red"; $size = "large"; echo $colour . " " . $size;', '<?php $label = chr(65) . chr(66) . chr(67);',
    '<?php $parts = [$a[0], $a[1], $a[2]];', '<?php $value = "base64_decode($encoded)"; // just a comment string',
    '<?php echo "jm" . "p to section"; // unrelated concatenation',
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

ok('ordinary WordPress-style code is not matched (no false positives in the corpus)', $fp === []);
ok('every rule has a known severity; the dangerous ones are "high"', count(array_filter(SignatureRules::PHP, static fn ($r) => in_array($r[0], ['high', 'medium', 'low'], true))) === count(SignatureRules::PHP)
    && SignatureRules::severity('eval_decode') === 'high' && SignatureRules::severity('hex_blob') === 'medium');
ok('a hostile file cannot make a pattern slow (a long line of junk is scanned fast)', (static function () use ($sg): bool {
    $t = microtime(true);
    $sg(str_repeat('$a(', 50000) . str_repeat('chr(1).', 20000) . str_repeat('"', 100000));

    return microtime(true) - $t < 2.0;
})());
ok('.htaccess rules: a handler in an upload folder is high, a prepend anywhere is flagged; a host\'s own AddHandler line is not in the "anywhere" table', SignatureRules::scan("AddHandler application/x-httpd-php .jpg\n", SignatureRules::HTACCESS_DATA) === ['htaccess_php_handler']
    && SignatureRules::scan("php_value auto_prepend_file /x/y.php\n", SignatureRules::HTACCESS_ANY) === ['htaccess_prepend'] && SignatureRules::scan("AddHandler application/x-httpd-php8 .php\n", SignatureRules::HTACCESS_ANY) === []);

ok('severities: the backdoor shapes are "high", the soft signs "medium"', array_reduce(['eval_decode', 'exec_request', 'include_request', 'preg_replace_e', 'webshell_name', 'extract_request', 'callback_decode', 'unsafe_ini_tamper', 'ld_preload'], static fn ($c, $r) => $c && SignatureRules::severity($r) === 'high', true)
    && array_reduce(['callback_request', 'write_request', 'create_function', 'eval_variable', 'long_base64', 'hex_blob', 'chr_chain', 'exploit_site_ref'], static fn ($c, $r) => $c && SignatureRules::severity($r) === 'medium', true));

ok('asianpa.org incident rules: severities match (high; the upload probe is only "low")', array_reduce(['cookie_superglobal_octal', 'xor_string_obfuscation', 'concat_func_name_exec', 'chr_built_eval', 'charmap_index_obfuscation', 'split_base64_decode'], static fn ($c, $r) => $c && SignatureRules::severity($r) === 'high', true)
    && SignatureRules::severity('upload_probe') === 'low');

echo "== File scanner: .htaccess SEO-cloaking rules (asianpa.org incident) ==\n";

$seoHtaccess = <<<'HTA'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (google|yahoo|bing) [OR]
RewriteCond %{HTTP_REFERER} (google|aol|yahoo|bing|twitter|t.co) [OR]
RewriteCond %{REMOTE_ADDR} "^(?:66\.249\.(?:6[4-9]|7[0-9])\.\d{1,3})$"
RewriteCond %{REQUEST_URI} /$ [OR]
RewriteCond %{REQUEST_FILENAME} (html|htm|php)$ [NC]
RewriteCond %{REQUEST_FILENAME} !common.php
RewriteCond %{DOCUMENT_ROOT}/log/common.php -f
RewriteRule ^.*$    /log/common.php [L]
</IfModule>
HTA;
ok('a cloaking redirect to a non-index PHP file by search-engine UA/referer is flagged high', in_array('seo_cloaking_bot_redirect', SignatureRules::scan($seoHtaccess, SignatureRules::HTACCESS_ANY), true));
ok('a RewriteCond keyed to Googlebot\'s own address range is flagged medium', in_array('googlebot_ip_condition', SignatureRules::scan($seoHtaccess, SignatureRules::HTACCESS_ANY), true) && SignatureRules::severity('googlebot_ip_condition', SignatureRules::HTACCESS_ANY) === 'medium');
ok('an ordinary "block common exploits" .htaccess block is not flagged by either new rule', (static function (): bool {
    $ordinary = "RewriteCond %{QUERY_STRING} base64_(en|de)code\\(.*\\) [OR]\nRewriteCond %{QUERY_STRING} GLOBALS(=|\\[|\\%[0-9A-Z]{0,2})\nRewriteRule .* index.php [F]\n";
    $hits = SignatureRules::scan($ordinary, SignatureRules::HTACCESS_ANY);

    return !in_array('seo_cloaking_bot_redirect', $hits, true) && !in_array('googlebot_ip_condition', $hits, true);
})());

echo "== File scanner: PHP hidden behind a short open tag in an image (asianpa.org incident) ==\n";

ok('a bare "<?" (short_open_tag) inside an image is caught, not just "<?php"/"<?="', preg_match(SignatureRules::PHP_IN_IMAGE, "GIF89a\n<? \$a=\"sys\".\"tem\";\$a(\$_GET[x]);?>") === 1);
ok('"<?xml" is not mistaken for a hidden PHP tag', preg_match(SignatureRules::PHP_IN_IMAGE, '<?xml version="1.0"?><svg></svg>') === 0);

echo "== File scanner: names and places ==\n";

$lc = static fn (string $rel, int $perms = 0100644): array => LocationRules::check($rel, $perms);
ok('PHP in wp-content/uploads/ is high; PHP in wp-content/tmp/ is medium; PHP in wp-content/cache/ is high too (unlike Joomla\'s own cache/, this is a plugin-written folder, not core); PHP in wp-content/plugins/ (a real plugin) is normal (not flagged by LocationRules alone)', $lc('wp-content/uploads/a/x.php') === ['php_in_uploads'] && $lc('wp-content/uploads/x.phtml') === ['php_in_uploads'] && $lc('wp-content/tmp/x.php') === ['php_in_tmp']
    && $lc('wp-content/cache/x.php') === ['php_in_uploads'] && $lc('wp-includes/x.php') === [] && $lc('wp-admin/includes/x.php') === [] && $lc('wp-content/plugins/some-plugin/x.php') === []);
ok('double extension, hidden PHP, shell names, a foreign (Joomla) config file, world-writable PHP', $lc('wp-content/themes/t/x.php.jpg') === ['double_extension'] && $lc('wp-content/uploads/x.php.jpg') === ['php_in_uploads', 'double_extension'] && $lc('wp-content/themes/t/.x.php') === ['hidden_php']
    && $lc('wp-content/themes/t/c99.php') === ['shell_name'] && $lc('a/Shell.PHP') === ['shell_name'] && $lc('configuration.php') === ['foreign_configphp'] && $lc('x/y.php', 0100666) === ['world_writable'] && $lc('x/y.txt', 0100666) === []);
ok('WordPress\'s own real files are never flagged as foreign (the inverse of the Joomla edition\'s "wp-*.php is foreign" check)', $lc('wp-login.php') === [] && $lc('wp-config.php') === [] && $lc('wp-admin/index.php') === [] && $lc('wp-cron.php') === []);

// From the asianpa.org incident: a nested uploads folder, a literal "?" in a file name, an
// already-quarantined ".suspected" file, and the "php\d*" extension generalisation (php56).
ok('wp-content/uploads/ is caught at any depth, not just the top level', $lc('wp-content/uploads/2026/01/a.php') === ['php_in_uploads'] && $lc('wp-content/themes/t/wp-content/uploads/a.php') === ['php_in_uploads']);
ok('a literal "?" in a file name is flagged regardless of its extension', $lc('wp-content/uploads/2026/thumbnail_w.jpg?.php') === ['php_in_uploads', 'question_mark_name']
    && $lc('wp-content/themes/t/thumbnail.png?.php') === ['question_mark_name'] && $lc('wp-content/uploads/2026/thumbnail_w.jpg?.phmlL') === ['question_mark_name']
    && $lc('index.php') === [] && $lc('wp-content/themes/t/x.jpg') === []);
ok('a host-renamed ".suspected" file is flagged even outside wp-content/uploads/', $lc('wp-content/plugins/some-plugin/local.php.suspected') === ['quarantined']);
ok('"php\\d*" generalisation: .php56 is treated as PHP, without widening to unrelated extensions', $lc('wp-content/uploads/2026/x.jpg?.php56') === ['php_in_uploads', 'question_mark_name'] && $lc('x/notes.phps56') === [] && $lc('x/php5-notes.txt') === []);
ok('ordinary names are quiet', $lc('index.php') === [] && $lc('wp-content/themes/t/index.php') === [] && $lc('wp-content/uploads/2026/photo.jpg') === [] && $lc('wp-includes/js/core.js') === [] && $lc('wp-admin/index.php') === []);

echo "== File scanner: the walk ==\n";

$fsRoot = sys_get_temp_dir() . '/cps-wp-scan-' . bin2hex(random_bytes(4));
$fsPut  = static function (string $rel, string $content) use ($fsRoot): void {
    $f = $fsRoot . '/' . $rel;
    @mkdir(dirname($f), 0777, true);
    file_put_contents($f, $content);
};
$fsPut('index.php', '<?php // front controller');
$fsPut('wp-content/plugins/some-plugin/x.php', '<?php echo "ok";');
$fsPut('wp-content/uploads/2026/photo.jpg', "\xFF\xD8\xFF\xE0JFIF clean image");
$fsPut('wp-content/uploads/2026/evil.jpg', "\xFF\xD8\xFF\xE0JFIF\n<?php system(\$_GET['c']); ?>");
$fsPut('wp-content/uploads/2026/tail.png', str_repeat('P', 20000) . "\n<?php eval(\$_POST['x']);");
$fsPut('wp-content/uploads/2026/shell.php', '<?php echo 1;');
$fsPut('wp-content/uploads/2026/.htaccess', "AddHandler application/x-httpd-php .jpg\n");
$fsPut('.htaccess', "AddHandler application/x-httpd-php8 .php\nRewriteEngine On\n");
$fsPut('wp-content/tmp/x.php', '<?php // x');
$fsPut('wp-content/cache/__abc.php', '<?php die("cache"); ?>');
$fsPut('wp-content/plugins/backdoor/b.php', '<?php @eval(base64_decode($_POST["z"]));');
$fsPut('wp-content/plugins/colorpack-shield/src/scanner/signaturerules.php', '<?php // c99shell FilesMan b374k');
$fsPut("odd\nname.php", '<?php system($_GET["c"]);');
$fsPut('.git/hooks/x.php', '<?php system($_GET["c"]);');
$fsPut('wp-content/uploads/colorpack-shield/scan/state.json.php', '<?php system($_GET["c"]);');
@symlink($fsRoot . '/wp-content/plugins', $fsRoot . '/linked');

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

ok('planted backdoors are found: PHP in an image, at the END of a big image, a decode-and-run shell, PHP in wp-content/uploads/, a handler in an upload .htaccess', isset($byPath['wp-content/uploads/2026/evil.jpg']) && in_array('php_in_image', $byPath['wp-content/uploads/2026/evil.jpg']['rules'], true) && isset($byPath['wp-content/uploads/2026/tail.png'])
    && isset($byPath['wp-content/plugins/backdoor/b.php']) && $byPath['wp-content/plugins/backdoor/b.php']['sev'] === 'high' && $byPath['wp-content/uploads/2026/shell.php']['sev'] === 'high' && isset($byPath['wp-content/uploads/2026/.htaccess']) && $byPath['wp-content/uploads/2026/.htaccess']['sev'] === 'high');
ok('normal files are quiet: front controller, an ordinary plugin file, clean image, a host\'s own AddHandler in the root .htaccess', !isset($byPath['index.php']) && !isset($byPath['wp-content/plugins/some-plugin/x.php']) && !isset($byPath['wp-content/uploads/2026/photo.jpg']) && !isset($byPath['.htaccess']));
ok('PHP sitting in wp-content/cache/ is flagged (a cache folder is written by plugins, not WordPress core, unlike Joomla\'s own cache/)', isset($byPath['wp-content/cache/__abc.php']));
ok('wp-content/tmp/x.php is medium; the scanner\'s own pattern files are not flagged for the words they contain', ($byPath['wp-content/tmp/x.php']['sev'] ?? '') === 'medium' && !isset($byPath['wp-content/plugins/colorpack-shield/src/scanner/signaturerules.php']));
ok('a hostile file name cannot break a line: control bytes are made printable', isset($byPath["odd?name.php"]) && !preg_match('/[\x00-\x1f]/', implode('', array_keys($byPath))));
ok('.git, symbolic links and the plugin\'s own data folder are not walked', !isset($byPath['.git/hooks/x.php']) && !isset($byPath['linked/backdoor/b.php']) && !isset($byPath['wp-content/uploads/colorpack-shield/scan/state.json.php']) && $r1['links'] >= 1);
ok('counts: files seen, PHP files, severities add up, worst first', $r1['seen'] >= 12 && $r1['php'] >= 8 && $r1['count']['high'] + $r1['count']['medium'] + $r1['count']['low'] === count($r1['findings']) && $r1['findings'][0]['sev'] === 'high' && end($r1['findings'])['sev'] !== 'high');
ok('each finding carries size, time and a short fingerprint', $byPath['wp-content/plugins/backdoor/b.php']['size'] > 10 && $byPath['wp-content/plugins/backdoor/b.php']['mtime'] > 0 && strlen($byPath['wp-content/plugins/backdoor/b.php']['hash']) === 12);

// Resumable: a budget of "no time at all" still makes progress and gives the same answer in the end.
$steps = 0;
$st    = FileScanner::newState(1_800_000_000);

while (!$st['done'] && $steps < 5000) {
    $st = FileScanner::step($st, $fsRoot, microtime(true) - 1, []);   // deadline already passed
    $steps++;
}

$st2 = FileScanner::newState(1_800_000_000);
$st2 = FileScanner::step($st2, $fsRoot, microtime(true) - 1, []);   // one call, no time left
ok('a step always ends in time, never loops, and a scan cut into many tiny steps finds exactly the same', $steps < 5000 && $st['done'] && FileScanner::result($st, null, 1)['findings'] == FileScanner::result($st1, null, 1)['findings'] && $st2['done'] === false && $st2['seen'] > 0 && $st2['seen'] < $st1['seen']);

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
ok('one folder of 300 files is cut into pieces and still every file is seen once (the planted one is found)', $st['done'] && in_array('many/zz.php', $paths, true) && $st['seen'] === $st1['seen'] + 301);
exec('rm -rf ' . escapeshellarg($fsMany));

// One call on a big folder with no time left does only a first piece (the clock is looked at inside a folder).
@mkdir($fsRoot . '/big');

for ($i = 0; $i < 300; $i++) {
    file_put_contents($fsRoot . "/big/f$i.txt", 'x');
}

$stOne = FileScanner::step(['v' => 1, 'started' => 1, 'queue' => [['big', 0]], 'findings' => [], 'more' => 0, 'files' => [], 'tracked' => true, 'seen' => 0, 'php' => 0, 'ignored' => 0, 'links' => 0, 'unreadable' => 0, 'done' => false], $fsRoot, microtime(true) - 1, []);
ok('a huge folder is worked on in pieces: one call with no time left sees only a part of it', $stOne['done'] === false && $stOne['seen'] > 0 && $stOne['seen'] < 300 && $stOne['queue'][0][0] === 'big' && $stOne['queue'][0][1] > 0);
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

ok('more findings than the cap: exactly the cap is kept, the rest is counted', count($stFlood['findings']) === FileScanner::MAX_FINDINGS && $stFlood['more'] >= 10);
exec('rm -rf ' . escapeshellarg($fsRoot . '/flood'));

// Marked as safe: by path AND fingerprint; a changed file comes back.
$ign = [$byPath['wp-content/tmp/x.php']['path'] => $byPath['wp-content/tmp/x.php']['hash']];
[, $r2] = $run($ign);
$p2 = array_column($r2['findings'], 'path');
ok('a file marked safe disappears from the findings (and is counted as ignored)', !in_array('wp-content/tmp/x.php', $p2, true) && $r2['ignored'] === 1 && in_array('wp-content/uploads/2026/shell.php', $p2, true));
file_put_contents($fsRoot . '/wp-content/tmp/x.php', '<?php // x changed after being marked safe');
[, $r3] = $run($ign);
ok('a marked file that CHANGES is reported again', in_array('wp-content/tmp/x.php', array_column($r3['findings'], 'path'), true) && $r3['ignored'] === 0);
file_put_contents($fsRoot . '/wp-content/tmp/x.php', '<?php // x');

// Baseline.
$base = FileScanner::baselineFrom($st1, 1_800_000_000);
ok('a baseline keeps size and fingerprint of every PHP file', is_array($base) && isset($base['files']['index.php']) && preg_match('/^\d+-[0-9a-f]{12}$/', $base['files']['index.php']) === 1);
[, $rb] = $run([], $base);
ok('scanning again with that baseline: nothing new, changed or removed', $rb['baseline'] === true && $rb['changes']['new'] === [] && $rb['changes']['changed'] === [] && $rb['changes']['removed'] === []);
$fsPut('wp-content/plugins/some-plugin/dropper.php', '<?php // new file');
file_put_contents($fsRoot . '/index.php', '<?php // front controller, edited');
unlink($fsRoot . '/wp-content/uploads/2026/shell.php');
[, $rc] = $run([], $base);
ok('new, changed and removed PHP files are listed (by path)', $rc['changes']['new'] === ['wp-content/plugins/some-plugin/dropper.php'] && $rc['changes']['changed'] === ['index.php'] && $rc['changes']['removed'] === ['wp-content/uploads/2026/shell.php']);
ok('a site with too many PHP files to remember gives no baseline (and no false "nothing changed")', FileScanner::baselineFrom(['tracked' => false, 'files' => []], 1) === null && FileScanner::result(['tracked' => false, 'files' => [], 'findings' => [], 'more' => 0, 'seen' => 0, 'php' => 0, 'ignored' => 0, 'links' => 0, 'unreadable' => 0, 'started' => 1], ['created' => 1, 'files' => ['a.php' => '1-x']], 2)['changes'] === null);
ok('without a baseline there is no change list (first scan)', $r1['baseline'] === false && $r1['changes'] === null);
$big = ['created' => 1, 'files' => []];

for ($i = 0; $i < 300; $i++) {
    $big['files']["old/$i.php"] = '1-aaaaaaaaaaaa';
}

[, $rd] = $run([], $big);
ok('a long change list is capped, and says how many more there were', count($rd['changes']['removed']) === FileScanner::MAX_CHANGES && $rd['changes']['more'] === 300 - FileScanner::MAX_CHANGES + 0 || $rd['changes']['more'] >= 100);

echo "== File scanner: the store ==\n";

$ss = new ScanStore($fsRoot . '/store');
ok('write then read gives the same data; the file starts with a die() line', $ss->write('result', ['a' => [1, 2], 'b' => 'ü']) && $ss->read('result') === ['a' => [1, 2], 'b' => 'ü'] && str_starts_with((string) file_get_contents($fsRoot . '/store/result.json.php'), ScanStore::HEADER));
ok('running the stored file as PHP shows nothing', trim((string) shell_exec('php ' . escapeshellarg($fsRoot . '/store/result.json.php'))) === 'Forbidden.' || trim((string) shell_exec('php ' . escapeshellarg($fsRoot . '/store/result.json.php'))) === 'Forbidden');
ok('missing, foreign or damaged files read as null; names are fixed short words only', $ss->read('nothing') === null && $ss->read('../evil') === null && $ss->write('../evil', ['x']) === false && $ss->write('A', ['x']) === false);
file_put_contents($fsRoot . '/store/state.json.php', str_repeat(' ', strlen(ScanStore::HEADER)) . '{"a":1}');   // valid JSON after the same number of bytes, but not written by us
file_put_contents($fsRoot . '/store/baseline.json.php', ScanStore::HEADER . '{broken');
ok('a file without our header, or with broken JSON, reads as null', $ss->read('state') === null && $ss->read('baseline') === null);
$ss->delete('result');
$hugeJson = ScanStore::HEADER . '{"a":"' . str_repeat('x', ScanStore::MAX + 10) . '"}';
file_put_contents($fsRoot . '/store/lastfiles.json.php', $hugeJson);
ok('a stored file bigger than the cap is not read at all', $ss->read('lastfiles') === null);
unlink($fsRoot . '/store/lastfiles.json.php');
ok('delete removes it; no temporary file is left behind', $ss->read('result') === null && glob($fsRoot . '/store/*.tmp') === []);
exec('rm -rf ' . escapeshellarg($fsRoot));
