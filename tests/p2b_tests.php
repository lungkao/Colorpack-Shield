<?php
/**
 * P2b: server-config exporter (text and CLI) and the endpoint inventory
 * (classifier and CLI). The exporter's output against a real Apache is in
 * apache_rig_tests.php. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Waf/Rules/PathRules.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Export/ApachePathPolicy.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Export/NginxPathPolicy.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Inventory/EndpointClassifier.php';

use Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy;
use Colorpack\Plugin\System\ColorpackShield\Export\NginxPathPolicy;
use Colorpack\Plugin\System\ColorpackShield\Inventory\EndpointClassifier as EC;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;

echo "== Exporter: Apache / LiteSpeed text ==\n";

$def  = ApachePathPolicy::render();
$full = ApachePathPolicy::render(['/components/com_pay/notify.php', '/shop/'], true);

ipCheck('default output is wrapped in IfModule and has the staging/backup instructions', str_contains($def, '<IfModule mod_rewrite.c>') && str_contains($def, '</IfModule>') && str_contains($def, 'staging') && str_contains($def, 'backup'));
ipCheck('default output keeps ACME (.well-known) open for the dot-file rule', str_contains($def, 'RewriteCond %{REQUEST_URI} !^/\.well-known/ [NC]') && str_contains($def, 'RewriteRule (?:^|/)\.[^/]* - [F,L]'));
ipCheck('default output blocks PHP in the data folders from the shared table', str_contains($def, '^(?:' . PathRules::DATA_DIRS . ')/'));
ipCheck('default output covers every PHP-type extension from the shared table', str_contains($def, PathRules::PHP_EXT));
ipCheck('default output refuses double extensions like x.php.jpg', str_contains($def, '(?:\.[a-z0-9]{1,6})?'));
ipCheck('default output has the leftovers, manifests and log rules', str_contains($def, 'configuration\.php') && str_contains($def, 'administrator/manifests/') && str_contains($def, 'error_log|php_errorlog'));
ipCheck('class D is off by default', !str_contains($def, PathRules::CODE_DIRS) && !str_contains($def, 'Direct requests to PHP files'));
ipCheck('class D on: rule from the shared table is present', str_contains($full, '^(?:' . PathRules::CODE_DIRS . ')/'));
ipCheck('class D on: every built-in entry point is an exception', (function () use ($full) {
    foreach (PathRules::ENTRY_POINT_FILES as $f) {
        if (!str_contains($full, '!^/' . str_replace('.', '\.', $f) . '$ [NC]')) {
            return false;
        }
    }

    return true;
})());
ipCheck('class D on: exact exception ends with $, prefix exception does not', str_contains($full, '!^/components/com_pay/notify\.php$ [NC]') && str_contains($full, '!^/shop/ [NC]'));
ipCheck('class D on: exceptions come before the rule they relax', strrpos($full, 'RewriteCond %{REQUEST_URI} !^/shop/') < strpos($full, 'RewriteRule ^(?:' . PathRules::CODE_DIRS));
ipCheck('no literal space inside any RewriteRule pattern (Apache would reject the file)', (function () use ($def, $full) {
    foreach ([$def, $full] as $text) {
        foreach (explode("\n", $text) as $line) {
            if (str_starts_with($line, 'RewriteRule ') && !preg_match('~^RewriteRule \S+ - \[[A-Z,]+\]$~', $line)) {
                return false;
            }
        }
    }

    return true;
})());
ipCheck('every Cond / Rule line is a single directive with no stray characters', (function () use ($full) {
    foreach (explode("\n", $full) as $line) {
        if ($line !== '' && $line[0] !== '#' && !preg_match('~^(?:<IfModule mod_rewrite\.c>|</IfModule>|RewriteEngine On|RewriteCond \S+ \S+ \[NC\]|RewriteRule \S+ - \[[A-Z,]+\])$~', $line)) {
            return false;
        }
    }

    return true;
})());
ipCheck('duplicate exceptions are listed once', substr_count(ApachePathPolicy::render(['/a/b.php', '/a/b.php'], true), '!^/a/b\.php$') === 1);
ipCheck('output is deterministic', ApachePathPolicy::render(['/x/y.php'], true) === ApachePathPolicy::render(['/x/y.php'], true));

foreach ([
    '', 'relative/path.php', "/ok\nRewriteRule .* - [R=301]", '/a b.php', '/a/../b.php', '//a.php', '/a;b.php', '/a$.php', "/a\r\nHeader set X y", '/a%2e.php', '/ä.php', '/a(b).php', '/a|b',
] as $bad) {
    $threw = false;

    try {
        ApachePathPolicy::render([$bad], true);
    } catch (InvalidArgumentException $e) {
        $threw = true;
    }

    ipCheck('exception line rejected: ' . json_encode($bad), $threw);
}

foreach (['/a.php', '/components/com_x/y-z_1.php', '/folder/', '/a/b/c.d/e.php', '  /spaced.php  '] as $ok) {
    $threw = false;

    try {
        ApachePathPolicy::render([$ok], true);
    } catch (InvalidArgumentException $e) {
        $threw = true;
    }

    ipCheck('exception line accepted: ' . json_encode($ok), !$threw);
}

// CLI.
$export = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/path_policy_export.php');
$crun   = static function (array $args) use ($export): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($export);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    $o = [];
    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o) . "\n"];
};

$tdir = sys_get_temp_dir() . '/cps-p2b-' . bin2hex(random_bytes(4));
mkdir($tdir);

[$code, $t] = $crun([]);
ipCheck('CLI default: exit 0 and the same text as the class', $code === 0 && $t === ApachePathPolicy::render());
[$code, $t] = $crun(['--with-code-dirs', '--allow=/components/com_pay/notify.php']);
ipCheck('CLI --with-code-dirs --allow: same as the class', $code === 0 && $t === ApachePathPolicy::render(['/components/com_pay/notify.php'], true));
file_put_contents("$tdir/allow.txt", "# reviewed\n/components/com_pay/notify.php\n\n/shop/\n");
[$code, $t] = $crun(['--with-code-dirs', "--allow-file=$tdir/allow.txt"]);
ipCheck('CLI --allow-file: comments and blank lines skipped, entries honoured', $code === 0 && str_contains($t, '!^/components/com_pay/notify\.php$') && str_contains($t, '!^/shop/ [NC]') && !str_contains($t, 'reviewed'));
[$code, $t] = $crun(['--target=litespeed']);
ipCheck('CLI litespeed: same rules plus an "untested" notice', $code === 0 && str_contains($t, 'not been tested') && str_contains($t, ApachePathPolicy::render()));
[$code, $t] = $crun(['--target=nginx']);
ipCheck('CLI nginx: same text as the class, no Apache directives', $code === 0 && $t === NginxPathPolicy::render() && !str_contains($t, 'RewriteRule'));
[$code, $t] = $crun(['--target=nginx', '--with-code-dirs', '--allow=/components/com_pay/notify.php']);
ipCheck('CLI nginx --with-code-dirs --allow: same as the class', $code === 0 && $t === NginxPathPolicy::render(['/components/com_pay/notify.php'], true));
[$code, $t] = $crun(['--target=nginx', '--allow=/bad path.php']);
ipCheck('CLI nginx bad exception: exit 1, nothing printed', $code === 1 && !str_contains($t, 'set $cps'));
[$code, $t] = $crun(['--target=weird']);
ipCheck('CLI unknown target: exit 1', $code === 1 && str_contains($t, '--target'));
[$code, $t] = $crun(['--allow=/ok.php', "--allow=/bad\n RewriteRule"]);
ipCheck('CLI bad exception: exit 1, error says why, no rules printed', $code === 1 && str_contains($t, 'ERROR') && !str_contains($t, 'RewriteEngine'));
file_put_contents("$tdir/bad.txt", "/ok.php\n/bad path.php\n");
[$code, $t] = $crun(["--allow-file=$tdir/bad.txt"]);
ipCheck('CLI bad line in --allow-file: exit 1, no rules printed', $code === 1 && !str_contains($t, 'RewriteEngine'));
[$code, $t] = $crun(["--allow-file=$tdir/missing.txt"]);
ipCheck('CLI missing --allow-file: exit 1', $code === 1);
ipCheck('CLI --help exits 0', $crun(['--help'])[0] === 0);
ipCheck('the exporter wrote nothing to disk', array_map('basename', glob("$tdir/*") ?: []) === ['allow.txt', 'bad.txt']);

echo "== Exporter: nginx text ==\n";

$ndef  = NginxPathPolicy::render();
$nfull = NginxPathPolicy::render(['/components/com_pay/notify.php', '/shop/'], true);

ipCheck('nginx output has the instructions: server block, nginx -t, staging, backup, why it also covers static files', str_contains($ndef, 'server { }') && str_contains($ndef, 'nginx -t') && str_contains($ndef, 'staging') && str_contains($ndef, 'backup') && str_contains($ndef, 'serve itself'));
ipCheck('nginx output is made only of set / if / return lines (no stray directives)', (function () use ($ndef, $nfull) {
    foreach ([$ndef, $nfull] as $text) {
        foreach (explode("\n", $text) as $line) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }

            if (!preg_match('#^(?:set \$cps_[a-z]+ [01];|if \(\$uri ~\*? "[^"]+"\) \{ (?:return 403|set \$cps_[a-z]+ [01]); \}|if \(\$cps_[a-z]+\) \{ return 403; \})$#', $line)) {
                echo "    odd line: $line\n";

                return false;
            }
        }
    }

    return true;
})());
ipCheck('every nginx regex compiles as PCRE', (function () use ($nfull) {
    preg_match_all('#\$uri ~\*? "([^"]+)"#', $nfull, $m);

    foreach ($m[1] as $re) {
        if (@preg_match('~' . str_replace('~', '\\~', $re) . '~', '') === false) {
            return false;
        }
    }

    return count($m[1]) >= 10;
})());
ipCheck('nginx output matches on $uri (decoded and normalised by nginx), never on $request_uri', str_contains($ndef, '$uri') && !str_contains($ndef, '$request_uri'));
ipCheck('nginx: .well-known exemption comes after the dot-file test and before the verdict', strpos($ndef, 'set $cps_dot 1;') < strpos($ndef, '^/\.well-known/') && strpos($ndef, '^/\.well-known/') < strpos($ndef, 'if ($cps_dot) { return 403; }'));
ipCheck('nginx: data-folder rule uses the shared folder and extension lists', str_contains($ndef, '^/(?:' . PathRules::DATA_DIRS . ')/') && str_contains($ndef, PathRules::PHP_EXT));
ipCheck('nginx: leftovers, manifests and logs use the shared patterns', str_contains($ndef, PathRules::LEFTOVER_ROOT_FILES) && str_contains($ndef, PathRules::LEFTOVER_ROOT_EXT) && str_contains($ndef, PathRules::LOG_FILES) && str_contains($ndef, 'administrator/manifests/'));
ipCheck('nginx: class D is off by default and on with the flag', !str_contains($ndef, 'cps_code') && str_contains($nfull, '^/(?:' . PathRules::CODE_DIRS . ')/'));
ipCheck('nginx: class D sets the flag first, clears it per exception, refuses last', (function () use ($nfull) {
    $set = strpos($nfull, 'set $cps_code 1;');
    $clr = strpos($nfull, 'com_pay/notify\.php$") { set $cps_code 0; }');
    $ref = strpos($nfull, 'if ($cps_code) { return 403; }');

    return $set !== false && $clr !== false && $ref !== false && $set < $clr && $clr < $ref;
})());
ipCheck('nginx: built-in entry points and the exact / prefix forms are exceptions', (function () use ($nfull) {
    foreach (PathRules::ENTRY_POINT_FILES as $f) {
        if (!str_contains($nfull, '"^/' . str_replace('.', '\\.', $f) . '$") { set $cps_code 0; }')) {
            return false;
        }
    }

    return str_contains($nfull, '"^/shop/") { set $cps_code 0; }') && str_contains($nfull, '"^/components/com_pay/notify\\.php$") { set $cps_code 0; }');
})());
ipCheck('nginx: duplicates listed once and output is deterministic', substr_count(NginxPathPolicy::render(['/a/b.php', '/a/b.php'], true), '^/a/b\\.php$') === 1 && NginxPathPolicy::render(['/x.php'], true) === NginxPathPolicy::render(['/x.php'], true));

foreach (["/ok\n}\nlocation / { proxy_pass http://evil; }", '/a"b.php', '/a b.php', '/a/../b', "/a;b", '/a$b', '//x', 'rel.php', '/\\x.php'] as $bad) {
    $threw = false;

    try {
        NginxPathPolicy::render([$bad], true);
    } catch (InvalidArgumentException $e) {
        $threw = true;
    }

    ipCheck('nginx exception rejected: ' . json_encode($bad), $threw);
}

echo "== Inventory: classifier ==\n";

$cases = [
    'guard: defined or die'                 => ["<?php\ndefined('_JEXEC') or die;\nclass A {}\n", EC::GUARDED],
    'guard: namespaced \\defined or die'    => ["<?php\n\\defined('_JEXEC') or die;\n\$x = \$_GET['a']; echo 1;\n", EC::GUARDED],
    'guard: JPATH_PLATFORM || exit'         => ["<?php\ndefined('JPATH_PLATFORM') || exit;\necho 1;\n", EC::GUARDED],
    'guard: if (!defined) { die }'          => ["<?php\nif (!defined('_JEXEC')) { die('x'); }\necho \$_GET[1];\n", EC::GUARDED],
    'guard: ABSPATH exit'                   => ["<?php\nif ( ! defined( 'ABSPATH' ) ) exit;\necho 1;", EC::GUARDED],
    'guard: leading die (Joomla file cache)' => ['<?php die("Access Denied"); ?>#x#a:2:{s:6:"result";s:6:"abd446";}', EC::GUARDED],
    'guard: Joomla log file'                => ["#\n#<?php die('Forbidden.'); ?>\n#Date: 2026\n", EC::GUARDED],
    'not a guard: only mentions _JEXEC'     => ["<?php\nif (defined('_JEXEC')) { \$a = 1; }\necho \$_GET['x'];\n", EC::UNGUARDED],
    'not a guard: guard inside a comment'   => ["<?php\n// defined('_JEXEC') or die;\n/* defined('_JEXEC') or die; */\necho \$_GET[1];\n", EC::UNGUARDED],
    'inert: class'                          => ["<?php\nnamespace A;\nuse B\\C;\nclass D { function f() { echo \$_GET['x']; eval(\$_POST[1]); } }\n", EC::INERT],
    'inert: functions and interfaces'       => ["<?php\ndeclare(strict_types=1);\nnamespace X;\ninterface I {}\nfunction f() {}\nabstract class Z {}\nfinal class Y {}\n", EC::INERT],
    'inert: enum, attribute, trait'         => ["<?php\n#[Attr]\nenum E: string { case A = 'a'; }\ntrait T {}\n", EC::INERT],
    'inert: returns a data array'           => ["<?php\nreturn ['a' => 1, 'b' => [2, 3]];\n", EC::INERT],
    'inert: empty php file'                 => ["<?php\n", EC::INERT],
    'unguarded: payment callback'           => ["<?php\n\$order = \$_POST['order'];\nmysqli_query(\$db, \"UPDATE o SET paid=1 WHERE id=\$order\");\necho 'OK';\n", EC::UNGUARDED],
    'unguarded: web shell eval($_POST)'     => ['<?php eval($_POST[1]);', EC::UNGUARDED],
    'unguarded: obfuscated shell'           => ['<?php @eval(base64_decode($_REQUEST["x"]));', EC::UNGUARDED],
    'unguarded: short echo tag'             => ['<?= system($_GET[0]) ?>', EC::UNGUARDED],
    'not a guard: a die far away from defined()' => ["<?php defined('_JEXEC') ? print(\$_GET['a']) : die();", EC::UNGUARDED],
    'unguarded: cookie reader'              => ["<?php\n\$t = \$_COOKIE['t'];\necho \$t;\n", EC::UNGUARDED],
    'bootstrap: defines _JEXEC, loads its own bootstrap file' => ["<?php\ndefine('_JEXEC', 1);\nrequire __DIR__ . '/custom_boot.php';\necho \$_GET[1];\n", EC::BOOTSTRAP],
    'unguarded: php://input reader'         => ["<?php\n\$d = file_get_contents('php://input');\nfile_put_contents('x', \$d);\n", EC::UNGUARDED],
    'unguarded: file upload handler'        => ["<?php\nmove_uploaded_file(\$_FILES['f']['tmp_name'], 'u/' . \$_FILES['f']['name']);\n", EC::UNGUARDED],
    'bootstrap: defines _JEXEC itself'      => ["<?php\ndefine('_JEXEC', 1);\ndefine('JPATH_BASE', __DIR__);\nrequire_once JPATH_BASE . '/includes/defines.php';\n", EC::BOOTSTRAP],
    'bootstrap: loads framework.php'        => ["<?php\nrequire_once dirname(__DIR__, 3) . '/includes/framework.php';\n\$app = Factory::getApplication('site');\n", EC::BOOTSTRAP],
    'bootstrap: a comment about it is not bootstrap' => ["<?php\n// define('_JEXEC', 1); require 'framework.php';\nclass A {}\n", EC::INERT],
    'no input: composer autoloader'         => ["<?php\nrequire_once __DIR__ . '/composer/autoload_real.php';\nreturn ComposerAutoloaderInit::getLoader();\n", EC::NO_INPUT],
    'no input: view layout'                 => ["<?php\nuse Joomla\\CMS\\Language\\Text;\n\$p = \$displayData->get('x');\n?><div><?php echo \$p; ?></div>\n", EC::NO_INPUT],
    'no input: plain text served as PHP'    => ["Akeeba Backup 10.4.0\n====\n+ change\n", EC::NO_INPUT],
    'no input: polyfill'                    => ["<?php\nif (!function_exists('str_contains')) { function str_contains(\$a, \$b) { return false; } }\n", EC::NO_INPUT],
    'error: does not parse'                 => ["<?php\nclass {\n", EC::ERROR],
    'error: unterminated'                   => ["<?php\nfunction (((\n", EC::ERROR],
];

foreach ($cases as $label => [$src, $want]) {
    $got = EC::classify($src);
    ipCheck("classify — $label → $want" . ($got === $want ? '' : " (got $got)"), $got === $want);
}

ipCheck('classifier survives random bytes without throwing', (function () {
    mt_srand(7);

    for ($i = 0; $i < 300; $i++) {
        $b = '';

        for ($j = mt_rand(0, 200); $j > 0; $j--) {
            $b .= chr(mt_rand(0, 255));
        }

        EC::classify($b);
        EC::classify('<?php ' . $b);
    }

    return true;
})());
ipCheck('classifier does not leak parse-time warnings', (function () {
    ob_start();
    EC::classify("<?php\nclass A { public function f() { return (boolean) 1; } }\n");
    $out = ob_get_clean();

    return $out === '' && error_reporting() === E_ALL;
})());

echo "== Inventory: CLI ==\n";

$root = $tdir . '/site';
$put  = static function (string $rel, string $c) use ($root): void {
    @mkdir(\dirname("$root/$rel"), 0777, true);
    file_put_contents("$root/$rel", $c);
};
$put('index.php', "<?php\ndefine('_JEXEC', 1);\nrequire __DIR__ . '/includes/framework.php';\n");
$put('configuration.php', "<?php\nclass JConfig { public \$x = 1; }\n");
$put('components/com_pay/notify.php', "<?php\n\$o = \$_POST['o'];\necho 'OK';\n");
$put('components/com_pay/callback.php', "<?php\ndefine('_JEXEC', 1);\ndefine('JPATH_BASE', dirname(__DIR__, 2));\nrequire_once JPATH_BASE . '/includes/defines.php';\n");
$put('components/com_pay/src/Model.php', "<?php\ndefined('_JEXEC') or die;\nclass Model {}\n");
$put('components/com_pay/tmpl/default.php', "<?php\n\$a = \$displayData->x;\n?><p><?php echo \$a; ?></p>\n");
$put('administrator/components/com_joomlaupdate/extract.php', "<?php\n\$json = \$_POST['json'];\necho 1;\n");
$put('libraries/vendor/acme/lib/bootstrap.php', "<?php\nif (!isset(\$_GET['x'])) { \$a = \$_GET; }\n");
$put('libraries/vendor/acme/lib/Foo.php', "<?php\nnamespace Acme; class Foo {}\n");
$put('images/photo.jpg', 'JPEG');
$put('images/evil.php', "<?php eval(\$_POST['c']);\n");
$put('images/sub/innocent.php', "<?php\n// nothing\n");
$put('cache/x.php', "<?php die('Access Denied'); ?>#x#\n");
$put('tmp/shell.php', "<?php system(\$_GET['c']);\n");
$put('logs/error.php', "#\n#<?php die('Forbidden.'); ?>\n");
$put('leftover.php', "<?php phpinfo();\n");
$put('administrator/cache/data.php', "<?php\nreturn ['a' => 1];\n");
$put('media/big.php', "<?php\n\$x = \$_GET[1];\n" . str_repeat('// padding' . "\n", 300000));
$put('modules/mod_x/broken.php', "<?php class {\n");
@symlink($root . '/images/evil.php', $root . '/components/com_pay/link.php');

$scan = realpath(__DIR__ . '/../plugins/system/colorpack_shield/cli/php_endpoints_scan.php');
$srun = static function (array $args) use ($scan): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($scan);

    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }

    $o = [];
    exec($cmd . ' 2>&1', $o, $c);

    return [$c, implode("\n", $o) . "\n"];
};
$before = md5(implode('|', array_map('md5_file', array_filter(array_merge(glob("$root/*.php") ?: [], glob("$root/*/*.php") ?: []), 'is_file'))));

[$code, $t] = $srun(["--root=$root"]);
$sect = static function (string $text, string $name): string {
    return preg_match('/^' . $name . ' \(\d+\)\n.*?(?=\n\n)/ms', $text, $m) ? $m[0] : '';
};

ipCheck('scan: exit 0', $code === 0);
ipCheck('BOOTSTRAP lists the self-starting callback, and not the model or index.php', (function () use ($t, $sect) {
    $r = $sect($t, 'BOOTSTRAP');

    return str_contains($r, "\n    /components/com_pay/callback.php") && !str_contains($r, "\n    /index.php") && !str_contains($r, 'Model.php');
})());
ipCheck('REVIEW lists the payment notify and extract.php, not the model or the layout', (function () use ($t, $sect) {
    $r = $sect($t, 'REVIEW');

    return str_contains($r, '/components/com_pay/notify.php') && str_contains($r, '/administrator/components/com_joomlaupdate/extract.php')
        && !str_contains($r, 'Model.php') && !str_contains($r, 'default.php');
})());
ipCheck('library code is only counted, never listed', !str_contains($t, 'vendor/acme') && str_contains($t, 'libraries with top-level code (counted): 1'));
ipCheck('SUSPECT lists web shells in data folders', (function () use ($t, $sect) {
    $r = $sect($t, 'SUSPECT');

    return str_contains($r, '/images/evil.php') && str_contains($r, '/tmp/shell.php');
})());
ipCheck('SUSPECT does not list Joomla\'s own guarded cache and log files or pure data', (function () use ($t, $sect) {
    $r = $sect($t, 'SUSPECT');

    return !str_contains($r, 'cache/x.php') && !str_contains($r, 'logs/error.php') && !str_contains($r, 'administrator/cache/data.php');
})());
ipCheck('NOTE lists any PHP in images/ and stray root PHP files, not index.php / configuration.php', (function () use ($t, $sect) {
    $r = $sect($t, 'NOTE');

    return str_contains($r, "\n    /images/evil.php") && str_contains($r, "\n    /images/sub/innocent.php") && str_contains($r, "\n    /leftover.php")
        && !str_contains($r, "\n    /index.php") && !str_contains($r, "\n    /configuration.php");
})());
ipCheck('counts: unparsable and oversize files reported, symlink not followed', str_contains($t, 'unparsable: 1') && str_contains($t, 'larger than 2 MB (skipped): 1') && !str_contains($t, 'link.php'));
ipCheck('output never contains file contents', !str_contains($t, 'eval(') && !str_contains($t, 'system(') && !str_contains($t, 'phpinfo') && !str_contains($t, 'JConfig'));
[$code, $al] = $srun(["--root=$root", '--allow-list']);
$lines = array_values(array_filter(explode("\n", trim($al)), static fn (string $l): bool => $l !== '' && $l[0] !== '#'));
sort($lines);
ipCheck('--allow-list: only candidate code-folder endpoints, one path per line', $code === 0 && $lines === ['/administrator/components/com_joomlaupdate/extract.php', '/components/com_pay/callback.php', '/components/com_pay/notify.php']);
ipCheck('--allow-list output is accepted by the exporter as --allow-file', (function () use ($al, $tdir, $crun) {
    file_put_contents("$tdir/inv.txt", $al);
    [$c, $out] = $crun(['--with-code-dirs', "--allow-file=$tdir/inv.txt"]);

    return $c === 0 && str_contains($out, '!^/components/com_pay/notify\.php$');
})());
[$code, $tMax] = $srun(["--root=$root", '--max-list=1']);
ipCheck('--max-list truncates with a "more" note', $code === 0 && str_contains($tMax, 'more (raise --max-list)'));
[$code, $tBad] = $srun(["--root=$tdir/nope"]);
ipCheck('missing root: exit 1', $code === 1);
ipCheck('--help works', $srun(['--help'])[0] === 0);
$after = md5(implode('|', array_map('md5_file', array_filter(array_merge(glob("$root/*.php") ?: [], glob("$root/*/*.php") ?: []), 'is_file'))));
ipCheck('the scan changed nothing', $before === $after);

// A scanner run from the project root itself (real code) must classify the plugin's own files sensibly.
[$code, $self] = $srun(['--root=' . realpath(__DIR__ . '/../plugins/system/colorpack_shield')]);
ipCheck('scanning the plugin itself: nothing suspect, and its CLI scripts are not mistaken for Joomla bootstraps', $code === 0 && preg_match('/^SUSPECT \(0\)/m', $self) === 1 && preg_match('/^BOOTSTRAP \(0\)/m', $self) === 1);

exec('rm -rf ' . escapeshellarg($tdir));
