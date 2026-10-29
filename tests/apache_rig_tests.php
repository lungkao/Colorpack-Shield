<?php
/**
 * The server-level half of the path policy, run against a REAL Apache (+ php-cgi):
 * the exporter's block is written to a throw-away document root and every URL
 * is requested with the exact path unchanged (raw sockets, no client-side
 * normalisation). Skipped, with a notice, where Apache or php-cgi is missing.
 * Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "== Apache rig: server-level path policy ==\n";

$httpd  = trim((string) @shell_exec('command -v httpd 2>/dev/null')) ?: trim((string) @shell_exec('command -v apache2 2>/dev/null'));
$phpcgi = trim((string) @shell_exec('command -v php-cgi 2>/dev/null'));
$perl   = trim((string) @shell_exec('command -v perl 2>/dev/null'));
$mods   = is_dir('/usr/libexec/apache2') ? '/usr/libexec/apache2' : '';

if ($httpd === '' || $perl === '' || $phpcgi === '' || $mods === '' || !is_file($mods . '/mod_rewrite.so')) {
    echo "  SKIPPED: needs httpd + php-cgi with the macOS module layout (/usr/libexec/apache2); the exporter text is still unit-tested.\n";

    return;
}

$rig = sys_get_temp_dir() . '/cps-apache-' . bin2hex(random_bytes(4));
$www = $rig . '/www';
mkdir($rig . '/logs', 0777, true);

$put = static function (string $rel, string $content) use ($www): void {
    $f = $www . '/' . $rel;
    @mkdir(\dirname($f), 0777, true);
    file_put_contents($f, $content);
};

$put('index.php', '<?php echo "JOOMLA-INDEX";');
$put('administrator/index.php', '<?php echo "JOOMLA-ADMIN";');
$put('images/photo.jpg', 'JPEGDATA');
$put('images/real.php', '<?php echo "SHELL-EXECUTED";');
$put('images/real.php.jpg', '<?php echo "SHELL-EXECUTED";');
$put('tmp/x.phtml', '<?php echo "SHELL-EXECUTED";');
$put('.env', 'SECRET=1');
$put('.git/config', '[core]');
$put('.well-known/acme-challenge/tok', 'ACME-TOKEN');
$put('backup.zip', 'ZIP');
$put('dump.sql', 'SQL');
$put('configuration.php', '<?php echo "CONFIG";');
$put('README.txt', 'Joomla');
$put('htaccess.txt', 'x');
$put('joomla.xml', '<x/>');
$put('administrator/manifests/files/joomla.xml', '<x/>');
$put('logs/error.log', 'log');
$put('error_log', 'log');
$put('robots.txt', 'User-agent: *');
$put('templates/t/css/a.css', 'body{}');
$put('media/yootheme/cache/ab/hero-9f8e7d6c.webp', 'WEBP');
$put('media/vendor/jquery/js/jquery.min.js', 'JQ');
foreach (['extract', 'restore', 'finalisation'] as $f) {
    $put("administrator/components/com_joomlaupdate/$f.php", '<?php echo "ENDPOINT-OK";');
}
$put('components/com_pay/notify.php', '<?php echo "PAY-OK";');
$put('components/com_x/other.php', '<?php echo "OTHER-DIRECT";');
$put('plugins/system/x/x.php', '<?php echo "PLUGIN-DIRECT";');

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Waf/Rules/PathRules.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Export/ApachePathPolicy.php';

use Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy;

// Joomla-style front controller rewrite, after our block.
$joomlaRules = "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule .* index.php [L]\n</IfModule>\n";

$sock = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$port = (int) substr(strrchr((string) stream_socket_get_name($sock, false), ':'), 1);
fclose($sock);

$conf = <<<CONF
ServerRoot "/usr"
PidFile "$rig/httpd.pid"
Listen 127.0.0.1:$port
ServerName localhost
LoadModule mpm_prefork_module $mods/mod_mpm_prefork.so
LoadModule authz_core_module $mods/mod_authz_core.so
LoadModule unixd_module $mods/mod_unixd.so
LoadModule dir_module $mods/mod_dir.so
LoadModule alias_module $mods/mod_alias.so
LoadModule mime_module $mods/mod_mime.so
LoadModule rewrite_module $mods/mod_rewrite.so
LoadModule actions_module $mods/mod_actions.so
LoadModule cgi_module $mods/mod_cgi.so
LoadModule env_module $mods/mod_env.so
ErrorLog "$rig/logs/error.log"
LogLevel warn
DocumentRoot "$www"
DirectoryIndex index.php
<Directory "$www">
    AllowOverride All
    Require all granted
    Options +FollowSymLinks +ExecCGI
</Directory>
SetEnv REDIRECT_STATUS 200
AddHandler php-script .php
ScriptAlias /php-cgi-bin/ "{$rig}/cgi/"
Action php-script /php-cgi-bin/php-cgi
<Directory "{$rig}/cgi">
    Require all granted
    Options +ExecCGI
</Directory>
CONF;
mkdir($rig . '/cgi');
symlink($phpcgi, $rig . '/cgi/php-cgi');
file_put_contents($rig . '/httpd.conf', $conf);

exec(escapeshellarg($httpd) . ' -t -f ' . escapeshellarg($rig . '/httpd.conf') . ' 2>&1', $tOut, $tCode);
ipCheck('rig: the throw-away Apache configuration is valid', $tCode === 0);

if ($tCode !== 0) {
    echo '    ' . implode("\n    ", $tOut) . "\n";
    exec('rm -rf ' . escapeshellarg($rig));

    return;
}

// Apache signals its whole process group on shutdown: give it a session of its own so the test run survives.
$proc = proc_open(['perl', '-e', 'use POSIX; POSIX::setsid(); exec @ARGV or die', $httpd, '-f', $rig . '/httpd.conf', '-D', 'FOREGROUND'], [['file', '/dev/null', 'r'], ['file', $rig . '/logs/out.txt', 'w'], ['file', $rig . '/logs/out.txt', 'a']], $pipes);
$up   = false;

for ($i = 0; $i < 50 && !$up; $i++) {
    usleep(100000);
    $c = @fsockopen('127.0.0.1', $port, $e1, $e2, 0.2);

    if ($c) {
        fclose($c);
        $up = true;
    }
}

ipCheck('rig: Apache started', $up);

/** @return array{0:int,1:string}  status, body */
$http = static function (string $path) use ($port): array {
    $c = @fsockopen('127.0.0.1', $port, $e1, $e2, 3);

    if (!$c) {
        return [0, ''];
    }

    fwrite($c, "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $raw = stream_get_contents($c);
    fclose($c);
    $status = preg_match('~^HTTP/\S+ (\d{3})~', (string) $raw, $m) ? (int) $m[1] : 0;
    $body   = (string) substr((string) $raw, (int) strpos((string) $raw, "\r\n\r\n") + 4);

    return [$status, $body];
};

if ($up) {
    $mustPass = [
        '/' => 'JOOMLA-INDEX', '/index.php' => 'JOOMLA-INDEX', '/index.php/component/content/article/12-news' => 'JOOMLA-INDEX',
        '/some-sef-page' => 'JOOMLA-INDEX', '/th/%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7' => 'JOOMLA-INDEX', '/some/page-with--double--hyphen' => 'JOOMLA-INDEX',
        '/administrator/index.php' => 'JOOMLA-ADMIN', '/robots.txt' => 'User-agent', '/images/photo.jpg' => 'JPEGDATA',
        '/.well-known/acme-challenge/tok' => 'ACME-TOKEN', '/.well-known/acme-challenge/nonexistent' => 'JOOMLA-INDEX',
        '/templates/t/css/a.css' => 'body', '/media/yootheme/cache/ab/hero-9f8e7d6c.webp' => 'WEBP', '/media/vendor/jquery/js/jquery.min.js' => 'JQ',
        '/administrator/components/com_joomlaupdate/extract.php' => 'ENDPOINT-OK', '/administrator/components/com_joomlaupdate/restore.php' => 'ENDPOINT-OK',
        '/administrator/components/com_joomlaupdate/finalisation.php' => 'ENDPOINT-OK', '/index.php?x=../../etc/passwd' => 'JOOMLA-INDEX',
    ];
    $mustBlock = [
        '/.env', '/.git/config', '/a/../.env', '/.htaccess', '/images/.hidden', '/%2eenv',
        '/images/real.php', '/images/REAL.PHP', '/images/%72eal.php', '/images/%69mages/real.php', '/IMAGES/real.php', '/images/real.php/extra', '/images/real.php.jpg', '/images/real.php.', '/images/real.php%20', '/tmp/x.phtml', '/images/a/../real.php',
        '/configuration.php', '/configuration.php.bak', '/README.txt', '/htaccess.txt', '/joomla.xml', '/administrator/manifests/files/joomla.xml',
        '/backup.zip', '/dump.sql', '/logs/error.log', '/error_log', '/administrator/logs/error.log', '/nonexistent.bak',
    ];
    $codeBlocked = ['/components/com_x/other.php', '/plugins/system/x/x.php', '/components/com_x/other.php/extra', '/COMPONENTS/COM_X/OTHER.PHP', '/components/com_pay/notify.php'];

    $phase = static function (string $label, string $block, array $codeExpectBlocked, array $codeExpectPass) use ($www, $joomlaRules, $http, $mustPass, $mustBlock): void {
        file_put_contents($www . '/.htaccess', $block . "\n" . $joomlaRules);
        clearstatcache();
        $bad = [];

        foreach ($mustPass as $path => $needle) {
            [$st, $body] = $http($path);

            if ($st !== 200 || !str_contains($body, $needle)) {
                $bad[] = "$path => $st";
            }
        }

        ipCheck("$label: all " . count($mustPass) . ' legitimate URLs still work' . ($bad ? ' — BROKEN: ' . implode(', ', $bad) : ''), $bad === []);

        $leak = [];
        $miss = [];

        foreach ($mustBlock as $path) {
            [$st, $body] = $http($path);

            if (str_contains($body, 'SHELL-EXECUTED') || str_contains($body, 'SECRET=1') || str_contains($body, 'CONFIG')) {
                $leak[] = $path;
            }

            if (getenv('CPS_RIG_DEBUG')) {
                echo "      $st $path\n";
            }

            if ($st !== 403) {
                $miss[] = "$path => $st";
            }
        }

        ipCheck("$label: all " . count($mustBlock) . ' dangerous URLs get 403' . ($miss ? ' — NOT REFUSED: ' . implode(', ', $miss) : ''), $miss === []);
        ipCheck("$label: nothing dangerous was executed or served" . ($leak ? ' — LEAKED: ' . implode(', ', $leak) : ''), $leak === []);

        $codeBad = [];

        foreach ($codeExpectBlocked as $path) {
            [$st] = $http($path);

            if ($st !== 403) {
                $codeBad[] = "$path => $st (expected 403)";
            }
        }

        foreach ($codeExpectPass as $path) {
            [$st] = $http($path);

            if ($st !== 200) {
                $codeBad[] = "$path => $st (expected 200)";
            }
        }

        ipCheck("$label: code-folder PHP requests behave as configured" . ($codeBad ? ' — ' . implode(', ', $codeBad) : ''), $codeBad === []);
    };

    // 1. Baseline: without our block the dangerous URLs really are exposed (the rig is not trivially "secure").
    file_put_contents($www . '/.htaccess', $joomlaRules);
    $exposed = 0;

    foreach (['/images/real.php' => 'SHELL-EXECUTED', '/.env' => 'SECRET=1', '/configuration.php.bak' => 'JOOMLA-INDEX', '/images/real.php.jpg' => 'SHELL-EXECUTED'] as $p => $needle) {
        $exposed += str_contains($http($p)[1], $needle) ? 1 : 0;
    }

    ipCheck('baseline without the policy: the shell executes, .env is readable (the rig can fail)', $exposed >= 3);

    if ($exposed < 3) {
        echo '    rig error log: ' . substr(str_replace("\n", "\n    ", (string) @file_get_contents($rig . '/logs/error.log')), -1500) . "\n";
    }

    // 2. Default block (class D off): data-dir shells and leftovers are stopped; code-folder PHP still reachable.
    $phase('default policy', ApachePathPolicy::render(), [], ['/components/com_x/other.php', '/components/com_pay/notify.php']);

    // 3. With class D and a per-site exception.
    $phase('with code folders + exception', ApachePathPolicy::render(['/components/com_pay/notify.php'], true), array_diff($codeBlocked, ['/components/com_pay/notify.php']), ['/components/com_pay/notify.php']);

    // 4. An exception given as a folder prefix.
    $phase('with code folders + prefix exception', ApachePathPolicy::render(['/components/com_pay/'], true), ['/components/com_x/other.php', '/plugins/system/x/x.php'], ['/components/com_pay/notify.php']);

    // 5. The generated block is accepted by Apache's own syntax check, and a stray directive cannot be smuggled in.
    ipCheck('Apache accepts the generated block syntactically (httpd -t with the rules loaded)', (function () use ($httpd, $rig) {
        exec(escapeshellarg($httpd) . ' -t -f ' . escapeshellarg($rig . '/httpd.conf') . ' 2>&1', $o, $c);

        return $c === 0;
    })());

    $errLog = (string) @file_get_contents($rig . '/logs/error.log');
    $syntaxOk = !preg_match('/Invalid command|RewriteRule: .*(bad|cannot compile)|Syntax error|\\.htaccess:/i', $errLog);
    ipCheck('Apache reported no .htaccess syntax error while serving', $syntaxOk);

    if (!$syntaxOk) {
        echo '    ' . str_replace("\n", "\n    ", substr($errLog, 0, 900)) . "\n";
    }
}

if (is_resource($proc)) {
    proc_terminate($proc);
    proc_close($proc);
}

exec('rm -rf ' . escapeshellarg($rig));
