<?php
/**
 * nginx in front of Apache, like the HelioAdmin / HestiaCP stack: nginx answers
 * files whose extension is on its "static" list itself and proxies the rest to
 * Apache (+ php-cgi). The exporters' output is applied to BOTH servers and every
 * URL is requested with the exact path unchanged. Skipped, with a notice, where
 * nginx, Apache or php-cgi is missing. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "== nginx → Apache rig: both layers of the path policy ==\n";

$ngx = trim((string) @shell_exec('command -v nginx 2>/dev/null'));

if ($ngx === '' && is_executable('/Applications/MAMP/Library/sbin/nginx')) {
    $ngx = '/Applications/MAMP/Library/sbin/nginx';
}

$httpd  = trim((string) @shell_exec('command -v httpd 2>/dev/null')) ?: trim((string) @shell_exec('command -v apache2 2>/dev/null'));
$phpcgi = trim((string) @shell_exec('command -v php-cgi 2>/dev/null'));
$perl   = trim((string) @shell_exec('command -v perl 2>/dev/null'));
$mods   = is_dir('/usr/libexec/apache2') ? '/usr/libexec/apache2' : '';

if ($ngx === '' || $httpd === '' || $perl === '' || $phpcgi === '' || $mods === '' || !is_file($mods . '/mod_rewrite.so')) {
    echo "  SKIPPED: needs nginx, httpd (macOS module layout) and php-cgi; the exporter text is still unit-tested.\n";

    return;
}

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Waf/Rules/PathRules.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Export/ApachePathPolicy.php';
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Export/NginxPathPolicy.php';

use Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy;
use Colorpack\Plugin\System\ColorpackShield\Export\NginxPathPolicy;

$rig = sys_get_temp_dir() . '/cps-nginx-' . bin2hex(random_bytes(4));
$www = $rig . '/www';
mkdir($rig . '/logs', 0777, true);
mkdir($rig . '/cgi');
mkdir($rig . '/nginx');
symlink($phpcgi, $rig . '/cgi/php-cgi');

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
$put('README.txt', 'JOOMLA-README');
$put('htaccess.txt', 'HTACCESS-TXT');
$put('joomla.xml', '<x>JOOMLA-XML</x>');
$put('composer.json', '{"name":"COMPOSER-JSON"}');
$put('package.json', '{"name":"PACKAGE-JSON"}');
$put('administrator/manifests/files/joomla.xml', '<x>MANIFEST</x>');
$put('logs/error.log', 'LOGDATA');
$put('error_log', 'LOGDATA');
$put('robots.txt', 'User-agent: *');
$put('sitemap.xml', '<urlset>SITEMAP</urlset>');
$put('templates/t/css/a.css', 'body{}');
$put('media/yootheme/cache/ab/hero-9f8e7d6c.webp', 'WEBP');
$put('media/vendor/jquery/js/jquery.min.js', 'JQ');
$put('manifest.json', '{"name":"WEBAPP-MANIFEST"}');
foreach (['extract', 'restore', 'finalisation'] as $f) {
    $put("administrator/components/com_joomlaupdate/$f.php", '<?php echo "ENDPOINT-OK";');
}
$put('components/com_pay/notify.php', '<?php echo "PAY-OK";');
$put('components/com_x/other.php', '<?php echo "OTHER-DIRECT";');
$put('plugins/system/x/x.php', '<?php echo "PLUGIN-DIRECT";');

$free = static function (): int {
    $s = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
    $p = (int) substr(strrchr((string) stream_socket_get_name($s, false), ':'), 1);
    fclose($s);

    return $p;
};
$aport = $free();
$nport = $free();

// Apache (with the Apache half of the policy in .htaccess).
file_put_contents($rig . '/httpd.conf', <<<CONF
ServerRoot "/usr"
PidFile "$rig/httpd.pid"
Listen 127.0.0.1:$aport
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
ErrorLog "$rig/logs/apache-error.log"
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
ScriptAlias /php-cgi-bin/ "$rig/cgi/"
Action php-script /php-cgi-bin/php-cgi
<Directory "$rig/cgi">
    Require all granted
    Options +ExecCGI
</Directory>
CONF);

$joomlaRules = "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule .* index.php [L]\n</IfModule>\n";

// nginx: static list like HestiaCP's proxy templates (served from disk, falls back to Apache), the rest proxied.
$static = 'css|htm|html|js|mjs|json|xml|gif|ico|jpg|jpeg|png|svg|webp|woff|woff2|ttf|otf|txt|csv|pdf|zip|tar|gz|rar|7z';
file_put_contents($rig . '/nginx/nginx.conf', <<<CONF
worker_processes 1;
daemon off;
pid $rig/nginx.pid;
error_log $rig/logs/nginx-error.log warn;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $rig/nginx/body;
    proxy_temp_path $rig/nginx/proxy;
    fastcgi_temp_path $rig/nginx/fcgi;
    uwsgi_temp_path $rig/nginx/uwsgi;
    scgi_temp_path $rig/nginx/scgi;
    types { text/plain txt; application/json json; text/css css; image/webp webp; }
    default_type application/octet-stream;
    server {
        listen 127.0.0.1:$nport;
        server_name localhost;
        root $www;
        include $rig/nginx/policy.conf;
        location ~* ^.+\.($static)\$ {
            try_files \$uri @fallback;
        }
        location / {
            proxy_pass http://127.0.0.1:$aport;
            proxy_set_header Host \$host;
        }
        location @fallback {
            proxy_pass http://127.0.0.1:$aport;
            proxy_set_header Host \$host;
        }
    }
}
CONF);
file_put_contents($rig . '/nginx/policy.conf', "# empty\n");
file_put_contents($www . '/.htaccess', ApachePathPolicy::render() . "\n" . $joomlaRules);

exec(escapeshellarg($ngx) . ' -t -p ' . escapeshellarg($rig . '/nginx/') . ' -c ' . escapeshellarg($rig . '/nginx/nginx.conf') . ' 2>&1', $tOut, $tCode);
ipCheck('rig: the throw-away nginx configuration is valid', $tCode === 0);

if ($tCode !== 0) {
    echo '    ' . implode("\n    ", $tOut) . "\n";
    exec('rm -rf ' . escapeshellarg($rig));

    return;
}

$start = static function (array $cmd, int $port) use ($rig): mixed {
    $proc = proc_open(array_merge(['perl', '-e', 'use POSIX; POSIX::setsid(); exec @ARGV or die'], $cmd), [['file', '/dev/null', 'r'], ['file', $rig . '/logs/out.txt', 'a'], ['file', $rig . '/logs/out.txt', 'a']], $pipes);

    for ($i = 0; $i < 60; $i++) {
        usleep(100000);
        $c = @fsockopen('127.0.0.1', $port, $e1, $e2, 0.2);

        if ($c) {
            fclose($c);

            return $proc;
        }
    }

    return $proc;
};

$aproc = $start([$httpd, '-f', $rig . '/httpd.conf', '-D', 'FOREGROUND'], $aport);
$nproc = $start([$ngx, '-p', $rig . '/nginx/', '-c', $rig . '/nginx/nginx.conf'], $nport);

$http = static function (string $path) use ($nport): array {
    $c = @fsockopen('127.0.0.1', $nport, $e1, $e2, 3);

    if (!$c) {
        return [0, ''];
    }

    fwrite($c, "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $raw = (string) stream_get_contents($c);
    fclose($c);

    return [preg_match('~^HTTP/\S+ (\d{3})~', $raw, $m) ? (int) $m[1] : 0, (string) substr($raw, (int) strpos($raw, "\r\n\r\n") + 4)];
};

$up = $http('/')[0] === 200;
ipCheck('rig: nginx and Apache are up and the home page works through nginx', $up);

$reload = static function (string $policy) use ($rig): void {
    file_put_contents($rig . '/nginx/policy.conf', $policy);
    $pid = (int) trim((string) @file_get_contents($rig . '/nginx.pid'));
    exec('kill -HUP ' . $pid);
    usleep(500000);
};

if ($up) {
    $mustPass = [
        '/' => 'JOOMLA-INDEX', '/index.php' => 'JOOMLA-INDEX', '/index.php/component/content/article/12-news' => 'JOOMLA-INDEX', '/some-sef-page' => 'JOOMLA-INDEX',
        '/th/%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7' => 'JOOMLA-INDEX', '/some/page-with--double--hyphen' => 'JOOMLA-INDEX', '/administrator/index.php' => 'JOOMLA-ADMIN',
        '/robots.txt' => 'User-agent', '/sitemap.xml' => 'SITEMAP', '/manifest.json' => 'WEBAPP-MANIFEST', '/images/photo.jpg' => 'JPEGDATA',
        '/.well-known/acme-challenge/tok' => 'ACME-TOKEN', '/.well-known/acme-challenge/nonexistent' => 'JOOMLA-INDEX',
        '/templates/t/css/a.css' => 'body', '/media/yootheme/cache/ab/hero-9f8e7d6c.webp' => 'WEBP', '/media/vendor/jquery/js/jquery.min.js' => 'JQ',
        '/administrator/components/com_joomlaupdate/extract.php' => 'ENDPOINT-OK', '/administrator/components/com_joomlaupdate/restore.php' => 'ENDPOINT-OK',
        '/administrator/components/com_joomlaupdate/finalisation.php' => 'ENDPOINT-OK', '/index.php?x=../../etc/passwd' => 'JOOMLA-INDEX',
    ];
    // Static-looking files the plugin-level rules must stop (they never reach Apache's .htaccess).
    $staticLeaks = ['/composer.json', '/package.json', '/joomla.xml', '/administrator/manifests/files/joomla.xml', '/README.txt', '/htaccess.txt', '/backup.zip'];
    $mustBlock   = array_merge($staticLeaks, [
        '/.env', '/.git/config', '/a/../.env', '/.htaccess', '/images/.hidden', '/%2eenv',
        '/images/real.php', '/images/REAL.PHP', '/images/%72eal.php', '/images/%69mages/real.php', '/IMAGES/real.php', '/images/real.php/extra', '/images/real.php.jpg', '/images/real.php.', '/images/real.php%20', '/tmp/x.phtml', '/images/a/../real.php',
        '/configuration.php', '/configuration.php.bak', '/dump.sql', '/logs/error.log', '/error_log', '/administrator/logs/error.log', '/nonexistent.bak',
    ]);

    // Odd encodings: nginx or Apache may answer 400/403/404 themselves, but never 200 and never a leak.
    $oddities = ['/images/real.php%00.jpg', '/%2e%2e/.env', '/a%2f..%2f.env', '/..%2f.env', '/images/real.php%2f', '/.env%20', '/.env.', '/.ENV', '/%2E%2Eenv', '/images/%2e%2e/real.php', '//.env', '/./.env', '/.env/', '/composer.json%00.txt', '/COMPOSER.JSON', '/composer%2ejson'];

    // 1. Without the nginx block the static leftovers are really exposed: Apache's .htaccess (already active) never sees them.
    $reload("# empty\n");
    $exposed = [];

    foreach ($staticLeaks as $p) {
        if ($http($p)[0] === 200) {
            $exposed[] = $p;
        }
    }

    ipCheck('baseline: with only the Apache policy (nginx has none), nginx still serves ' . count($exposed) . ' of ' . count($staticLeaks) . ' static leftovers (the gap the nginx block closes)' . ($exposed ? '' : ' — NONE EXPOSED, rig is not showing the gap'), count($exposed) >= 4);
    echo '    exposed through nginx: ' . implode(' ', $exposed) . "\n";

    // 2. From here on Apache has NO policy of its own: the nginx block must be self-sufficient.
    file_put_contents($www . '/.htaccess', $joomlaRules);

    $phase = static function (string $label, string $policy, array $codeBlocked, array $codePass) use ($reload, $http, $mustPass, $mustBlock, $oddities): void {
        $reload($policy);
        $bad = [];

        foreach ($mustPass as $path => $needle) {
            [$st, $body] = $http($path);

            if ($st !== 200 || !str_contains($body, $needle)) {
                $bad[] = "$path => $st";
            }
        }

        ipCheck("$label: all " . count($mustPass) . ' legitimate URLs still work' . ($bad ? ' — BROKEN: ' . implode(', ', $bad) : ''), $bad === []);

        $miss = [];
        $leak = [];

        foreach ($mustBlock as $path) {
            [$st, $body] = $http($path);

            if ($st !== 403) {
                $miss[] = "$path => $st";
            }

            foreach (['SHELL-EXECUTED', 'SECRET=1', 'CONFIG', 'JOOMLA-README', 'HTACCESS-TXT', 'JOOMLA-XML', 'COMPOSER-JSON', 'PACKAGE-JSON', 'MANIFEST', 'LOGDATA'] as $secret) {
                if (str_contains($body, $secret)) {
                    $leak[] = $path;
                }
            }
        }

        ipCheck("$label: all " . count($mustBlock) . ' dangerous URLs get 403' . ($miss ? ' — NOT REFUSED: ' . implode(', ', $miss) : ''), $miss === []);
        ipCheck("$label: nothing dangerous was executed or served" . ($leak ? ' — LEAKED: ' . implode(', ', array_unique($leak)) : ''), $leak === []);

        $odd = [];

        foreach ($oddities as $path) {
            [$st, $body] = $http($path);

            // A 200 is only acceptable when the path really resolved to the front page (e.g. /images/%2e%2e/x → /x → index.php).
            if ((!in_array($st, [400, 403, 404], true) && !($st === 200 && str_contains($body, 'JOOMLA-INDEX'))) || preg_match('/SECRET=1|SHELL-EXECUTED|COMPOSER-JSON/', $body)) {
                $odd[] = "$path => $st";
            }
        }

        ipCheck("$label: " . count($oddities) . ' oddly encoded / cased variants are refused (or land on the front page), never served' . ($odd ? ' — ' . implode(', ', $odd) : ''), $odd === []);

        $codeBad = [];

        foreach ($codeBlocked as $path) {
            if ($http($path)[0] !== 403) {
                $codeBad[] = "$path (expected 403)";
            }
        }

        foreach ($codePass as $path) {
            if ($http($path)[0] !== 200) {
                $codeBad[] = "$path (expected 200)";
            }
        }

        ipCheck("$label: code-folder PHP requests behave as configured" . ($codeBad ? ' — ' . implode(', ', $codeBad) : ''), $codeBad === []);
    };

    $phase('nginx default policy', NginxPathPolicy::render(), [], ['/components/com_x/other.php', '/components/com_pay/notify.php']);
    $phase('nginx with code folders + exception', NginxPathPolicy::render(['/components/com_pay/notify.php'], true), ['/components/com_x/other.php', '/plugins/system/x/x.php', '/components/com_x/other.php/extra', '/COMPONENTS/COM_X/OTHER.PHP'], ['/components/com_pay/notify.php']);
    $phase('nginx with code folders + prefix exception', NginxPathPolicy::render(['/components/com_pay/'], true), ['/components/com_x/other.php', '/plugins/system/x/x.php'], ['/components/com_pay/notify.php']);

    // 3. Both layers together, as deployed.
    file_put_contents($www . '/.htaccess', ApachePathPolicy::render(['/components/com_pay/notify.php'], true) . "\n" . $joomlaRules);
    $phase('both layers', NginxPathPolicy::render(['/components/com_pay/notify.php'], true), ['/components/com_x/other.php', '/plugins/system/x/x.php'], ['/components/com_pay/notify.php']);

    // nginx must not have logged an error while serving, and must still accept the generated block syntactically.
    $nerr = (string) @file_get_contents($rig . '/logs/nginx-error.log');
    ipCheck('nginx reported no configuration or rewrite error while serving', !preg_match('/\[(?:emerg|alert|crit)\]|rewrite or internal redirection cycle/', $nerr));
    $aerr = (string) @file_get_contents($rig . '/logs/apache-error.log');
    ipCheck('Apache reported no .htaccess error while serving', !preg_match('/Invalid command|bad flag delimiters|\.htaccess:/', $aerr));
}

foreach ([$nproc ?? null, $aproc ?? null] as $p) {
    if (is_resource($p)) {
        proc_terminate($p);
        proc_close($p);
    }
}

exec('rm -rf ' . escapeshellarg($rig));
