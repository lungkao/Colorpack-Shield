<?php
/**
 * The block kept in the site's .htaccess (HtaccessBlock): its text, the exact insert / remove
 * surgery, and — against a REAL Apache with mod_headers and mod_rewrite — that the file still
 * serves the site, adds the headers, and that removing the block restores the
 * original bytes. Skipped (with a notice) where Apache is missing. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Export\HtaccessBlock;

echo "== .htaccess block: text and surgery ==\n";

$hb = HtaccessBlock::render();
ipCheck('markers frame the block; the manual-paste notes are not in the file', str_starts_with($hb, HtaccessBlock::BEGIN . "\n") && str_ends_with($hb, HtaccessBlock::END . "\n") && !preg_match('/^# [123]\. /m', $hb));
ipCheck('path policy and the four headers are in; the X-Powered-By header is removed', str_contains($hb, 'RewriteRule (?:^|/)\.[^/]* - [F,L]') && !str_contains($hb, 'TRACE') && str_contains($hb, 'X-Content-Type-Options "nosniff"')
    && str_contains($hb, 'X-Frame-Options "SAMEORIGIN"') && str_contains($hb, 'Referrer-Policy') && str_contains($hb, 'Permissions-Policy') && str_contains($hb, 'unset X-Powered-By'));
ipCheck('only directives that need the same permission as Joomla\'s own rewrite rules: no Options, no ServerSignature, no php_flag, no CSP', !preg_match('/^\s*(Options|ServerSignature|php_flag|php_value|Header .*Content-Security-Policy)/mi', $hb));
ipCheck('every Header line is inside <IfModule mod_headers.c> (a host without it must not break)', (static function () use ($hb): bool {
    $in = false;

    foreach (explode("\n", $hb) as $l) {
        if (trim($l) === '<IfModule mod_headers.c>') {
            $in = true;
        } elseif (trim($l) === '</IfModule>') {
            $in = false;
        } elseif (preg_match('/^\s*Header\b/', $l) && !$in) {
            return false;
        }
    }

    return true;
})());
ipCheck('HSTS only when asked, only over https; headers can be left out', !str_contains($hb, 'Strict-Transport-Security') && str_contains(HtaccessBlock::render([], ['hsts' => true]), "\"expr=%{HTTPS} == 'on'\"") && !str_contains(HtaccessBlock::render([], ['headers' => false]), 'Header ') && str_contains(HtaccessBlock::render([], ['headers' => false]), 'RewriteRule'));
ipCheck('SameSite only when asked, only appends when a cookie has none yet, and still no CSP', (static function () use ($hb): bool {
    $on = HtaccessBlock::render([], ['samesite' => true]);

    return !str_contains($hb, 'SameSite') && str_contains($on, 'Header always edit Set-Cookie') && str_contains($on, 'SameSite=Lax')
        && str_contains($on, '(?!;\s*(?i:samesite)=)') && !preg_match('/Header .*Content-Security-Policy/i', $on);
})());
ipCheck('allow entries are validated (a hostile line never gets in) and class D is optional', (static function (): bool {
    try {
        HtaccessBlock::render(['/ok.php', "x\nRewriteRule . - [R]"]);

        return false;
    } catch (\InvalidArgumentException) {
        return str_contains(HtaccessBlock::render(['/components/com_pay/notify.php'], ['code_dirs' => true]), 'notify');
    }
})());

ipCheck('an allow entry that would cover the whole site ("/" alone) is refused, ordinary prefixes still work', (static function (): bool {
    foreach (['/', ' / ', '///'] as $bad) {
        try {
            \Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy::validate($bad);

            return false;
        } catch (\InvalidArgumentException) {
        }
    }

    return \Colorpack\Plugin\System\ColorpackShield\Export\ApachePathPolicy::validate('/components/com_pay/') === '/components/com_pay/';
})());

$hbJoomla = "##\n# Joomla htaccess\n##\n\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule .* index.php [L]\n</IfModule>\n";
$hbOnce   = HtaccessBlock::insert($hbJoomla, $hb);
ipCheck('insert puts the block at the TOP and leaves the rest byte for byte', str_starts_with($hbOnce, HtaccessBlock::BEGIN) && str_ends_with($hbOnce, $hbJoomla) && HtaccessBlock::has($hbOnce) && !HtaccessBlock::has($hbJoomla));
ipCheck('insert twice = once (idempotent), and a changed block REPLACES the old one', HtaccessBlock::insert($hbOnce, $hb) === $hbOnce && substr_count(HtaccessBlock::insert($hbOnce, HtaccessBlock::render([], ['hsts' => true])), HtaccessBlock::BEGIN) === 1
    && str_ends_with(HtaccessBlock::insert($hbOnce, HtaccessBlock::render([], ['hsts' => true])), $hbJoomla));
$samples = ['', "no trailing newline", "a\n", "\n\nstarts with blank lines\n", "line1\r\nline2\r\n", "# only a comment\n", $hbJoomla, "x\n\n\ny\n", str_repeat("RewriteRule a b\n", 200)];
$allBack = true;

foreach ($samples as $smp) {
    $allBack = $allBack && HtaccessBlock::remove(HtaccessBlock::insert($smp, $hb)) === $smp;
}

ipCheck('remove(insert(x)) gives back x exactly, for empty, CRLF, blank-first and long files', $allBack);
ipCheck('CRLF files stay CRLF', !str_contains(str_replace("\r\n", '', HtaccessBlock::insert("a\r\nb\r\n", $hb)), "\n") && !str_contains(str_replace("\r\n", '', HtaccessBlock::insert("a\r\nb\r\n", $hb)), "\r"));
ipCheck('remove on a file without the block changes nothing; a lone BEGIN marker is left alone', HtaccessBlock::remove($hbJoomla) === $hbJoomla && HtaccessBlock::remove("x\n" . HtaccessBlock::BEGIN . "\ny\n") === "x\n" . HtaccessBlock::BEGIN . "\ny\n" && !HtaccessBlock::has(HtaccessBlock::BEGIN . "\nonly begin"));
ipCheck('two old copies are both removed', HtaccessBlock::remove($hb . "\n" . $hb . "\n" . $hbJoomla) === $hbJoomla || !HtaccessBlock::has(HtaccessBlock::remove($hb . "\n" . $hb . "\n" . $hbJoomla)));
ipCheck('an administrator\'s own lines above and below the markers survive an update', (static function () use ($hb): bool {
    $f = "# mine above\n" . HtaccessBlock::insert("# mine below\n", $hb);

    return str_contains(HtaccessBlock::insert($f, $hb), "# mine above") && str_contains(HtaccessBlock::insert($f, $hb), "# mine below");
})());

echo "== .htaccess block: against a real Apache ==\n";

$httpd = trim((string) @shell_exec('command -v httpd 2>/dev/null')) ?: trim((string) @shell_exec('command -v apache2 2>/dev/null'));
$mods  = is_dir('/usr/libexec/apache2') ? '/usr/libexec/apache2' : '';
$perl  = trim((string) @shell_exec('command -v perl 2>/dev/null'));

if ($httpd === '' || $perl === '' || $mods === '' || !is_file($mods . '/mod_headers.so') || !is_file($mods . '/mod_rewrite.so')) {
    echo "  SKIPPED: needs httpd with mod_headers and mod_rewrite (macOS module layout); the text above is still unit-tested.\n";

    return;
}

$rig = sys_get_temp_dir() . '/cps-htb-' . bin2hex(random_bytes(4));
$www = $rig . '/www';
mkdir($rig . '/logs', 0777, true);
mkdir($www . '/images', 0777, true);
file_put_contents($www . '/index.html', 'JOOMLA-INDEX');
file_put_contents($www . '/images/photo.jpg', 'JPEGDATA');
file_put_contents($www . '/.env', 'SECRET');
file_put_contents($www . '/nosam.html', 'NOSAM');
file_put_contents($www . '/hassam.html', 'HASSAM');
$sock = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$port = (int) substr(strrchr((string) stream_socket_get_name($sock, false), ':'), 1);
fclose($sock);
file_put_contents($rig . '/httpd.conf', <<<CONF
ServerRoot "/usr"
PidFile "$rig/httpd.pid"
Listen 127.0.0.1:$port
ServerName localhost
LoadModule mpm_prefork_module $mods/mod_mpm_prefork.so
LoadModule authz_core_module $mods/mod_authz_core.so
LoadModule unixd_module $mods/mod_unixd.so
LoadModule dir_module $mods/mod_dir.so
LoadModule mime_module $mods/mod_mime.so
LoadModule rewrite_module $mods/mod_rewrite.so
LoadModule headers_module $mods/mod_headers.so
LoadModule alias_module $mods/mod_alias.so
ErrorLog "$rig/logs/error.log"
LogLevel warn
DocumentRoot "$www"
DirectoryIndex index.html
<Directory "$www">
    AllowOverride FileInfo
    Require all granted
</Directory>
<IfModule headers_module>
    Header always set Set-Cookie "a=1" "expr=%{REQUEST_URI} == '/nosam.html'"
    Header always set Set-Cookie "b=2; SameSite=Strict" "expr=%{REQUEST_URI} == '/hassam.html'"
</IfModule>
CONF);
exec(escapeshellarg($httpd) . ' -t -f ' . escapeshellarg($rig . '/httpd.conf') . ' 2>&1', $tOut, $tCode);

if ($tCode !== 0) {
    echo "  SKIPPED: the throw-away configuration did not load here:\n    " . implode("\n    ", $tOut) . "\n";
    exec('rm -rf ' . escapeshellarg($rig));

    return;
}

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

ipCheck('rig: Apache (AllowOverride FileInfo only, like a restricted host) started', $up);

$http = static function (string $method, string $path) use ($port): array {
    $c = @fsockopen('127.0.0.1', $port, $e1, $e2, 3);

    if (!$c) {
        return [0, '', ''];
    }

    fwrite($c, "$method $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $raw  = (string) stream_get_contents($c);
    fclose($c);
    $pos  = (int) strpos($raw, "\r\n\r\n");

    return [preg_match('~^HTTP/\S+ (\d{3})~', $raw) ? (int) substr($raw, 9, 3) : 0, substr($raw, 0, $pos), substr($raw, $pos + 4)];
};

if ($up) {
    [$s0, $h0] = $http('GET', '/');
    ipCheck('before: the page works and no hardening headers are sent', $s0 === 200 && !stripos($h0, 'X-Content-Type-Options'));
    file_put_contents($www . '/.htaccess', HtaccessBlock::insert($hbJoomla, HtaccessBlock::render([], ['hsts' => false])));
    [$s1, $h1, $b1] = $http('GET', '/');

    if ($s1 !== 200) {
        echo "    status $s1\n    apache error log: " . trim((string) @file_get_contents($rig . '/logs/error.log')) . "\n";
    }

    ipCheck('after: the page still works (no 500 from our directives on a FileInfo-only host)', $s1 === 200 && $b1 === 'JOOMLA-INDEX', "status $s1");
    ipCheck('after: the hardening headers are sent', stripos($h1, 'X-Content-Type-Options: nosniff') !== false && stripos($h1, 'X-Frame-Options: SAMEORIGIN') !== false && stripos($h1, 'Referrer-Policy: strict-origin-when-cross-origin') !== false && stripos($h1, 'Permissions-Policy:') !== false);
    ipCheck('after: no Strict-Transport-Security unless asked', stripos($h1, 'Strict-Transport-Security') === false);
    ipCheck('after: GET, HEAD and static files work', $http('HEAD', '/')[0] === 200 && $http('GET', '/images/photo.jpg')[2] === 'JPEGDATA');
    ipCheck('after: dot-files are refused by the path policy inside the same block', $http('GET', '/.env')[0] === 403);
    file_put_contents($www . '/.htaccess', HtaccessBlock::insert(file_get_contents($www . '/.htaccess'), HtaccessBlock::render([], ['hsts' => true])));
    ipCheck('with HSTS asked for: still 200; the header is not sent over plain http (only over https)', $http('GET', '/')[0] === 200 && stripos($http('GET', '/')[1], 'Strict-Transport-Security') === false);
    file_put_contents($www . '/.htaccess', HtaccessBlock::insert(file_get_contents($www . '/.htaccess'), HtaccessBlock::render([], ['samesite' => true])));
    [, $hNo]  = $http('GET', '/nosam.html');
    [, $hHas] = $http('GET', '/hassam.html');
    ipCheck('with SameSite asked for: appended to a cookie that had none', (bool) preg_match('/Set-Cookie:\s*a=1;\s*SameSite=Lax/i', $hNo));
    ipCheck('with SameSite asked for: a cookie that already chose one is left alone, not doubled', (bool) preg_match('/Set-Cookie:\s*b=2;\s*SameSite=Strict\s*$/im', $hHas) && !preg_match('/SameSite=Lax/i', $hHas));
    file_put_contents($www . '/.htaccess', HtaccessBlock::remove(file_get_contents($www . '/.htaccess')));
    [$s3, $h3] = $http('GET', '/');
    ipCheck('removed: the original file is back byte for byte, and the headers are gone', file_get_contents($www . '/.htaccess') === $hbJoomla && $s3 === 200 && !stripos($h3, 'X-Content-Type-Options'));
}

if (is_resource($proc)) {
    $st = proc_get_status($proc);
    @posix_kill($st['pid'], SIGTERM);
    proc_close($proc);
}

exec('rm -rf ' . escapeshellarg($rig));
