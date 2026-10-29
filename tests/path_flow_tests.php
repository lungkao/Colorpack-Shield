<?php
/**
 * URL-path inspection through the real plugin class (with Joomla stand-ins):
 * settings, modes, trust levels, log output. Included by run.php after
 * path_tests.php (uses flow() / flowCheck() from plugin_flow_tests.php).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Joomla\CMS\Log\Log;

/** Like flow(), but fires the api application's event (onAfterApiRoute). */
function flowApi(array $params, array $server): array
{
    $_SERVER = array_merge(['REQUEST_URI' => '/api/index.php', 'CONTENT_TYPE' => ''], $server);
    $_GET    = [];
    $_POST   = [];
    $_COOKIE = [];
    $_FILES  = [];

    $subject = new stdClass();
    $plugin  = new Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield($subject, ['params' => $params]);
    $app    = new Colorpack\Tests\FakeApp('api');
    $plugin->setApplication($app);
    ob_start();

    try {
        $plugin->onAfterApiRoute(new Joomla\Event\Event('onAfterApiRoute'));
        $blocked = false;
    } catch (Colorpack\Tests\RequestEnded $e) {
        $blocked = true;
    }

    ob_end_clean();

    return ['blocked' => $blocked, 'status' => $app->headers['status'] ?? ''];
}

echo "== Plugin flow: URL path ==\n";

$peer = ['REMOTE_ADDR' => '198.51.100.1'];
$uri  = static fn (string $u, array $extra = []): array => $peer + ['REQUEST_URI' => $u] + $extra;
$logs = static fn (): string => implode("\n", Log::$messages);

Log::$messages = [];
flowCheck('ordinary SEF URL', flow([], $uri('/index.php/component/content/article/12-news')), false);
flowCheck('Thai URL (percent-encoded)', flow([], $uri('/th/%E0%B8%82%E0%B9%88%E0%B8%B2%E0%B8%A7')), false);
flowCheck('ACME challenge', flow([], $uri('/.well-known/acme-challenge/AbC-123_x')), false);
flowCheck('administrator login page, with a query string', flow([], $uri('/administrator/index.php?option=com_login'), [], [], 'administrator'), false);
ipCheck('…none of those wrote to the log', Log::$messages === []);

// Blocking.
Log::$messages = [];
flowCheck('path traversal', flow([], $uri('/index.php/%2e%2e/%2e%2e/etc/passwd?token=SECRET99')), true);
ipCheck('…answered 403', flow([], $uri('/a/../x'))['status'] === '403 Forbidden');
ipCheck('…logged as BLOCK with shield, rule, source and key', str_contains($logs(), 'BLOCK') && str_contains($logs(), 'shield=path rule=path_traversal src=PATH key=path'));
ipCheck('…and the query string is not in the log', !str_contains($logs(), 'SECRET99') && !str_contains($logs(), 'token='));
flowCheck('NUL byte in the path', flow([], $uri('/a%00.jpg')), true);
flowCheck('overlong UTF-8', flow([], $uri('/%c0%ae%c0%ae/x')), true);
flowCheck('script tag in the path', flow([], $uri('/index.php/%3Cscript%3Ealert(1)%3C/script%3E')), true);
flowCheck('UNION SELECT in the path', flow([], $uri('/x/union%20select%201')), true);
flowCheck('PHP tag in the path', flow([], $uri('/x/%3C%3Fphp%20phpinfo()')), true);
flowCheck('on the administrator app too', flow([], $uri('/administrator/..;/x'), [], [], 'administrator'), true);
flowCheck('on the api app too', flowApi([], $uri('/api/index.php/v1/%2e%2e/x')), true);
flowCheck('…and a normal api URL passes', flowApi([], $uri('/api/index.php/v1/content/articles')), false);
flowCheck('cover_api=0 leaves the api alone', flowApi(['cover_api' => 0], $uri('/api/index.php/v1/%2e%2e/x')), false);

// PHP_SELF / PATH_INFO carriers.
flowCheck('PHP_SELF with a script tag', flow([], $uri('/index.php', ['PHP_SELF' => '/index.php/"><script>alert(1)</script>'])), true);
flowCheck('PATH_INFO with a PHP tag', flow([], $uri('/index.php', ['PATH_INFO' => '/<?php system(1);'])), true);
flowCheck('normal PHP_SELF / PATH_INFO', flow([], $uri('/index.php/component/x', ['PHP_SELF' => '/index.php/component/x', 'PATH_INFO' => '/component/x'])), false);

// Detect-only findings.
Log::$messages = [];
flowCheck('/.env is only logged by default', flow([], $uri('/.env')), false);
ipCheck('…as DETECT, rule scanner_probe, with the path as sample', str_contains($logs(), 'DETECT') && str_contains($logs(), 'rule=scanner_probe') && str_contains($logs(), 'sample=/.env'));
ipCheck('…and not as BLOCK', !str_contains($logs(), 'BLOCK'));
Log::$messages = [];
flowCheck('PHP file in images/ is only logged (this release)', flow([], $uri('/images/shell.php')), false);
ipCheck('…rule php_in_data_dir', str_contains($logs(), 'rule=php_in_data_dir'));
Log::$messages = [];
flowCheck('/backup.zip is only logged', flow([], $uri('/backup.zip?x=1')), false);
ipCheck('…rule joomla_internal, query not logged', str_contains($logs(), 'rule=joomla_internal') && !str_contains($logs(), 'x=1'));
Log::$messages = [];
flowCheck('direct PHP in a component is only logged', flow([], $uri('/components/com_pay/notify.php')), false);
ipCheck('…rule direct_php_in_code', str_contains($logs(), 'rule=direct_php_in_code'));
Log::$messages = [];
flowCheck('Joomla Update extract.php is not reported', flow([], $uri('/administrator/components/com_joomlaupdate/extract.php')), false);
ipCheck('…nothing logged', Log::$messages === []);

Log::$messages = [];
flow([], $uri('//images/x.php/.env/backup.zip'));
ipCheck('at most 3 DETECT lines per request', substr_count($logs(), 'DETECT') === 3);

// Settings.
flowCheck('path_scan=0 turns the path shield off', flow(['path_scan' => 0], $uri('/a/../x')), false);
Log::$messages = [];
flowCheck('path_mode=log: traversal is only logged', flow(['path_mode' => 'log'], $uri('/a/../x')), false);
ipCheck('…as DETECT rule=path_traversal', str_contains($logs(), 'DETECT') && str_contains($logs(), 'rule=path_traversal'));
flowCheck('path_mode=block: a log-only finding blocks', flow(['path_mode' => 'block'], $uri('/images/x.php')), true);
flowCheck('path_mode=junk behaves like the default', flow(['path_mode' => 'nonsense'], $uri('/.env')), false);
flowCheck('path_probe_mode=block: scanner probe blocks', flow(['path_probe_mode' => 'block'], $uri('/.env')), true);
Log::$messages = [];
flowCheck('path_probe_mode=off: scanner probe ignored', flow(['path_probe_mode' => 'off'], $uri('/.env')), false);
ipCheck('…and not logged', Log::$messages === []);
flowCheck('path_probe_mode=block does not block ordinary pages', flow(['path_probe_mode' => 'block'], $uri('/index.php/component/content/article/12-news')), false);
flowCheck('phpMyAdmin is never a probe by default', flow(['path_probe_mode' => 'block'], $uri('/phpmyadmin/index.php')), false);
flowCheck('…unless the exemption list is changed', flow(['path_probe_mode' => 'block', 'path_tools_exempt' => "webmail\n"], $uri('/phpmyadmin/index.php')), true);
flowCheck('path_allow (prefix) exempts a payment callback in block mode', flow(['path_mode' => 'block', 'path_allow' => "/components/com_pay/notify.php\n"], $uri('/components/com_pay/notify.php')), false);
flowCheck('path_allow (regex with a comma) works', flow(['path_mode' => 'block', 'path_allow' => 're:^/components/shop/ipn[0-9]{1,3}\\.php$'], $uri('/components/shop/ipn42.php')), false);
flowCheck('…and only that path', flow(['path_mode' => 'block', 'path_allow' => 're:^/components/shop/ipn[0-9]{1,3}\\.php$'], $uri('/components/shop/other.php')), true);
flowCheck('path_allow does not exempt traversal', flow(['path_allow' => "/components/\n"], $uri('/components/../x')), true);
flowCheck('path_extra_deny blocks', flow(['path_extra_deny' => "/private/\n"], $uri('/private/report.pdf')), true);
flowCheck('path_extra_deny is ignored in log mode', flow(['path_extra_deny' => "/private/\n", 'path_mode' => 'log'], $uri('/private/report.pdf')), false);
flowCheck('cover_admin=0: no path checks in the administrator', flow(['cover_admin' => 0], $uri('/administrator/..;/x'), [], [], 'administrator'), false);
flowCheck('…but the site is still covered', flow(['cover_admin' => 0], $uri('/a/../x')), true);

// Trust levels (AUDIT.md C1 semantics).
$trust = ['allow_ips' => "203.0.113.5\n"];
flowCheck('trusted IP connecting directly skips path checks (full trust)', flow($trust, ['REMOTE_ADDR' => '203.0.113.5', 'REQUEST_URI' => '/a/../x']), false);
flowCheck('trusted IP learned from a Cloudflare header is still inspected (soft trust)',
    flow($trust, ['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5', 'REQUEST_URI' => '/a/../x']), true);

// Interplay with the other shields and the log.
flowCheck('the path step does not weaken parameter checks', flow([], $uri('/index.php?q=1'), ['q' => "1' UNION SELECT user,pass FROM x-- -"]), true);
Log::$messages = [];
flow([], $uri('/index.php?q=1'), ['q' => "1' UNION SELECT user,pass FROM x-- -"]);
ipCheck('…and that block is attributed to the parameter shield, not the path', str_contains($logs(), 'shield=sqli') && !str_contains($logs(), 'shield=path'));
flowCheck('a missing REQUEST_URI is not an error', flow([], $peer + ['REQUEST_URI' => '']), false);
flowCheck('the path step runs before the upload scan (an attack path + clean upload is blocked)', flow([], $uri('/a/../x'), [], ['f' => ['name' => 'a.txt', 'type' => 'text/plain', 'tmp_name' => '', 'error' => 4, 'size' => 0]]), true);

// Log lines cannot be forged.
Log::$messages = [];
flow([], $peer + ['HTTP_USER_AGENT' => "x\r\nBLOCK client=site shield=forged rule=fake", 'REQUEST_URI' => '/index.php']);
ipCheck('a hostile header value cannot add log lines (control bytes are neutralised)', Log::$messages !== [] && !preg_match('/[\r\n]/', implode('', Log::$messages)));
Log::$messages = [];
flow([], $uri("/x%0d%0aBLOCK client=site shield=forged"));
ipCheck('a hostile path cannot add log lines either', Log::$messages !== [] && !preg_match('/[\r\n]/', implode('', Log::$messages)));
