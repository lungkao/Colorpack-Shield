<?php
/**
 * WAF core tests: normalizer, path normalizer, request data, body parser,
 * every signature shield, header shield, path shield, and engine wiring.
 * Included by run.php, shares its ok() helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Net\ClientIpResolver;
use Colorpack\WP\ColorpackShield\Waf\BodyParser;
use Colorpack\WP\ColorpackShield\Waf\Normalizer;
use Colorpack\WP\ColorpackShield\Waf\PathNormalizer;
use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\RequestMeta;
use Colorpack\WP\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\WP\ColorpackShield\Waf\Rules\PathRules;
use Colorpack\WP\ColorpackShield\Waf\Shield\HeaderShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\PathShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\WP\ColorpackShield\Waf\WafEngine;
use Colorpack\WP\ColorpackShield\Waf\WafResult;

// --- Normalizer -------------------------------------------------------

ok('normalizer: decodes one layer', Normalizer::normalize('%3Cscript%3E') === '<script>');
ok('normalizer: decodes two layers', Normalizer::normalize('%253Cscript%253E') === '<script>');
ok('normalizer: strips NUL', Normalizer::normalize("a\0b") === 'ab');
ok('normalizer: collapses whitespace', Normalizer::normalize("a\t\n b") === 'a b');
ok('normalizer: lowercases', Normalizer::normalize('UNION') === 'union');
ok('normalizer: "+" is not a space', Normalizer::normalize('joomla+union+select+tutorial') === 'joomla+union+select+tutorial');

// --- PathNormalizer -----------------------------------------------------

$n = PathNormalizer::normalize('/wp-content/uploads/../../wp-config.php');
ok('pathnorm: traversal flagged', in_array(PathNormalizer::F_TRAVERSAL, $n['flags'], true));
ok('pathnorm: traversal resolved', $n['canonical'] === '/wp-config.php');

$n = PathNormalizer::normalize('/wp-admin/admin-ajax.php');
ok('pathnorm: clean path has no flags', $n['flags'] === []);
ok('pathnorm: clean canonical unchanged', $n['canonical'] === '/wp-admin/admin-ajax.php');

$n = PathNormalizer::normalize("/foo\x00bar");
ok('pathnorm: control byte flagged', in_array(PathNormalizer::F_CTRL, $n['flags'], true));

$n = PathNormalizer::normalize('/foo\\bar');
ok('pathnorm: backslash flagged and rewritten', in_array(PathNormalizer::F_BACKSLASH, $n['flags'], true) && $n['canonical'] === '/foo/bar');

// --- RequestData ----------------------------------------------------------

$rd = new RequestData(['GET' => ['q' => 'hello', 'nested' => ['a' => 'b']]]);
$items = $rd->items();
ok('requestdata: flattens scalars', count(array_filter($items, static fn ($i) => $i['key'] === 'q' && $i['value'] === 'hello')) === 1);
ok('requestdata: flattens nested arrays with dotted key', count(array_filter($items, static fn ($i) => $i['key'] === 'nested.a' && $i['value'] === 'b')) === 1);
ok('requestdata: not truncated for small input', $rd->truncated === false);

$deep = [];
$ref = &$deep;
for ($i = 0; $i < 10; $i++) {
    $ref['x'] = [];
    $ref = &$ref['x'];
}
$ref = 'leaf';
$rdDeep = new RequestData(['GET' => $deep]);
ok('requestdata: depth cap truncates', $rdDeep->truncated === true);

$long = str_repeat('a', RequestData::MAX_VALUE_LEN + 100);
$rdLong = new RequestData(['GET' => ['q' => $long]]);
$pieces = array_filter($rdLong->items(), static fn ($i) => $i['key'] === 'q');
ok('requestdata: long value is chunked into overlapping pieces', count($pieces) === 2);

// --- BodyParser -------------------------------------------------------

$bp = new BodyParser();
ok('bodyparser: empty body => no sources', $bp->parse('', '') === []);

$bp = new BodyParser();
$out = $bp->parse('{"title":"hello"}', 'application/json');
ok('bodyparser: JSON decoded as JSON source', isset($out['JSON']) && $out['JSON']['title'] === 'hello');

$bp = new BodyParser();
$out = $bp->parse('a=1&b=2', 'application/x-www-form-urlencoded');
ok('bodyparser: urlencoded form body skipped (already in $_POST)', $out === []);

$bp = new BodyParser();
$out = $bp->parse('<xml>not json</xml>', 'text/xml');
ok('bodyparser: non-JSON blob scanned under BODY', isset($out['BODY'][0]) && $out['BODY'][0] === '<xml>not json</xml>');

// --- SqliShield -------------------------------------------------------

$sqli = new SqliShield();
ok('sqli: union select blocked', $sqli->inspect(new RequestData(['GET' => ['id' => '1 UNION SELECT user,pass FROM wp_users']]))->matched);
ok('sqli: sleep() blocked', $sqli->inspect(new RequestData(['GET' => ['id' => '1 OR SLEEP(5)']]))->matched);
ok('sqli: ordinary search term is clean', !$sqli->inspect(new RequestData(['GET' => ['s' => 'best union jack t-shirt']]))->matched);

// --- XssShield -------------------------------------------------------

$xss = new XssShield();
ok('xss: script tag blocked', $xss->inspect(new RequestData(['GET' => ['c' => '<script>alert(1)</script>']]))->matched);
ok('xss: onerror handler blocked', $xss->inspect(new RequestData(['GET' => ['c' => '<img src=x onerror=alert(1)>']]))->matched);
ok('xss: ordinary comment is clean', !$xss->inspect(new RequestData(['GET' => ['c' => 'great plugin, 5 stars!']]))->matched);

// --- LfiShield -------------------------------------------------------

$lfi = new LfiShield();
ok('lfi: deep traversal to /etc/passwd blocked', $lfi->inspect(new RequestData(['GET' => ['f' => '../../../../etc/passwd']]))->matched);
ok('lfi: php://filter wrapper blocked', $lfi->inspect(new RequestData(['GET' => ['f' => 'php://filter/convert.base64-encode/resource=wp-config.php']]))->matched);
ok('lfi: wp-config.php sensitive target blocked', $lfi->inspect(new RequestData(['GET' => ['f' => '/var/www/html/wp-config.php']]))->matched);
ok('lfi: a single relative ../ is clean', !$lfi->inspect(new RequestData(['GET' => ['f' => '../images/logo.png']]))->matched);

// --- RfiShield -------------------------------------------------------

$rfi = new RfiShield();
ok('rfi: remote .php inclusion blocked', $rfi->inspect(new RequestData(['GET' => ['f' => 'http://evil.example/shell.php']]))->matched);
ok('rfi: a plain https return URL is clean', !$rfi->inspect(new RequestData(['GET' => ['redirect' => 'https://example.com/thank-you']]))->matched);

// --- HeaderRules / ClientIpResolver -----------------------------------------

ok('clientip: valid IPv4 normalises', ClientIpResolver::normalise('203.0.113.7') === '203.0.113.7');
ok('clientip: invalid token normalises to empty', ClientIpResolver::normalise('not-an-ip') === '');
ok('headerrules: valid XFF list passes', HeaderRules::validIpList('203.0.113.7, 198.51.100.2'));
ok('headerrules: garbage XFF fails', !HeaderRules::validIpList('<script>'));
ok('headerrules: x-wp-nonce is never scanned', HeaderRules::profile('x-wp-nonce') === HeaderRules::P_NEVER);
ok('headerrules: cookie is never scanned', HeaderRules::profile('cookie') === HeaderRules::P_NEVER);

// --- HeaderShield -------------------------------------------------------

function headerResult(string $name, string $value): WafResult
{
    $data = new RequestData(['HEADER' => RequestMeta::headers(['HTTP_' . strtoupper(str_replace('-', '_', $name)) => $value])]);

    return (new HeaderShield())->inspect($data);
}

ok('headershield: CRLF header-splitting blocked', headerResult('User-Agent', "a\r\nSet-Cookie: x=1")->matched);
ok('headershield: php object injection in UA blocked', headerResult('User-Agent', 'O:21:"SomeClass":1:{s:4:"prop";}')->matched);
ok('headershield: malformed X-Forwarded-For blocked', headerResult('X-Forwarded-For', '<script>')->matched);
ok('headershield: ordinary user-agent is clean', !headerResult('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1)')->matched);
ok('headershield: valid host is clean', !headerResult('Host', 'shop.example.com')->matched);

// --- PathShield: WordPress-specific location rules ---------------------------

function pathResults(string $uri): array
{
    $data = new RequestData(['PATH' => ['path' => $uri]]);

    return (new PathShield())->inspectAll($data);
}

function pathRuleIds(string $uri): array
{
    return array_map(static fn (WafResult $r) => $r->rule, pathResults($uri));
}

ok('pathshield: wp-admin own files are never flagged', pathRuleIds('/wp-admin/admin-ajax.php') === []);
ok('pathshield: wp-login.php is never flagged', pathRuleIds('/wp-login.php') === []);
ok('pathshield: wp-json REST route is never flagged', pathRuleIds('/wp-json/wp/v2/posts') === []);
ok('pathshield: PHP in wp-content/uploads flagged php_in_data_dir', in_array('php_in_data_dir', pathRuleIds('/wp-content/uploads/2026/01/shell.php'), true));
ok('pathshield: double-extension shell in uploads flagged', in_array('php_in_data_dir', pathRuleIds('/wp-content/uploads/image.php.jpg'), true));
ok('pathshield: direct PHP in a plugin folder flagged direct_php_in_code', in_array('direct_php_in_code', pathRuleIds('/wp-content/plugins/some-plugin/webhook.php'), true));
ok('pathshield: wp-config.php backup leftover flagged', in_array('wp_leftover', pathRuleIds('/wp-config.php.bak'), true));
ok('pathshield: Joomla administrator probe flagged as a foreign-CMS scanner_probe', in_array('scanner_probe', pathRuleIds('/administrator/index.php'), true));
ok('pathshield: generic webshell filename flagged scanner_probe', in_array('scanner_probe', pathRuleIds('/c99.php'), true));
ok('pathshield: phpMyAdmin probe is exempt from its own default tools-exempt list', pathRuleIds('/phpmyadmin/index.php') === []);

function pathResultsNoToolExempt(string $uri): array
{
    $data = new RequestData(['PATH' => ['path' => $uri]]);

    return (new PathShield('recommended', 'log', [], [], []))->inspectAll($data);
}

ok('pathshield: phpMyAdmin probe flagged admin_tool_probe when not exempted', in_array('admin_tool_probe', array_map(static fn (WafResult $r) => $r->rule, pathResultsNoToolExempt('/phpmyadmin/index.php')), true));
ok('pathshield: path traversal blocks', pathResults('/wp-content/uploads/../../../../etc/passwd')[0]->mode === WafResult::MODE_BLOCK);
ok('pathshield: PHP tag in path blocks', pathResults('/foo%3C%3Fphp%20x%3D1%3B%3F%3E')[0]->mode === WafResult::MODE_BLOCK);
ok('pathshield: robots.txt is exempt from all classes', pathRuleIds('/robots.txt') === []);

// --- WafEngine: scoping + first-block-wins ---------------------------------------

$engine = new WafEngine(
    [new SqliShield(), new HeaderShield()],
    ['sqli' => ['site', 'admin'], 'header' => ['site']]
);

$siteHit = $engine->inspect('site', new RequestData(['GET' => ['id' => 'UNION SELECT 1']]));
ok('engine: sqli hit on site client', $siteHit->matched && $siteHit->shield === 'sqli');

$adminClean = $engine->inspectAll('admin', new RequestData(['HEADER' => ['User-Agent' => str_repeat('a', 3000)]]));
ok('engine: header shield scoped out of admin client', $adminClean['block'] === null && $adminClean['logged'] === []);
