<?php
/**
 * Reference code on blocked pages and per-field exceptions (not tied to any IP address).
 * Included by run.php after the plugin-flow tests (shares ok()).
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$wx = __DIR__ . '/../colorpack-shield/src';
require_once $wx . '/Waf/BlockPage.php';
require_once $wx . '/Waf/ExceptionRules.php';
require_once $wx . '/Admin/ExceptionLine.php';

use Colorpack\WP\ColorpackShield\Admin\ExceptionLine;
use Colorpack\WP\ColorpackShield\Waf\BlockPage;
use Colorpack\WP\ColorpackShield\Waf\ExceptionRules;
use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\WP\ColorpackShield\Waf\WafEngine;

echo "== Block page: reference code ==\n";

$ref = BlockPage::newRef();
ok('reference is 8 upper-case hex characters', BlockPage::isRef($ref) && strlen($ref) === 8);
ok('two blocks get different references', BlockPage::newRef() !== BlockPage::newRef());
ok('isRef rejects lookalikes', !BlockPage::isRef('8f3a2c1d') && !BlockPage::isRef('8F3A2C1') && !BlockPage::isRef('8F3A2C1G'));
$html = BlockPage::html('8F3A2C1D');
ok('page shows the reference in both languages', substr_count($html, '8F3A2C1D') === 1 && str_contains($html, 'Request blocked') && str_contains($html, 'คำขอนี้ถูกบล็อก'));
ok('page teaches the paste-as-plain-text fix in both languages, without naming any rule', str_contains($html, 'plain text') && str_contains($html, 'ข้อความธรรมดา') && !str_contains(strtolower($html), 'remote_script') && !str_contains(strtolower($html), 'colorpack'));
ok('page does not reveal the product name', stripos($html, 'colorpack') === false && stripos($html, 'shield') === false);
ok('plain text answer carries the reference', BlockPage::text('8F3A2C1D') === "Forbidden\nReference: 8F3A2C1D\n");
ok('browsers get HTML, scripts get text', BlockPage::wantsHtml('text/html,application/xhtml+xml') && !BlockPage::wantsHtml('application/json') && !BlockPage::wantsHtml(''));

echo "== Exceptions: parsing ==\n";

$ok = ExceptionRules::parseLine('xss|post|content|/wp-admin/post.php|wpforms-builder');
ok('a full line parses (case-insensitive rule and source)', $ok === ['shield' => 'xss', 'source' => 'POST', 'key' => 'content', 'path' => '/wp-admin/post.php', 'option' => 'wpforms-builder']);
ok('the component part is optional', (ExceptionRules::parseLine('sqli|*|q|/search')['option'] ?? 'x') === '');
foreach ([
    'any rule group', 'path|POST|a|/x', 'header|POST|a|/x',        // unknown shield: path and header have their own controls
    '*|POST|a|/x',                                                  // never every rule group
    'xss|HEADER|a|/x', 'xss|PATH|a|/x', 'xss|BODY|a|/x',           // headers and the path cannot be excepted
    'xss|POST|*|/x',                                                // never every field
    'xss|POST||/x', 'xss|POST|a|', 'xss|POST|a|x', 'xss|POST|a|/*', // empty field / path, no leading slash, whole site
    'xss|POST|a|/x|Bad Page!', 'xss|POST|a', 'xss|POST|a|/x|c|d',  // bad component, too few / many parts
    '# xss|POST|a|/x', '',
] as $bad) {
    ok('rejected: ' . $bad, ExceptionRules::parseLine($bad) === null);
}
$many = implode("\n", array_fill(0, 500, 'xss|POST|a|/x'));
ok('a huge list is capped', count(ExceptionRules::parse($many)) === ExceptionRules::MAX_RULES);

echo "== Exceptions: which ones apply to a request ==\n";

$rules = ExceptionRules::parse("xss|POST|content|/wp-admin/post.php|wpforms-builder\nsqli|*|q|/search*\nxss|POST|other|/wp-admin/post.php|other-page");
$hit = fn (string $path, string $opt) => array_column(ExceptionRules::forRequest($rules, $path, $opt), 'key');
ok('exact path and page match', $hit('/wp-admin/post.php', 'wpforms-builder') === ['content']);
ok('another admin page on the same file does not get it', $hit('/wp-admin/post.php', 'some-page') === []);
ok('another page does not get it', $hit('/wp-admin/other.php', 'wpforms-builder') === []);
ok('a trailing * on the path is a prefix', $hit('/search/results', '') === ['q'] && $hit('/searching', '') === ['q'] && $hit('/other', '') === []);

echo "== Exceptions: the engine skips only the allowed field ==\n";

$engine = fn (array $ex) => new WafEngine([new SqliShield(), new XssShield()], ['sqli' => ['administrator'], 'xss' => ['administrator']], $ex);
$post = ['POST' => ['jform' => ['params' => ['body' => '<script>alert(1)</script>'], 'title' => 'x']]];
$except = ExceptionRules::forRequest(ExceptionRules::parse('xss|POST|jform.params.body|/wp-admin/post.php|wpforms-builder'), '/wp-admin/post.php', 'wpforms-builder');
ok('without an exception the field is blocked by xss', $engine([])->inspect('administrator', new RequestData($post))->shield === 'xss');
ok('with the exception it passes', !$engine($except)->inspect('administrator', new RequestData($post))->matched);

$other = $post;
$other['POST']['jform']['title'] = '<script>alert(2)</script>';
ok('another field in the same request is still blocked', $engine($except)->inspect('administrator', new RequestData($other))->key === 'jform.title');

$both = ['POST' => ['jform' => ['params' => ['body' => "<script>alert(1)</script> 1' union select 1,2 -- "]]]];
ok('a different rule group still checks the allowed field', $engine($except)->inspect('administrator', new RequestData($both))->shield === 'sqli');
ok('a GET field of the same name is not excused by a POST exception', $engine($except)->inspect('administrator', new RequestData(['GET' => ['jform' => ['params' => ['body' => '<script>alert(1)</script>']]]]))->matched);
$prefix = ExceptionRules::forRequest(ExceptionRules::parse('xss|POST|jform.params.*|/wp-admin/post.php'), '/wp-admin/post.php', '');
ok('a trailing * on the field is a prefix', !$engine($prefix)->inspect('administrator', new RequestData($post))->matched);

$data = new RequestData(['POST' => ['a' => 'x'], 'HEADER' => ['a' => '<script>']]);
ok('headers are never removed by an exception', count($data->without([['source' => '*', 'key' => 'a', 'shield' => 'xss']])->items()) === 1);

echo "== Exceptions: the Allow button builds the line from the log row ==\n";

$row = ['shield' => 'xss', 'src' => 'POST', 'key' => 'jform.params.body', 'uri' => '/wp-admin/admin.php?page=wpforms-builder&view=fields&form_id=3', 'ref' => '8F3A2C1D'];
$line = ExceptionLine::fromRow($row);
ok('a parameter hit becomes a line the plugin accepts', $line === 'xss|POST|jform.params.body|/wp-admin/admin.php|wpforms-builder' && ExceptionRules::parseLine($line) !== null);
ok('a hit on a page without a page/action has no such part', ExceptionLine::fromRow(['uri' => '/contact?x=1'] + $row) === 'xss|POST|jform.params.body|/contact');
foreach (['header shield' => ['shield' => 'header', 'src' => 'HEADER'], 'path shield' => ['shield' => 'path'], 'no field' => ['key' => ''], 'wildcard field' => ['key' => 'a*'], 'pipe in field' => ['key' => 'a|b'], 'no uri' => ['uri' => '']] as $why => $change) {
    ok("no line for: $why", ExceptionLine::fromRow($change + $row) === null);
}
ok('adding the same line twice is detected', ExceptionLine::contains("# note\n$line\n", $line) && !ExceptionLine::contains('', $line));
ok('lines are appended one per row', ExceptionLine::append("a\n", 'b') === "a\nb" && ExceptionLine::append('', 'b') === 'b');

echo "== Trusted editors: tolerance by how dangerous the rule is ==\n";

require_once $wx . '/Waf/Tolerance.php';

use Colorpack\WP\ColorpackShield\Waf\Tolerance;

ok('off by default: nobody is tolerated', Tolerance::level(false, true, true, true, true, true, true) === Tolerance::NONE);
ok('front-end requests are never tolerated', Tolerance::level(true, false, true, true, true, true, true) === Tolerance::NONE);
ok('a visitor who is not a signed-in editor is never tolerated', Tolerance::level(true, true, false, true, true, true, true) === Tolerance::NONE);
ok('signed-in editor without the full set of conditions gets the low level', Tolerance::level(true, true, true, false, true, true, true) === Tolerance::LOW && Tolerance::level(true, true, true, true, false, true, true) === Tolerance::LOW && Tolerance::level(true, true, true, true, true, false, true) === Tolerance::LOW);
ok('wrong country keeps the editor at the low level', Tolerance::level(true, true, true, true, true, true, false) === Tolerance::LOW);
ok('entry address + enforced 2FA + user has 2FA + right country = medium', Tolerance::level(true, true, true, true, true, true, true) === Tolerance::MEDIUM);
ok('no country rule (null) does not block the medium level', Tolerance::level(true, true, true, true, true, true, null) === Tolerance::MEDIUM);
ok('no level tolerates a real attack pattern', array_intersect(['script_tag', 'event_handler', 'js_uri', 'union_select', 'deep_traversal', 'php_wrapper', 'remote_script', 'img_handler', 'stacked_query'], Tolerance::rulesFor(Tolerance::MEDIUM)) === []);

$sqli = new SqliShield();
$xss  = new XssShield();
$comment = ['POST' => ['jform' => ['articletext' => 'Price list -- see below /* draft */']]];
$iframe  = ['POST' => ['jform' => ['articletext' => '<p>Video</p><iframe src="https://www.youtube.com/embed/abc"></iframe>']]];
$script  = ['POST' => ['jform' => ['articletext' => '<p>Hi</p><script>alert(1)</script>']]];
$handler = ['POST' => ['jform' => ['articletext' => '<img src=x onerror=alert(1)>']]];
$unionq  = ['POST' => ['jform' => ['articletext' => 'x UNION SELECT password FROM users']]];

ok('without tolerance an SQL-style comment in an article is blocked', $sqli->inspect(new RequestData($comment))->matched);
ok('low level lets the comment through', !$sqli->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData($comment))->matched);
ok('low level still blocks an iframe', $xss->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData($iframe))->matched);
ok('medium level lets the iframe through', !$xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($iframe))->matched);
ok('medium level still blocks a script tag', $xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($script))->matched);
ok('medium level still blocks an event handler', $xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($handler))->matched);
ok('medium level still blocks UNION SELECT', $sqli->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($unionq))->matched);
ok('tolerance applies to form fields only, not to the query string', $sqli->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData(['GET' => ['q' => 'a -- b']]))->matched);
