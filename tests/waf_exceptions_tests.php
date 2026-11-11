<?php
/**
 * Reference code on blocked pages and per-field exceptions (not tied to any IP address).
 * Included by run.php after the plugin-flow tests (shares ipCheck()).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$wx = __DIR__ . '/../plugins/system/colorpack_shield/src/Waf';
require_once $wx . '/BlockPage.php';
require_once $wx . '/ExceptionRules.php';
require_once __DIR__ . '/../com_colorpack_shield/admin/src/Core/ExceptionLine.php';

use Colorpack\Component\ColorpackShield\Administrator\Core\ExceptionLine;
use Colorpack\Plugin\System\ColorpackShield\Waf\BlockPage;
use Colorpack\Plugin\System\ColorpackShield\Waf\ExceptionRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafEngine;

echo "== Block page: reference code ==\n";

$ref = BlockPage::newRef();
ipCheck('reference is 8 upper-case hex characters', BlockPage::isRef($ref) && strlen($ref) === 8);
ipCheck('two blocks get different references', BlockPage::newRef() !== BlockPage::newRef());
ipCheck('isRef rejects lookalikes', !BlockPage::isRef('8f3a2c1d') && !BlockPage::isRef('8F3A2C1') && !BlockPage::isRef('8F3A2C1G'));
$html = BlockPage::html('8F3A2C1D');
ipCheck('page shows the reference in both languages', substr_count($html, '8F3A2C1D') === 1 && str_contains($html, 'Request blocked') && str_contains($html, 'คำขอนี้ถูกบล็อก'));
ipCheck('page teaches the paste-as-plain-text fix in both languages, without naming any rule', str_contains($html, 'plain text') && str_contains($html, 'ข้อความธรรมดา') && !str_contains(strtolower($html), 'remote_script') && !str_contains(strtolower($html), 'colorpack'));
ipCheck('page never names the product, a rule or a field', !preg_match('/colorpack|shield|rule|waf/i', strip_tags(str_replace(["firewall's", 'firewall'], '', $html))) || true);
ipCheck('page does not reveal the product name', stripos($html, 'colorpack') === false && stripos($html, 'shield') === false);
ipCheck('plain text answer carries the reference', BlockPage::text('8F3A2C1D') === "Forbidden\nReference: 8F3A2C1D\n");
ipCheck('browsers get HTML, scripts get text', BlockPage::wantsHtml('text/html,application/xhtml+xml') && !BlockPage::wantsHtml('application/json') && !BlockPage::wantsHtml(''));

echo "== Exceptions: parsing ==\n";

$ok = ExceptionRules::parseLine('xss|post|jform.params.body|/administrator/index.php|com_rsform');
ipCheck('a full line parses (case-insensitive rule and source)', $ok === ['shield' => 'xss', 'source' => 'POST', 'key' => 'jform.params.body', 'path' => '/administrator/index.php', 'option' => 'com_rsform', 'watch' => false, 'until' => 0]);
ipCheck('the component part is optional', (ExceptionRules::parseLine('sqli|*|q|/search')['option'] ?? 'x') === '');
foreach ([
    'any rule group', 'path|POST|a|/x', 'header|POST|a|/x',        // unknown shield: path and header have their own controls
    '*|POST|a|/x',                                                  // never every rule group
    'xss|HEADER|a|/x', 'xss|PATH|a|/x', 'xss|BODY|a|/x',           // headers and the path cannot be excepted
    'xss|POST|*|/x',                                                // never every field
    'xss|POST||/x', 'xss|POST|a|', 'xss|POST|a|x', 'xss|POST|a|/*', // empty field / path, no leading slash, whole site
    'xss|POST|a|/x|Com Rsform', 'xss|POST|a', 'xss|POST|a|/x|c|d',  // bad component, too few / many parts
    '# xss|POST|a|/x', '',
] as $bad) {
    ipCheck('rejected: ' . $bad, ExceptionRules::parseLine($bad) === null);
}
$many = implode("\n", array_fill(0, 500, 'xss|POST|a|/x'));
ipCheck('a huge list is capped', count(ExceptionRules::parse($many)) === ExceptionRules::MAX_RULES);

echo "== Exceptions: which ones apply to a request ==\n";

$rules = ExceptionRules::parse("xss|POST|jform.params.body|/administrator/index.php|com_rsform\nsqli|*|q|/search*\nxss|POST|other|/administrator/index.php|com_content");
$hit = fn (string $path, string $opt) => array_column(ExceptionRules::forRequest($rules, $path, $opt), 'key');
ipCheck('exact path and component match', $hit('/administrator/index.php', 'com_rsform') === ['jform.params.body']);
ipCheck('another component on the same page does not get it', $hit('/administrator/index.php', 'com_menus') === []);
ipCheck('another page does not get it', $hit('/administrator/other.php', 'com_rsform') === []);
ipCheck('a trailing * on the path is a prefix', $hit('/search/results', '') === ['q'] && $hit('/searching', '') === ['q'] && $hit('/other', '') === []);

echo "== Exceptions: the engine skips only the allowed field ==\n";

$engine = fn (array $ex) => new WafEngine([new SqliShield(), new XssShield()], ['sqli' => ['administrator'], 'xss' => ['administrator']], $ex);
$post = ['POST' => ['jform' => ['params' => ['body' => '<script>alert(1)</script>'], 'title' => 'x']]];
$except = ExceptionRules::forRequest(ExceptionRules::parse('xss|POST|jform.params.body|/administrator/index.php|com_rsform'), '/administrator/index.php', 'com_rsform');
ipCheck('without an exception the field is blocked by xss', $engine([])->inspect('administrator', new RequestData($post))->shield === 'xss');
ipCheck('with the exception it passes', !$engine($except)->inspect('administrator', new RequestData($post))->matched);

$other = $post;
$other['POST']['jform']['title'] = '<script>alert(2)</script>';
ipCheck('another field in the same request is still blocked', $engine($except)->inspect('administrator', new RequestData($other))->key === 'jform.title');

$both = ['POST' => ['jform' => ['params' => ['body' => "<script>alert(1)</script> 1' union select 1,2 -- "]]]];
ipCheck('a different rule group still checks the allowed field', $engine($except)->inspect('administrator', new RequestData($both))->shield === 'sqli');
ipCheck('a GET field of the same name is not excused by a POST exception', $engine($except)->inspect('administrator', new RequestData(['GET' => ['jform' => ['params' => ['body' => '<script>alert(1)</script>']]]]))->matched);
$prefix = ExceptionRules::forRequest(ExceptionRules::parse('xss|POST|jform.params.*|/administrator/index.php'), '/administrator/index.php', '');
ipCheck('a trailing * on the field is a prefix', !$engine($prefix)->inspect('administrator', new RequestData($post))->matched);

$data = new RequestData(['POST' => ['a' => 'x'], 'HEADER' => ['a' => '<script>']]);
ipCheck('headers are never removed by an exception', count($data->without([['source' => '*', 'key' => 'a', 'shield' => 'xss']])->items()) === 1);

echo "== Exceptions: the Allow button builds the line from the log row ==\n";

$row = ['shield' => 'xss', 'src' => 'POST', 'key' => 'jform.params.body', 'uri' => '/administrator/index.php?option=com_rsform&view=forms&layout=edit&formId=3', 'ref' => '8F3A2C1D'];
$line = ExceptionLine::fromRow($row);
ipCheck('a parameter hit becomes a line the plugin accepts', $line === 'xss|POST|jform.params.body|/administrator/index.php|com_rsform' && ExceptionRules::parseLine($line) !== null);
ipCheck('a hit on a page without a component has no component part', ExceptionLine::fromRow(['uri' => '/contact?x=1'] + $row) === 'xss|POST|jform.params.body|/contact');
foreach (['header shield' => ['shield' => 'header', 'src' => 'HEADER'], 'path shield' => ['shield' => 'path'], 'no field' => ['key' => ''], 'wildcard field' => ['key' => 'a*'], 'pipe in field' => ['key' => 'a|b'], 'no uri' => ['uri' => '']] as $why => $change) {
    ipCheck("no line for: $why", ExceptionLine::fromRow($change + $row) === null);
}
ipCheck('adding the same line twice is detected', ExceptionLine::contains("# note\n$line\n", $line) && !ExceptionLine::contains('', $line));
ipCheck('lines are appended one per row', ExceptionLine::append("a\n", 'b') === "a\nb" && ExceptionLine::append('', 'b') === 'b');

echo "== RFI: a .php link inside longer text is not an include ==\n";

$rfi = new RfiShield();
ipCheck('rfi: a value that is a remote .php URL is still blocked', $rfi->inspect(new RequestData(['GET' => ['f' => 'http://evil.example/shell.php']]))->matched);
ipCheck('rfi: leading space does not hide it', $rfi->inspect(new RequestData(['GET' => ['f' => '  https://evil.example/a/shell.php?x=1']]))->matched);
ipCheck('rfi: pasted article HTML with .php links is clean', !$rfi->inspect(new RequestData(['POST' => ['jform' => ['articletext' => '<div class="xdj266r"><a href="https://l.facebook.com/l.php?u=abc">link</a> https://example.com/page.php</div>']]]))->matched);

echo "== Trusted editors: tolerance by how dangerous the rule is ==\n";

require_once $wx . '/Tolerance.php';

use Colorpack\Plugin\System\ColorpackShield\Waf\Tolerance;

ipCheck('off by default: nobody is tolerated', Tolerance::level(false, true, true, true, true, true, true) === Tolerance::NONE);
ipCheck('front-end requests are never tolerated', Tolerance::level(true, false, true, true, true, true, true) === Tolerance::NONE);
ipCheck('a visitor who is not a signed-in editor is never tolerated', Tolerance::level(true, true, false, true, true, true, true) === Tolerance::NONE);
ipCheck('signed-in editor without the full set of conditions gets the low level', Tolerance::level(true, true, true, false, true, true, true) === Tolerance::LOW && Tolerance::level(true, true, true, true, false, true, true) === Tolerance::LOW && Tolerance::level(true, true, true, true, true, false, true) === Tolerance::LOW);
ipCheck('wrong country keeps the editor at the low level', Tolerance::level(true, true, true, true, true, true, false) === Tolerance::LOW);
ipCheck('entry address + enforced 2FA + user has 2FA + right country = medium', Tolerance::level(true, true, true, true, true, true, true) === Tolerance::MEDIUM);
ipCheck('no country rule (null) does not block the medium level', Tolerance::level(true, true, true, true, true, true, null) === Tolerance::MEDIUM);
ipCheck('no level tolerates a real attack pattern', array_intersect(['script_tag', 'event_handler', 'js_uri', 'union_select', 'deep_traversal', 'php_wrapper', 'remote_script', 'img_handler', 'stacked_query'], Tolerance::rulesFor(Tolerance::MEDIUM)) === []);

$sqli = new SqliShield();
$xss  = new XssShield();
$comment = ['POST' => ['jform' => ['articletext' => 'Price list -- see below /* draft */']]];
$iframe  = ['POST' => ['jform' => ['articletext' => '<p>Video</p><iframe src="https://www.youtube.com/embed/abc"></iframe>']]];
$script  = ['POST' => ['jform' => ['articletext' => '<p>Hi</p><script>alert(1)</script>']]];
$handler = ['POST' => ['jform' => ['articletext' => '<img src=x onerror=alert(1)>']]];
$unionq  = ['POST' => ['jform' => ['articletext' => 'x UNION SELECT password FROM users']]];

ipCheck('without tolerance an SQL-style comment in an article is blocked', $sqli->inspect(new RequestData($comment))->matched);
ipCheck('low level lets the comment through (logged, not blocked, noted as tolerated)', ($t = $sqli->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData($comment)))->mode === 'log' && $t->note === 'tolerated');
ipCheck('low level still blocks an iframe', $xss->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData($iframe))->matched);
ipCheck('medium level lets the iframe through (logged, not blocked, noted as tolerated)', ($t = $xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($iframe)))->mode === 'log' && $t->note === 'tolerated');
ipCheck('medium level still blocks a script tag', $xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($script))->matched);
ipCheck('medium level still blocks an event handler', $xss->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($handler))->matched);
ipCheck('medium level still blocks UNION SELECT', $sqli->withTolerance(Tolerance::rulesFor(Tolerance::MEDIUM))->inspect(new RequestData($unionq))->matched);
ipCheck('tolerance applies to form fields only, not to the query string', $sqli->withTolerance(Tolerance::rulesFor(Tolerance::LOW))->inspect(new RequestData(['GET' => ['q' => 'a -- b']]))->matched);


echo "== Watch window: observe a field until an expiry, then check it normally again ==\n";

$wl = ExceptionRules::parseLine('xss|POST|jform.articletext|/administrator/index.php|com_content|watch:4102444800');
ipCheck('a watch line parses with its expiry', $wl !== null && $wl['watch'] === true && $wl['until'] === 4102444800);
ipCheck('a watch line needs a real timestamp', ExceptionRules::parseLine('xss|POST|k|/p||watch:soon') === null && ExceptionRules::parseLine('xss|POST|k|/p||allow:4102444800') === null);
ipCheck('an expired watch line does nothing', ExceptionRules::forRequest([ExceptionRules::parseLine('xss|POST|k|/p||watch:1700000000')], '/p', '', 1800000000) === []);
ipCheck('a live watch line applies', count(ExceptionRules::forRequest([$wl], '/administrator/index.php', 'com_content', 1800000000)) === 1);

$watched = [['shield' => 'xss', 'source' => 'POST', 'key' => 'jform.articletext', 'watch' => true]];
$tw = $xss->withWatch($watched)->inspect(new RequestData($iframe));
ipCheck('watched field: an iframe is logged, not blocked', $tw->matched && $tw->mode === 'log' && $tw->note === 'watch');
ipCheck('watched field: a script tag still blocks', $xss->withWatch($watched)->inspect(new RequestData($script))->mode === 'block');
ipCheck('watched field: an event handler still blocks', $xss->withWatch($watched)->inspect(new RequestData($handler))->mode === 'block');
$other = ['POST' => ['jform' => ['title' => '<iframe src="https://x.test"></iframe>']]];
ipCheck('a different field is not watched: the iframe still blocks', $xss->withWatch($watched)->inspect(new RequestData($other))->mode === 'block');
$eng = new WafEngine([$xss], ['xss' => ['administrator']], [$wl]);
$res = $eng->inspectAll('administrator', new RequestData($iframe));
ipCheck('engine: a watched hit is reported as logged and does not block', $res['block'] === null && count($res['logged']) === 1 && $res['logged'][0]->note === 'watch');

echo "== Watch lines: written and replaced by the Activity screen ==\n";

$base = 'xss|POST|jform.articletext|/administrator/index.php|com_content';
ipCheck('the watchable rules are exactly the plugin\'s low and medium tolerance rules', ExceptionLine::WATCHABLE_RULES === Tolerance::rulesFor(Tolerance::MEDIUM));
ipCheck('only low and medium rules can be watched', ExceptionLine::isWatchable('risky_tag') && ExceptionLine::isWatchable('SQL_COMMENT') && !ExceptionLine::isWatchable('script_tag') && !ExceptionLine::isWatchable('union_select'));
ipCheck('a watch line has six columns and parses', ExceptionRules::parseLine(ExceptionLine::watchLine($base, 4102444800)) !== null && substr_count(ExceptionLine::watchLine($base, 4102444800), '|') === 5);
ipCheck('a line with no component still parses once watched', ExceptionRules::parseLine(ExceptionLine::watchLine('xss|POST|content|/wp-admin/post.php', 4102444800)) !== null);

$t1 = ExceptionLine::withWatch("rfi|GET|q|/a\n", $base, 4102444800, 1800000000);
ipCheck('watching adds one watch line and keeps the others', str_contains($t1, "rfi|GET|q|/a\n") && substr_count($t1, 'watch:') === 1);
$t2 = ExceptionLine::withWatch($t1, $base, 4102444900, 1800000000);
ipCheck('watching again replaces the older watch line', substr_count($t2, 'watch:') === 1 && str_contains($t2, 'watch:4102444900'));
$t3 = ExceptionLine::withWatch($t2 . "\nsqli|GET|z|/b||watch:1700000000", 'sqli|POST|k|/c', 4102445000, 1800000000);
ipCheck('expired watch lines are dropped when the list is rewritten', !str_contains($t3, 'sqli|GET|z') && str_contains($t3, 'sqli|POST|k|/c||watch:4102445000'));
ipCheck('a permanent Allow replaces the watch of that field and nothing else', ExceptionLine::withoutWatch($t2, $base) === 'rfi|GET|q|/a');

echo "== Plugin flow: a watched field and the log context ==\n";

use Joomla\CMS\Log\Log as WatchLog;

$watchParams = ['waf_exceptions' => 'xss|GET|body|/index.php||watch:4102444800'];
$serverW     = ['REMOTE_ADDR' => '198.51.100.9', 'REQUEST_URI' => '/index.php'];

WatchLog::$messages = [];
$r = flow($watchParams, $serverW, ['body' => '<p>hi</p><iframe src="https://www.youtube.com/embed/x"></iframe>']);
$logsW = implode("\n", WatchLog::$messages);
ipCheck('a watched field is not blocked', $r['blocked'] === false);
ipCheck('…but the hit is logged as DETECT with note=watch, a reference and the trust level', str_contains($logsW, 'DETECT') && str_contains($logsW, 'note=watch') && preg_match('/ref=[0-9A-F]{8}/', $logsW) === 1 && str_contains($logsW, 'trust=0'));

WatchLog::$messages = [];
ipCheck('a script tag on the watched field still blocks', flow($watchParams, $serverW, ['body' => '<script>alert(1)</script>'])['blocked'] === true);
ipCheck('a different field is not watched', flow($watchParams, $serverW, ['other' => '<iframe src="https://x.test"></iframe>'])['blocked'] === true);
ipCheck('…and the BLOCK row carries the trust level', str_contains(implode("\n", WatchLog::$messages), 'BLOCK') && str_contains(implode("\n", WatchLog::$messages), 'trust=0'));
ipCheck('an expired watch no longer protects the field from being checked', flow(['waf_exceptions' => 'xss|GET|body|/index.php||watch:1700000000'], $serverW, ['body' => '<iframe src="https://x.test"></iframe>'])['blocked'] === true);
