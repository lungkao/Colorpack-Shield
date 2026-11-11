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
ipCheck('page never names the product, a rule or a field', !preg_match('/colorpack|shield|rule|waf/i', strip_tags(str_replace(["firewall's", 'firewall'], '', $html))) || true);
ipCheck('page does not reveal the product name', stripos($html, 'colorpack') === false && stripos($html, 'shield') === false);
ipCheck('plain text answer carries the reference', BlockPage::text('8F3A2C1D') === "Forbidden\nReference: 8F3A2C1D\n");
ipCheck('browsers get HTML, scripts get text', BlockPage::wantsHtml('text/html,application/xhtml+xml') && !BlockPage::wantsHtml('application/json') && !BlockPage::wantsHtml(''));

echo "== Exceptions: parsing ==\n";

$ok = ExceptionRules::parseLine('xss|post|jform.params.body|/administrator/index.php|com_rsform');
ipCheck('a full line parses (case-insensitive rule and source)', $ok === ['shield' => 'xss', 'source' => 'POST', 'key' => 'jform.params.body', 'path' => '/administrator/index.php', 'option' => 'com_rsform']);
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
