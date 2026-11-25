<?php
/**
 * An HTML comment is not an SQL comment: pasting HTML with comments into an article must not be refused, while real
 * SQL comments and every other attack pattern are still caught. Included by run.php (reuses ipCheck).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;

echo "== SQL shield: HTML comments in pasted content ==\n";

$sqliRule = static function (string $value): string {
    $r = (new SqliShield())->inspect(new RequestData(['POST' => ['jform' => ['articletext' => $value]]]));

    return $r->matched ? $r->rule : '';
};

ipCheck('an article starting with an HTML comment is allowed', $sqliRule("<!-- Joomla 6.3 Alpha 1 summary — UIkit 3 markup for YOOtheme Pro (paste into an HTML element or article in Code view) -->\n<div class=\"uk-article\"><p>ข้อความ</p></div>") === '');
ipCheck('block-editor and "read more" comments are allowed', $sqliRule('<!-- wp:paragraph --><p>x</p><!-- /wp:paragraph --><!--more--><hr id="system-readmore" /><!-- end -->') === '');
ipCheck('a comment spread over several lines is allowed', $sqliRule("<!--\n  section: header\n  author: team\n-->\n<h2>x</h2>") === '');
ipCheck('a bare SQL comment is still caught', $sqliRule("admin' -- ") === 'sql_comment' && $sqliRule("1 # x") === 'sql_comment');
ipCheck('a C-style SQL comment is still caught, also beside HTML comments', $sqliRule("1/**/or/**/1") !== '' && $sqliRule("<!-- a --> 1/**/order/**/by/**/1 <!-- b -->") === 'sql_comment');
ipCheck('a real SQL comment between two HTML comments is still caught', $sqliRule("<!-- a --> x' -- <!-- b -->") === 'sql_comment');
ipCheck('an unclosed "<!--" is not treated as an HTML comment', $sqliRule("x' <!-- ") === 'sql_comment');
ipCheck('a SQL comment written inside an HTML comment is still caught', $sqliRule("<!-- ' -- drop -->") === 'sql_comment');
ipCheck('UNION SELECT is caught even inside an HTML comment, and next to one', $sqliRule('<!-- 1 union select pass from users -->') === 'union_select' && $sqliRule('<!-- note --> 1 union select 2') === 'union_select');
ipCheck('a stacked query next to an HTML comment is still caught', $sqliRule('<!-- n --> 1; drop table users') === 'stacked_query');
ipCheck('URL-encoded HTML comments behave the same', $sqliRule('%3C%21--%20note%20--%3E%3Cp%3Ex%3C%2Fp%3E') === '');
