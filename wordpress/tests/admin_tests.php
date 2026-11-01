<?php
/**
 * Admin-side plain-PHP classes (no WordPress functions touched): ActivityLog -> LogReader ->
 * LogFilter round trip, and SimpleMarkdown. Included by run.php, shares its ok() helper and
 * $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Admin\ActivityLog;
use Colorpack\WP\ColorpackShield\Admin\LogFilter;
use Colorpack\WP\ColorpackShield\Admin\LogReader;
use Colorpack\WP\ColorpackShield\Admin\SimpleMarkdown;

// --- ActivityLog -> LogReader round trip -------------------------------------------------------

$logPath = sys_get_temp_dir() . '/cps-wp-activity-' . bin2hex(random_bytes(4)) . '.log';
$writer  = new ActivityLog($logPath);

$writer->write('BLOCK', [
    'client' => 'site',
    'shield' => 'sqli',
    'rule'   => 'union_select',
    'src'    => 'POST',
    'key'    => 'q',
    'uri'    => '/index.php',
    'sample' => "' UNION SELECT user_login,user_pass FROM wp_users--",
], '127.0.0.1');

$writer->write('BLOCK', [
    'client' => 'administrator',
    'shield' => 'xss',
    'rule'   => 'script_tag',
    'uri'    => '/wp-admin/admin.php',
    'sample' => '<script>alert(1)</script>',
], '203.0.113.7');

$read = (new LogReader($logPath))->read();

ok('ActivityLog -> LogReader: file is readable, both lines parsed', $read['readable'] === true && \count($read['entries']) === 2);
ok('ActivityLog -> LogReader: type and simple fields round-trip', $read['entries'][0]['type'] === 'BLOCK' && $read['entries'][0]['f']['shield'] === 'sqli' && $read['entries'][0]['f']['rule'] === 'union_select');
ok('ActivityLog -> LogReader: "sample" (last field) keeps its spaces intact', $read['entries'][0]['f']['sample'] === "' UNION SELECT user_login,user_pass FROM wp_users--");
ok('ActivityLog -> LogReader: a second, differently-shaped event round-trips too', $read['entries'][1]['f']['client'] === 'administrator' && $read['entries'][1]['f']['sample'] === '<script>alert(1)</script>');

// A hostile value must not be able to forge a second log line by smuggling a tab/newline into a
// field - the exact concern ActivityLog::write()'s control-byte stripping exists for.
$forgedPath = sys_get_temp_dir() . '/cps-wp-activity-forge-' . bin2hex(random_bytes(4)) . '.log';
(new ActivityLog($forgedPath))->write('BLOCK', [
    'client' => 'site',
    'shield' => 'sqli',
    'sample' => "x\tfaked\tcolumns\tcolorpack_shield\tBLOCK client=administrator shield=fake",
], '127.0.0.1');
$forgedRead = (new LogReader($forgedPath))->read();
ok('ActivityLog: an embedded tab in a field cannot forge a second log line', \count($forgedRead['entries']) === 1 && !str_contains($forgedRead['entries'][0]['f']['sample'], "\t"));

unlink($logPath);
unlink($forgedPath);

// --- LogFilter over what ActivityLog actually wrote -------------------------------------------

$criteria = LogFilter::criteria(['client' => 'administrator']);
$filtered = LogFilter::apply($read['entries'], $criteria, $read['entries'][1]['time'] + 10);
ok('LogFilter: filtering by client on real ActivityLog output returns only that client\'s row', \count($filtered) === 1 && $filtered[0]['f']['client'] === 'administrator');

// --- SimpleMarkdown (renders the Gemini advisor's free-text reply) ------------------------------

ok('SimpleMarkdown: heading levels become h1-h6', SimpleMarkdown::toHtml("# A\n## B\n### C") === '<h1>A</h1><h2>B</h2><h3>C</h3>');
ok('SimpleMarkdown: bold and inline code render inside a paragraph', SimpleMarkdown::toHtml('a **bold** and `code` word') === '<p>a <strong>bold</strong> and <code>code</code> word</p>');
ok('SimpleMarkdown: a bullet list becomes <ul><li>', SimpleMarkdown::toHtml("- one\n- two") === '<ul><li>one</li><li>two</li></ul>');
ok('SimpleMarkdown: a model reply can never inject raw HTML - every byte is escaped before any pattern is applied', SimpleMarkdown::toHtml('<script>alert(1)</script> and **bold**') === '<p>&lt;script&gt;alert(1)&lt;/script&gt; and <strong>bold</strong></p>');
ok('SimpleMarkdown: a fenced code block becomes <pre><code> verbatim', SimpleMarkdown::toHtml("```\nrule => /a**b/\n```") === '<pre><code>rule =&gt; /a**b/</code></pre>');
