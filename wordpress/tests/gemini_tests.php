<?php
/**
 * Gemini AI advisor library (not wired to anything yet - see README): Config, PromptBuilder
 * (privacy sweep), and Client against a fake transport. Included by run.php, shares its ok()
 * helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Gemini\Client;
use Colorpack\WP\ColorpackShield\Gemini\Config;
use Colorpack\WP\ColorpackShield\Gemini\HttpTransport;
use Colorpack\WP\ColorpackShield\Gemini\PromptBuilder;

// --- Config -------------------------------------------------------

ok('config: disabled -> null even with a key', Config::fromParams('a-key', false, '', false, 24) === null);
ok('config: enabled but blank key -> null', Config::fromParams('   ', true, '', false, 24) === null);
ok('config: enabled + key -> populated', Config::fromParams('a-key', true, '', false, 24)?->apiKey === 'a-key');
ok('config: blank model falls back to the default', Config::fromParams('a-key', true, '  ', false, 24)?->model === Config::DEFAULT_MODEL);
ok('config: schedule interval floors at 1 hour', Config::fromParams('a-key', true, '', true, 0)?->scheduleIntervalHours === 1);

// --- PromptBuilder privacy sweep (WAF activity) -------------------------------------------------------

$logEntries = [
    ['time' => 1_800_000_000, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'ip' => '203.0.113.7', 'key' => 'username', 'src' => 'POST', 'uri' => '/wp-login.php', 'sample' => "' UNION SELECT user_login,user_pass FROM wp_users--"]],
    ['time' => 1_800_000_010, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'ip' => '198.51.100.9', 'key' => 'username', 'src' => 'POST', 'uri' => '/wp-login.php', 'sample' => "' UNION SELECT user_login,user_pass FROM wp_users--"]],
];

$wafPrompt = (new PromptBuilder())->forWafActivity($logEntries);

ok('promptbuilder: groups identical rows into one count', str_contains($wafPrompt, 'count=2'));
ok('promptbuilder: keeps the matched sample text', str_contains($wafPrompt, 'UNION SELECT user_login'));
ok('promptbuilder: no raw IP address ever appears', !str_contains($wafPrompt, '203.0.113.7') && !str_contains($wafPrompt, '198.51.100.9'));
ok('promptbuilder: no parameter name/source (key/src) appears', !str_contains($wafPrompt, 'username') && !preg_match('/\bPOST\b/', $wafPrompt));
ok('promptbuilder: no field named ip/username/email/password/token/cookie appears', !preg_match('/\bip\b|username|email|password|token|cookie/i', $wafPrompt));

// Matches the Joomla edition: the advisor answers once, in the admin's current interface
// language, not twice (Thai + English) as an earlier round had it.
ok('promptbuilder: lang=th instructs a Thai-only reply', str_contains((new PromptBuilder())->forWafActivity($logEntries, 'th'), 'Write the whole reply in Thai only'));
ok('promptbuilder: an unrecognised language code falls back to English', str_contains((new PromptBuilder())->forWafActivity($logEntries, 'fr'), 'Write the whole reply in English only'));
ok('promptbuilder: omitting lang defaults to English', str_contains($wafPrompt, 'Write the whole reply in English only'));

// Regression: a real attack sample can carry raw bytes that are not valid UTF-8, and even a clean
// sample can have a multibyte character land right on the old byte-counted truncation point -
// either way json_encode() used to fail silently. Matches the Joomla edition's 0.10.2 fix.
$invalidUtf8Entries = [
    ['time' => 1_800_000_000, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'sample' => str_repeat('A', 298) . "\xE0\xA0"]],
    ['time' => 1_800_000_010, 'type' => 'BLOCK', 'f' => ['shield' => 'lfi', 'rule' => 'raw_bytes', 'client' => 'site', 'sample' => "payload\xC0\x80more\xFF"]],
];
$invalidUtf8Prompt = (new PromptBuilder())->forWafActivity($invalidUtf8Entries);
ok('promptbuilder: a truncated/invalid-UTF-8 sample still produces a json_encode()-able prompt', json_encode(['text' => $invalidUtf8Prompt], JSON_UNESCAPED_UNICODE) !== false);
ok('promptbuilder: the cleaned output is itself valid UTF-8', mb_check_encoding($invalidUtf8Prompt, 'UTF-8'));

// --- PromptBuilder privacy sweep (scan findings) -------------------------------------------------------

$findings = [
    ['path' => 'wp-content/uploads/2026/01/shell.php', 'rules' => ['eval_base64'], 'sev' => 'high', 'size' => 4096, 'mtime' => 1_800_000_000, 'hash' => 'deadbeef', 'content' => "<?php eval(base64_decode('...'));"],
];

$scanPrompt = (new PromptBuilder())->forScanFindings($findings);

ok('promptbuilder: scan findings keep path/rules/severity/hash', str_contains($scanPrompt, 'wp-content/uploads/2026/01/shell.php') && str_contains($scanPrompt, 'eval_base64') && str_contains($scanPrompt, 'deadbeef'));
ok('promptbuilder: scan findings never include file content', !str_contains($scanPrompt, 'eval(base64_decode'));

// --- Client against a fake transport -------------------------------------------------------

final class FakeGeminiTransportWp implements HttpTransport
{
    public ?array $lastRequest = null;

    public function __construct(private readonly ?array $response, private readonly bool $recordOnly = false)
    {
    }

    public function post(string $url, array $headers, string $body, int $timeoutSeconds): ?array
    {
        $this->lastRequest = ['url' => $url, 'headers' => $headers, 'body' => $body];

        return $this->recordOnly ? null : $this->response;
    }
}

$cfg = Config::fromParams('s3cr3t-key', true, 'gemini-2.5-flash', false, 24);

$okTransport = new FakeGeminiTransportWp(['status' => 200, 'body' => '{"candidates":[{"content":{"parts":[{"text":"It looks like a SQLi probe."}]}}]}']);
$answer      = (new Client($okTransport))->ask($cfg, 'analyse this');

ok('client: a 200 reply is parsed into the model text', $answer === 'It looks like a SQLi probe.');
ok('client: posts to the model-specific generateContent endpoint', str_contains($okTransport->lastRequest['url'], '/models/gemini-2.5-flash:generateContent'));
ok('client: the API key appears only in the query string, never the body', str_contains($okTransport->lastRequest['url'], 's3cr3t-key') && !str_contains($okTransport->lastRequest['body'], 's3cr3t-key'));

$timeoutTransport = new FakeGeminiTransportWp(null, true);
ok('client: a transport failure (null) returns null, never throws', (new Client($timeoutTransport))->ask($cfg, 'x') === null);

$malformedTransport = new FakeGeminiTransportWp(['status' => 200, 'body' => 'not json']);
ok('client: a 200 with an unparsable body returns null', (new Client($malformedTransport))->ask($cfg, 'x') === null);
