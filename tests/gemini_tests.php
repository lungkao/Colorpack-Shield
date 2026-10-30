<?php
/**
 * Gemini AI advisor: Config, PromptBuilder (privacy sweep), Client against a fake transport,
 * AnalysisHistory. Included by run.php (reuses ipCheck and both autoloaders already registered
 * by plugin_flow_tests.php / component_core_tests.php).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\Gemini\AnalysisHistory;
use Colorpack\Plugin\System\ColorpackShield\Gemini\Client;
use Colorpack\Plugin\System\ColorpackShield\Gemini\Config;
use Colorpack\Plugin\System\ColorpackShield\Gemini\HttpTransport;
use Colorpack\Plugin\System\ColorpackShield\Gemini\PromptBuilder;

echo "== Gemini advisor: Config ==\n";

ipCheck('Config::fromParams: disabled -> null even with a key', Config::fromParams('a-key', false, '', false, 24) === null);
ipCheck('Config::fromParams: enabled but blank key -> null', Config::fromParams('   ', true, '', false, 24) === null);
ipCheck('Config::fromParams: enabled + key -> populated', Config::fromParams('a-key', true, '', false, 24)?->apiKey === 'a-key');
ipCheck('Config::fromParams: blank model falls back to the default', Config::fromParams('a-key', true, '  ', false, 24)?->model === Config::DEFAULT_MODEL);
ipCheck('Config::fromParams: a custom model is kept as-is', Config::fromParams('a-key', true, 'gemini-3.0-pro', false, 24)?->model === 'gemini-3.0-pro');
ipCheck('Config::fromParams: schedule interval floors at 1 hour', Config::fromParams('a-key', true, '', true, 0)?->scheduleIntervalHours === 1);

echo "== Gemini advisor: PromptBuilder privacy sweep (WAF activity) ==\n";

$logEntries = [
    ['time' => 1_800_000_000, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'ip' => '203.0.113.7', 'key' => 'username', 'src' => 'POST', 'uri' => '/wp-login.php', 'sample' => "' UNION SELECT user_login,user_pass FROM wp_users--"]],
    ['time' => 1_800_000_010, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'ip' => '198.51.100.9', 'key' => 'username', 'src' => 'POST', 'uri' => '/wp-login.php', 'sample' => "' UNION SELECT user_login,user_pass FROM wp_users--"]],
    ['time' => 1_800_000_020, 'type' => 'DETECT', 'f' => ['shield' => 'xss', 'rule' => 'script_tag', 'client' => 'administrator', 'ip' => '203.0.113.7', 'uri' => '/admin/comment', 'sample' => '<script>alert(1)</script>']],
];

$wafPrompt = (new PromptBuilder())->forWafActivity($logEntries);

ipCheck('PromptBuilder::forWafActivity: groups identical (type,shield,rule,client) rows into one count', str_contains($wafPrompt, 'count=2') && str_contains($wafPrompt, 'count=1'));
ipCheck('PromptBuilder::forWafActivity: keeps the matched sample text', str_contains($wafPrompt, 'UNION SELECT user_login'));
ipCheck('PromptBuilder::forWafActivity: no raw IP address ever appears', !str_contains($wafPrompt, '203.0.113.7') && !str_contains($wafPrompt, '198.51.100.9'));
ipCheck('PromptBuilder::forWafActivity: no parameter name/source (key/src) appears', !str_contains($wafPrompt, 'username') && !preg_match('/\bPOST\b/', $wafPrompt));
ipCheck('PromptBuilder::forWafActivity: no field named ip/username/email/password/token/cookie appears', !preg_match('/\bip\b|username|email|password|token|cookie/i', $wafPrompt));

// Regression: a real attack sample can carry raw bytes that are not valid UTF-8 (url-decoded
// binary, overlong sequences meant to evade filters), and even a clean sample can have a
// multibyte character land right on the old byte-counted truncation point. Either way,
// json_encode() used to fail *silently* (return false) on the resulting prompt, which Client::ask()
// could only see as "the call failed" - with no HTTP request ever sent, and nothing to find in
// any transport-level log, because execution never got that far.
$invalidUtf8Entries = [
    ['time' => 1_800_000_000, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => 'union_select', 'client' => 'site', 'sample' => str_repeat('A', 298) . "\xE0\xA0" /* truncated multibyte char */]],
    ['time' => 1_800_000_010, 'type' => 'BLOCK', 'f' => ['shield' => 'lfi', 'rule' => 'raw_bytes', 'client' => 'site', 'sample' => "payload\xC0\x80more\xFF"]],
];
$invalidUtf8Prompt = (new PromptBuilder())->forWafActivity($invalidUtf8Entries);
ipCheck('PromptBuilder::forWafActivity: a truncated/invalid-UTF-8 sample still produces a json_encode()-able prompt', json_encode(['text' => $invalidUtf8Prompt], JSON_UNESCAPED_UNICODE) !== false);
ipCheck('PromptBuilder::forWafActivity: the cleaned output is itself valid UTF-8', mb_check_encoding($invalidUtf8Prompt, 'UTF-8'));

$manyGroups = [];
for ($i = 0; $i < 60; $i++) {
    $manyGroups[] = ['time' => 1_800_000_000 + $i, 'type' => 'BLOCK', 'f' => ['shield' => 'sqli', 'rule' => "rule_$i", 'client' => 'site']];
}
$cappedPrompt = (new PromptBuilder())->forWafActivity($manyGroups);
ipCheck('PromptBuilder::forWafActivity: groups are capped (not one line per every distinct rule)', substr_count($cappedPrompt, 'rule=rule_') <= 40);

echo "== Gemini advisor: PromptBuilder privacy sweep (scan findings) ==\n";

$findings = [
    ['path' => 'wp-content/uploads/2026/01/shell.php', 'rules' => ['eval_base64'], 'sev' => 'high', 'size' => 4096, 'mtime' => 1_800_000_000, 'hash' => 'deadbeef', 'content' => "<?php eval(base64_decode('...'));"],
    ['path' => 'wp-content/plugins/some-plugin/webhook.php', 'rules' => ['direct_php_in_code'], 'sev' => 'low', 'size' => 512, 'mtime' => 1_800_000_000, 'hash' => 'cafef00d', 'content' => 'super-secret-admin-password=hunter2'],
];

$scanPrompt = (new PromptBuilder())->forScanFindings($findings);

ipCheck('PromptBuilder::forScanFindings: keeps path, rules, severity, hash', str_contains($scanPrompt, 'wp-content/uploads/2026/01/shell.php') && str_contains($scanPrompt, 'eval_base64') && str_contains($scanPrompt, 'deadbeef'));
ipCheck('PromptBuilder::forScanFindings: never includes file content, even when present in the fixture', !str_contains($scanPrompt, 'eval(base64_decode') && !str_contains($scanPrompt, 'hunter2'));
ipCheck('PromptBuilder::forScanFindings: no field named password/token/secret appears', !preg_match('/password|token|secret/i', $scanPrompt));

echo "== Gemini advisor: Client against a fake transport ==\n";

final class FakeGeminiTransport implements HttpTransport
{
    /** @var array{url:string,headers:array<string,string>,body:string}|null */
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

$okTransport = new FakeGeminiTransport(['status' => 200, 'body' => '{"candidates":[{"content":{"parts":[{"text":"It looks like a SQLi probe."}]}}]}']);
$answer      = (new Client($okTransport))->ask($cfg, 'analyse this');

ipCheck('Client::ask: a 200 reply is parsed into the model text', $answer === 'It looks like a SQLi probe.');
ipCheck('Client::ask: posts to the model-specific generateContent endpoint', str_contains($okTransport->lastRequest['url'], '/models/gemini-2.5-flash:generateContent'));
ipCheck('Client::ask: the API key appears only in the query string, never the body', str_contains($okTransport->lastRequest['url'], 's3cr3t-key') && !str_contains($okTransport->lastRequest['body'], 's3cr3t-key'));
ipCheck('Client::ask: the prompt text is sent as contents[0].parts[0].text', str_contains($okTransport->lastRequest['body'], 'analyse this'));

$deniedTransport = new FakeGeminiTransport(['status' => 401, 'body' => '{"error":"bad key"}']);
ipCheck('Client::ask: a non-200 reply returns null, never throws', (new Client($deniedTransport))->ask($cfg, 'x') === null);

$timeoutTransport = new FakeGeminiTransport(null, true);
ipCheck('Client::ask: a transport failure (null) returns null, never throws', (new Client($timeoutTransport))->ask($cfg, 'x') === null);

$malformedTransport = new FakeGeminiTransport(['status' => 200, 'body' => 'not json']);
ipCheck('Client::ask: a 200 with an unparsable body returns null', (new Client($malformedTransport))->ask($cfg, 'x') === null);

$emptyTransport = new FakeGeminiTransport(['status' => 200, 'body' => '{"candidates":[]}']);
ipCheck('Client::ask: a 200 with no candidates returns null rather than an empty string', (new Client($emptyTransport))->ask($cfg, 'x') === null);

echo "== Gemini advisor: AnalysisHistory ==\n";

$histDir = sys_get_temp_dir() . '/cps-gemini-' . bin2hex(random_bytes(4));
$T       = 1_800_000_000;
$history = new AnalysisHistory(new FileStateStore($histDir));

ipCheck('AnalysisHistory: nothing recorded yet -> empty', $history->recent($T) === []);

$history->record('waf', 'prompt one', 'answer one', $T);
$history->record('scan', 'prompt two', 'answer two', $T + 10);

$recent = $history->recent($T + 10, 10);
ipCheck('AnalysisHistory: recent() returns newest first', \count($recent) === 2 && $recent[0]['kind'] === 'scan' && $recent[1]['kind'] === 'waf');
ipCheck('AnalysisHistory: recent() respects the limit', \count($history->recent($T + 10, 1)) === 1);
ipCheck('AnalysisHistory: recent() filters by kind, so one screen never shows another screen\'s analysis', $history->recent($T + 10, 10, ['waf']) === [$recent[1]] && $history->recent($T + 10, 10, ['scan']) === [$recent[0]]);
