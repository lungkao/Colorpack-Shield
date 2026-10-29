<?php
/**
 * Colorpack Shield WAF core — standalone test harness (no Joomla required).
 *
 * Run:  php pkg_colorpack_shield/tests/run.php
 * Exits 0 if every fixture behaves, 1 otherwise.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

define('COLORPACK_SHIELD_TEST', 1);

$base = __DIR__ . '/../plugins/system/colorpack_shield/src/Waf';
require $base . '/WafResult.php';
require $base . '/Normalizer.php';
require $base . '/RequestData.php';
require $base . '/BodyParser.php';
require $base . '/UploadThreat.php';
require $base . '/UploadScanner.php';
$geo = __DIR__ . '/../plugins/system/colorpack_shield/src/Geo';
require $geo . '/CidrMatcher.php';
require $geo . '/GeoPolicy.php';
$rl = __DIR__ . '/../plugins/system/colorpack_shield/src/RateLimit';
require $rl . '/RateStore.php';
require $rl . '/RateVerdict.php';
require $rl . '/RateLimiter.php';
require $base . '/Shield/ShieldInterface.php';
require $base . '/Shield/MultiResultShield.php';
require $base . '/Shield/AbstractRegexShield.php';
require $base . '/Shield/SqliShield.php';
require $base . '/Shield/XssShield.php';
require $base . '/Shield/LfiShield.php';
require $base . '/Shield/RfiShield.php';
require $base . '/WafEngine.php';

use Colorpack\Plugin\System\ColorpackShield\Waf\BodyParser;
use Colorpack\Plugin\System\ColorpackShield\Waf\RequestData;
use Colorpack\Plugin\System\ColorpackShield\Geo\CidrMatcher;
use Colorpack\Plugin\System\ColorpackShield\Geo\GeoPolicy;
use Colorpack\Plugin\System\ColorpackShield\Waf\UploadScanner;
use Colorpack\Plugin\System\ColorpackShield\Waf\WafEngine;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\LfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\RfiShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield;
use Colorpack\Plugin\System\ColorpackShield\Waf\Shield\XssShield;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateStore;
use Colorpack\Plugin\System\ColorpackShield\RateLimit\RateLimiter;

$clients = ['site', 'administrator', 'api'];
$shields = [new SqliShield(), new XssShield(), new LfiShield(), new RfiShield()];
$scopes  = [];
foreach ($shields as $s) {
    $scopes[$s->id()] = $clients; // P0.1: cover every client
}
$engine = new WafEngine($shields, $scopes);

$pass = 0;
$fail = 0;

/** Assert a request is BLOCKED (and, when given, by the expected shield). */
function mustBlock(WafEngine $e, string $client, array $get, string $wantShield = ''): void
{
    global $pass, $fail;
    $r = $e->inspect($client, new RequestData(['GET' => $get]));
    $label = "$client " . json_encode($get);

    if (!$r->matched) {
        echo "  FAIL (expected block) : $label\n";
        $fail++;

        return;
    }

    if ($wantShield !== '' && $r->shield !== $wantShield) {
        echo "  FAIL (want $wantShield got {$r->shield}) : $label\n";
        $fail++;

        return;
    }

    $pass++;
}

/** Assert a request is ALLOWED (no shield fires). */
function mustPass(WafEngine $e, string $client, array $get): void
{
    global $pass, $fail;
    $r = $e->inspect($client, new RequestData(['GET' => $get]));

    if ($r->matched) {
        echo "  FAIL (false positive by {$r->shield}/{$r->rule}) : $client " . json_encode($get) . "\n";
        $fail++;

        return;
    }

    $pass++;
}

echo "== Malicious payloads must be blocked on ALL clients (P0.1 admin/api coverage) ==\n";
$malicious = [
    ['sqli', ['q' => "1' UNION SELECT username,password FROM users-- -"]],
    ['sqli', ['id' => '1 OR 1=1']],
    ['sqli', ['id' => '1); DROP TABLE users;']],
    ['sqli', ['t'  => 'x%27%20UNION%20SELECT%201']],           // single-encoded
    ['sqli', ['s'  => "1 AND SLEEP(5)"]],
    ['xss',  ['name' => '<script>alert(1)</script>']],
    ['xss',  ['u' => 'javascript:alert(document.cookie)']],
    ['xss',  ['bio' => '<img src=x onerror=alert(1)>']],
    ['xss',  ['svg' => '<svg onload=alert(1)>']],
    ['lfi',  ['file' => '../../../../etc/passwd']],
    ['lfi',  ['p' => 'php://filter/convert.base64-encode/resource=index.php']],
    ['lfi',  ['tpl' => '....//....//etc/passwd']],
    ['rfi',  ['inc' => 'http://evil.example.com/shell.php']],
    ['rfi',  ['w' => 'data://text/plain;base64,PD9waHA=']],
];
foreach ($malicious as [$want, $get]) {
    foreach (['site', 'administrator', 'api'] as $client) {
        mustBlock($engine, $client, $get, $want);
    }
}

echo "== Benign traffic must pass (no false positives) ==\n";
$benign = [
    ['q' => 'hello world'],
    ['search' => 'shoes and socks'],
    ['return' => 'https://mysite.example.com/account/orders'],
    ['path' => 'images/2026/07/logo.png'],
    ['email' => 'john.doe@example.com'],
    ['name' => "O'Brien"],                        // apostrophe, not SQLi
    ['msg' => 'price is 3 < 5 but 5 > 3'],
    ['url' => 'https://cdn.example.com/app.js'],   // remote .js is not RFI
    ['comment' => 'read more about union rules and select committees'],
    ['dir' => '../assets/style.css'],              // single traversal, benign
];
foreach ($benign as $get) {
    foreach (['site', 'administrator', 'api'] as $client) {
        mustPass($engine, $client, $get);
    }
}

echo "== Scope enforcement: a shield not covering a client must NOT fire ==\n";
$siteOnly = new WafEngine([new SqliShield()], ['sqli' => ['site']]);
$sqli = ['id' => '1 UNION SELECT 1'];
// site covered -> block
$r = $siteOnly->inspect('site', new RequestData(['GET' => $sqli]));
$r->matched ? $pass++ : ($fail++ + print("  FAIL: site scope should block\n"));
// admin NOT covered -> pass
$r = $siteOnly->inspect('administrator', new RequestData(['GET' => $sqli]));
!$r->matched ? $pass++ : ($fail++ + print("  FAIL: admin scope should be skipped\n"));

echo "== Caps: oversize / deep body is truncated, not fatal ==\n";
$big = new RequestData(['POST' => ['x' => str_repeat('A', 50000)]]);
$ok  = !$big->truncated && count($big->items()) > 1;
foreach ($big->items() as $it) {
    $ok = $ok && strlen($it['value']) <= RequestData::MAX_VALUE_LEN;
}
$ok ? $pass++ : ($fail++ + print("  FAIL: long value must be cut into pieces, none above the cap\n"));

// A payload placed after the cap, or behind a flood of dummy fields, is still seen (it used to be skipped).
$sqlTail  = new RequestData(['POST' => ['t' => str_repeat('A', 20000) . " ' UNION SELECT 1,2-- -"]]);
$flood    = array_fill_keys(array_map(static fn (int $i): string => 'f' . $i, range(1, 2100)), 'x');
$sqlFlood = new RequestData(['GET' => $flood + ['q' => "1' UNION SELECT 1,2-- -"]]);
$sh       = new \Colorpack\Plugin\System\ColorpackShield\Waf\Shield\SqliShield('block');
($sh->inspect($sqlTail)->matched && $sh->inspect($sqlFlood)->matched && $sqlFlood->truncated)
    ? $pass++ : ($fail++ + print("  FAIL: a payload after the value cap or behind a field flood must still be inspected\n"));
// A signature that straddles a cut between two pieces is still whole in one of them.
$edge  = str_repeat('A', RequestData::MAX_VALUE_LEN - RequestData::CHUNK_OVERLAP - 6) . "' UNION SELECT 1,2-- -" . str_repeat('B', 20000);
$found = false;
foreach ((new RequestData(['POST' => ['e' => $edge]]))->items() as $it) {
    $found = $found || str_contains($it['value'], "' UNION SELECT 1,2-- -");
}
$found ? $pass++ : ($fail++ + print("  FAIL: a signature on a piece boundary must stay whole\n"));
// JSON sent with a form content type: Joomla reads it anyway, so it is decoded and scanned too.
$bp = new \Colorpack\Plugin\System\ColorpackShield\Waf\BodyParser();
$jb = $bp->parse('{"data":{"t":"x\\u0027 UNION SELECT 1,2-- -"}}', 'application/x-www-form-urlencoded');
(isset($jb['JSON']) && $bp->parse('a=1&b=2', 'application/x-www-form-urlencoded') === [])
    ? $pass++ : ($fail++ + print("  FAIL: JSON body with a form content type must be decoded\n"));

echo "== P0.2: raw request body (php://input) is inspected ==\n";

/** Build RequestData from a raw body the way the plugin's guard() does. */
function bodyData(string $raw, string $ct): array
{
    $parser  = new BodyParser();
    $sources = ['GET' => [], 'POST' => []] + $parser->parse($raw, $ct);

    return [new RequestData($sources), $parser];
}

/** Assert a raw body is BLOCKED. */
function bodyBlock(WafEngine $e, string $raw, string $ct, string $label): void
{
    global $pass, $fail;
    [$data] = bodyData($raw, $ct);

    if ($e->inspect('site', $data)->matched) {
        $pass++;

        return;
    }
    echo "  FAIL (expected block) : $label\n";
    $fail++;
}

/** Assert a raw body is ALLOWED. */
function bodyPass(WafEngine $e, string $raw, string $ct, string $label): void
{
    global $pass, $fail;
    [$data] = bodyData($raw, $ct);
    $r = $e->inspect('site', $data);

    if (!$r->matched) {
        $pass++;

        return;
    }
    echo "  FAIL (false positive by {$r->shield}) : $label\n";
    $fail++;
}

// SQLi / XSS in a JSON REST payload — the core P0.2 gap.
bodyBlock($engine, '{"q":"1 UNION SELECT username,password FROM users"}', 'application/json', 'sqli in json');
bodyBlock($engine, '{"user":{"bio":"<script>alert(1)</script>"}}', 'application/json', 'xss nested in json');
bodyBlock($engine, '{"a":{"b":{"c":"../../../../etc/passwd"}}}', 'application/json', 'lfi deep in json');
// Content-Type missing but body structurally JSON -> still decoded.
bodyBlock($engine, '{"inc":"http://evil.example.com/shell.php"}', '', 'rfi in json, no content-type');
// Malformed JSON falls back to raw blob scan.
bodyBlock($engine, '{"q":"1 OR 1=1" ', 'application/json', 'sqli in malformed json (blob fallback)');
// Non-JSON raw text body.
bodyBlock($engine, 'name=<img src=x onerror=alert(1)>', 'text/plain', 'xss in raw text body');

// Benign JSON must not false-positive.
bodyPass($engine, '{"name":"O\'Brien","email":"john@example.com"}', 'application/json', 'benign json');
bodyPass($engine, '{"msg":"read more about union rules"}', 'application/json', 'benign json prose');

// Form bodies are already in $_POST — BodyParser must skip them (empty source bag).
$fp = new BodyParser();
$fp->parse('q=1+UNION+SELECT+1', 'application/x-www-form-urlencoded') === []
    ? $pass++ : ($fail++ + print("  FAIL: urlencoded body should be skipped\n"));
$mp = new BodyParser();
$mp->parse('------boundary\r\n...', 'multipart/form-data; boundary=----boundary') === []
    ? $pass++ : ($fail++ + print("  FAIL: multipart body should be skipped\n"));

// Oversize body: flagged, truncated to the cap, still scanned (signature in head caught).
$huge = '{"q":"1 UNION SELECT 1",' . str_repeat('"pad":"x",', 40000) . '"end":"z"}';
[$data, $parser] = bodyData($huge, 'application/json');
$parser->oversize && \strlen($huge) > BodyParser::MAX_BODY_BYTES
    ? $pass++ : ($fail++ + print("  FAIL: oversize flag not set\n"));

// Signature straddling a chunk boundary in a >MAX_VALUE_LEN raw blob is still caught.
$sig    = "1' UNION SELECT username,password FROM users-- -";
$prefix = str_repeat('a', RequestData::MAX_VALUE_LEN - 10); // pushes sig across the first cut
bodyBlock($engine, $prefix . $sig, 'text/plain', 'sqli straddling chunk boundary');

echo '== P1.1: uploaded files ($_FILES) are inspected ==' . "\n";

$tmpFiles = [];

/** Write a temp file and return a normalized $_FILES record for it. */
function tmpUpload(string $name, string $content, int $sizeOverride = -1): array
{
    global $tmpFiles;
    $path = tempnam(sys_get_temp_dir(), 'fgtest');
    file_put_contents($path, $content);
    $tmpFiles[] = $path;

    return [
        'name'     => $name,
        'type'     => 'application/octet-stream',
        'tmp_name' => $path,
        'error'    => 0,
        'size'     => $sizeOverride >= 0 ? $sizeOverride : \strlen($content),
    ];
}

/** Assert an upload is BLOCKED (optionally by the expected reason). */
function upBlock(UploadScanner $s, array $file, string $wantReason, string $label): void
{
    global $pass, $fail;
    $t = $s->inspectFile($file);

    if ($t === null) {
        echo "  FAIL (expected block) : $label\n";
        $fail++;

        return;
    }
    if ($wantReason !== '' && $t->reason !== $wantReason) {
        echo "  FAIL (want $wantReason got {$t->reason}) : $label\n";
        $fail++;

        return;
    }
    $pass++;
}

/** Assert an upload is ALLOWED. */
function upPass(UploadScanner $s, array $file, string $label): void
{
    global $pass, $fail;
    $t = $s->inspectFile($file);

    if ($t === null) {
        $pass++;

        return;
    }
    echo "  FAIL (false positive {$t->reason}) : $label\n";
    $fail++;
}

$scanner  = new UploadScanner();
$php      = '<?php system($_GET["c"]); ?>';
$realGif  = hex2bin('47494638396101000100800000000000ffffff21f9040100000000002c00000000010001000002024401003b');

// Executable / script extensions.
upBlock($scanner, tmpUpload('shell.php', $php), 'denied_extension', 'shell.php');
upBlock($scanner, tmpUpload('x.phtml', $php), 'denied_extension', 'x.phtml');
upBlock($scanner, tmpUpload('a.PHP', $php), 'denied_extension', 'uppercase .PHP');
// Classic double-extension bypass — a real payload wearing an image suffix.
upBlock($scanner, tmpUpload('img.php.jpg', $php), 'double_extension', 'img.php.jpg');
// Renamed payload: image extension, but the bytes are PHP.
upBlock($scanner, tmpUpload('avatar.jpg', $php), 'executable_content', 'php bytes as .jpg');
// Claims to be a JPEG but is not a decodable image.
upBlock($scanner, tmpUpload('fake.jpg', 'this is plain text, not an image'), 'fake_image', 'non-image .jpg');
// Shell script by shebang.
upBlock($scanner, tmpUpload('run.txt', "#!/bin/sh\nrm -rf /"), 'executable_content', 'shebang script');

// Real images and benign docs pass.
upPass($scanner, tmpUpload('photo.gif', (string) $realGif), 'real gif');
upPass($scanner, tmpUpload('notes.txt', 'just some harmless notes about unions and selections'), 'benign text');
upPass($scanner, tmpUpload('report.pdf', "%PDF-1.4\n1 0 obj<<>>endobj"), 'benign pdf');

// Size cap.
$capped = new UploadScanner(100);
upBlock($capped, tmpUpload('big.gif', (string) $realGif, 5000), 'oversize', 'oversize file');
upPass($capped, tmpUpload('small.gif', (string) $realGif, 40), 'under cap');

// Allowlist mode: only jpg permitted.
$allow = new UploadScanner(0, ['jpg']);
upBlock($allow, tmpUpload('doc.png', (string) $realGif), 'not_allowlisted', 'png not on jpg allowlist');

// normalize(): a multi-file array field flattens to one record per file.
$flat = UploadScanner::normalize([
    'single' => ['name' => 'a.jpg', 'type' => 'image/jpeg', 'tmp_name' => '/tmp/a', 'error' => 0, 'size' => 10],
    'many'   => [
        'name'     => ['b.png', 'c.gif'],
        'type'     => ['image/png', 'image/gif'],
        'tmp_name' => ['/tmp/b', '/tmp/c'],
        'error'    => [0, 0],
        'size'     => [20, 30],
    ],
]);
\count($flat) === 3 && $flat[2]['name'] === 'c.gif'
    ? $pass++ : ($fail++ + print("  FAIL: normalize() did not flatten nested \$_FILES\n"));

// scan() stops at the first threat across a set.
$firstBad = $scanner->scan([tmpUpload('ok.gif', (string) $realGif), tmpUpload('bad.php', $php)]);
$firstBad !== null && $firstBad->file === 'bad.php'
    ? $pass++ : ($fail++ + print("  FAIL: scan() missed a threat in a set\n"));

foreach ($tmpFiles as $p) {
    @unlink($p);
}

echo "== P1.2: CIDR matching (IPv4/IPv6, family-correct) ==\n";

/** @param bool $want */
function cidr(string $ip, string $cidr, bool $want, string $label): void
{
    global $pass, $fail;
    CidrMatcher::matches($ip, $cidr) === $want
        ? $pass++ : ($fail++ + print("  FAIL: $label\n"));
}

cidr('192.168.1.50', '192.168.1.0/24', true, 'v4 in /24');
cidr('192.168.2.50', '192.168.1.0/24', false, 'v4 outside /24');
cidr('10.0.0.1', '10.0.0.1', true, 'v4 exact (no mask)');
cidr('10.0.0.2', '10.0.0.1', false, 'v4 exact mismatch');
cidr('203.0.113.7', '0.0.0.0/0', true, 'v4 /0 matches all');
cidr('2001:db8::1', '2001:db8::/32', true, 'v6 in /32');
cidr('2001:dead::1', '2001:db8::/32', false, 'v6 outside /32');
cidr('192.168.1.1', '2001:db8::/32', false, 'v4 never matches v6 subnet');
cidr('2001:db8::1', '192.168.1.0/24', false, 'v6 never matches v4 subnet');
cidr('not-an-ip', '192.168.1.0/24', false, 'invalid ip');
cidr('192.168.1.1', '192.168.1.0/33', false, 'invalid prefix length');
CidrMatcher::matchesAny('10.0.0.5', ['192.168.0.0/16', '10.0.0.0/8'])
    ? $pass++ : ($fail++ + print("  FAIL: matchesAny\n"));

echo "== P1.2: GeoIP allow/deny policy (precedence) ==\n";

/** @param string|null $want */
function geo(GeoPolicy $p, string $ip, ?string $country, ?string $want, string $label): void
{
    global $pass, $fail;
    $p->decide($ip, $country) === $want
        ? $pass++ : ($fail++ + print("  FAIL: $label (got " . var_export($p->decide($ip, $country), true) . ")\n"));
}

// Deny mode: block listed countries, pass the rest and unknowns.
$deny = new GeoPolicy('deny', ['CN', 'RU']);
geo($deny, '1.1.1.1', 'CN', 'geo_denied', 'deny-mode blocks CN');
geo($deny, '1.1.1.1', 'ru', 'geo_denied', 'deny-mode case-insensitive');
geo($deny, '1.1.1.1', 'TH', null, 'deny-mode passes TH');
geo($deny, '1.1.1.1', null, null, 'deny-mode passes unknown (fail-open)');

// Allow mode: block everything not listed.
$allow = new GeoPolicy('allow', ['TH', 'SG']);
geo($allow, '1.1.1.1', 'TH', null, 'allow-mode passes TH');
geo($allow, '1.1.1.1', 'US', 'geo_not_allowed', 'allow-mode blocks US');
geo($allow, '1.1.1.1', null, null, 'allow-mode unknown fail-open (default)');

$allowClosed = new GeoPolicy('allow', ['TH'], [], [], false);
geo($allowClosed, '1.1.1.1', null, 'geo_unknown', 'allow-mode unknown fail-closed');

// IP allowlist beats a denied country; IP denylist beats a passing one.
$mixed = new GeoPolicy('deny', ['CN'], ['203.0.113.0/24'], ['198.51.100.5']);
geo($mixed, '203.0.113.9', 'CN', null, 'IP allowlist overrides country deny');
geo($mixed, '198.51.100.5', 'TH', 'ip_denylist', 'IP denylist blocks a passing country');
geo($mixed, '8.8.8.8', 'CN', 'geo_denied', 'no IP rule → country deny applies');

// needsCountry(): only when a country list is configured.
(new GeoPolicy('deny', []))->needsCountry() === false
    ? $pass++ : ($fail++ + print("  FAIL: needsCountry empty\n"));
(new GeoPolicy('deny', ['CN']))->needsCountry() === true
    ? $pass++ : ($fail++ + print("  FAIL: needsCountry set\n"));
// IP-only policy (no countries) still enforces the denylist without a lookup.
geo(new GeoPolicy('deny', [], [], ['10.0.0.0/8']), '10.1.2.3', null, 'ip_denylist', 'IP-only denylist, no country');

echo "\n";
echo "== P1.3: rate limiter (fixed-window + escalating ban) ==\n";

/**
 * In-memory RateStore with a caller-controlled clock so window rollover and
 * ban expiry are deterministic — mirrors ApcuRateStore semantics (native TTL,
 * ban value = absolute expiry epoch).
 */
final class ArrayRateStore implements RateStore
{
    /** @var array<string,array{val:int,exp:int}> */
    private array $data = [];

    public function __construct(private int $now)
    {
    }

    public function tick(int $seconds): void
    {
        $this->now += $seconds;
    }

    private function gc(): void
    {
        foreach ($this->data as $k => $row) {
            if ($row['exp'] <= $this->now) {
                unset($this->data[$k]);
            }
        }
    }

    public function increment(string $key, int $ttl): int
    {
        $this->gc();

        if (!isset($this->data[$key])) {
            $this->data[$key] = ['val' => 0, 'exp' => $this->now + $ttl];
        }

        return ++$this->data[$key]['val'];
    }

    public function ttl(string $key): int
    {
        $this->gc();

        return isset($this->data[$key]) ? max(0, $this->data[$key]['exp'] - $this->now) : 0;
    }

    public function put(string $key, int $ttl): void
    {
        $this->data[$key] = ['val' => $this->now + $ttl, 'exp' => $this->now + $ttl];
    }
}

// window=60 limit=3, no ban.
$store = new ArrayRateStore(1000);
$lim   = new RateLimiter($store, 60, 3);
$allowed = 0;
for ($i = 0; $i < 3; $i++) {
    $allowed += $lim->decide(1000, '1.1.1.1', 'site:')->allowed ? 1 : 0;
}
$allowed === 3 ? $pass++ : ($fail++ + print("  FAIL: first 3 under limit should pass\n"));

$v = $lim->decide(1000, '1.1.1.1', 'site:');
(!$v->allowed && $v->reason === 'rate_limited') ? $pass++ : ($fail++ + print("  FAIL: 4th over limit should soft-block\n"));
// Retry-After = seconds left in the window (now%60 == 40 → 20 left).
$v->retryAfter === 20 ? $pass++ : ($fail++ + print("  FAIL: retryAfter want 20 got {$v->retryAfter}\n"));

// Window rollover resets the counter.
$store->tick(60);
$lim->decide(1060, '1.1.1.1', 'site:')->allowed ? $pass++ : ($fail++ + print("  FAIL: new window should reset counter\n"));

// Per-IP isolation: a different IP has its own budget.
$lim->decide(1060, '2.2.2.2', 'site:')->allowed ? $pass++ : ($fail++ + print("  FAIL: per-IP isolation\n"));

// Per-route isolation: same IP, different route, independent budget.
$store2 = new ArrayRateStore(2000);
$lim2   = new RateLimiter($store2, 60, 1);
$lim2->decide(2000, '9.9.9.9', 'site:com_a')->allowed ? $pass++ : ($fail++ + print("  FAIL: route A first should pass\n"));
!$lim2->decide(2000, '9.9.9.9', 'site:com_a')->allowed ? $pass++ : ($fail++ + print("  FAIL: route A second should block\n"));
$lim2->decide(2000, '9.9.9.9', 'site:com_b')->allowed ? $pass++ : ($fail++ + print("  FAIL: route B should have own budget\n"));

// Escalating ban: window=60 limit=1, ban after 2 violations in banWindow=300 for 3600.
$bs  = new ArrayRateStore(5000);
$ban = new RateLimiter($bs, 60, 1, 2, 300, 3600);
$ban->decide(5000, '7.7.7.7', 'site:');                         // 1st ok
$b1 = $ban->decide(5000, '7.7.7.7', 'site:');                   // violation 1 → soft
($b1->reason === 'rate_limited') ? $pass++ : ($fail++ + print("  FAIL: first violation should be rate_limited\n"));
$bs->tick(60);
$ban->decide(5060, '7.7.7.7', 'site:');                         // new window, 1st ok
$b2 = $ban->decide(5060, '7.7.7.7', 'site:');                   // violation 2 → ban armed
($b2->reason === 'rate_banned' && $b2->retryAfter === 3600) ? $pass++ : ($fail++ + print("  FAIL: 2nd violation should arm ban got {$b2->reason}\n"));

// Banned IP stays blocked even under limit, until the ban expires.
$b3 = $ban->decide(5061, '7.7.7.7', 'site:');
($b3->reason === 'rate_banned') ? $pass++ : ($fail++ + print("  FAIL: banned IP should stay blocked\n"));
$bs->tick(3600);
$ban->decide(8661, '7.7.7.7', 'site:')->allowed ? $pass++ : ($fail++ + print("  FAIL: ban should expire\n"));

// Disabled limiter (window<=0 or limit<=0) always allows.
(new RateLimiter(new ArrayRateStore(0), 0, 5))->decide(0, '1.2.3.4', 'x')->allowed
    ? $pass++ : ($fail++ + print("  FAIL: window<=0 should allow\n"));
(new RateLimiter(new ArrayRateStore(0), 60, 0))->decide(0, '1.2.3.4', 'x')->allowed
    ? $pass++ : ($fail++ + print("  FAIL: limit<=0 should allow\n"));

echo "\n";
require __DIR__ . '/client_ip_tests.php';
require __DIR__ . "/safety_tests.php";
require __DIR__ . "/trust_policy_tests.php";
require __DIR__ . "/plugin_flow_tests.php";
require __DIR__ . "/proxy_probe_tests.php";
require __DIR__ . "/hardening_tests.php";
require __DIR__ . "/header_tests.php";
require __DIR__ . "/header_flow_tests.php";
require __DIR__ . "/path_tests.php";
require __DIR__ . "/path_flow_tests.php";
require __DIR__ . "/targeted_ban_tests.php";
require __DIR__ . "/replay_tests.php";
require __DIR__ . "/replay_path_tests.php";
require __DIR__ . "/p2b_tests.php";
require __DIR__ . "/cf_refresh_tests.php";
require __DIR__ . "/language_tests.php";
require __DIR__ . "/admin_protect_tests.php";
require __DIR__ . "/admin_login_flow_tests.php";
require __DIR__ . "/admin_alerts_tests.php";
require __DIR__ . "/admin_mfa_tests.php";
require __DIR__ . "/admin_gate_tests.php";
require __DIR__ . "/admin_gate_flow_tests.php";
require __DIR__ . "/component_core_tests.php";
require __DIR__ . "/file_scanner_tests.php";
require __DIR__ . "/scanner_actions_tests.php";
require __DIR__ . "/htaccess_block_tests.php";
require __DIR__ . "/apache_rig_tests.php";
require __DIR__ . "/nginx_rig_tests.php";
require __DIR__ . "/site_manager_tests.php";

echo "\n";
echo "PASS: $pass   FAIL: $fail\n";
exit($fail === 0 ? 0 : 1);
