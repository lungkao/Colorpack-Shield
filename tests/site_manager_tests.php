<?php
/**
 * Colorpack Site Manager integration (docs/shield-integration.md): signing, config reading,
 * the health/event mapping, the outbound client against a fake transport, the login-burst
 * aggregator, and a privacy sweep over a realistic payload. Included by run.php (reuses
 * ipCheck and both autoloaders already registered by plugin_flow_tests.php / component_core_tests.php).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Component\ColorpackShield\Administrator\Core\HealthReport;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScoreCalculator;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AlertThrottle;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\BurstWindow;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\Client;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\Config;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\EventQueue;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\HealthCache;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\HttpTransport;
use Colorpack\Plugin\System\ColorpackShield\SiteManager\Signer;

echo "== Site Manager integration: signing ==\n";

ipCheck(
    'Signer::sign matches hash_hmac(time.".".body, secret) exactly',
    Signer::sign('s3cr3t', '1700000000', '{"a":1}') === hash_hmac('sha256', '1700000000.{"a":1}', 's3cr3t')
);

echo "== Site Manager integration: Config ==\n";

// A dedicated fake plugins root - never the real JPATH_PLUGINS (another test file may already have
// defined that constant as this repo's actual plugins/ folder; writing fixtures there would pollute it).
$fakePlugins = sys_get_temp_dir() . '/cps-sm-plugins-' . bin2hex(random_bytes(4));
$agentDir    = $fakePlugins . '/system/colorpack';
mkdir($agentDir, 0777, true);

ipCheck('Config::load: missing file -> null', Config::load($fakePlugins) === null);

file_put_contents($agentDir . '/config.php', "<?php\nreturn ['manager_url' => 'http://panel.example.com', 'site_id' => 17, 'secret' => 'abc'];\n");
ipCheck('Config::load: http:// on a non-local host -> null', Config::load($fakePlugins) === null);

file_put_contents($agentDir . '/config.php', "<?php\nreturn ['manager_url' => 'http://localhost.attacker.example', 'site_id' => 17, 'secret' => 'abc'];\n");
ipCheck('Config::load: a host that merely CONTAINS "localhost" is not exempt from https:// (exact-host check, not substring)', Config::load($fakePlugins) === null);

file_put_contents($agentDir . '/config.php', "<?php\nreturn ['manager_url' => 'http://localhost:8080', 'site_id' => 17, 'secret' => 'abc'];\n");
ipCheck('Config::load: exact "localhost" host is exempt from https:// (testing)', Config::load($fakePlugins) === ['manager_url' => 'http://localhost:8080', 'site_id' => 17, 'secret' => 'abc']);

file_put_contents($agentDir . '/config.php', "<?php\nreturn ['manager_url' => 'https://panel.colorpack.co.th', 'site_id' => 17, 'secret' => 'abcdef0123456789', 'login_user' => 'x'];\n");
ipCheck('Config::load: a valid https:// config parses (login_user is dropped)', Config::load($fakePlugins) === ['manager_url' => 'https://panel.colorpack.co.th', 'site_id' => 17, 'secret' => 'abcdef0123456789']);

file_put_contents($agentDir . '/config.php', "<?php\nreturn ['manager_url' => 'https://panel.colorpack.co.th', 'site_id' => 0, 'secret' => 'x'];\n");
ipCheck('Config::load: site_id <= 0 -> null', Config::load($fakePlugins) === null);

file_put_contents($agentDir . '/config.php', "<?php\nthrow new RuntimeException('boom');\n");
ipCheck('Config::load: a file that throws on include -> null, never propagates', Config::load($fakePlugins) === null);

echo "== Site Manager integration: HealthReport mapping ==\n";

$score = [
    'score' => 82,
    'items' => [
        ['id' => 'protection', 'weight' => 20, 'status' => ScoreCalculator::OK],
        ['id' => 'admin_login', 'weight' => 10, 'status' => ScoreCalculator::WARN],
        ['id' => 'lockout_safety', 'weight' => 10, 'status' => ScoreCalculator::BAD],
        ['id' => 'server_rules', 'weight' => 10, 'status' => ScoreCalculator::UNKNOWN],
    ],
];
$health = HealthReport::build($score, '0.8.0');

ipCheck('HealthReport: score passes through unchanged', $health['score'] === 82 && $health['shield_version'] === '0.8.0');
ipCheck('HealthReport: ok/warn/bad map to pass/should_fix/must_fix', $health['items'][0]['status'] === 'pass' && $health['items'][1]['status'] === 'should_fix' && $health['items'][2]['status'] === 'must_fix');
ipCheck('HealthReport: unknown items are omitted entirely', \count($health['items']) === 3);
ipCheck('HealthReport: a pass item has no detail, a should_fix one does', !isset($health['items'][0]['detail']) && isset($health['items'][1]['detail']) && $health['items'][1]['detail'] !== '');
ipCheck('HealthReport: can_autofix only for ids with a quick-fix target (admin_login, not protection/lockout_safety)', ($health['items'][1]['can_autofix'] ?? false) === true && !isset($health['items'][0]['can_autofix']) && !isset($health['items'][2]['can_autofix']));
ipCheck('HealthReport: every title is non-empty Thai text', $health['items'][0]['title'] === 'ระบบป้องกันเปิดอยู่');

$manyItems = [];
for ($i = 0; $i < 90; $i++) {
    $manyItems[] = ['id' => 'protection', 'weight' => 1, 'status' => ScoreCalculator::OK];
}
ipCheck('HealthReport: capped at 80 items', \count(HealthReport::build(['score' => 100, 'items' => $manyItems], '0.8.0')['items']) === 80);

echo "== Site Manager integration: EventQueue ==\n";

$smDir = sys_get_temp_dir() . '/cps-sm-' . bin2hex(random_bytes(4));
$T     = 1_800_000_000;
$fs    = new FileStateStore($smDir);
$q     = new EventQueue($fs);

ipCheck('EventQueue: empty queue drains to nothing', $q->drain(100, $T) === []);
$q->enqueue(['id' => 'e1', 'type' => 'lockout'], $T);
$q->enqueue(['id' => 'e2', 'type' => 'lockout'], $T);
ipCheck('EventQueue: drain() is non-destructive (peeks)', \count($q->drain(100, $T)) === 2 && \count($q->drain(100, $T)) === 2);
$q->ack(['e1'], $T);
$after = $q->drain(100, $T);
ipCheck('EventQueue: ack() removes only the acked id; the rest survive', \count($after) === 1 && $after[0]['id'] === 'e2');
$q->ack(['e2'], $T);
ipCheck('EventQueue: acking everything empties the queue', $q->drain(100, $T) === []);

$capQ = new EventQueue(new FileStateStore($smDir . '-cap'));
for ($i = 0; $i < 520; $i++) {
    $capQ->enqueue(['id' => "c$i"], $T);
}
ipCheck('EventQueue: bounded at 500, oldest dropped first', \count($capQ->drain(1000, $T)) === 500 && $capQ->drain(1, $T)[0]['id'] === 'c20');

$drainCapQ = new EventQueue(new FileStateStore($smDir . '-draincap'));
for ($i = 0; $i < 10; $i++) {
    $drainCapQ->enqueue(['id' => "d$i"], $T);
}
ipCheck('EventQueue: drain() respects its own $max, independent of the queue size', \count($drainCapQ->drain(3, $T)) === 3);

echo "== Site Manager integration: HealthCache ==\n";

$hc = new HealthCache(new FileStateStore($smDir . '-health'));
ipCheck('HealthCache: nothing cached yet -> not due, peek is null', $hc->peek($T) === null && $hc->dueToday($T) === false);
$hc->put(['score' => 90, 'items' => []], $T);
ipCheck('HealthCache: freshly put payload is due immediately', $hc->peek($T)['score'] === 90 && $hc->dueToday($T) === true);
$hc->markSent($T);
ipCheck('HealthCache: not due again right after sending', $hc->dueToday($T) === false);
ipCheck('HealthCache: due again after 24h', $hc->dueToday($T + 86401) === true);
$hc->put(['score' => 40, 'items' => []], $T + 3600);
ipCheck('HealthCache: put() (a settings change) makes it due again immediately, even before 24h', $hc->dueToday($T + 3600) === true && $hc->peek($T + 3600)['score'] === 40);

echo "== Site Manager integration: BurstWindow + AlertThrottle (login_burst, P4) ==\n";

$burstStore = new FileStateStore($smDir . '-burst');
$burst      = new BurstWindow($burstStore);

$c1 = $burst->recordLock($T);
$c2 = $burst->recordLock($T + 10);
ipCheck('BurstWindow: 2 lock-outs in the window -> count is 2, below the threshold of 3', $c1 === 1 && $c2 === 2);

$c3 = $burst->recordLock($T + 20);
ipCheck('BurstWindow: the 3rd lock-out brings the count to 3', $c3 === 3);
$claim1 = AlertThrottle::claim($burstStore, 'site_manager_login_burst', $T + 20, 600);
ipCheck('AlertThrottle: the burst event fires exactly once when the threshold is first crossed', $claim1['send'] === true);

$c4 = $burst->recordLock($T + 30);
$claim2 = AlertThrottle::claim($burstStore, 'site_manager_login_burst', $T + 30, 600);
ipCheck('AlertThrottle: a 4th lock-out in the same window does not fire again', $c4 === 4 && $claim2['send'] === false);

$claim3 = AlertThrottle::claim($burstStore, 'site_manager_login_burst', $T + 700, 600);
ipCheck('AlertThrottle: after the window clears, a fresh burst can fire again', $claim3['send'] === true);

echo "== Site Manager integration: Client against a fake transport ==\n";

final class FakeTransport implements HttpTransport
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

$cfg = ['manager_url' => 'https://panel.example.com', 'site_id' => 17, 'secret' => 's3cr3t'];

$okTransport = new FakeTransport(['status' => 200, 'body' => '{"ok":true,"health":true,"events":2}']);
$client      = new Client($okTransport);
$result      = $client->send($cfg, ['events' => [['id' => 'e1']]]);

ipCheck('Client: a 200 ok:true reply is parsed into ok/health/events', $result === ['ok' => true, 'health' => true, 'events' => 2]);
ipCheck('Client: posts to {manager_url}/api/agent/shield', $okTransport->lastRequest['url'] === 'https://panel.example.com/api/agent/shield');
ipCheck('Client: sends the required headers with the right site id', $okTransport->lastRequest['headers']['X-CP-Site'] === '17' && $okTransport->lastRequest['headers']['Content-Type'] === 'application/json');
ipCheck(
    'Client: X-CP-Sig matches Signer::sign() on the exact body bytes actually sent',
    $okTransport->lastRequest['headers']['X-CP-Sig'] === Signer::sign('s3cr3t', $okTransport->lastRequest['headers']['X-CP-Time'], $okTransport->lastRequest['body'])
);
ipCheck('Client: the secret itself never appears in the request body', !str_contains($okTransport->lastRequest['body'], 's3cr3t'));

$deniedTransport = new FakeTransport(['status' => 401, 'body' => '{"ok":false}']);
ipCheck('Client: a non-200 reply (e.g. 401) returns null, never throws', (new Client($deniedTransport))->send($cfg, ['events' => []]) === null);

$timeoutTransport = new FakeTransport(null, true);
ipCheck('Client: a transport failure (null) returns null, never throws', (new Client($timeoutTransport))->send($cfg, ['events' => []]) === null);

$malformedTransport = new FakeTransport(['status' => 200, 'body' => 'not json']);
ipCheck('Client: a 200 with an unparsable body returns null rather than a half-filled result', (new Client($malformedTransport))->send($cfg, ['events' => []]) === null);

echo "== Site Manager integration: privacy sweep over a realistic payload ==\n";

$sweepEvents = [
    ['id' => 'x1', 'at' => '2026-10-29T10:00:00Z', 'type' => 'lockout', 'severity' => 'warning', 'count' => 1, 'detail' => 'ล็อกบัญชีแล้ว 1 บัญชี'],
    ['id' => 'x2', 'at' => '2026-10-29T10:01:00Z', 'type' => 'login_burst', 'severity' => 'high', 'count' => 3, 'detail' => sprintf('มีบัญชีถูกล็อกแล้ว %d บัญชีใน 10 นาที', 3)],
];
$sweepHealth = HealthReport::build([
    'score' => 60,
    'items' => [['id' => 'admin_login', 'weight' => 10, 'status' => ScoreCalculator::BAD]],
], '0.8.0');
$sweepBody = (string) json_encode(['events' => $sweepEvents, 'health' => $sweepHealth], JSON_UNESCAPED_UNICODE);

$forbidden = [
    '192.168.1.1', '203.0.113.7',                 // a raw IPv4 anywhere
    'admin@', '@example.com',                      // an email shape
    'super-secret-admin', 'root_user',              // stand-in usernames that must never appear
];
$leaked = array_filter($forbidden, static fn (string $needle): bool => str_contains($sweepBody, $needle));
ipCheck('Privacy sweep: a realistic events+health payload contains none of the forbidden shapes', $leaked === []);
ipCheck('Privacy sweep: no field name for username/ip/email/password/token/cookie appears at all', !preg_match('/username|"ip"|email|password|sha1|token|cookie/i', $sweepBody));
