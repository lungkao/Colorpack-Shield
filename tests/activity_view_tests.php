<?php
/**
 * The Activity screen's plain-language layer: the level and sentence of a row (EventPresenter), the owner's Block /
 * Unblock button (IpBlocker) and the request path honouring it. Included by run.php after plugin_flow_tests.php
 * (reuses ipCheck, flow(), flowCheck() and the autoloaders).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Component\ColorpackShield\Administrator\Core\EventPresenter;
use Colorpack\Component\ColorpackShield\Administrator\Core\IpBlocker;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\MemoryStateStore;
use Colorpack\Plugin\System\ColorpackShield\Waf\TargetedBanPolicy;

echo "== Activity: level and plain-language description of a row ==\n";

$row = static fn (string $type, array $f = []): array => ['time' => 1_800_000_000, 'type' => $type, 'f' => $f];

ipCheck('an injection that was blocked is high', EventPresenter::level($row('BLOCK', ['rule' => 'union_select'])) === 'high');
ipCheck('a blocked upload is high', EventPresenter::level($row('BLOCK', ['kind' => 'upload'])) === 'high');
ipCheck('a blocked scanner probe is medium', EventPresenter::level($row('BLOCK', ['rule' => 'scanner_probe'])) === 'medium');
ipCheck('a lock-out is high, an alert medium, a log-only hit low, a note info', EventPresenter::level($row('LOCK')) === 'high' && EventPresenter::level($row('ALERT')) === 'medium' && EventPresenter::level($row('DETECT', ['rule' => 'union_select'])) === 'low' && EventPresenter::level($row('NOTE')) === 'info');
ipCheck('a row with a known rule is explained by that rule\'s sentence', EventPresenter::descriptionKey($row('BLOCK', ['rule' => 'union_select']), ['union_select']) === 'COM_COLORPACK_SHIELD_RULE_UNION_SELECT');
ipCheck('a row with an unknown rule falls back to the sentence of its type', EventPresenter::descriptionKey($row('BLOCK', ['rule' => 'kind:odd']), ['union_select']) === 'COM_COLORPACK_SHIELD_TYPE_BLOCK_HINT' && EventPresenter::descriptionKey($row('NOTE'), []) === 'COM_COLORPACK_SHIELD_TYPE_NOTE');

echo "== Activity: Block / Unblock button (IpBlocker) ==\n";

$T       = 1_800_000_000;
$blocker = new IpBlocker(new MemoryStateStore());

ipCheck('a public address is blocked, and then reported as blocked', $blocker->block('198.51.100.50', $T, '203.0.113.1', '') === '' && $blocker->isBlocked('198.51.100.50', $T));
ipCheck('the block is a manual ban of seven days', (new TargetedBanPolicy(new MemoryStateStore()))->ban('198.51.100.51', $T, IpBlocker::HOURS * 3600, IpBlocker::REASON) === $T + 7 * 86400);
ipCheck('another address is not affected', $blocker->isBlocked('198.51.100.52', $T) === false);
ipCheck('the block ends by itself after a week', $blocker->isBlocked('198.51.100.50', $T + 7 * 86400 + 1) === false);
ipCheck('unblock lifts it and says so; unblocking again says there was nothing to lift', $blocker->unblock('198.51.100.50', $T) === true && $blocker->isBlocked('198.51.100.50', $T) === false && $blocker->unblock('198.51.100.50', $T) === false);
ipCheck('a block can be lifted even when it was made by an automatic rule', (static function () use ($T): bool {
    $store = new MemoryStateStore();
    (new TargetedBanPolicy($store))->ban('198.51.100.60', $T, 3600, 'scanner_probe');
    $b = new IpBlocker($store);

    return $b->isBlocked('198.51.100.60', $T) && $b->unblock('198.51.100.60', $T) && !$b->isBlocked('198.51.100.60', $T);
})());
ipCheck('nonsense, private and reserved addresses are refused', $blocker->block('not-an-ip', $T, '', '') === 'invalid' && $blocker->block('192.168.1.5', $T, '', '') === 'not_public' && $blocker->block('10.0.0.1', $T, '', '') === 'not_public' && $blocker->block('127.0.0.1', $T, '', '') === 'not_public');
ipCheck('you cannot block your own address (an IPv6 address counts by its /64)', $blocker->block('198.51.100.70', $T, '198.51.100.70', '') === 'self' && $blocker->block('2001:db8::5', $T, '2001:db8::9', '') === 'self');
ipCheck('a trusted address (single or range) cannot be blocked', $blocker->block('198.51.100.80', $T, '', "198.51.100.80\n") === 'trusted' && $blocker->block('198.51.100.81', $T, '', "198.51.100.0/24\n") === 'trusted' && $blocker->block('198.51.101.5', $T, '', "198.51.100.0/24\n") === '');

echo "== Activity: the request path honours a manual block whatever the other settings are ==\n";

$bans = new FileStateStore(JPATH_ROOT . '/cache/colorpack_shield/bans');
$real = new IpBlocker($bans);
$ip   = '198.51.100.121';

flowCheck('before: an ordinary visit is allowed', flow(['path_probe_mode' => 'off'], ['REMOTE_ADDR' => $ip, 'REQUEST_URI' => '/index.php']), false);
ipCheck('block (with the scanner-probe mode off and path inspection off)', $real->block($ip, time(), '203.0.113.1', '') === '');
flowCheck('after: the blocked address is refused even with the probe mode off', flow(['path_probe_mode' => 'off'], ['REMOTE_ADDR' => $ip, 'REQUEST_URI' => '/index.php']), true);
flowCheck('…and with path inspection switched off too', flow(['path_scan' => 0], ['REMOTE_ADDR' => $ip, 'REQUEST_URI' => '/index.php']), true);
flowCheck('a different address is still allowed', flow(['path_probe_mode' => 'off'], ['REMOTE_ADDR' => '198.51.100.122', 'REQUEST_URI' => '/index.php']), false);
ipCheck('unblock', $real->unblock($ip, time()) === true);
flowCheck('after unblocking the address is allowed again', flow(['path_probe_mode' => 'off'], ['REMOTE_ADDR' => $ip, 'REQUEST_URI' => '/index.php']), false);
