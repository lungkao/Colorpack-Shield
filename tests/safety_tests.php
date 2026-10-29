<?php
/**
 * Lock-out protection tests: emergency kill-switch file and trusted-IP list.
 * Included by run.php (shares $pass / $fail and the ipCheck() helper from
 * client_ip_tests.php).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$plug = __DIR__ . '/../plugins/system/colorpack_shield/src';
require_once $plug . '/Safety/KillSwitch.php';
require_once $plug . '/Net/IpAllowList.php';

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Safety\KillSwitch;

echo "== Kill-switch file ==\n";

$base  = sys_get_temp_dir() . '/cps-ks-' . bin2hex(random_bytes(4));
$root  = $base . '/root';
$admin = $base . '/root/administrator';
mkdir($admin, 0777, true);

ipCheck('no file → inactive', KillSwitch::find([$root, $admin]) === null);
ipCheck('filename is colorpack_shield.disable', KillSwitch::FILENAME === 'colorpack_shield.disable');

touch($admin . '/colorpack_shield.disable');
ipCheck('file in administrator/ → active', KillSwitch::find([$root, $admin]) === $admin . '/colorpack_shield.disable');

touch($root . '/colorpack_shield.disable');
ipCheck('root is checked first', KillSwitch::find([$root, $admin]) === $root . '/colorpack_shield.disable');
ipCheck('trailing slash tolerated', KillSwitch::find([$root . '/']) === $root . '/colorpack_shield.disable');
ipCheck('empty dir entry skipped', KillSwitch::find(['', $admin]) === $admin . '/colorpack_shield.disable');

unlink($root . '/colorpack_shield.disable');
unlink($admin . '/colorpack_shield.disable');
ipCheck('file removed → inactive again', KillSwitch::find([$root, $admin]) === null);

mkdir($root . '/colorpack_shield.disable');                 // a DIRECTORY with that name must not count
ipCheck('directory with the same name does not disable', KillSwitch::find([$root]) === null);
rmdir($root . '/colorpack_shield.disable');

// Near-miss names (a wrong-case name is deliberately not tested: macOS/Windows
// file systems are case-insensitive, Linux servers are not).
touch($root . '/colorpack_shield.disable.txt');
touch($root . '/colorpack_shield.disabled');
touch($root . '/colorpackshield.disable');
ipCheck('near-miss file names do not disable', KillSwitch::find([$root]) === null);
@unlink($root . '/colorpack_shield.disable.txt');
@unlink($root . '/colorpack_shield.disabled');
@unlink($root . '/colorpackshield.disable');
ipCheck('nonexistent dir is safe', KillSwitch::find([$base . '/nope']) === null);
@rmdir($admin);
@rmdir($root);
@rmdir($base);

echo "== Trusted IP list ==\n";

$l = IpAllowList::fromText("# office\n203.0.113.5\n198.51.100.0/24, 2001:db8::/32\n  \n10.1.2.3 # home vpn\n");
ipCheck('parses 4 entries', \count($l->entries()) === 4 && $l->invalid() === []);
ipCheck('exact IP matches', $l->matches('203.0.113.5'));
ipCheck('neighbour of exact IP does not match', !$l->matches('203.0.113.6'));
ipCheck('CIDR matches inside', $l->matches('198.51.100.200'));
ipCheck('CIDR does not match outside', !$l->matches('198.51.101.1'));
ipCheck('IPv6 CIDR matches', $l->matches('2001:db8:1::5'));
ipCheck('inline comment stripped', $l->matches('10.1.2.3'));
ipCheck('v4-mapped v6 matches v4 entry', $l->matches('::ffff:203.0.113.5'));
ipCheck('empty IP never matches', !$l->matches(''));
ipCheck('garbage never matches', !$l->matches('not-an-ip'));
ipCheck('empty list matches nothing', !IpAllowList::fromText('')->matches('1.2.3.4'));

// Bad lines must never widen the list.
$bad = IpAllowList::fromText("0.0.0.0/0\n::/0\n64.0.0.0/7\n2000::/15\n1.2.3.4/33\n1.2.3.4/x\nfoo\n1.2.3.4/24/8\n203.0.113.9\n");
ipCheck('too-broad / malformed lines rejected', \count($bad->invalid()) === 8);
ipCheck('good line survives bad neighbours', $bad->entries() === ['203.0.113.9']);
ipCheck('0.0.0.0/0 does NOT trust everyone', !$bad->matches('8.8.8.8'));
ipCheck('/8 is the widest allowed', IpAllowList::fromText('10.0.0.0/8')->invalid() === []);
ipCheck('duplicates collapse', \count(IpAllowList::fromText("1.2.3.4\n1.2.3.4\n1.2.3.4")->entries()) === 1);

echo "== Auto-adding the admin's IP ==\n";

ipCheck('adds to empty text', IpAllowList::appendIp('', '203.0.113.5') === '203.0.113.5');
ipCheck('appends on a new line, keeps comments',
    IpAllowList::appendIp("# office\n198.51.100.1\n", '203.0.113.5') === "# office\n198.51.100.1\n203.0.113.5");
ipCheck('no duplicate when already listed', IpAllowList::appendIp('203.0.113.5', '203.0.113.5') === '203.0.113.5');
ipCheck('no duplicate when covered by a CIDR', IpAllowList::appendIp('203.0.113.0/24', '203.0.113.77') === '203.0.113.0/24');
ipCheck('invalid IP leaves text unchanged', IpAllowList::appendIp('1.2.3.4', 'garbage') === '1.2.3.4');
ipCheck('empty IP leaves text unchanged', IpAllowList::appendIp('1.2.3.4', '') === '1.2.3.4');
ipCheck('IPv6 added in canonical form', IpAllowList::appendIp('', '2001:0DB8:0:0:0:0:0:1') === '2001:db8::1');

$full = implode("\n", array_map(static fn ($i) => '10.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1), range(0, IpAllowList::MAX_ENTRIES - 1)));
ipCheck('cap: list at MAX_ENTRIES is not extended', IpAllowList::appendIp($full, '203.0.113.5') === $full);

// Which resolved addresses may be auto-added?
$cfRanges = \Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges::bundled();
$proxies  = ['127.0.0.1', '::1'];
$safe     = static fn (ClientIp $c): bool => IpAllowList::isSafeToAutoAdd($c, $cfRanges, $proxies);

ipCheck('real visitor via Cloudflare header → safe',
    $safe(new ClientIp('198.51.100.7', '104.16.0.1', ClientIp::VIA_CLOUDFLARE)));
ipCheck('direct visitor → safe', $safe(new ClientIp('203.0.113.5', '203.0.113.5', ClientIp::VIA_DIRECT)));
ipCheck('private LAN address is refused (add LAN admins by hand)', !$safe(new ClientIp('192.168.1.20', '192.168.1.20', ClientIp::VIA_DIRECT)));
ipCheck('REFUSE Cloudflare edge address (would trust every visitor)',
    !$safe(new ClientIp('104.16.0.1', '104.16.0.1', ClientIp::VIA_DIRECT)));
ipCheck('REFUSE Cloudflare edge when header missing',
    !$safe(new ClientIp('198.51.100.7', '104.16.0.1', ClientIp::VIA_CLOUDFLARE_NOHEADER)));
ipCheck('REFUSE loopback / own proxy', !$safe(new ClientIp('127.0.0.1', '127.0.0.1', ClientIp::VIA_DIRECT)));
ipCheck('REFUSE empty IP', !$safe(new ClientIp('', '', ClientIp::VIA_DIRECT)));
