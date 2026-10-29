<?php
/**
 * TrustPolicy + proxy-default tests (AUDIT.md C1). Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Net/TrustPolicy.php';

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;
use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;
use Colorpack\Plugin\System\ColorpackShield\Net\TrustPolicy;

echo "== C1: proxy trust is off by default ==\n";

$cfAll   = CloudflareRanges::bundled();
$default = new ClientIpResolver($cfAll);                       // no proxies configured
$declared = new ClientIpResolver($cfAll, ['127.0.0.1', '::1']); // operator declared a local proxy
$list    = IpAllowList::fromText('203.0.113.5');

$forged = [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '104.16.0.1',
    'HTTP_CF_CONNECTING_IP' => '203.0.113.5',
];

$c = $default->resolve($forged);
ipCheck('default: loopback peer cannot forge the visitor IP', $c->ip === '127.0.0.1' && $c->via === ClientIp::VIA_DIRECT);
ipCheck('default: forged header is reported as ignored', $c->headerIgnored === true);
ipCheck('default: forged request is not on the trusted list', !$list->matches($c->ip));
ipCheck('default: forged request gets NO trust',
    TrustPolicy::decide($c, $list->matches($c->ip)) === TrustPolicy::NONE);

$c = $default->resolve(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5']);
ipCheck('default: plain XFF from loopback is ignored', $c->ip === '127.0.0.1');

echo "== C1: trust level depends on how the IP was learned ==\n";

$direct = $default->resolve(['REMOTE_ADDR' => '203.0.113.5']);
ipCheck('listed + direct peer → FULL', TrustPolicy::decide($direct, $list->matches($direct->ip)) === TrustPolicy::FULL);

$viaCf = $default->resolve(['REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5']);
ipCheck('listed + Cloudflare header → SOFT', TrustPolicy::decide($viaCf, $list->matches($viaCf->ip)) === TrustPolicy::SOFT);

$viaProxy = $declared->resolve($forged);
ipCheck('proxy declared: the forgery still resolves to the trusted IP…', $viaProxy->ip === '203.0.113.5');
ipCheck('…but only earns SOFT trust (WAF keeps running)',
    TrustPolicy::decide($viaProxy, $list->matches($viaProxy->ip)) === TrustPolicy::SOFT);

$viaProxyOnly = $declared->resolve(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5']);
ipCheck('proxy declared, XFF only → SOFT', TrustPolicy::decide($viaProxyOnly, true) === TrustPolicy::SOFT);

ipCheck('not listed → NONE', TrustPolicy::decide($direct, false) === TrustPolicy::NONE);
ipCheck('no IP → NONE even if listed', TrustPolicy::decide(new ClientIp('', '', ClientIp::VIA_DIRECT), true) === TrustPolicy::NONE);
ipCheck('Cloudflare edge without header → SOFT, not FULL',
    TrustPolicy::decide(new ClientIp('203.0.113.5', '104.16.0.1', ClientIp::VIA_CLOUDFLARE_NOHEADER), true) === TrustPolicy::SOFT);
ipCheck('direct peer that also sent a CF header (ignored) → still FULL',
    TrustPolicy::decide($default->resolve(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_CF_CONNECTING_IP' => '9.9.9.9']), true) === TrustPolicy::FULL);

echo "== C1: auto-add refuses addresses that stand for many visitors ==\n";

$cf = CloudflareRanges::bundled();
$no = [];   // the new default: no proxies configured
$ok = static fn (string $ip, string $via = ClientIp::VIA_DIRECT): bool =>
    IpAllowList::isSafeToAutoAdd(new ClientIp($ip, $ip, $via), $cf, $no);

ipCheck('public address → allowed', $ok('198.51.100.7'));
ipCheck('REFUSE 127.0.0.1 even with no proxy configured', !$ok('127.0.0.1'));
ipCheck('REFUSE ::1', !$ok('::1'));
ipCheck('REFUSE 10.0.0.5 (private)', !$ok('10.0.0.5'));
ipCheck('REFUSE 172.16.4.4 (private)', !$ok('172.16.4.4'));
ipCheck('REFUSE 192.168.1.20 (private)', !$ok('192.168.1.20'));
ipCheck('REFUSE fc00::1 (private IPv6)', !$ok('fc00::1'));
ipCheck('REFUSE 169.254.1.1 (link-local)', !$ok('169.254.1.1'));
ipCheck('REFUSE 0.0.0.0', !$ok('0.0.0.0'));
ipCheck('REFUSE a Cloudflare edge address', !$ok('104.16.0.1'));
