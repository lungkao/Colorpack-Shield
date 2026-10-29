<?php
/**
 * Visitor-IP resolution tests (Cloudflare + trusted proxies). Included by run.php,
 * so it shares its $pass / $fail counters.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$net = __DIR__ . '/../plugins/system/colorpack_shield/src/Net';
require_once $net . '/ClientIp.php';
require_once $net . '/CloudflareRanges.php';
require_once $net . '/ClientIpResolver.php';

use Colorpack\Plugin\System\ColorpackShield\Net\ClientIp;
use Colorpack\Plugin\System\ColorpackShield\Net\ClientIpResolver;
use Colorpack\Plugin\System\ColorpackShield\Net\CloudflareRanges;

/**
 * @param array<string,string> $server
 * @param string|null          $wantIgnored  null = don't assert
 */
function ipCase(
    string $label,
    ClientIpResolver $r,
    array $server,
    string $wantIp,
    string $wantVia,
    ?bool $wantIgnored = null
): void {
    global $pass, $fail;
    $c   = $r->resolve($server);
    $bad = [];

    if ($c->ip !== $wantIp) {
        $bad[] = "ip want '$wantIp' got '{$c->ip}'";
    }

    if ($c->via !== $wantVia) {
        $bad[] = "via want '$wantVia' got '{$c->via}'";
    }

    if ($wantIgnored !== null && $c->headerIgnored !== $wantIgnored) {
        $bad[] = 'headerIgnored want ' . var_export($wantIgnored, true);
    }

    if ($bad) {
        echo "  FAIL: $label — " . implode('; ', $bad) . "\n";
        $fail++;

        return;
    }

    $pass++;
}

function ipCheck(string $label, bool $ok): void
{
    global $pass, $fail;

    if ($ok) {
        $pass++;

        return;
    }

    echo "  FAIL: $label\n";
    $fail++;
}

echo "== Visitor IP: Cloudflare range list ==\n";

$cf = CloudflareRanges::bundled();
ipCheck('bundled list has 15 v4 + 7 v6', \count($cf) === 22);
ipCheck('bundled list passes its own parser', CloudflareRanges::parse(implode("\n", $cf)) !== null);

// Membership boundaries (family-correct, mask edges).
use Colorpack\Plugin\System\ColorpackShield\Geo\CidrMatcher;
require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Geo/CidrMatcher.php';
ipCheck('104.27.255.255 inside 104.24.0.0/14', CidrMatcher::matchesAny('104.27.255.255', $cf));
ipCheck('104.28.0.0 outside Cloudflare', !CidrMatcher::matchesAny('104.28.0.0', $cf));
ipCheck('173.245.64.1 outside 173.245.48.0/20', !CidrMatcher::matchesAny('173.245.64.1', $cf));
ipCheck('2606:4700::1 inside', CidrMatcher::matchesAny('2606:4700::1', $cf));
ipCheck('2606:4701::1 outside', !CidrMatcher::matchesAny('2606:4701::1', $cf));
ipCheck('203.0.113.5 (documentation range) outside', !CidrMatcher::matchesAny('203.0.113.5', $cf));

// A refreshed list is dangerous if poisoned: it decides who may spoof the IP.
$valid = implode("\n", $cf);
ipCheck('comments and blanks tolerated', CloudflareRanges::parse("# cf\n\n" . $valid . "\n") !== null);
ipCheck('duplicate lines collapse', \count(CloudflareRanges::parse($valid . "\n" . $cf[0]) ?? []) === 22);
ipCheck('REJECT list containing 0.0.0.0/0', CloudflareRanges::parse($valid . "\n0.0.0.0/0") === null);
ipCheck('REJECT list containing ::/0', CloudflareRanges::parse($valid . "\n::/0") === null);
ipCheck('REJECT v4 broader than /8', CloudflareRanges::parse($valid . "\n64.0.0.0/7") === null);
ipCheck('REJECT v6 broader than /16', CloudflareRanges::parse($valid . "\n2000::/15") === null);
ipCheck('REJECT malformed line', CloudflareRanges::parse($valid . "\nnot-a-cidr") === null);
ipCheck('REJECT bad mask', CloudflareRanges::parse($valid . "\n1.2.3.0/33") === null);
ipCheck('REJECT bare IP (no mask)', CloudflareRanges::parse($valid . "\n1.2.3.4") === null);
ipCheck('REJECT truncated list', CloudflareRanges::parse("173.245.48.0/20\n103.21.244.0/22") === null);

// Refreshed files must be signed (AUDIT.md C2). Floors are /12 (v4) and /24 (v6).
ipCheck('/12 is the widest IPv4 range accepted', CloudflareRanges::parse($valid . "\n64.0.0.0/12") !== null);
ipCheck('REJECT IPv4 /11', CloudflareRanges::parse($valid . "\n64.0.0.0/11") === null);
ipCheck('REJECT IPv4 /8 (was accepted before the C2 fix)', CloudflareRanges::parse($valid . "\n1.0.0.0/8") === null);
ipCheck('/24 is the widest IPv6 range accepted', CloudflareRanges::parse($valid . "\n2a00::/24") !== null);
ipCheck('REJECT IPv6 /23', CloudflareRanges::parse($valid . "\n2a00::/23") === null);

$dir = sys_get_temp_dir() . '/cps-cf-' . bin2hex(random_bytes(4));
$tmp = $dir . '/cloudflare-ips.txt';
$key = CloudflareRanges::deriveKey('site-secret');
$ext = array_merge($cf, ['198.51.100.0/24']);

ipCheck('deriveKey: empty secret → empty key', CloudflareRanges::deriveKey('') === '');
ipCheck('deriveKey: different secrets → different keys', $key !== CloudflareRanges::deriveKey('other') && $key !== '');

ipCheck('store(): writes list and signature', CloudflareRanges::store($tmp, $ext, $key) && is_file($tmp) && is_file($tmp . '.sig'));
ipCheck('load(): correctly signed refreshed file is used', \in_array('198.51.100.0/24', CloudflareRanges::load($tmp, $key), true));
ipCheck('load(): file is not world-writable after store()', (fileperms($tmp) & 0002) === 0);
ipCheck('load(): no key → refreshed file ignored', CloudflareRanges::load($tmp, '') === $cf);
ipCheck('load(): wrong key → refreshed file ignored', CloudflareRanges::load($tmp, CloudflareRanges::deriveKey('other')) === $cf);

// Attacker with write access to the cache dir but without the secret.
file_put_contents($tmp, $valid . "\n198.51.100.0/24\n198.18.0.0/16\n");
ipCheck('ATTACK: edited file with the old signature is ignored', CloudflareRanges::load($tmp, $key) === $cf);
unlink($tmp . '.sig');
ipCheck('ATTACK: unsigned file is ignored', CloudflareRanges::load($tmp, $key) === $cf);
file_put_contents($tmp . '.sig', CloudflareRanges::sign(file_get_contents($tmp), 'attacker-guess') . "\n");
ipCheck('ATTACK: file signed with a guessed key is ignored', CloudflareRanges::load($tmp, $key) === $cf);

// Signed but poisoned (e.g. a bug in the refresher): parse() still refuses it.
file_put_contents($tmp, $valid . "\n0.0.0.0/0\n");
file_put_contents($tmp . '.sig', CloudflareRanges::sign(file_get_contents($tmp), $key) . "\n");
ipCheck('signed but poisoned list is still refused', CloudflareRanges::load($tmp, $key) === $cf);
ipCheck('store(): refuses to write a poisoned list', !CloudflareRanges::store($dir . '/x.txt', array_merge($cf, ['0.0.0.0/0']), $key) && !is_file($dir . '/x.txt'));
// Forged with the one key an attacker can always guess: the empty one.
file_put_contents($tmp, $valid . "\n198.51.100.0/24\n");
file_put_contents($tmp . '.sig', CloudflareRanges::sign(file_get_contents($tmp), '') . "\n");
ipCheck('ATTACK: file "signed" with an empty key is ignored when no key is available', CloudflareRanges::load($tmp, '') === $cf);
ipCheck('store(): refuses without a key', !CloudflareRanges::store($dir . '/y.txt', $ext, '') && !is_file($dir . '/y.txt'));

// A world-writable file is not trusted even with a valid signature.
CloudflareRanges::store($tmp, $ext, $key);
chmod($tmp, 0666);
clearstatcache();
ipCheck('world-writable file is ignored even if correctly signed', CloudflareRanges::load($tmp, $key) === $cf);
chmod($tmp, 0644);
clearstatcache();
ipCheck('…and used again once permissions are sane', \in_array('198.51.100.0/24', CloudflareRanges::load($tmp, $key), true));

array_map('unlink', glob($dir . '/*') ?: []);
@rmdir($dir);
ipCheck('load(): missing file falls back to bundled', CloudflareRanges::load('/nonexistent/cf.txt', $key) === $cf);
ipCheck('load(): empty path falls back to bundled', CloudflareRanges::load('', $key) === $cf);

echo "== Visitor IP: normalise() ==\n";
ipCheck('plain v4', ClientIpResolver::normalise(' 1.2.3.4 ') === '1.2.3.4');
ipCheck('v4 with port', ClientIpResolver::normalise('1.2.3.4:8080') === '1.2.3.4');
ipCheck('bracketed v6 with port', ClientIpResolver::normalise('[2001:db8::1]:443') === '2001:db8::1');
ipCheck('v4-mapped v6 unmapped', ClientIpResolver::normalise('::ffff:104.16.0.1') === '104.16.0.1');
ipCheck('v6 canonicalised', ClientIpResolver::normalise('2001:0DB8:0:0:0:0:0:1') === '2001:db8::1');
ipCheck('garbage rejected', ClientIpResolver::normalise('1.2.3.4, 5.6.7.8') === '');
ipCheck('hostname rejected', ClientIpResolver::normalise('evil.example.com') === '');
ipCheck('empty rejected', ClientIpResolver::normalise('') === '');
ipCheck('overlong rejected', ClientIpResolver::normalise(str_repeat('1', 200)) === '');
ipCheck('octal-ish rejected', ClientIpResolver::normalise('0177.0.0.1') === '');

echo "== Visitor IP: resolver ==\n";
// A local nginx (HestiaCP-style) is declared explicitly: proxy trust is OFF by default (AUDIT.md C1).
$r = new ClientIpResolver($cf, ['127.0.0.1', '::1']);

ipCase('direct visitor', $r, ['REMOTE_ADDR' => '203.0.113.5'], '203.0.113.5', ClientIp::VIA_DIRECT, false);
ipCase('Cloudflare v4 edge', $r, [
    'REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE, false);
ipCase('Cloudflare v6 edge + v6 visitor', $r, [
    'REMOTE_ADDR' => '2606:4700::1', 'HTTP_CF_CONNECTING_IP' => '2001:db8::5',
], '2001:db8::5', ClientIp::VIA_CLOUDFLARE);
ipCase('v4-mapped REMOTE_ADDR on Cloudflare edge', $r, [
    'REMOTE_ADDR' => '::ffff:104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE);

// Spoof attempts must be ignored.
ipCase('SPOOF: direct hit with CF-Connecting-IP', $r, [
    'REMOTE_ADDR' => '203.0.113.5', 'HTTP_CF_CONNECTING_IP' => '1.1.1.1',
], '203.0.113.5', ClientIp::VIA_DIRECT, true);
ipCase('SPOOF: direct hit with X-Forwarded-For', $r, [
    'REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9',
], '203.0.113.5', ClientIp::VIA_DIRECT, false);
ipCase('SPOOF: non-trusted private peer cannot vouch for headers', $r, [
    'REMOTE_ADDR' => '10.0.0.9', 'HTTP_CF_CONNECTING_IP' => '1.1.1.1',
], '10.0.0.9', ClientIp::VIA_DIRECT, true);

// Cloudflare edge but unusable header.
ipCase('Cloudflare edge, header missing, XFF has visitor', $r, [
    'REMOTE_ADDR' => '104.16.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE_NOHEADER);
ipCase('Cloudflare edge, header missing, no XFF', $r, [
    'REMOTE_ADDR' => '104.16.0.1',
], '104.16.0.1', ClientIp::VIA_CLOUDFLARE_NOHEADER);
ipCase('Cloudflare edge, header not an IP', $r, [
    'REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => 'not-an-ip',
], '104.16.0.1', ClientIp::VIA_CLOUDFLARE_NOHEADER);
ipCase('Cloudflare edge, header is a list', $r, [
    'REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4, 5.6.7.8',
], '104.16.0.1', ClientIp::VIA_CLOUDFLARE_NOHEADER);

// HestiaCP-style: nginx (127.0.0.1) in front of Apache.
ipCase('local nginx → Apache, via Cloudflare', $r, [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '198.51.100.7, 172.64.0.9',
    'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE);
ipCase('local nginx, only X-Real-IP, via Cloudflare', $r, [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_REAL_IP'        => '172.64.0.9',
    'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE);
ipCase('local nginx, XFF with port and brackets', $r, [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '198.51.100.7:4433, [2606:4700::1]:443',
    'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE);
ipCase('SPOOF: attacker hits origin through local nginx', $r, [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '1.1.1.1, 203.0.113.5',   // 1.1.1.1 supplied by attacker, nginx appended the real peer
    'HTTP_CF_CONNECTING_IP' => '8.8.8.8',
], '203.0.113.5', ClientIp::VIA_PROXY, true);
ipCase('SPOOF: attacker fakes a Cloudflare edge in XFF', $r, [
    'REMOTE_ADDR'           => '127.0.0.1',
    'HTTP_X_FORWARDED_FOR'  => '172.64.0.9, 203.0.113.5',  // fake CF hop is left of the real peer
    'HTTP_CF_CONNECTING_IP' => '8.8.8.8',
], '203.0.113.5', ClientIp::VIA_PROXY, true);
ipCase('local proxy, no forwarding headers', $r, [
    'REMOTE_ADDR' => '127.0.0.1',
], '127.0.0.1', ClientIp::VIA_DIRECT);

// Extra trusted proxy range configured.
$r2 = new ClientIpResolver($cf, ['10.0.0.0/8', '127.0.0.1']);
ipCase('extra trusted proxy chain skipped', $r2, [
    'REMOTE_ADDR'           => '10.0.0.2',
    'HTTP_X_FORWARDED_FOR'  => '198.51.100.7, 172.64.0.9, 10.0.0.1',
    'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_CLOUDFLARE);

// Server already restored the visitor IP (mod_remoteip / nginx realip).
ipCase('REMOTE_ADDR already rewritten by server', $r, [
    'REMOTE_ADDR' => '198.51.100.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '198.51.100.7', ClientIp::VIA_DIRECT);

// Switch off.
$off = new ClientIpResolver($cf, ['127.0.0.1', '::1'], false);
ipCase('trust_cloudflare=off ignores the header', $off, [
    'REMOTE_ADDR' => '104.16.0.1', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
], '104.16.0.1', ClientIp::VIA_DIRECT, true);

// Unusable REMOTE_ADDR.
ipCase('missing REMOTE_ADDR', $r, [], '', ClientIp::VIA_DIRECT);
ipCase('garbage REMOTE_ADDR', $r, ['REMOTE_ADDR' => 'nope'], '', ClientIp::VIA_DIRECT);
