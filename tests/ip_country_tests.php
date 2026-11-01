<?php
/**
 * IP country: Cloudflare header memory, remote lookup limits, privacy. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

require_once __DIR__ . '/../plugins/system/colorpack_shield/src/Net/IpCountry.php';

use Colorpack\Plugin\System\ColorpackShield\Net\IpCountry;

echo "\n== IP country ==\n";

$dir   = sys_get_temp_dir() . '/cps-cc-' . bin2hex(random_bytes(4));
$calls = [];
$fetch = static function (string $ip) use (&$calls): ?string {
    $calls[] = $ip;

    return $ip === '203.0.113.7' ? 'th' : ($ip === '198.51.100.9' ? 'US' : null);
};
$cc = new IpCountry($dir, $fetch, 1_800_000_000);

ipCheck('Cloudflare header: a good code is remembered and found without any lookup', ($cc->remember('203.0.113.5', 'jp') || true) && $cc->lookup('203.0.113.5', false) === 'JP' && $calls === []);
ipCheck('Cloudflare header: junk, XX and T1 are ignored', ($cc->remember('203.0.113.6', 'XX') || $cc->remember('203.0.113.6', 'T1') || $cc->remember('203.0.113.6', '<script>') || true) && $cc->lookup('203.0.113.6', false) === null);
ipCheck('private and reserved addresses never get a country or a lookup', $cc->lookup('10.0.0.1', true) === null && $cc->lookup('127.0.0.1', true) === null && $calls === []);
ipCheck('lookup is not made when remote lookups are not allowed', $cc->lookup('203.0.113.7', false) === null && $calls === []);
ipCheck('lookup asks once, upper-cases the code, and remembers it', $cc->lookup('203.0.113.7', true) === 'TH' && $cc->lookup('203.0.113.7', true) === 'TH' && $calls === ['203.0.113.7']);
ipCheck('an unknown answer is remembered too (a dead service is not asked again)', $cc->lookup('192.0.2.50', true) === null && $cc->lookup('192.0.2.50', true) === null && count($calls) === 2);

$many = new IpCountry($dir . '-many', static function (string $ip) use (&$calls): ?string { $calls[] = $ip; return 'US'; }, 1_800_000_000);
$before = count($calls);

for ($i = 1; $i <= 30; $i++) {
    $many->lookup('198.51.100.' . $i, true);
}

ipCheck('at most MAX_LOOKUPS remote lookups per page view', count($calls) - $before === IpCountry::MAX_LOOKUPS);
ipCheck('label shows the code (flag is only decoration)', str_ends_with(IpCountry::label('TH'), ' TH') && str_contains(IpCountry::label('TH'), "\u{1F1F9}\u{1F1ED}"));

$later = new IpCountry($dir, $fetch, 1_800_000_000 + 31 * 86400);
ipCheck('a remembered country is forgotten after 30 days', $later->lookup('203.0.113.5', false) === null);

foreach ([$dir, $dir . '-many'] as $d) {
    foreach (glob($d . '/*') ?: [] as $f) {
        @unlink($f);
    }

    @rmdir($d);
}
