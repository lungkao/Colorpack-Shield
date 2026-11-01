<?php
/**
 * IP -> country for the admin screens: Cloudflare's header is kept, remote lookups are cached, rate limited,
 * public-only and fail quiet. Included by run.php, shares its ok() helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Admin\LogReader;
use Colorpack\WP\ColorpackShield\Net\IpCountry;

$GLOBALS['cps_transients'] = [];

if (!function_exists('get_transient')) {
    function get_transient(string $k)
    {
        return $GLOBALS['cps_transients'][$k] ?? false;
    }

    function set_transient(string $k, $v, int $ttl): bool
    {
        $GLOBALS['cps_transients'][$k] = $v;

        return true;
    }
}

$calls = 0;
$fetch = static function (string $ip) use (&$calls): ?string {
    $calls++;

    return $ip === '203.0.113.9' ? 'th' : null;
};

ok('ip country: a Cloudflare-reported code is kept and found without any lookup', (function () use (&$calls) {
    IpCountry::remember('198.51.100.20', 'de');

    return IpCountry::lookup('198.51.100.20', false) === 'DE' && $calls === 0;
})());
ok('ip country: junk codes, Cloudflare unknowns (XX, T1) and private addresses are never stored', (function () {
    IpCountry::remember('198.51.100.21', 'xx');
    IpCountry::remember('198.51.100.22', "TH\n<x>");
    IpCountry::remember('10.0.0.5', 'TH');

    return IpCountry::lookup('198.51.100.21', false) === null && IpCountry::lookup('198.51.100.22', false) === null && IpCountry::lookup('10.0.0.5', true) === null;
})());
ok('ip country: remote lookup is skipped when the setting is off', IpCountry::lookup('203.0.113.9', false, $fetch) === null && $calls === 0);
ok('ip country: remote answer is upper-cased and cached (second call asks nobody)', IpCountry::lookup('203.0.113.9', true, $fetch) === 'TH' && IpCountry::lookup('203.0.113.9', true, $fetch) === 'TH' && $calls === 1);
ok('ip country: an unknown answer is remembered too, so a dead service is not asked again', IpCountry::lookup('203.0.113.77', true, $fetch) === null && IpCountry::lookup('203.0.113.77', true, $fetch) === null && $calls === 2);
ok('ip country: private and reserved addresses are never sent anywhere', IpCountry::lookup('192.168.1.5', true, $fetch) === null && IpCountry::lookup('127.0.0.1', true, $fetch) === null && IpCountry::lookup('not an ip', true, $fetch) === null && $calls === 2);
ok('ip country: at most a dozen remote lookups per page view', (function () use ($fetch) {
    $asked = 0;
    $count = static function (string $ip) use (&$asked): ?string {
        $asked++;

        return 'US';
    };

    for ($i = 1; $i <= 30; $i++) {
        IpCountry::lookup('203.0.113.' . (100 + $i), true, $count);
    }

    return $asked <= IpCountry::MAX_LOOKUPS;
})());
ok('ip country: label is the code with a flag', IpCountry::label('TH') === "\u{1F1F9}\u{1F1ED} TH");
ok('ip country: the log reader keeps the client address of each line', (function () {
    $e = LogReader::parseLine("2026-11-01T01:02:03+00:00\tWARNING\t203.0.113.9\tcolorpack_shield\tBLOCK client=site shield=sqli rule=union uri=/ sample=x");
    $n = LogReader::parseLine("2026-11-01T01:02:03+00:00\tWARNING\t-\tcolorpack_shield\tBLOCK client=site shield=sqli rule=union uri=/ sample=x");

    return $e !== null && $e['ip'] === '203.0.113.9' && $n !== null && $n['ip'] === '';
})());
