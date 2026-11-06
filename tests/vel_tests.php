<?php
/**
 * The JED Vulnerable Extensions List check: feed items -> rules, matching against installed extensions, and the
 * once-a-day refresh against a fake downloader. Included by run.php (reuses ipCheck and the plugin autoloader).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;
use Colorpack\Plugin\System\ColorpackShield\Vulnerable\VelFeed;
use Colorpack\Plugin\System\ColorpackShield\Vulnerable\VelRules;

echo "== Vulnerable extensions (JED list) ==\n";

$items = [
    ['id' => '1', 'title' => 'JEVents, 3.6.87, SQL Injection', 'status' => '1'],
    ['id' => '2', 'title' => 'HikaShop, 5.1.3, Other ACL', 'status' => '2', 'patch_version' => '5.1.4', 'cve_id' => 'CVE-2026-1', 'update_notice' => 'https://example.com/n'],
    ['id' => '3', 'title' => 'EasyDiscuss by Stackideas,, , SQL Injection', 'status' => '1'],
    ['id' => '4', 'title' => 'Google Map Landkarten,4.2.3,SQL Injection', 'status' => '1', 'install_data' => ['name' => 'COM_GMAP', 'type' => 'component']],
    ['id' => '5', 'title' => 'Mystery Thing, , Other', 'status' => '2'],
    ['id' => '6', 'title' => 'JS, 1.0, XSS', 'status' => '1'],
    ['id' => '7', 'title' => 'Evil Plugin, 1.0, Back Door', 'status' => '1', 'install_data' => ['name' => 'plg_system_evilthing', 'type' => 'plugin']],
    ['id' => '8', 'title' => 'Old Thing, 2.0, XSS', 'status' => '1', 'start_version' => '1.5'],
];
$rules = VelRules::fromFeed($items);

ipCheck('VEL: items that cannot be judged are dropped (resolved without versions, 2-letter name)', \count($rules) === 6);
$byId = array_column($rules, null, 'id');
ipCheck('VEL: a named item is keyed by its normalised name', $byId['1']['key'] === '~jevents' && $byId['1']['last'] === '3.6.87' && $byId['1']['sev'] === 'high');
ipCheck('VEL: a fixed version bounds the rule from above (and the notice URL is kept)', $byId['2']['fixed'] === '5.1.4' && $byId['2']['last'] === null && $byId['2']['url'] === 'https://example.com/n' && !$byId['2']['live']);
ipCheck('VEL: "by author" and versions are not part of the name', $byId['3']['key'] === '~easydiscuss');
ipCheck('VEL: install_data gives the element; a plugin element drops its group', $byId['4']['key'] === 'com_gmap' && $byId['7']['key'] === 'evilthing');
ipCheck('VEL: a back door is critical', $byId['7']['sev'] === 'critical');

$installed = [
    ['name' => 'JEvents', 'element' => 'com_jevents', 'type' => 'component', 'version' => '3.6.80'],
    ['name' => 'HikaShop', 'element' => 'com_hikashop', 'type' => 'component', 'version' => '5.1.3'],
    ['name' => 'COM_GMAP', 'element' => 'com_gmap', 'type' => 'component', 'version' => '4.2.3'],
    ['name' => 'plg_system_evilthing', 'element' => 'evilthing', 'type' => 'plugin', 'version' => '0.9'],
    ['name' => 'EasyDiscuss', 'element' => 'com_easydiscuss', 'type' => 'component', 'version' => '5.0'],
    ['name' => 'Old Thing', 'element' => 'com_oldthing', 'type' => 'component', 'version' => '1.0'],
    ['name' => 'Fine', 'element' => 'com_fine', 'type' => 'component', 'version' => '9.9'],
];
$found = VelRules::match($rules, $installed);
$names = array_column($found, 'name');

ipCheck('VEL: affected installed extensions are found, most severe first', $names[0] === 'plg_system_evilthing' && \count($found) === 5);
ipCheck('VEL: a version before "introduced" is not affected', !\in_array('Old Thing', $names, true));
ipCheck('VEL: unrelated extensions are not found', !\in_array('Fine', $names, true));
ipCheck('VEL: the fixed version itself is not affected', \count(VelRules::match($rules, [['name' => 'HikaShop', 'element' => 'com_hikashop', 'type' => 'component', 'version' => '5.1.4']])) === 0);
ipCheck('VEL: a version newer than the last affected one is not affected', \count(VelRules::match($rules, [['name' => 'JEvents', 'element' => 'com_jevents', 'type' => 'component', 'version' => '3.6.90']])) === 0);
ipCheck('VEL: normName', VelRules::normName('EasyDiscuss by Stackideas') === 'easydiscuss' && VelRules::normName('SP Page Builder Pro 6.7.0') === 'sppagebuilderpro');

$dir   = sys_get_temp_dir() . '/cps-vel-' . bin2hex(random_bytes(4));
@mkdir($dir, 0777, true);
$store = new ScanStore($dir);
$feed  = new VelFeed($store);
$calls = [];
$T     = 1_800_000_000;
$net   = static function (string $hash, ?array $payload = null) use (&$calls): callable {
    return static function (string $url) use ($hash, $payload, &$calls): ?string {
        $calls[] = $url;

        if ($url === VelFeed::VERIFY) {
            return json_encode(['success' => true, 'data' => $hash]);
        }

        return $payload === null ? null : json_encode(['success' => true, 'data' => ['items' => $payload]]);
    };
};

ipCheck('VEL feed: nothing stored at first', $feed->stored() === null);
ipCheck('VEL feed: first refresh downloads', $feed->refresh($net('h1', $items), $T) === 'updated' && \count($feed->stored()['rules']) === 6 && $feed->stored()['hash'] === 'h1');
$calls = [];
ipCheck('VEL feed: a copy under a day old is not even asked about', $feed->refresh($net('h1', $items), $T + 3600) === 'fresh' && $calls === []);
$calls = [];
ipCheck('VEL feed: an old copy with the same hash is not downloaded again', $feed->refresh($net('h1', $items), $T + 90000) === 'unchanged' && $calls === [VelFeed::VERIFY] && $feed->stored()['at'] === $T + 90000);
ipCheck('VEL feed: a changed hash downloads again', $feed->refresh($net('h2', $items), $T + 200000) === 'updated' && $feed->stored()['hash'] === 'h2');
ipCheck('VEL feed: a failed download keeps the stored copy', $feed->refresh($net('h3', null), $T + 400000) === 'failed' && $feed->stored()['hash'] === 'h2' && \count($feed->stored()['rules']) === 6);
ipCheck('VEL feed: a forced refresh always downloads', $feed->refresh($net('h2', $items), $T + 400001, true) === 'updated');
ipCheck('VEL feed: curlGet refuses any other host and plain http', VelFeed::curlGet('https://evil.example.com/vel-feed') === null && VelFeed::curlGet('http://extensions.joomla.org/vel-feed') === null);
