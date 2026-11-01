<?php
/**
 * Settings schema, typed reading/cleaning, the Thai/English texts, the rate-limit counter without APCu,
 * and the kept AI analyses. Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

$base = __DIR__ . '/../colorpack-shield/src';

/** label first, then the condition; a third argument is shown only when it fails. */
function check(string $label, bool $condition, string $detail = ''): void
{
    ok($label . (!$condition && $detail !== '' ? ' [' . $detail . ']' : ''), $condition);
}

foreach (['Admin/IniStrings', 'Admin/LocalePick', 'Admin/SettingsSchema', 'Admin/Lang', 'Admin/Settings', 'Admin/SettingsGuard',
          'RateLimit/RateStore', 'RateLimit/RateVerdict', 'RateLimit/RateLimiter', 'RateLimit/ApcuRateStore', 'RateLimit/FileRateStore', 'RateLimit/RateStores',
          'Gemini/AnalysisHistory', 'AdminProtect/AccessGateConfig', 'AdminProtect/AdminProtectConfig', 'Net/TrustPolicy', 'Safety/KillSwitch', 'Waf/UploadThreat', 'Waf/UploadScanner', 'Geo/GeoPolicy'] as $f) {
    require_once $base . '/' . $f . '.php';
}

use Colorpack\WP\ColorpackShield\Admin\IniStrings;
use Colorpack\WP\ColorpackShield\Admin\Lang;
use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\Admin\SettingsGuard;
use Colorpack\WP\ColorpackShield\Admin\SettingsSchema;
use Colorpack\WP\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\WP\ColorpackShield\Gemini\AnalysisHistory;
use Colorpack\WP\ColorpackShield\RateLimit\FileRateStore;
use Colorpack\WP\ColorpackShield\RateLimit\RateLimiter;
use Colorpack\WP\ColorpackShield\RateLimit\RateStores;

echo "\n== Settings schema: same groups as the Joomla edition, every text in both languages ==\n";

$fields = SettingsSchema::fields();
$sets   = SettingsSchema::fieldsets();
$texts  = [];

foreach (['th-TH', 'en-GB'] as $tag) {
    $texts[$tag] = IniStrings::parse((string) file_get_contents(__DIR__ . '/../colorpack-shield/languages/' . $tag . '.ini'));
}

check('all 12 tabs of the Joomla form are present', array_keys($sets) === ['basic', 'safety', 'clientip', 'shields', 'headers', 'paths', 'adminprotect', 'geoip', 'ratelimit', 'advanced', 'sitemanager', 'gemini']);
check('70 fields (66 Joomla + 4 WordPress switches)', count($fields) === 70);

$missing = [];

foreach ($sets as $set) {
    foreach (['th-TH', 'en-GB'] as $tag) {
        isset($texts[$tag][$set['label']]) || $missing[] = $tag . ':' . $set['label'];
    }

    foreach ($set['fields'] as $f) {
        foreach (['th-TH', 'en-GB'] as $tag) {
            isset($texts[$tag][$f['label']]) || $missing[] = $tag . ':' . $f['label'];
            $f['desc'] === '' || isset($texts[$tag][$f['desc']]) || $missing[] = $tag . ':' . $f['desc'];

            foreach ($f['options'] ?? [] as $o) {
                isset($texts[$tag][$o]) || $missing[] = $tag . ':' . $o;
            }
        }
    }
}

check('every tab, label, help text and option has Thai and English text', $missing === [], implode(', ', array_slice($missing, 0, 5)));
check('every setting the Basic view lists exists', array_diff(SettingsSchema::BASIC, array_keys($fields)) === []);

echo "\n== Settings: typed values and cleaning ==\n";

$d = Settings::normalise([]);

check('nothing stored: login lock-out and Site Manager reporting are on, the firewall is off', $d['login_lockout'] === true && $d['site_manager_enabled'] === true && $d['waf_enabled'] === false);
check('switches are booleans, numbers are integers, lists are strings', $d['shield_sqli'] === true && $d['login_max_failures'] === 5 && $d['path_mode'] === 'recommended');
check('older names stay as aliases (login_protect_enabled, mfa_mode)', $d['login_protect_enabled'] === $d['login_lockout'] && $d['mfa_mode'] === $d['mfa_enforce']);
check('options saved by the first release are carried over', Settings::normalise(['login_protect_enabled' => false, 'mfa_mode' => 'warn'])['login_lockout'] === false && Settings::normalise(['mfa_mode' => 'warn'])['mfa_enforce'] === 'warn');

$c = Settings::clean(['login_max_failures' => '9999', 'login_lock_minutes' => '-4', 'path_mode' => 'nonsense', 'waf_enabled' => '1', 'allow_ips' => "10.0.0.1\n10.0.0.2", 'unknown_key' => 'x', 'rate_limit' => 'abc']);

check('a number above its range is moved to the top, below to the bottom', $c['login_max_failures'] === 100 && $c['login_lock_minutes'] === 1);
check('an unknown list value becomes the default', $c['path_mode'] === 'recommended');
check('text areas keep their lines; unknown keys are dropped; junk numbers fall back', $c['allow_ips'] === "10.0.0.1\n10.0.0.2" && !array_key_exists('unknown_key', $c) && $c['rate_limit'] === 120);
check('an unticked switch (not posted) is off', Settings::clean([])['cover_site'] === false);

$guard = SettingsGuard::check(['gate_enabled' => '1', 'gate_key' => 'x', 'alert_email' => 'not-an-email', 'allow_ips' => "bad line!!\n203.0.113.5"]);
$codes = array_column($guard['errors'], 'code');

check('the guard refuses a short access key, a bad e-mail and a bad address line', in_array('gate_key_invalid', $codes, true) && in_array('email_invalid', $codes, true) && in_array('invalid_line', $codes, true));

echo "\n== Language: Thai and English from the same files ==\n";

Lang::force('th-TH');
check('Thai text', Lang::t('COM_COLORPACK_SHIELD_NAV_SETTINGS') === 'การตั้งค่า');
Lang::force('en-GB');
check('English text', Lang::t('COM_COLORPACK_SHIELD_NAV_SETTINGS') === 'Settings');
check('a text with a number', str_contains(Lang::t('COM_COLORPACK_SHIELD_TL_AI_CLEARED', 3), '3'));
check('an unknown key shows the key, not a blank', Lang::t('NOT_A_KEY') === 'NOT_A_KEY');
Lang::force(null);

echo "\n== Rate limit without APCu: file counter (WordPress) ==\n";

$dir   = sys_get_temp_dir() . '/cps-wp-rate-' . bin2hex(random_bytes(4));
$now   = 1_800_000_000;
$store = static fn (int $t): FileRateStore => new FileRateStore($dir, $t);

check('counts up inside a window, then starts again', $store($now)->increment('w', 60) === 1 && $store($now + 5)->increment('w', 60) === 2 && $store($now + 61)->increment('w', 60) === 1);
$store($now)->put('ban', 300);
check('a ban lasts its time and then ends', $store($now + 100)->ttl('ban') === 200 && $store($now + 301)->ttl('ban') === 0);

$limiter = new RateLimiter($store($now), 60, 3, 2, 300, 600);
$v       = [];

for ($i = 0; $i < 5; $i++) {
    $v[] = $limiter->decide($now, '203.0.113.9', 'site:');
}

check('the limiter lets 3 through and stops the 4th', $v[2]->allowed && !$v[3]->allowed);
check('an unwritable folder fails open', (new FileRateStore('/proc/cps-none/rate', $now))->increment('k', 60) === 1);
check('picker offers a counter when the folder is writable', RateStores::pick($dir) !== null);

echo "\n== AI analyses: keep, list, clear (WordPress) ==\n";

$hist = new AnalysisHistory(new FileStateStore($dir . '-ai'));
$hist->record('waf_ondemand', 'p', 'a', $now);
$hist->record('scan_ondemand', 'p', 'b', $now + 1);

check('both kinds are listed, newest first', array_column($hist->recent($now + 5, 10), 'kind') === ['scan_ondemand', 'waf_ondemand']);
check('clear removes them all and says how many', $hist->clear($now + 5) === 2 && $hist->recent($now + 5, 10) === []);

foreach ([$dir, $dir . '-ai'] as $d2) {
    foreach (glob($d2 . '/*') ?: [] as $f) {
        @unlink($f);
    }

    @rmdir($d2);
}
