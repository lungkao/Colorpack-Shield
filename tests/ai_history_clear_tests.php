<?php
/**
 * Clearing the kept AI analyses (Tools > Analyse with AI). Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore;
use Colorpack\Plugin\System\ColorpackShield\Gemini\AnalysisHistory;

echo "\n== AI analyses: list and clear ==\n";

$now  = 1_800_000_000;
$dir  = sys_get_temp_dir() . '/cps-ai-' . bin2hex(random_bytes(4));
$hist = new AnalysisHistory(new FileStateStore($dir));

$hist->record('waf_ondemand', 'p1', 'answer one', $now);
$hist->record('scan_ondemand', 'p2', 'answer two', $now + 10);
$hist->record('waf_digest', 'p3', null, $now + 20);

ipCheck('every kind is listed, newest first', array_column($hist->recent($now + 30, 20), 'kind') === ['waf_digest', 'scan_ondemand', 'waf_ondemand']);
ipCheck('clear reports how many it removed', $hist->clear($now + 30) === 3);
ipCheck('after clear the list is empty', $hist->recent($now + 30, 20) === []);
ipCheck('clear on an empty history removes nothing and does not fail', $hist->clear($now + 31) === 0);

$hist->record('scan_ondemand', 'p4', 'again', $now + 40);
ipCheck('a new analysis after clearing is kept', count($hist->recent($now + 50, 20)) === 1);

// Other state sharing the same folder (login locks, alert throttles) must survive a clear.
$store = new FileStateStore($dir . '-b');
$store->mutate('lock:1.2.3.4', $now, static fn (): array => ['exp' => $now + 600]);
$h2 = new AnalysisHistory($store);
$h2->record('waf_ondemand', 'p', 'a', $now);
$h2->clear($now);
ipCheck('clear leaves other entries (locks, throttles) alone', $store->get('lock:1.2.3.4', $now) !== null);

foreach ([$dir, $dir . '-b'] as $d) {
    foreach (glob($d . '/*') ?: [] as $f) {
        @unlink($f);
    }

    @rmdir($d);
}
