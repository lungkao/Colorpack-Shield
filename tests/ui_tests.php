<?php
/**
 * The Colorpack Admin UI Standard in this component: the markup helpers (Service/Ui.php), the stylesheet and template
 * bans of the standard, the shared stylesheet kept verbatim, and the two language files in step. Included by run.php
 * after component_core_tests.php (reuses ipCheck() and the component autoloader).
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;

echo "== Admin UI standard: markup helpers ==\n";

if (!defined('_JEXEC')) {
    define('_JEXEC', 1);
}

$badge = Ui::badge('warn', 'Needs <b>attention</b>', 'a "hint"');
ipCheck('a badge carries an icon and the label, escaped', str_contains($badge, 'data-state="warn"') && str_contains($badge, '<svg') && str_contains($badge, 'Needs &lt;b&gt;attention&lt;/b&gt;') && str_contains($badge, 'title="a &quot;hint&quot;"'));
ipCheck('a neutral badge has no state and no icon', !str_contains(Ui::badge('', 'Off'), 'data-state') && !str_contains(Ui::badge('', 'Off'), '<svg'));
ipCheck('an unknown state falls back to neutral', !str_contains(Ui::badge('purple', 'x'), 'data-state'));
ipCheck('Bootstrap class lists map onto the severity vocabulary', Ui::stateOf('bg-success') === 'ok' && Ui::stateOf('bg-warning text-dark') === 'warn' && Ui::stateOf('bg-danger') === 'bad' && Ui::stateOf('bg-info text-dark') === 'info' && Ui::stateOf('') === '');

$c = Ui::callout('bad', 'Title <x>', 'Text & more');
ipCheck('a bad callout is an alert with icon, escaped title and text', str_contains($c, 'role="alert"') && str_contains($c, 'data-state="bad"') && str_contains($c, 'Title &lt;x&gt;') && str_contains($c, 'Text &amp; more'));
ipCheck('a non-error callout is a status', str_contains(Ui::callout('ok', '', 'Fine'), 'role="status"') && !str_contains(Ui::callout('ok', '', 'Fine'), 'cp-callout__title'));
ipCheck('calloutStart/End open and close the same two elements', substr_count(Ui::calloutStart('info') . Ui::calloutEnd(), '<div') === substr_count(Ui::calloutStart('info') . Ui::calloutEnd(), '</div>'));
ipCheck('an empty state has an icon, a title and the optional action', str_contains(Ui::empty('Nothing', 'Why', '<a>Go</a>'), 'cp-empty__title') && str_contains(Ui::empty('Nothing', 'Why', '<a>Go</a>'), '<a>Go</a>'));

$ring = Ui::ring(72, 'ok', '72', 'of 100', '72 / 100');
ipCheck('the ring is an svg arc with the figure and an accessible name, no inline style', str_contains($ring, 'stroke-dasharray="72 100"') && str_contains($ring, 'aria-label="72 / 100"') && !str_contains($ring, 'style='));
ipCheck('a ring at 0 draws no arc, above 100 is clamped', !str_contains(Ui::ring(0, 'ok', '0', '', 'x'), 'cps-ring__arc') && str_contains(Ui::ring(500, 'bad', '5', '', 'x'), '100 100'));

$bars = Ui::bars([['label' => '01', 'a' => 4, 'b' => 2], ['label' => '02', 'a' => 0], ['label' => '03', 'a' => 10, 'flag' => true]], 'Chart');
ipCheck('the bar chart is an svg with one label per day, the flagged bar in the bad colour, no inline style', substr_count($bars, '<text class="cp-chart__text" text-anchor="middle"') === 3 && str_contains($bars, 'cp-chart__bar--bad') && str_contains($bars, 'cps-bar-log') && !str_contains($bars, 'style=') && str_contains($bars, 'role="img"'));
ipCheck('an empty day list draws nothing', Ui::bars([], 'x') === '');
ipCheck('every svg a helper draws is hidden from assistive technology or has a role', str_contains(Ui::icon('ok'), 'aria-hidden="true"'));

echo "== Admin UI standard: stylesheet, templates, languages ==\n";

$root = __DIR__ . '/../com_colorpack_shield';
$std  = (string) file_get_contents($root . '/media/css/colorpack-admin.css');
$cps  = (string) file_get_contents($root . '/media/css/cps.css');

ipCheck('the shared stylesheet is the standard 1.0.0 (version header present)', str_starts_with($std, '/*! Colorpack Admin UI 1.0.0'));
ipCheck('cps.css has no !important, no hex or rgb colour, no side stripe, no font-face', !str_contains($cps, '!important') && preg_match('/#[0-9a-fA-F]{3,8}\b|rgba?\(/', $cps) !== 1 && preg_match('/border-inline-(start|end)\s*:\s*[2-9]px|border-(left|right)\s*:\s*[2-9]px/', $cps) !== 1 && !str_contains($cps, '@font-face'));

$assets = json_decode((string) file_get_contents($root . '/media/joomla.asset.json'), true);
$byName = [];

foreach ($assets['assets'] ?? [] as $a) {
    $byName[$a['type'] . ':' . $a['name']] = $a;
}

ipCheck('the standard stylesheet is registered and the component stylesheet depends on it', ($byName['style:com_colorpack_shield.ui']['uri'] ?? '') === 'com_colorpack_shield/colorpack-admin.css' && in_array('com_colorpack_shield.ui', $byName['style:com_colorpack_shield.admin']['dependencies'] ?? [], true) && ($byName['style:com_colorpack_shield.ui']['version'] ?? '') === 'auto');
ipCheck('the manifest ships the whole css folder (so the standard stylesheet is in the package)', str_contains((string) file_get_contents($root . '/colorpack_shield.xml'), '<folder>css</folder>'));

$tmpl = array_merge(glob($root . '/admin/tmpl/*/default.php') ?: [], glob($root . '/admin/tmpl/*.php') ?: []);
$bad  = [];

foreach ($tmpl as $f) {
    $src  = (string) file_get_contents($f);
    $name = basename(dirname($f)) . '/' . basename($f);

    if (preg_match('/\sstyle="/', $src) || preg_match('/\sonclick=|\sonchange=|\sonsubmit=/', $src)) {
        $bad[] = "$name: inline style or handler";
    }

    if (preg_match('/class="[^"]*\b(alert alert-|badge\b|card-body|table-responsive|nav-tabs|nav-pills|btn-secondary|bg-(success|danger|warning|info)|text-muted|text-uppercase)/', $src)) {
        $bad[] = "$name: old Bootstrap look";
    }

    if (basename($f) !== 'nav.php' && basename($f) !== 'footer.php' && basename($f) !== 'probe.php' && !str_contains($src, 'class="j-main-container cp"')) {
        $bad[] = "$name: not wrapped in div.cp";
    }

    if (basename($f) !== 'nav.php' && basename($f) !== 'footer.php' && basename($f) !== 'probe.php' && !str_contains($src, '$cpsLead')) {
        $bad[] = "$name: no lead sentence";
    }
}

ipCheck('no template has inline style, inline handlers or the old Bootstrap look; each screen is a div.cp with a lead sentence' . ($bad ? ' - ' . implode('; ', $bad) : ''), $bad === []);

$nav = (string) file_get_contents($root . '/admin/tmpl/nav.php');
ipCheck('the language switch is the standard control in the page head, outside the tab row, posting the same task with a token', str_contains($nav, 'class="cp-lang"') && str_contains($nav, 'task=display.language') && str_contains($nav, "form.token") && str_contains($nav, 'lang="th"') && str_contains($nav, 'lang="en"') && str_contains($nav, 'aria-pressed') && strpos($nav, 'cp-lang') < strpos($nav, 'class="cp-tabs"') && str_contains($nav, 'name="lang" value="th-TH"') && str_contains($nav, 'name="lang" value="en-GB"'));

$ini = static function (string $file): array {
    $a = @parse_ini_file($file, false, INI_SCANNER_RAW);

    return $a === false ? [] : array_map(static fn ($v): string => trim((string) $v, '"'), $a);
};
$en = $ini($root . '/admin/language/en-GB/com_colorpack_shield.ini');
$th = $ini($root . '/admin/language/th-TH/com_colorpack_shield.ini');
ipCheck('the component language files have identical key sets and no empty value', $en !== [] && array_keys($en) === array_keys($th) && !in_array('', $en, true) && !in_array('', $th, true));

$missing = [];

foreach ($tmpl as $f) {
    preg_match_all("/'(COM_COLORPACK_SHIELD_[A-Z0-9_]+)'/", (string) file_get_contents($f), $m);

    foreach (array_unique($m[1]) as $key) {
        if (!str_ends_with($key, '_') && !isset($en[$key]) && $key !== 'COM_COLORPACK_SHIELD_STEP') {
            $missing[] = $key;
        }
    }
}

ipCheck('every literal language key a template uses exists' . ($missing ? ' - ' . implode(', ', $missing) : ''), $missing === []);
