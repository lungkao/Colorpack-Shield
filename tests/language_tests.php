<?php
/**
 * Language files: every en-GB string has a th-TH twin with the same placeholders,
 * every key the manifests and code use exists, and the files parse. Included by run.php.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

echo "== Language files ==\n";

$lang = __DIR__ . '/../plugins/system/colorpack_shield/language';
$ini  = static function (string $file): array {
    $a = @parse_ini_file($file, false, INI_SCANNER_RAW);

    return $a === false ? [] : array_map(static fn ($v): string => trim((string) $v, '"'), $a);
};

foreach (['plg_system_colorpack_shield.ini', 'plg_system_colorpack_shield.sys.ini'] as $file) {
    $en = $ini("$lang/en-GB/$file");
    $th = $ini("$lang/th-TH/$file");
    ipCheck("$file: both languages parse and are not empty", $en !== [] && $th !== []);
    ipCheck("$file: th-TH has exactly the keys of en-GB", array_keys($en) === array_keys($th));

    $bad = [];

    foreach ($en as $k => $v) {
        $ph = static function (string $s): array {
            preg_match_all('/%(?:\d+\$)?[sd]/', $s, $m);
            sort($m[0]);

            return $m[0];
        };

        if (isset($th[$k]) && ($ph($v) !== $ph($th[$k]) || substr_count($v, '\n') !== substr_count($th[$k], '\n'))) {
            $bad[] = $k;
        }
    }

    ipCheck("$file: th-TH keeps every %s / %1\$s placeholder and every line break" . ($bad ? ' — ' . implode(', ', $bad) : ''), $bad === []);
    ipCheck("$file: no th-TH value is empty or still identical English", (function () use ($en, $th) {
        foreach ($th as $k => $v) {
            if ($k === 'PLG_SYSTEM_COLORPACK_SHIELD') {
                continue;   // the product name stays in English
            }

            if ($v === '' || (preg_match('/[\x{0E00}-\x{0E7F}]/u', $v) !== 1 && $v === ($en[$k] ?? null) && strlen($v) > 25)) {
                return false;
            }
        }

        return true;
    })());
}

// Every language key used by the manifest exists.
$xml = (string) file_get_contents(__DIR__ . '/../plugins/system/colorpack_shield/colorpack_shield.xml');
preg_match_all('/PLG_SYSTEM_COLORPACK_SHIELD[A-Z0-9_]*/', $xml, $m);
$en   = $ini("$lang/en-GB/plg_system_colorpack_shield.ini") + $ini("$lang/en-GB/plg_system_colorpack_shield.sys.ini");
$th   = $ini("$lang/th-TH/plg_system_colorpack_shield.ini") + $ini("$lang/th-TH/plg_system_colorpack_shield.sys.ini");
$gone = array_values(array_filter(array_unique($m[0]), static fn (string $k): bool => !isset($en[$k]) || !isset($th[$k])));
ipCheck('every key used in the plugin manifest exists in en-GB and th-TH' . ($gone ? ' — missing: ' . implode(', ', $gone) : ''), $gone === []);

// Every key the code asks Text for exists.
$src  = (string) file_get_contents(__DIR__ . '/../plugins/system/colorpack_shield/src/Extension/ColorpackShield.php');
preg_match_all("/Text::(?:_|sprintf)\('(PLG_SYSTEM_COLORPACK_SHIELD[A-Z0-9_]*)'/", $src, $c);
$gone = array_values(array_filter(array_unique($c[1]), static fn (string $k): bool => !isset($en[$k]) || !isset($th[$k])));
ipCheck('every key the plugin code passes to Text exists in en-GB and th-TH' . ($gone ? ' — missing: ' . implode(', ', $gone) : ''), $gone === [] && $c[1] !== []);

$mailKeys = [];
preg_match_all("/'(PLG_SYSTEM_COLORPACK_SHIELD_MAIL_[A-Z0-9_]*)'/", $src, $mk);
ipCheck('the mail strings the code builds exist in both languages', (function () use ($mk, $en, $th) {
    foreach (array_unique($mk[1]) as $k) {
        if (!isset($en[$k]) || !isset($th[$k])) {
            return false;
        }
    }

    return $mk[1] !== [];
})());
