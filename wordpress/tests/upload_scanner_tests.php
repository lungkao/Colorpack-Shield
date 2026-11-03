<?php
/**
 * Upload scanner: short markers ("<%", "#!/") must not block real binary files.
 * Included by run.php, shares its ok() helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

require_once __DIR__ . '/../colorpack-shield/src/Waf/UploadThreat.php';
require_once __DIR__ . '/../colorpack-shield/src/Waf/UploadScanner.php';

use Colorpack\WP\ColorpackShield\Waf\UploadScanner;

echo "== Upload scanner: short markers in binary data ==\n";

$uploadReason = static function (string $name, string $bytes): ?string {
    $t = tempnam(sys_get_temp_dir(), 'cpsw');
    file_put_contents($t, $bytes);
    $threat = (new UploadScanner(0, []))->inspectFile(['name' => $name, 'type' => '', 'tmp_name' => $t, 'error' => 0, 'size' => strlen($bytes)]);
    @unlink($t);

    return $threat === null ? null : $threat->reason;
};

$onePx = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
$noise = static fn (int $n): string => substr(hash('sha512', 'noise', true) . hash('sha512', 'noise2', true), 0, $n);

ok('upload: real image with "<%" by chance in its data passes', $uploadReason('cover.png', $onePx . $noise(60) . "\x08<%\xc0\x81" . $noise(60)) === null);
ok('upload: real image with "#!/" by chance in its data passes', $uploadReason('cover.png', $onePx . $noise(60) . 'x#!/y' . $noise(60)) === null);
ok('upload: zip with "<%" by chance in its data passes', $uploadReason('ext.zip', "PK\x03\x04\x14\x00\x00\x00\x08\x00" . $noise(80) . '<%' . $noise(80)) === null);
ok('upload: ASP tag in a text file still blocks', $uploadReason('page.txt', '<% eval request("x") %>') === 'executable_content');
ok('upload: shebang on byte 0 of a binary-looking file still blocks', $uploadReason('run.bin', "#!/bin/sh\n\x00\x01\x02 tail") === 'executable_content');
ok('upload: PHP tag inside a real image still blocks', $uploadReason('cover.png', $onePx . "\x00\x00" . '<?php system($_GET[1]); ?>') === 'executable_content');
ok('upload: <script> inside a real image still blocks', $uploadReason('cover.png', $onePx . "\x00\x00" . '<script>alert(1)</script>') === 'executable_content');
