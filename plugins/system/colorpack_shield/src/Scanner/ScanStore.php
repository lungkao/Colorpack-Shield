<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Small JSON files under cache/colorpack_shield/scan/ (job state, last result, baseline, "marked
 * safe" list). Every file starts with a PHP line that stops the server from ever showing it.
 * Writes are whole-file and moved into place; nothing here throws.
 */
final class ScanStore
{
    public const HEADER = "<?php die('Forbidden'); ?>\n";
    public const MAX    = 16777216;

    public function __construct(private readonly string $dir)
    {
    }

    /**
     * @return array<mixed>|null
     */
    public function read(string $name): ?array
    {
        $f = $this->file($name);

        if ($f === null || !is_file($f) || !is_readable($f) || (int) @filesize($f) > self::MAX) {
            return null;
        }

        $raw = (string) @file_get_contents($f);

        if (!str_starts_with($raw, self::HEADER)) {
            return null;
        }

        $data = json_decode(substr($raw, \strlen(self::HEADER)), true, 12);

        return \is_array($data) ? $data : null;
    }

    /**
     * @param  array<mixed>  $data
     */
    public function write(string $name, array $data): bool
    {
        $f = $this->file($name);

        if ($f === null || (!is_dir($this->dir) && !@mkdir($this->dir, 0755, true) && !is_dir($this->dir))) {
            return false;
        }

        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

        if ($json === false || \strlen($json) > self::MAX) {
            return false;
        }

        $tmp = $f . '.' . bin2hex(random_bytes(3)) . '.tmp';

        if (@file_put_contents($tmp, self::HEADER . $json, LOCK_EX) === false) {
            @unlink($tmp);

            return false;
        }

        if (!@rename($tmp, $f)) {
            @unlink($tmp);

            return false;
        }

        return true;
    }

    public function delete(string $name): void
    {
        $f = $this->file($name);

        if ($f !== null && is_file($f)) {
            @unlink($f);
        }
    }

    /** Only fixed short names, so no caller can make this touch another file. */
    private function file(string $name): ?string
    {
        return preg_match('/^[a-z_]{1,20}$/', $name) === 1 ? rtrim($this->dir, '/\\') . '/' . $name . '.json.php' : null;
    }
}
