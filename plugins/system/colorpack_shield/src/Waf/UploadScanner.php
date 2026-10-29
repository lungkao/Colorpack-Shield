<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * P1.1: inspect uploaded files ($_FILES) — the gap the chosen fleet baseline
 * leaves wide open. A file is blocked when ANY of these hold:
 *
 *   - its final extension is a known executable/script type (shell.php);
 *   - a NON-final segment is executable (img.php.jpg — the classic Apache
 *     mod_mime double-extension bypass);
 *   - an allowlist is configured and the extension is not on it;
 *   - it exceeds the size cap;
 *   - its bytes carry a server-executable marker (`<?php`, `<script`, `<%`,
 *     shebang) regardless of extension — catches a renamed/polyglot payload;
 *   - it claims a raster-image extension but is not a decodable image, or its
 *     real MIME (via finfo) is not image/* — catches a script wearing a .jpg.
 *
 * The head (8 KiB) gets the full marker set; the rest of the file (up to 4 MiB, plus the
 * last 64 KiB of a larger one) is searched for PHP open tags only. A huge upload
 * is never pulled into memory whole. Deliberately Joomla-free so the whole
 * name→verdict path is unit-testable against real temp files.
 */
final class UploadScanner
{
    /** How many bytes of a file body are ever examined. */
    public const MAX_SNIFF = 8192;

    /** Whole-file scan limit for the PHP-tag search (bytes), plus the tail beyond it. */
    public const DEEP_SCAN_MAX = 4194304;
    public const DEEP_TAIL     = 65536;

    private const CHUNK   = 262144;
    private const OVERLAP = 1032;

    /**
     * Extensions that must never be accepted — anything a web/app server (or a
     * misconfigured handler) could execute or interpret server-side.
     *
     * @var string[]
     */
    private const DENY_EXT = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phtml', 'phar',
        'shtml', 'asp', 'aspx', 'asa', 'jsp', 'jspx', 'cgi', 'pl', 'py', 'rb',
        'sh', 'bash', 'exe', 'com', 'bat', 'cmd', 'msi', 'dll', 'so', 'jar',
        'htaccess', 'htpasswd', 'ini', 'phtm',
    ];

    /** Raster extensions we can structurally verify with getimagesize(). */
    private const RASTER_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'];

    /**
     * @param  int       $maxBytes   per-file size cap (0 = no cap)
     * @param  string[]  $allowExt   if non-empty, ONLY these extensions pass
     */
    public function __construct(
        private readonly int $maxBytes = 10485760,
        private readonly array $allowExt = []
    ) {
    }

    /**
     * Scan a normalized file list; return the first threat, or null if clean.
     *
     * @param  array<int, array{name:string,type:string,tmp_name:string,error:int,size:int}>  $files
     */
    public function scan(array $files): ?UploadThreat
    {
        foreach ($files as $file) {
            $threat = $this->inspectFile($file);

            if ($threat !== null) {
                return $threat;
            }
        }

        return null;
    }

    /**
     * @param  array{name:string,type:string,tmp_name:string,error:int,size:int}  $file
     */
    public function inspectFile(array $file): ?UploadThreat
    {
        // Nothing actually uploaded on this field — ignore.
        if (($file['error'] ?? \UPLOAD_ERR_NO_FILE) === \UPLOAD_ERR_NO_FILE || $file['name'] === '') {
            return null;
        }

        $name = $file['name'];

        if ($this->maxBytes > 0 && ($file['size'] ?? 0) > $this->maxBytes) {
            return new UploadThreat($name, 'oversize', (string) $file['size']);
        }

        $segments = array_map('strtolower', explode('.', $name));
        $ext      = end($segments) ?: '';
        $middle   = \count($segments) > 2 ? \array_slice($segments, 1, -1) : [];

        if (\in_array($ext, self::DENY_EXT, true)) {
            return new UploadThreat($name, 'denied_extension', $ext);
        }

        foreach ($middle as $seg) {
            if (\in_array($seg, self::DENY_EXT, true)) {
                return new UploadThreat($name, 'double_extension', $seg);
            }
        }

        if ($this->allowExt !== [] && !\in_array($ext, $this->allowExt, true)) {
            return new UploadThreat($name, 'not_allowlisted', $ext);
        }

        // Content checks need the temp file; skip cleanly if unreadable.
        $tmp = $file['tmp_name'] ?? '';

        if ($tmp === '' || !is_readable($tmp)) {
            return null;
        }

        $head = (string) file_get_contents($tmp, false, null, 0, self::MAX_SNIFF);

        if (($marker = $this->executableMarker($head)) !== null) {
            return new UploadThreat($name, 'executable_content', $marker);
        }

        // Past the head: a valid image can carry a payload anywhere (EXIF,
        // appended bytes). Only high-precision PHP markers are used here —
        // short ones like "<%" occur by chance in compressed image data.
        if (($marker = $this->deepMarker($tmp)) !== null) {
            return new UploadThreat($name, 'executable_content', $marker . ' (deep)');
        }

        if (\in_array($ext, self::RASTER_EXT, true)) {
            if (@getimagesize($tmp) === false) {
                return new UploadThreat($name, 'fake_image', 'not decodable');
            }

            $mime = $this->realMime($tmp);

            if ($mime !== '' && !str_starts_with($mime, 'image/')) {
                return new UploadThreat($name, 'mime_mismatch', $mime);
            }
        }

        return null;
    }

    /**
     * First server-executable marker found in the head, or null.
     */
    private function executableMarker(string $head): ?string
    {
        foreach (['<?php', '<?=', '<script', '<%', '#!/'] as $marker) {
            if (stripos($head, $marker) !== false) {
                return $marker;
            }
        }

        // PHP short-open followed by whitespace (avoids matching "<?xml").
        if (preg_match('/<\?\s/', $head) === 1) {
            return '<?';
        }

        return null;
    }

    /**
     * Look for a PHP open tag in the part of the file the head check did not
     * cover: everything up to DEEP_SCAN_MAX, plus the last DEEP_TAIL bytes of a
     * larger file (appended payloads are the classic case). Reads in chunks
     * with an overlap so a tag split across two reads is still found.
     */
    private function deepMarker(string $tmp): ?string
    {
        $size = @filesize($tmp);

        if ($size === false || $size <= self::MAX_SNIFF) {
            return null;
        }

        $fh = @fopen($tmp, 'rb');

        if ($fh === false) {
            return null;
        }

        try {
            $regions = [[max(0, self::MAX_SNIFF - self::OVERLAP), min($size, self::DEEP_SCAN_MAX)]];

            if ($size > self::DEEP_SCAN_MAX) {
                $regions[] = [max(self::DEEP_SCAN_MAX, $size - self::DEEP_TAIL), $size];
            }

            foreach ($regions as [$from, $to]) {
                $pos = $from;

                while ($pos < $to) {
                    fseek($fh, $pos);
                    $buf = (string) fread($fh, min(self::CHUNK + self::OVERLAP, $to - $pos));

                    if ($buf === '') {
                        break;
                    }

                    if (preg_match('/<\?php(?=\s|\z)/i', $buf) === 1) {
                        return '<?php';
                    }

                    if (preg_match('/<\?=.{0,1024}?\?>/s', $buf) === 1) {
                        return '<?=';
                    }

                    $pos += self::CHUNK;
                }
            }
        } finally {
            fclose($fh);
        }

        return null;
    }

    private function realMime(string $tmp): string
    {
        if (!\function_exists('finfo_open')) {
            return '';
        }

        $finfo = finfo_open(\FILEINFO_MIME_TYPE);

        if ($finfo === false) {
            return '';
        }

        // Note: no finfo_close() — the resource is freed automatically and the
        // function is deprecated in PHP 8.5.
        $mime = finfo_file($finfo, $tmp);

        return \is_string($mime) ? $mime : '';
    }

    /**
     * Flatten PHP's $_FILES (which nests differently for array field names)
     * into a flat list of per-file records.
     *
     * @param  array<string, mixed>  $files  the $_FILES superglobal
     *
     * @return array<int, array{name:string,type:string,tmp_name:string,error:int,size:int}>
     */
    public static function normalize(array $files): array
    {
        $out = [];

        foreach ($files as $info) {
            if (!\is_array($info) || !isset($info['name'])) {
                continue;
            }

            self::flatten(
                $info['name'],
                $info['type'] ?? '',
                $info['tmp_name'] ?? '',
                $info['error'] ?? \UPLOAD_ERR_NO_FILE,
                $info['size'] ?? 0,
                $out
            );
        }

        return $out;
    }

    /**
     * @param  mixed  $name
     * @param  mixed  $type
     * @param  mixed  $tmp
     * @param  mixed  $error
     * @param  mixed  $size
     * @param  array<int, array{name:string,type:string,tmp_name:string,error:int,size:int}>  $out
     */
    private static function flatten($name, $type, $tmp, $error, $size, array &$out): void
    {
        if (\is_array($name)) {
            foreach ($name as $k => $v) {
                self::flatten(
                    $v,
                    \is_array($type) ? ($type[$k] ?? '') : '',
                    \is_array($tmp) ? ($tmp[$k] ?? '') : '',
                    \is_array($error) ? ($error[$k] ?? \UPLOAD_ERR_NO_FILE) : \UPLOAD_ERR_NO_FILE,
                    \is_array($size) ? ($size[$k] ?? 0) : 0,
                    $out
                );
            }

            return;
        }

        $out[] = [
            'name'     => (string) $name,
            'type'     => (string) $type,
            'tmp_name' => (string) $tmp,
            'error'    => (int) $error,
            'size'     => (int) $size,
        ];
    }
}
