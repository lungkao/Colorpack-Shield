<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Copies of files taken before they are edited or deleted from the scan screen, kept so that
 * nothing done there is final. A copy is stored as text (base64) in a file that stops itself if it
 * is ever run, in a folder the web server is told never to serve, so a stored backdoor can neither
 * run nor be read as code. Nothing is ever dropped silently: when the store is full, the next
 * change is refused until old copies are removed.
 */
final class Quarantine
{
    public const HEADER   = "<?php die('Forbidden'); ?>\n";
    public const MAX_SIZE = 4194304;
    public const MAX_ITEMS = 300;

    public function __construct(private readonly string $dir)
    {
    }

    /**
     * Take a copy of a file.
     *
     * @return string|null  the id of the copy, or null when it could not be made (the caller must then NOT go on)
     */
    public function store(string $realFile, string $rel, string $action): ?string
    {
        if (!is_file($realFile) || (int) @filesize($realFile) > self::MAX_SIZE || \count($this->ids()) >= self::MAX_ITEMS) {
            return null;
        }

        $bytes = @file_get_contents($realFile);

        if ($bytes === false) {
            return null;
        }

        if (!$this->guard()) {
            return null;
        }

        $id   = gmdate('Ymd-His') . '-' . bin2hex(random_bytes(4));
        $meta = json_encode([
            'path'   => $rel,
            'action' => $action,
            'time'   => time(),
            'size'   => \strlen($bytes),
            'mode'   => (int) (@fileperms($realFile) & 0777),
            'mtime'  => (int) @filemtime($realFile),
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        $file = $this->dir . '/' . $id . '.php';

        if ($meta === false || @file_put_contents($file, self::HEADER . $meta . "\n" . base64_encode($bytes), LOCK_EX) === false) {
            @unlink($file);

            return null;
        }

        @chmod($file, 0600);

        // Trust but verify: the copy must read back to the same bytes before anything is changed.
        return $this->bytes($id) === $bytes ? $id : $this->drop($id, null);
    }

    /**
     * @return array<int,array{id:string,path:string,action:string,time:int,size:int}>  newest first
     */
    public function items(int $limit = 100): array
    {
        $out = [];

        foreach (array_reverse($this->ids()) as $id) {
            $m = $this->meta($id);

            if ($m !== null) {
                $out[] = ['id' => $id, 'path' => (string) $m['path'], 'action' => (string) $m['action'], 'time' => (int) $m['time'], 'size' => (int) $m['size']];
            }

            if (\count($out) >= $limit) {
                break;
            }
        }

        return $out;
    }

    /**
     * Put a copy back where it came from. An existing file is only replaced when $overwrite says so
     * (the file that is there now is then kept as a new copy first).
     *
     * @return string  ok | not_found | exists | failed | bad_path
     */
    public function restore(string $id, string $root, bool $overwrite): string
    {
        $m     = $this->meta($id);
        $bytes = $m === null ? null : $this->bytes($id);

        if ($m === null || $bytes === null) {
            return 'not_found';
        }

        $rel = (string) $m['path'];

        if ($rel === '' || str_contains($rel, "\0") || preg_match('~(?:^|/)\.\.?(?:/|$)~', $rel) === 1 || str_starts_with($rel, '/')) {
            return 'bad_path';
        }

        if (FileGuard::isProtected($rel)) {
            return 'protected';
        }

        $realRoot = realpath($root);
        $target   = $realRoot === false ? '' : $realRoot . '/' . $rel;
        $dirReal  = $realRoot === false ? false : realpath(\dirname($target));
        $dirWant  = $realRoot === false ? '' : (\dirname($rel) === '.' ? $realRoot : $realRoot . '/' . \dirname($rel));

        // The folder must exist and be exactly where the path says: a link on the way changes the real path.
        if ($realRoot === false || $dirReal === false || $dirReal !== $dirWant || is_link($target)) {
            return 'bad_path';
        }

        if (is_file($target)) {
            if (!$overwrite) {
                return 'exists';
            }

            if ($this->store($target, $rel, 'before_restore') === null) {
                return 'failed';
            }
        }

        if (@file_put_contents($target, $bytes, LOCK_EX) === false) {
            return 'failed';
        }

        // The mode comes from the copy's own header: only the two ordinary modes are accepted.
        @chmod($target, ((int) ($m['mode'] ?? 0644) & 0111) !== 0 ? 0755 : 0644);

        return 'ok';
    }

    /** Remove one copy for good. */
    public function drop(string $id, mixed $ret = true): mixed
    {
        if (preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $id) === 1) {
            @unlink($this->dir . '/' . $id . '.php');
        }

        return $ret;
    }

    /** @return string[] ids, oldest first */
    public function ids(): array
    {
        $out = [];

        foreach (glob($this->dir . '/*.php') ?: [] as $f) {
            $id = basename($f, '.php');

            if (preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $id) === 1) {
                $out[] = $id;
            }
        }

        sort($out);

        return $out;
    }

    /** @return array<string,mixed>|null */
    private function meta(string $id): ?array
    {
        $raw = $this->read($id);

        if ($raw === null) {
            return null;
        }

        $lines = explode("\n", $raw, 2);
        $m     = json_decode($lines[0], true);

        return \is_array($m) && \is_string($m['path'] ?? null) ? $m : null;
    }

    public function bytes(string $id): ?string
    {
        $raw = $this->read($id);
        $b   = $raw === null ? null : (explode("\n", $raw, 2)[1] ?? null);
        $out = $b === null ? false : base64_decode(trim($b), true);

        return $out === false ? null : $out;
    }

    private function read(string $id): ?string
    {
        if (preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $id) !== 1) {
            return null;
        }

        $f = $this->dir . '/' . $id . '.php';

        if (!is_file($f) || (int) @filesize($f) > self::MAX_SIZE * 2) {
            return null;
        }

        $raw = (string) @file_get_contents($f);

        return str_starts_with($raw, self::HEADER) ? substr($raw, \strlen(self::HEADER)) : null;
    }

    /** The folder and its "never serve this" files. */
    private function guard(): bool
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return false;
        }

        if (!is_file($this->dir . '/.htaccess')) {
            @file_put_contents($this->dir . '/.htaccess', "Require all denied\nOrder allow,deny\nDeny from all\n");
        }

        if (!is_file($this->dir . '/index.html')) {
            @file_put_contents($this->dir . '/index.html', '');
        }

        return true;
    }
}
