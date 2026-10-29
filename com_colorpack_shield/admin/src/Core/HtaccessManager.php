<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

use Colorpack\Plugin\System\ColorpackShield\Export\HtaccessBlock;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Puts the Colorpack Shield block into the site's own .htaccess, and takes it out again, the
 * careful way (shared hosting: a bad .htaccess line turns the whole site into an error page):
 *
 *  1. the live site is asked (before) for a few fixed addresses; if that cannot be done at all
 *     nothing is touched, because a change could not be checked;
 *  2. a backup of the exact original is written next to the file (".htaccess.cps-backup": Apache
 *     refuses to serve files that start with ".ht");
 *  3. the file is written whole, then the same addresses are asked again;
 *  4. if ANY answer differs from before, the original bytes are put back at once.
 *
 * Joomla-free: the file system and the "ask the site" step are plain inputs, so the whole
 * thing is tested with temporary folders and a fake site.
 */
final class HtaccessManager
{
    public const BACKUP = '.htaccess.cps-backup';

    /** Addresses asked before and after. The administrator may answer 404 when the access key is on: only a CHANGE counts. */
    public const PATHS = ['/', '/administrator/'];

    /**
     * @param  callable(string):int  $probe  HTTP status of the live site for a path, 0 when it cannot be asked
     */
    public function __construct(private readonly string $root, private $probe)
    {
    }

    public function path(): string
    {
        return rtrim($this->root, '/\\') . '/.htaccess';
    }

    /**
     * @return array{exists:bool,writable:bool,hasBlock:bool,backup:bool}
     */
    public function state(): array
    {
        $f = $this->path();

        return [
            'exists'   => is_file($f),
            'writable' => is_file($f) && is_writable($f) && is_writable(\dirname($f)),
            'hasBlock' => is_file($f) && HtaccessBlock::has((string) @file_get_contents($f)),
            'backup'   => is_file($this->root . '/' . self::BACKUP),
        ];
    }

    /**
     * @return array{result:string,before:array<string,int>,after:array<string,int>}
     *         result: applied | reverted | no_file | not_writable | cannot_verify | write_failed
     */
    public function apply(string $block): array
    {
        return $this->change(static fn (string $orig): string => HtaccessBlock::insert($orig, $block));
    }

    /**
     * @return array{result:string,before:array<string,int>,after:array<string,int>}
     */
    public function remove(): array
    {
        return $this->change(static fn (string $orig): string => HtaccessBlock::remove($orig));
    }

    /**
     * @param  callable(string):string  $transform
     *
     * @return array{result:string,before:array<string,int>,after:array<string,int>}
     */
    private function change(callable $transform): array
    {
        $none = ['before' => [], 'after' => []];
        $f    = $this->path();
        $st   = $this->state();

        if (!$st['exists']) {
            return ['result' => 'no_file'] + $none;
        }

        if (!$st['writable']) {
            return ['result' => 'not_writable'] + $none;
        }

        $orig = (string) @file_get_contents($f);
        $new  = $transform($orig);

        if ($new === $orig) {
            return ['result' => 'applied', 'before' => [], 'after' => []];
        }

        $before = $this->ask();

        // Nothing can be checked (no answer for the front page): do not touch the file.
        if (($before['/'] ?? 0) === 0) {
            return ['result' => 'cannot_verify', 'before' => $before, 'after' => []];
        }

        if (@file_put_contents($this->root . '/' . self::BACKUP, $orig, LOCK_EX) === false || !$this->write($f, $new)) {
            return ['result' => 'write_failed', 'before' => $before, 'after' => []];
        }

        $after = $this->ask();

        if ($after !== $before) {
            $this->write($f, $orig);

            return ['result' => 'reverted', 'before' => $before, 'after' => $after];
        }

        return ['result' => 'applied', 'before' => $before, 'after' => $after];
    }

    /**
     * @return array<string,int>
     */
    private function ask(): array
    {
        $out = [];

        foreach (self::PATHS as $p) {
            $out[$p] = (int) ($this->probe)($p);
        }

        return $out;
    }

    /** Whole file, written beside it and moved into place, keeping the permissions. */
    private function write(string $file, string $content): bool
    {
        $perms = @fileperms($file);
        $tmp   = $file . '.cps-tmp';

        if (@file_put_contents($tmp, $content, LOCK_EX) === false) {
            @unlink($tmp);

            return false;
        }

        if ($perms !== false) {
            @chmod($tmp, $perms & 0777);
        }

        if (@rename($tmp, $file)) {
            return true;
        }

        @unlink($tmp);

        return @file_put_contents($file, $content, LOCK_EX) !== false;
    }
}
