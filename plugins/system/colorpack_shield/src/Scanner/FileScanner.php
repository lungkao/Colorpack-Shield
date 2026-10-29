<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Walks the site folder in short, resumable steps (a shared host gives a request a few seconds to a
 * few tens of seconds): each call works until its deadline and returns a state that is saved and
 * handed to the next call. Nothing is followed through symbolic links, nothing is executed, no file
 * is changed. A file is read only up to 512 KB.
 *
 * It looks for: PHP code where it does not belong (images/, tmp/), tell-tale names, PHP hidden in
 * "images", a short list of backdoor patterns inside PHP files ({@see SignatureRules}), and unusual
 * .htaccess files in upload folders. It also remembers a short fingerprint of every PHP file so a
 * later scan can say what is new or changed since a baseline the owner accepted.
 */
final class FileScanner
{
    public const MAX_READ       = 524288;
    public const MAX_FINDINGS   = 500;
    public const MAX_TRACKED    = 80000;
    public const MAX_CHANGES    = 200;
    public const SKIP_DIRS      = ['.git', '.svn', 'node_modules'];
    private const IMAGE_EXT     = 'jpg|jpeg|png|gif|ico|bmp|webp|pdf';
    private const DATA_DIR      = '~^(?:images|media|tmp|cache|logs|administrator/(?:cache|logs|tmp))/~i';

    /** The two files that hold the patterns themselves contain the words they look for. Their NAMES and changes are still checked. */
    private const OWN_RULE_FILES = ['colorpack_shield/src/scanner/signaturerules.php', 'colorpack_shield/src/scanner/locationrules.php'];

    private const RANK = ['high' => 3, 'medium' => 2, 'low' => 1];

    /**
     * @return array<string,mixed>
     */
    public static function newState(int $now): array
    {
        return [
            'v' => 1, 'started' => $now, 'queue' => [['', 0]], 'findings' => [], 'more' => 0, 'files' => [], 'tracked' => true,
            'seen' => 0, 'php' => 0, 'ignored' => 0, 'links' => 0, 'unreadable' => 0, 'done' => false,
        ];
    }

    /**
     * Work until $deadline (microtime) or until everything is done.
     *
     * @param  array<string,mixed>   $state
     * @param  array<string,string>  $ignore  path => fingerprint of files the owner marked as safe
     *
     * @return array<string,mixed>
     */
    public static function step(array $state, string $root, float $deadline, array $ignore = []): array
    {
        $root = rtrim($root, '/\\');

        // At least one piece of work per call, even if the clock says there is no time left: a slow disk must slow the scan, never stop it.
        $first = true;

        while ($state['queue'] !== [] && ($first || microtime(true) < $deadline)) {
            $first = false;
            [$dir, $offset] = array_pop($state['queue']);
            $abs            = $dir === '' ? $root : $root . '/' . $dir;
            $names          = @scandir($abs);

            if ($names === false) {
                $state['unreadable']++;

                continue;
            }

            $names = array_values(array_filter($names, static fn (string $n): bool => $n !== '.' && $n !== '..'));
            $n     = \count($names);

            for ($i = $offset; $i < $n; $i++) {
                // Look at the clock now and then, so one huge folder cannot overrun the budget.
                if (($i & 63) === 0 && $i > $offset && microtime(true) >= $deadline) {
                    $state['queue'][] = [$dir, $i];

                    break 2;
                }

                $rel  = $dir === '' ? $names[$i] : $dir . '/' . $names[$i];
                $full = $root . '/' . $rel;

                if (is_link($full)) {
                    $state['links']++;

                    continue;
                }

                if (is_dir($full)) {
                    if (!\in_array($names[$i], self::SKIP_DIRS, true) && $rel !== 'cache/colorpack_shield') {
                        $state['queue'][] = [$rel, 0];
                    }

                    continue;
                }

                if (is_file($full)) {
                    self::file($state, $full, $rel, $ignore);
                }
            }
        }

        $state['done'] = $state['queue'] === [];

        return $state;
    }

    /**
     * @param  array<string,mixed>   $state
     * @param  array<string,string>  $ignore
     */
    private static function file(array &$state, string $full, string $rel, array $ignore): void
    {
        $state['seen']++;
        $size  = (int) @filesize($full);
        $perms = (int) @fileperms($full);
        $lower = strtolower($rel);
        $base  = basename($lower);
        $isPhp = preg_match('/\.(?:' . LocationRules::PHP_EXT . ')$/', $base) === 1;
        $rules = LocationRules::check($rel, $perms);
        $sev   = [];

        foreach ($rules as $r) {
            $sev[$r] = LocationRules::SEVERITY[$r] ?? 'low';
        }

        $content = null;
        $hash    = '';

        if ($isPhp) {
            $state['php']++;
            $content = self::read($full, self::MAX_READ);

            if ($content === null) {
                $state['unreadable']++;

                return;
            }

            $hash = substr(sha1($content), 0, 12);

            if (!self::isOwnRuleFile($lower)) {
                foreach (SignatureRules::scan($content) as $id) {
                    $rules[]  = $id;
                    $sev[$id] = SignatureRules::severity($id);
                }
            }

            if ($state['tracked'] && \count($state['files']) < self::MAX_TRACKED) {
                $state['files'][$rel] = $size . '-' . $hash;
            } else {
                $state['tracked'] = false;
            }
        } elseif ($base === '.htaccess') {
            $content = self::read($full, 65536);

            if ($content !== null) {
                $table = preg_match(self::DATA_DIR, $lower) === 1 ? SignatureRules::HTACCESS_DATA : SignatureRules::HTACCESS_ANY;

                foreach (SignatureRules::scan($content, $table) as $id) {
                    $rules[]  = $id;
                    $sev[$id] = SignatureRules::severity($id, $table);
                }

                $hash = substr(sha1($content), 0, 12);
            }
        } elseif (preg_match('/\.(?:' . self::IMAGE_EXT . ')$/', $base) === 1 && $size > 0) {
            $head = self::read($full, 4096);
            $tail = $size > 8192 ? self::readTail($full, $size, 4096) : '';

            if ($head !== null && preg_match(SignatureRules::PHP_IN_IMAGE, $head . "\n" . ($tail ?? '')) === 1) {
                $rules[]              = 'php_in_image';
                $sev['php_in_image']  = 'high';
                $content              = $head;
            }
        }

        if ($rules === []) {
            return;
        }

        if ($hash === '') {
            $whole = $content ?? self::read($full, self::MAX_READ);
            $hash  = $whole === null ? '' : substr(sha1($whole), 0, 12);
        }

        if ($hash !== '' && ($ignore[$rel] ?? null) === $hash) {
            $state['ignored']++;

            return;
        }

        $top = 'low';

        foreach ($sev as $s) {
            if (self::RANK[$s] > self::RANK[$top]) {
                $top = $s;
            }
        }

        if (\count($state['findings']) >= self::MAX_FINDINGS) {
            $state['more']++;

            return;
        }

        $state['findings'][] = [
            'path'  => self::clean($rel),
            'rules' => array_values(array_unique($rules)),
            'sev'   => $top,
            'size'  => $size,
            'mtime' => (int) @filemtime($full),
            'hash'  => $hash,
        ];
    }

    /**
     * Look at ONE file again (after an edit): its finding as the scan would report it, or null when it is
     * clean now (or no longer there).
     *
     * @param  array<string,string>  $ignore
     *
     * @return array<string,mixed>|null
     */
    public static function inspectFile(string $root, string $rel, array $ignore = []): ?array
    {
        $full = rtrim($root, '/\\') . '/' . $rel;

        if (!is_file($full) || is_link($full)) {
            return null;
        }

        $st = self::newState(time());
        self::file($st, $full, $rel, $ignore);

        return $st['findings'][0] ?? null;
    }

    /**
     * The finished scan as a result record, with what changed since the baseline (when there is one).
     *
     * @param  array<string,mixed>       $state
     * @param  array<string,mixed>|null  $baseline  ['created' => ts, 'files' => [path => 'size-hash']]
     *
     * @return array<string,mixed>
     */
    public static function result(array $state, ?array $baseline, int $now): array
    {
        $findings = $state['findings'];
        usort($findings, static fn (array $a, array $b): int => [self::RANK[$b['sev']], $a['path']] <=> [self::RANK[$a['sev']], $b['path']]);
        $count = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($findings as $f) {
            $count[$f['sev']]++;
        }

        $changes = null;

        if ($baseline !== null && \is_array($baseline['files'] ?? null) && $state['tracked']) {
            $old     = $baseline['files'];
            $new     = $state['files'];
            $changes = ['new' => [], 'changed' => [], 'removed' => [], 'more' => 0];

            foreach ($new as $path => $fp) {
                if (!isset($old[$path])) {
                    $changes['new'][] = $path;
                } elseif ($old[$path] !== $fp) {
                    $changes['changed'][] = $path;
                }
            }

            foreach ($old as $path => $fp) {
                if (!isset($new[$path])) {
                    $changes['removed'][] = $path;
                }
            }

            foreach (['new', 'changed', 'removed'] as $k) {
                sort($changes[$k]);

                if (\count($changes[$k]) > self::MAX_CHANGES) {
                    $changes['more'] += \count($changes[$k]) - self::MAX_CHANGES;
                    $changes[$k]      = \array_slice($changes[$k], 0, self::MAX_CHANGES);
                }
            }
        }

        return [
            'started'    => (int) $state['started'],
            'finished'   => $now,
            'seen'       => (int) $state['seen'],
            'php'        => (int) $state['php'],
            'count'      => $count,
            'findings'   => $findings,
            'more'       => (int) $state['more'],
            'ignored'    => (int) $state['ignored'],
            'links'      => (int) $state['links'],
            'unreadable' => (int) $state['unreadable'],
            'baseline'   => $baseline !== null,
            'baselineAt' => (int) ($baseline['created'] ?? 0),
            'tracked'    => (bool) $state['tracked'],
            'changes'    => $changes,
        ];
    }

    /**
     * The baseline a finished scan would become.
     *
     * @param  array<string,mixed>  $state
     *
     * @return array{created:int,files:array<string,string>}|null  null when the file list was too long to keep
     */
    public static function baselineFrom(array $state, int $now): ?array
    {
        return $state['tracked'] ? ['created' => $now, 'files' => $state['files']] : null;
    }

    private static function isOwnRuleFile(string $lowerRel): bool
    {
        foreach (self::OWN_RULE_FILES as $f) {
            if ($lowerRel === 'plugins/system/' . $f) {
                return true;
            }
        }

        return false;
    }

    private static function read(string $file, int $max): ?string
    {
        $h = @fopen($file, 'rb');

        if ($h === false) {
            return null;
        }

        $data = stream_get_contents($h, $max);
        fclose($h);

        return \is_string($data) ? $data : null;
    }

    private static function readTail(string $file, int $size, int $len): ?string
    {
        $h = @fopen($file, 'rb');

        if ($h === false) {
            return null;
        }

        fseek($h, max(0, $size - $len));
        $data = stream_get_contents($h, $len);
        fclose($h);

        return \is_string($data) ? $data : null;
    }

    /** A path comes from the disk, and a hostile file name must not break a line, a table or a log. */
    private static function clean(string $path): string
    {
        $path = preg_replace('/[\x00-\x1f\x7f]/', '?', $path) ?? '';

        if (preg_match('//u', $path) !== 1) {
            $path = preg_replace('/[\x80-\xff]/', '?', $path) ?? '';
        }

        return mb_substr($path, 0, 300);
    }
}
