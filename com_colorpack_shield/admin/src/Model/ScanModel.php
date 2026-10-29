<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\LogFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\ScanFilter;
use Colorpack\Plugin\System\ColorpackShield\Scanner\FileGuard;
use Colorpack\Plugin\System\ColorpackShield\Scanner\FileScanner;
use Colorpack\Plugin\System\ColorpackShield\Scanner\LineMarker;
use Colorpack\Plugin\System\ColorpackShield\Scanner\PhpSyntax;
use Colorpack\Plugin\System\ColorpackShield\Scanner\Quarantine;
use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * The file scanner as the web screen drives it: short steps (a shared host gives each request only a
 * few seconds), state kept between them, nothing executed, no file ever changed or deleted.
 */
class ScanModel extends BaseDatabaseModel
{
    public const FINDINGS_PER_PAGE = 100;

    /** @return ScanStore */
    private function store(): ScanStore
    {
        return new ScanStore(JPATH_ROOT . '/cache/colorpack_shield/scan');
    }

    /**
     * Seconds one step may work: well inside the host's PHP time limit, never more than 6.
     */
    public function budget(): float
    {
        $max = (int) ini_get('max_execution_time');

        return $max > 0 ? max(1.0, min(6.0, $max * 0.35)) : 6.0;
    }

    /**
     * @param  array<string,mixed>  $request  GET values (the findings filter: sev, q, page)
     *
     * @return array<string,mixed>
     */
    public function getScan(array $request = []): array
    {
        $s      = $this->store();
        $result = $s->read('result');
        $state  = $s->read('state');
        $base   = $s->read('baseline');
        $ignore = $s->read('ignore');

        return [
            'result'    => $result,
            'running'   => $state !== null && empty($state['done']) ? ['seen' => (int) ($state['seen'] ?? 0), 'started' => (int) ($state['started'] ?? 0)] : null,
            'baseline'  => $base !== null ? ['created' => (int) ($base['created'] ?? 0), 'count' => \count((array) ($base['files'] ?? []))] : null,
            'ignored'   => \is_array($ignore) ? \count($ignore) : 0,
            'canAccept' => $s->read('lastfiles') !== null,
            'copies'    => $this->copies(),
            'budget'    => $this->budget(),
            'findList'  => $result !== null ? $this->findings((array) $result['findings'], $request) : null,
        ];
    }

    /**
     * The findings table: filtered by severity/path text, counted and paged, for the screen's
     * tabs, search box and pager. Pure over the array already in the scan result.
     *
     * @param  array<int,array{path:string,sev:string}>  $findings
     * @param  array<string,mixed>  $request
     *
     * @return array{criteria:array<string,mixed>,counts:array<string,int>,list:array<string,mixed>}
     */
    private function findings(array $findings, array $request): array
    {
        $criteria = ScanFilter::criteria($request);
        $filtered = ScanFilter::apply($findings, $criteria);

        return [
            'criteria' => $criteria,
            'counts'   => ScanFilter::counts($findings),
            'total'    => \count($findings),
            'list'     => LogFilter::page($filtered, (int) ($request['page'] ?? 1), self::FINDINGS_PER_PAGE),
        ];
    }

    public function start(): bool
    {
        return $this->store()->write('state', FileScanner::newState(time()));
    }

    /**
     * One step. Returns progress; on the last step the result (and the file list for a baseline) is saved.
     *
     * @return array{ok:bool,busy?:bool,done?:bool,seen?:int,php?:int,findings?:int,high?:int}
     */
    public function step(): array
    {
        $s    = $this->store();
        $dir  = JPATH_ROOT . '/cache/colorpack_shield/scan';

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return ['ok' => false];
        }

        // One step at a time: a double click or a second browser tab must not run two steps over the same state.
        $lock = @fopen($dir . '/lock', 'c');

        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['ok' => true, 'busy' => true];
        }

        try {
            $state = $s->read('state');

            if ($state === null) {
                return ['ok' => false];
            }

            $ignore = $s->read('ignore');
            $state  = FileScanner::step($state, JPATH_ROOT, microtime(true) + $this->budget(), \is_array($ignore) ? array_map('strval', $ignore) : []);

            if ($state['done']) {
                $now  = time();
                $base = $s->read('baseline');
                $s->write('result', FileScanner::result($state, $base, $now));
                $s->write('lastfiles', ['at' => $now, 'files' => $state['tracked'] ? $state['files'] : null]);
                $s->delete('state');
            } elseif (!$s->write('state', $state)) {
                return ['ok' => false];
            }

            $high = \count(array_filter($state['findings'], static fn (array $f): bool => $f['sev'] === 'high'));

            return ['ok' => true, 'done' => (bool) $state['done'], 'seen' => (int) $state['seen'], 'php' => (int) $state['php'], 'findings' => \count($state['findings']), 'high' => $high];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** The files of the last finished scan become the baseline: "this is how my site is supposed to look". */
    public function acceptBaseline(): bool
    {
        $s    = $this->store();
        $last = $s->read('lastfiles');

        if ($last === null || !\is_array($last['files'] ?? null)) {
            return false;
        }

        $ok = $s->write('baseline', ['created' => (int) ($last['at'] ?? time()), 'files' => $last['files']]);

        // The "changes since baseline" list of the shown result is now empty by definition.
        $res = $s->read('result');

        if ($ok && $res !== null) {
            $res['baseline']   = true;
            $res['baselineAt'] = (int) ($last['at'] ?? time());
            $res['changes']    = ['new' => [], 'changed' => [], 'removed' => [], 'more' => 0];
            $s->write('result', $res);
        }

        return $ok;
    }

    /**
     * Mark one finding of the LAST scan as safe (by path and fingerprint: if the file changes it
     * is reported again). Only a finding that is really in the last result can be marked.
     */
    public function markSafe(string $path, string $hash): bool
    {
        $s   = $this->store();
        $res = $s->read('result');

        if ($res === null || !preg_match('/^[0-9a-f]{12}$/', $hash)) {
            return false;
        }

        $found = false;

        foreach ((array) ($res['findings'] ?? []) as $f) {
            if (($f['path'] ?? null) === $path && ($f['hash'] ?? null) === $hash) {
                $found = true;
            }
        }

        if (!$found) {
            return false;
        }

        $ign = $s->read('ignore') ?? [];

        if (\count($ign) >= 500 && !isset($ign[$path])) {
            return false;
        }

        $ign[$path] = $hash;
        $ok         = $s->write('ignore', $ign);

        // Take it out of the list shown now (the next scan does the same by itself).
        if ($ok) {
            $res['findings'] = array_values(array_filter((array) $res['findings'], static fn (array $f): bool => !($f['path'] === $path && $f['hash'] === $hash)));
            $res['count']    = ['high' => 0, 'medium' => 0, 'low' => 0];

            foreach ($res['findings'] as $f) {
                $res['count'][$f['sev']]++;
            }

            $res['ignored'] = (int) ($res['ignored'] ?? 0) + 1;
            $s->write('result', $res);
        }

        return $ok;
    }

    public function clearSafe(): void
    {
        $this->store()->delete('ignore');
    }

    // ------------------------------------------------------------------
    // View, edit, delete: only files the last scan reported, a copy is kept before any change.
    // ------------------------------------------------------------------

    public const MAX_EDIT = 2097152;
    public const MAX_BULK = 200;

    private function quarantine(): Quarantine
    {
        return new Quarantine(JPATH_ROOT . '/cache/colorpack_shield/quarantine');
    }

    /**
     * The paths the person may look at: what the last scan reported, plus the new and changed PHP files.
     *
     * @return array<string,int>
     */
    private function allowed(): array
    {
        $r   = $this->store()->read('result');
        $out = [];

        foreach ((array) ($r['findings'] ?? []) as $f) {
            if (\is_string($f['path'] ?? null)) {
                $out[$f['path']] = 1;
            }
        }

        foreach (['new', 'changed'] as $k) {
            foreach ((array) ($r['changes'][$k] ?? []) as $p) {
                if (\is_string($p)) {
                    $out[$p] = 1;
                }
            }
        }

        return $out;
    }

    /** One line in the plugin's own log: who did what to which file. */
    private function audit(string $action, string $detail): void
    {
        try {
            Log::addLogger(['text_file' => 'colorpack_shield.php'], Log::ALL, ['colorpack_shield']);
            $user = (int) Factory::getApplication()->getIdentity()->id;
            $d    = substr(preg_replace('/[\x00-\x1f\x7f]/', '?', $detail) ?? '', 0, 200);
            Log::add(sprintf('NOTE client=administrator kind=scan_action action=%s user=%d path=%s', $action, $user, $d), Log::WARNING, 'colorpack_shield');
        } catch (\Throwable) {
            // The log must never stop the action it records.
        }
    }

    /**
     * @return array{ok:bool,err?:string,real?:string}
     */
    private function guard(string $rel, string $action): array
    {
        $g = FileGuard::check(JPATH_ROOT, $rel, $this->allowed(), $action);

        if ($g['code'] !== FileGuard::OK) {
            $this->audit('denied', $action . ' ' . $g['code'] . ' ' . $rel);

            return ['ok' => false, 'err' => $g['code']];
        }

        return ['ok' => true, 'real' => (string) $g['real']];
    }

    /**
     * The file's text for the code viewer / editor, with the suspicious lines.
     *
     * @return array<string,mixed>
     */
    public function view(string $rel): array
    {
        $g = $this->guard($rel, 'view');

        if (!$g['ok']) {
            return $g;
        }

        $size = (int) @filesize($g['real']);

        if ($size > self::MAX_EDIT) {
            return ['ok' => false, 'err' => 'too_big', 'size' => $size];
        }

        $raw = @file_get_contents($g['real']);

        if ($raw === false) {
            return ['ok' => false, 'err' => 'unreadable'];
        }

        $text = !str_contains($raw, "\0") && preg_match('//u', $raw) === 1;
        $kind = LineMarker::kindOf($rel);
        $dd   = preg_match('~^(?:images|media|tmp|cache|logs|administrator/(?:cache|logs|tmp))/~i', $rel) === 1;
        $edit = FileGuard::check(JPATH_ROOT, $rel, $this->allowed(), 'edit')['code'] === FileGuard::OK;
        $del  = FileGuard::check(JPATH_ROOT, $rel, $this->allowed(), 'delete');
        $syn  = $text && $kind === 'php' ? PhpSyntax::error($raw) : null;
        $this->audit('view', $rel);

        return [
            'ok'        => true,
            'path'      => $rel,
            'name'      => basename($rel),
            'content'   => $text ? $raw : substr(mb_convert_encoding(substr($raw, 0, 65536), 'UTF-8', 'UTF-8'), 0, 65536),
            'binary'    => !$text,
            'size'      => $size,
            'hash'      => substr(sha1($raw), 0, 12),
            'marks'     => LineMarker::marks($text ? $raw : substr($raw, 0, 524288), $kind, $dd),
            'syntax'    => $syn,
            'canEdit'   => $edit && $text,
            'canDelete' => $del['code'] === FileGuard::OK,
            'deleteWhy' => $del['code'] === FileGuard::OK ? '' : $del['code'],
        ];
    }

    /**
     * Save an edit. The file is copied first; PHP that no longer parses is refused unless $force.
     *
     * @return array<string,mixed>
     */
    public function save(string $rel, string $content, string $baseHash, bool $force): array
    {
        $g = $this->guard($rel, 'edit');

        if (!$g['ok']) {
            return $g;
        }

        if (\strlen($content) > self::MAX_EDIT) {
            return ['ok' => false, 'err' => 'too_big'];
        }

        $now = @file_get_contents($g['real']);

        if ($now === false || str_contains($now, "\0") || preg_match('//u', $now) !== 1) {
            return ['ok' => false, 'err' => 'binary'];
        }

        // Somebody (or the site) changed the file since the person opened it: do not overwrite blindly.
        if ($baseHash !== '' && !hash_equals(substr(sha1($now), 0, 12), $baseHash)) {
            return ['ok' => false, 'err' => 'changed'];
        }

        if (!$force && LineMarker::kindOf($rel) === 'php' && ($syn = PhpSyntax::error($content)) !== null) {
            return ['ok' => false, 'err' => 'syntax', 'syntax' => $syn];
        }

        if ($this->quarantine()->store($g['real'], $rel, 'edit') === null) {
            return ['ok' => false, 'err' => 'no_backup'];
        }

        if (@file_put_contents($g['real'], $content, LOCK_EX) === false) {
            $this->audit('save_failed', $rel);

            return ['ok' => false, 'err' => 'write_failed'];
        }

        $this->audit('save', $rel . ' (' . \strlen($content) . ' B)');
        $this->refresh($rel);

        return ['ok' => true, 'hash' => substr(sha1($content), 0, 12), 'marks' => LineMarker::marks($content, LineMarker::kindOf($rel)), 'syntax' => LineMarker::kindOf($rel) === 'php' ? PhpSyntax::error($content) : null];
    }

    /**
     * @return array<string,mixed>
     */
    public function delete(string $rel, string $confirm): array
    {
        $g = $this->guard($rel, 'delete');

        if (!$g['ok']) {
            return $g;
        }

        if ($confirm !== basename($rel)) {
            return ['ok' => false, 'err' => 'confirm'];
        }

        return $this->remove($rel, $g['real'], 'delete');
    }

    /**
     * @param  string[]  $rels
     *
     * @return array{ok:bool,deleted:int,errors:array<int,array{path:string,err:string}>}
     */
    public function bulkDelete(array $rels): array
    {
        $deleted = 0;
        $errors  = [];

        foreach (\array_slice(array_values(array_unique(array_filter($rels, '\is_string'))), 0, self::MAX_BULK) as $rel) {
            $g = $this->guard($rel, 'delete');

            if (!$g['ok']) {
                $errors[] = ['path' => $rel, 'err' => $g['err'] ?? 'failed'];

                continue;
            }

            $r = $this->remove($rel, $g['real'], 'bulk_delete');

            if ($r['ok']) {
                $deleted++;
            } else {
                $errors[] = ['path' => $rel, 'err' => (string) ($r['err'] ?? 'failed')];
            }
        }

        return ['ok' => true, 'deleted' => $deleted, 'errors' => $errors];
    }

    /**
     * Mark several findings of the last scan as safe at once (by path; the hash is read from the
     * result itself, so the caller only ever needs to send the paths it showed on screen).
     *
     * @param  string[]  $rels
     *
     * @return array{ok:bool,marked:int,errors:array<int,array{path:string,err:string}>}
     */
    public function bulkSafe(array $rels): array
    {
        $res = $this->store()->read('result');

        if ($res === null) {
            return ['ok' => true, 'marked' => 0, 'errors' => []];
        }

        $hashes = [];

        foreach ((array) ($res['findings'] ?? []) as $f) {
            if (\is_string($f['path'] ?? null) && \is_string($f['hash'] ?? null)) {
                $hashes[$f['path']] = $f['hash'];
            }
        }

        $marked = 0;
        $errors = [];

        foreach (\array_slice(array_values(array_unique(array_filter($rels, '\is_string'))), 0, self::MAX_BULK) as $rel) {
            if (!isset($hashes[$rel])) {
                $errors[] = ['path' => $rel, 'err' => 'not_found'];

                continue;
            }

            if ($this->markSafe($rel, $hashes[$rel])) {
                $marked++;
            } else {
                $errors[] = ['path' => $rel, 'err' => 'failed'];
            }
        }

        return ['ok' => true, 'marked' => $marked, 'errors' => $errors];
    }

    /**
     * Delete or mark-safe every finding that matches a severity/path filter, without the caller
     * having to enumerate paths itself (a filter such as ".htaccess" can match far more rows than
     * fit on one page). Still capped per call by {@see self::MAX_BULK}; the count matched is
     * returned so the screen can say to press the button again if more remain.
     *
     * @param  array<string,mixed>  $rawCriteria
     *
     * @return array{ok:bool,matched:int,deleted?:int,marked?:int,errors:array<int,array{path:string,err:string}>}
     */
    public function bulkByFilter(string $action, array $rawCriteria): array
    {
        $res      = $this->store()->read('result');
        $findings = (array) ($res['findings'] ?? []);
        $matched  = ScanFilter::apply($findings, ScanFilter::criteria($rawCriteria));
        $paths    = array_values(array_map(static fn (array $f): string => (string) $f['path'], $matched));

        $out = $action === 'safe' ? $this->bulkSafe($paths) : $this->bulkDelete($paths);

        return $out + ['matched' => \count($paths)];
    }

    /**
     * @return array<string,mixed>
     */
    private function remove(string $rel, string $real, string $label): array
    {
        if ($this->quarantine()->store($real, $rel, 'delete') === null) {
            return ['ok' => false, 'err' => 'no_backup'];
        }

        if (!@unlink($real)) {
            $this->audit('delete_failed', $rel);

            return ['ok' => false, 'err' => 'permission'];
        }

        $this->audit($label, $rel);
        $this->refresh($rel);

        return ['ok' => true];
    }

    /** @return array<int,array{id:string,path:string,action:string,time:int,size:int}> */
    public function copies(): array
    {
        return $this->quarantine()->items(100);
    }

    /**
     * @return array<string,mixed>
     */
    public function restore(string $id, bool $overwrite): array
    {
        $q   = $this->quarantine();
        $res = $q->restore($id, JPATH_ROOT, $overwrite);
        $this->audit($res === 'ok' ? 'restore' : 'restore_refused', $id . ' ' . $res);

        if ($res === 'ok') {
            foreach ($q->items(300) as $it) {
                if ($it['id'] === $id) {
                    $this->refresh($it['path']);
                }
            }
        }

        return ['ok' => $res === 'ok', 'err' => $res];
    }

    public function dropCopy(string $id): bool
    {
        $this->audit('drop_copy', $id);
        $this->quarantine()->drop($id);

        return true;
    }

    /**
     * After a change: look at that one file again and update the shown result (findings, counts, lists).
     */
    private function refresh(string $rel): void
    {
        $s   = $this->store();
        $res = $s->read('result');

        if ($res === null) {
            return;
        }

        $ign   = $s->read('ignore');
        $one   = FileScanner::inspectFile(JPATH_ROOT, $rel, \is_array($ign) ? array_map('strval', $ign) : []);
        $list  = array_values(array_filter((array) ($res['findings'] ?? []), static fn (array $f): bool => ($f['path'] ?? '') !== $rel));

        if ($one !== null && \count($list) < FileScanner::MAX_FINDINGS) {
            $list[] = $one;
        }

        usort($list, static fn (array $a, array $b): int => [['high' => 3, 'medium' => 2, 'low' => 1][$b['sev']], $a['path']] <=> [['high' => 3, 'medium' => 2, 'low' => 1][$a['sev']], $b['path']]);
        $res['findings'] = $list;
        $res['count']    = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($list as $f) {
            $res['count'][$f['sev']]++;
        }

        if (!is_file(JPATH_ROOT . '/' . $rel) && \is_array($res['changes'] ?? null)) {
            foreach (['new', 'changed'] as $k) {
                $res['changes'][$k] = array_values(array_filter((array) ($res['changes'][$k] ?? []), static fn ($p): bool => $p !== $rel));
            }
        }

        $s->write('result', $res);
    }
}
