<?php

namespace Colorpack\Shield\Wp;

use Colorpack\Plugin\System\ColorpackShield\Scanner\FileScanner;
use Colorpack\Plugin\System\ColorpackShield\Scanner\ScanStore;

defined('ABSPATH') || die;

/** Resumable file-integrity scan of the whole WordPress folder, a few seconds per step (works on any shared host). */
final class Scan
{
    private static function store(): ScanStore
    {
        return new ScanStore(Settings::stateDir('scan'));
    }

    /** @return array<string,mixed>|null */
    public static function lastFinished(): ?array
    {
        return self::store()->read('result');
    }

    public static function status(): array
    {
        $s     = self::store();
        $state = $s->read('state');
        $base  = $s->read('baseline');

        return [
            'result'    => $s->read('result'),
            'running'   => $state !== null && empty($state['done']) ? ['seen' => (int) ($state['seen'] ?? 0)] : null,
            'baseline'  => $base !== null ? ['created' => (int) ($base['created'] ?? 0), 'count' => count((array) ($base['files'] ?? []))] : null,
            'canAccept' => $s->read('lastfiles') !== null,
        ];
    }

    public static function start(): bool
    {
        return self::store()->write('state', FileScanner::newState(time()));
    }

    /** @return array{ok:bool,busy?:bool,done?:bool,seen?:int,php?:int,findings?:int,high?:int} */
    public static function step(): array
    {
        $s   = self::store();
        $dir = Settings::stateDir('scan');
        $lock = @fopen($dir . '/lock', 'c');

        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['ok' => true, 'busy' => true];
        }

        try {
            $state = $s->read('state');

            if ($state === null) {
                return ['ok' => false];
            }

            $state = FileScanner::step($state, rtrim(ABSPATH, '/'), microtime(true) + 3.0, []);

            if ($state['done']) {
                $now  = time();
                $s->write('result', FileScanner::result($state, $s->read('baseline'), $now));
                $s->write('lastfiles', ['at' => $now, 'files' => $state['tracked'] ? $state['files'] : null]);
                $s->delete('state');
            } elseif (!$s->write('state', $state)) {
                return ['ok' => false];
            }

            $high = count(array_filter($state['findings'], static fn (array $f): bool => $f['sev'] === 'high'));

            return ['ok' => true, 'done' => (bool) $state['done'], 'seen' => (int) $state['seen'], 'php' => (int) $state['php'], 'findings' => count($state['findings']), 'high' => $high];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** The files of the last finished scan become the baseline: "this is how my site is supposed to look". */
    public static function acceptBaseline(): bool
    {
        $s    = self::store();
        $last = $s->read('lastfiles');

        if ($last === null || !is_array($last['files'] ?? null)) {
            return false;
        }

        $ok  = $s->write('baseline', ['created' => (int) ($last['at'] ?? time()), 'files' => $last['files']]);
        $res = $s->read('result');

        if ($ok && $res !== null) {
            $res['baseline']   = true;
            $res['baselineAt'] = (int) ($last['at'] ?? time());
            $res['changes']    = ['new' => [], 'changed' => [], 'removed' => [], 'more' => 0];
            $s->write('result', $res);
        }

        return $ok;
    }
}
