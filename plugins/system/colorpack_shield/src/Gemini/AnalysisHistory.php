<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Gemini;

use Colorpack\Plugin\System\ColorpackShield\AdminProtect\StateStore;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * A small local history of past Gemini analyses - the "kept to inform future development" part
 * of this feature. Nothing here is ever sent anywhere; the Colorpack Site Manager (a separate
 * product the admin may also run) is expected to come read this on its own schedule, not be
 * pushed to - so this class only ever writes and lists, never calls out.
 *
 * Thin wrapper over {@see StateStore}: each analysis is one entry, keyed by time + a random
 * suffix (so two analyses in the same second never collide), with a 90-day TTL. Bounded growth is
 * entirely {@see \Colorpack\Plugin\System\ColorpackShield\AdminProtect\FileStateStore}'s own
 * already-tested behaviour - no new size-management code here.
 */
final class AnalysisHistory
{
    /** How long one analysis is kept before FileStateStore's own expiry sweep drops it. */
    private const TTL_SECONDS = 90 * 24 * 3600;

    private const PREFIX = 'analysis:';

    public function __construct(private readonly StateStore $store)
    {
    }

    public function record(string $kind, string $prompt, ?string $answer, int $when): void
    {
        $key = self::PREFIX . $when . ':' . bin2hex(random_bytes(4));

        $this->store->mutate($key, $when, static fn (): array => [
            'exp'    => $when + self::TTL_SECONDS,
            'kind'   => $kind,
            'prompt' => $prompt,
            'answer' => $answer,
            'when'   => $when,
        ]);
    }

    /**
     * @param  string[]|null  $kinds  only these kinds (e.g. the screen's own analyses), or null for every kind
     *
     * @return array<int, array{kind:string,prompt:string,answer:?string,when:int}>  newest first
     */
    public function recent(int $now, int $limit = 20, ?array $kinds = null): array
    {
        $all = $this->store->entries(self::PREFIX, $now);
        $out = array_values($all);

        if ($kinds !== null) {
            $out = array_values(array_filter($out, static fn (array $e): bool => \in_array($e['kind'] ?? '', $kinds, true)));
        }

        usort($out, static fn (array $a, array $b): int => ($b['when'] ?? 0) <=> ($a['when'] ?? 0));

        return \array_slice($out, 0, max(0, $limit));
    }
}
