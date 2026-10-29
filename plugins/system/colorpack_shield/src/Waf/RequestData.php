<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Flattens request superglobals into a bounded list of scannable scalars.
 *
 * Every value is capped at {@see self::MAX_VALUE_LEN} and the structure is
 * walked to a maximum depth ({@see self::MAX_DEPTH}) with a hard key count
 * ({@see self::MAX_KEYS}) — the three caps that keep shield regexes ReDoS-
 * and CPU-safe regardless of attacker-controlled body size.
 *
 * Deliberately Joomla-free so it is unit-testable in isolation.
 */
final class RequestData
{
    public const MAX_VALUE_LEN = 8192;
    public const MAX_DEPTH     = 6;
    public const MAX_KEYS      = 2000;

    /** Overlap between the pieces of a long value, so a signature on a boundary is still seen whole. */
    public const CHUNK_OVERLAP = 256;

    /** At most this many pieces from one value (about 1 MB); more than that is only flagged. */
    public const MAX_CHUNKS = 128;

    /** Values past the key limit are gathered here and scanned as pieces, up to this many bytes. */
    public const MAX_OVERFLOW = 1048576;

    /** @var array<int, array{source:string,key:string,value:string}> */
    private array $items = [];

    private int $keyCount = 0;

    public bool $truncated = false;

    private string $overflow = '';

    /**
     * @param  array<string, mixed>  $sources  e.g. ['GET' => $_GET, 'POST' => $_POST]
     */
    public function __construct(array $sources)
    {
        foreach ($sources as $source => $bag) {
            if (\is_array($bag)) {
                $this->walk((string) $source, '', $bag, 0);
            }
        }

        // Fields past the key limit are not dropped: a flood of dummy fields must not hide the one that matters.
        if ($this->overflow !== '') {
            foreach ($this->pieces($this->overflow) as $piece) {
                $this->items[] = ['source' => 'OVERFLOW', 'key' => '', 'value' => $piece];
            }
        }
    }

    /**
     * @return array<int, array{source:string,key:string,value:string}>
     */
    public function items(): array
    {
        return $this->items;
    }

    /**
     * Recursively flatten an array/scalar tree into $this->items.
     *
     * @param  mixed  $value
     */
    private function walk(string $source, string $key, $value, int $depth): void
    {
        if (\is_array($value)) {
            if ($depth >= self::MAX_DEPTH) {
                $this->truncated = true;

                return;
            }

            foreach ($value as $k => $v) {
                $childKey = $key === '' ? (string) $k : $key . '.' . $k;
                $this->walk($source, $childKey, $v, $depth + 1);
            }

            return;
        }

        // Scalars only; ignore objects/resources that shouldn't appear in request bags.
        if (\is_scalar($value) || $value === null) {
            $str = (string) $value;

            if ($this->keyCount >= self::MAX_KEYS) {
                $this->truncated = true;

                if (\strlen($this->overflow) < self::MAX_OVERFLOW) {
                    $this->overflow .= substr($key . '=' . $str, 0, self::MAX_OVERFLOW - \strlen($this->overflow)) . "\n";
                }

                return;
            }

            if (\strlen($str) > self::MAX_VALUE_LEN) {
                $pieces = $this->pieces($str);

                if (\strlen($str) > (self::MAX_VALUE_LEN - self::CHUNK_OVERLAP) * self::MAX_CHUNKS) {
                    $this->truncated = true;
                }

                foreach ($pieces as $piece) {
                    $this->items[] = ['source' => $source, 'key' => $key, 'value' => $piece];
                }

                $this->keyCount++;

                return;
            }

            // Also scan the KEY itself — parameter names can carry payloads.
            $this->items[] = ['source' => $source, 'key' => $key, 'value' => $str];
            $this->keyCount++;
        }
    }

    /**
     * Cut a long string into overlapping pieces no longer than the value cap, so nothing is
     * skipped and a signature that straddles a cut is still whole in one piece.
     *
     * @return string[]
     */
    private function pieces(string $str): array
    {
        $size = self::MAX_VALUE_LEN;
        $len  = \strlen($str);

        if ($len <= $size) {
            return [$str];
        }

        $step   = $size - self::CHUNK_OVERLAP;
        $pieces = [];

        for ($off = 0; $off < $len && \count($pieces) < self::MAX_CHUNKS; $off += $step) {
            $pieces[] = substr($str, $off, $size);

            if ($off + $size >= $len) {
                break;
            }
        }

        return $pieces;
    }
}
