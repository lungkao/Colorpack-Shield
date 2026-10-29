<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns a raw request body (php://input) into a source bag for {@see RequestData}.
 *
 * P0.2: the WAF must see more than $_GET/$_POST. This parser is content-type
 * aware:
 *   - application/json (or a body that structurally looks like JSON) is decoded
 *     and returned as a nested tree under the "JSON" source, so RequestData's
 *     recursive flatten gives every value its own depth/key/value cap for free.
 *   - form bodies (urlencoded / multipart) are SKIPPED — PHP already surfaced
 *     them via $_POST/$_FILES, and multipart's php://input is unreadable after
 *     PHP consumes it. Double-scanning would only waste the key budget.
 *   - anything else (raw text, XML, malformed JSON) is scanned as a blob under
 *     the "BODY" source, sliced into overlapping chunks so a signature past the
 *     per-value cap is still caught and can't hide on a chunk boundary. XML is
 *     deliberately NOT structurally parsed (that would open XXE) — blob scanning
 *     is the safe choice.
 *
 * Deliberately Joomla-free so it is unit-testable in isolation.
 */
final class BodyParser
{
    /** Hard ceiling on how much of the body is ever examined (256 KB). */
    public const MAX_BODY_BYTES = 262144;

    /**
     * Overlap between adjacent raw-body chunks. Must exceed the longest single
     * signature so a payload straddling a boundary appears whole in one chunk.
     */
    public const CHUNK_OVERLAP = 256;

    /** True when the body exceeded MAX_BODY_BYTES and only the head was scanned. */
    public bool $oversize = false;

    /**
     * @param  string  $raw          the raw request body
     * @param  string  $contentType  the request Content-Type header (may be empty)
     *
     * @return array<string, mixed>  a source bag for RequestData, or [] if nothing to scan
     */
    public function parse(string $raw, string $contentType): array
    {
        if ($raw === '') {
            return [];
        }

        if (\strlen($raw) > self::MAX_BODY_BYTES) {
            $this->oversize = true;
            $raw            = substr($raw, 0, self::MAX_BODY_BYTES);
        }

        $ct = strtolower($contentType);

        // Multipart's stream is gone, and a form body is already in $_POST. But Joomla reads a JSON
        // body whatever the Content-Type says, so a form-typed body that is really JSON is decoded too.
        if (str_contains($ct, 'multipart/form-data') || (str_contains($ct, 'x-www-form-urlencoded') && !$this->looksLikeJson($raw))) {
            return [];
        }

        if (str_contains($ct, 'json') || $this->looksLikeJson($raw)) {
            $decoded = json_decode($raw, true);

            if (\is_array($decoded)) {
                return ['JSON' => $decoded];
            }
            // Malformed JSON: fall through and scan the raw text as a blob.
        }

        return ['BODY' => $this->chunk($raw)];
    }

    /**
     * Cheap structural sniff: does the trimmed body start like a JSON value?
     */
    private function looksLikeJson(string $raw): bool
    {
        $head = ltrim($raw);

        return $head !== '' && ($head[0] === '{' || $head[0] === '[');
    }

    /**
     * Slice an over-cap blob into overlapping pieces no larger than the value
     * cap, so RequestData never truncates a piece and no signature is lost on a
     * boundary. A body within the cap is returned as a single-element list.
     *
     * @return string[]
     */
    private function chunk(string $raw): array
    {
        $size = RequestData::MAX_VALUE_LEN;
        $len  = \strlen($raw);

        if ($len <= $size) {
            return [$raw];
        }

        $step   = $size - self::CHUNK_OVERLAP;
        $chunks = [];

        for ($off = 0; $off < $len; $off += $step) {
            $chunks[] = substr($raw, $off, $size);

            if ($off + $size >= $len) {
                break;
            }
        }

        return $chunks;
    }
}
