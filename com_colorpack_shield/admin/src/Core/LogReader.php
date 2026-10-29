<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Reads the plugin's text log (Joomla "text_file" format) from the end, within a
 * byte budget, and turns each line into a small array. Every value comes from
 * attacker-influenced data (paths, headers), so values are only ever cut and
 * stripped of control bytes here; escaping is the view's job.
 *
 * Line: "datetime<TAB>priority<TAB>clientip<TAB>category<TAB>TYPE key=value …"
 * "sample=", "detail=" and "file=" take the rest of their text; other values end at a space.
 */
final class LogReader
{
    public const MAX_VALUE = 300;

    private const TYPES = ['BLOCK', 'DETECT', 'LOCK', 'OBSERVE', 'ALERT', 'NOTE'];

    public function __construct(private readonly string $path, private readonly int $maxBytes = 2097152)
    {
    }

    /**
     * @return array{readable:bool,truncated:bool,size:int,entries:array<int,array{time:int,type:string,f:array<string,string>}>}
     */
    public function read(): array
    {
        $out = ['readable' => false, 'truncated' => false, 'size' => 0, 'entries' => []];

        if ($this->path === '' || !is_file($this->path) || !is_readable($this->path)) {
            return $out;
        }

        $size = (int) @filesize($this->path);
        $fh   = @fopen($this->path, 'rb');

        if ($fh === false) {
            return $out;
        }

        $out['readable'] = true;
        $out['size']     = $size;
        $budget          = max(1024, $this->maxBytes);

        if ($size > $budget) {
            $out['truncated'] = true;
            fseek($fh, $size - $budget);
            // The first line is probably cut in half.
            fgets($fh);
        }

        $data = stream_get_contents($fh);
        fclose($fh);

        if (!\is_string($data)) {
            return $out;
        }

        foreach (explode("\n", $data) as $line) {
            $entry = self::parseLine($line);

            if ($entry !== null) {
                $out['entries'][] = $entry;
            }
        }

        return $out;
    }

    /**
     * @return array{time:int,type:string,f:array<string,string>}|null
     */
    public static function parseLine(string $line): ?array
    {
        $line = rtrim($line, "\r");

        if ($line === '' || $line[0] === '#') {
            return null;
        }

        $parts = explode("\t", $line, 5);

        if (\count($parts) < 5 || $parts[3] !== 'colorpack_shield') {
            return null;
        }

        $time = strtotime($parts[0]);

        if ($time === false) {
            return null;
        }

        $message = $parts[4];
        $sp      = strpos($message, ' ');
        $type    = $sp === false ? $message : substr($message, 0, $sp);

        if (!\in_array($type, self::TYPES, true)) {
            return null;
        }

        $fields = [];
        $rest   = $sp === false ? '' : substr($message, $sp + 1);

        while ($rest !== '') {
            if (!preg_match('/^([a-z_]+)=/', $rest, $m)) {
                // Free text between fields: keep a little of it, skip to the next field.
                $next = preg_match('/\s([a-z_]+)=/', $rest, $mm, PREG_OFFSET_CAPTURE) ? $mm[0][1] + 1 : \strlen($rest);
                $fields['text'] = self::clean(($fields['text'] ?? '') . substr($rest, 0, $next));
                $rest = substr($rest, $next);

                continue;
            }

            $key  = $m[1];
            $rest = substr($rest, \strlen($m[0]));

            if ($key === 'sample' || $key === 'detail' || $key === 'file') {
                if ($key === 'sample') {
                    $fields[$key] = self::clean($rest);
                    $rest         = '';

                    continue;
                }

                // Up to the next " key=" field.
                $end = preg_match('/\s(?:[a-z_]+)=/', $rest, $mm, PREG_OFFSET_CAPTURE) ? $mm[0][1] : \strlen($rest);
                $fields[$key] = self::clean(substr($rest, 0, $end));
                $rest         = ltrim(substr($rest, $end));

                continue;
            }

            $end          = strcspn($rest, " \t");
            $fields[$key] = self::clean(substr($rest, 0, $end));
            $rest         = ltrim(substr($rest, $end));
        }

        return ['time' => $time, 'type' => $type, 'f' => $fields];
    }

    private static function clean(string $value): string
    {
        $value = preg_replace('/[\x00-\x1f\x7f]/', '?', trim($value)) ?? '';

        if (preg_match('//u', $value) !== 1) {
            $value = preg_replace('/[\x80-\xff]/', '?', $value) ?? '';
        }

        return mb_substr($value, 0, self::MAX_VALUE);
    }
}
