<?php

declare(strict_types=1);

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns a stored UTC Unix timestamp into the site's configured local time for display - every
 * log line is written and parsed in UTC (see ColorpackShield::writeLog()), so a screen that
 * shows one of those times must convert here rather than printing the UTC value raw, or it
 * reads as "wrong" by exactly the site's UTC offset.
 */
final class TimeFormat
{
    public static function local(int $ts, string $offset, string $format = 'Y-m-d H:i:s'): string
    {
        try {
            $tz = new \DateTimeZone($offset !== '' ? $offset : 'UTC');
        } catch (\Exception) {
            $tz = new \DateTimeZone('UTC');
        }

        $dt = new \DateTime('@' . $ts);
        $dt->setTimezone($tz);

        return $dt->format($format);
    }
}
