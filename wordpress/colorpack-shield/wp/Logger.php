<?php

namespace Colorpack\Shield\Wp;

defined('ABSPATH') || die;

/** One line per event in a die()-guarded file; never throws, trimmed when it grows past 1 MB. */
final class Logger
{
    private const HEADER = "<?php die('Forbidden'); ?>\n";
    private const MAX    = 1048576;

    public static function add(string $line): void
    {
        try {
            $file = Settings::stateDir() . '/shield.log.php';

            if (!is_file($file)) {
                @file_put_contents($file, self::HEADER);
            } elseif (@filesize($file) > self::MAX) {
                $tail = (string) @file_get_contents($file, false, null, (int) (self::MAX / 2));
                $tail = substr($tail, (int) strpos($tail, "\n") + 1);
                @file_put_contents($file, self::HEADER . $tail, LOCK_EX);
            }

            // One event, one line: a hostile value must not be able to forge log lines.
            $clean = preg_replace('/[\x00-\x1f\x7f]/', '?', $line) ?? '';
            @file_put_contents($file, gmdate('Y-m-d H:i:s') . ' ' . $clean . "\n", FILE_APPEND | LOCK_EX);
        } catch (\Throwable) {
            // Logging must never break a request.
        }
    }

    /** @return string[]  newest first */
    public static function tail(int $lines = 50): array
    {
        $file = Settings::stateDir() . '/shield.log.php';

        if (!is_file($file)) {
            return [];
        }

        $all = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        array_shift($all);

        return array_reverse(array_slice($all, -$lines));
    }
}
