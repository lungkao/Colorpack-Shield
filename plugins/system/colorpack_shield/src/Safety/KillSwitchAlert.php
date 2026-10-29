<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Safety;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Tell the admin when the kill-switch file shows up (AUDIT.md C4), without
 * ever flooding their inbox.
 *
 * claim() is the throttle: it answers "should THIS request send the alert?" and
 * records the answer in a small state file under an exclusive lock, so
 * concurrent requests send one mail, not many. Same file + same modification
 * time + same mode (active / ignored) is announced once, then repeated as a
 * reminder every REPEAT seconds while it stays. If the state cannot be written
 * it answers NO — a mail flood is worse than a missed reminder.
 */
final class KillSwitchAlert
{
    public const REPEAT = 86400;

    public static function claim(string $stateFile, string $path, int $mtime, string $mode, int $now): bool
    {
        $dir = \dirname($stateFile);

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }

        $fh = @fopen($stateFile, 'c+');

        if ($fh === false) {
            return false;
        }

        try {
            if (!flock($fh, LOCK_EX)) {
                return false;
            }

            $state = json_decode((string) stream_get_contents($fh), true);

            if (
                \is_array($state)
                && ($state['path'] ?? null) === $path
                && ($state['mtime'] ?? null) === $mtime
                && ($state['mode'] ?? null) === $mode
                && \is_int($state['sent'] ?? null)
                && $now - $state['sent'] < self::REPEAT
                && $now >= $state['sent']
            ) {
                return false;
            }

            $new = json_encode(['path' => $path, 'mtime' => $mtime, 'mode' => $mode, 'sent' => $now]);

            if (!ftruncate($fh, 0) || fseek($fh, 0) !== 0 || fwrite($fh, (string) $new) === false) {
                return false;
            }

            fflush($fh);

            return true;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /**
     * Send one plain-text mail through Joomla's mailer. Never throws.
     */
    public static function send(string $to, string $subject, string $body): bool
    {
        try {
            $mailer = \Joomla\CMS\Factory::getContainer()
                ->get(\Joomla\CMS\Mail\MailerFactoryInterface::class)
                ->createMailer();

            $mailer->addRecipient($to);
            $mailer->setSubject($subject);
            $mailer->setBody($body);

            return (bool) $mailer->Send();
        } catch (\Throwable $e) {
            return false;
        }
    }
}
