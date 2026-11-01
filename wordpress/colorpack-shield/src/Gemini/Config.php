<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Gemini;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Immutable settings for the Gemini advisor. The key is entered by the admin - there is no WP
 * Settings screen yet to collect it from, so this is a plain value object the future screen will
 * construct, same as the Joomla edition's Gemini\Config.
 */
final class Config
{
    public const DEFAULT_MODEL = 'gemini-3.5-flash-lite';

    private function __construct(
        public readonly string $apiKey,
        public readonly string $model,
        public readonly bool $scheduleEnabled,
        public readonly int $scheduleIntervalHours
    ) {
    }

    /**
     * @return self|null  null when the feature is off, or no key is configured
     */
    public static function fromParams(?string $apiKey, bool $enabled, string $model, bool $scheduleEnabled, int $scheduleIntervalHours): ?self
    {
        if (!$enabled) {
            return null;
        }

        $apiKey = trim((string) $apiKey);

        if ($apiKey === '') {
            return null;
        }

        $model = trim($model) !== '' ? trim($model) : self::DEFAULT_MODEL;

        return new self($apiKey, $model, $scheduleEnabled, max(1, $scheduleIntervalHours));
    }
}
