<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Gemini;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Immutable settings for the Gemini advisor. Unlike {@see \Colorpack\Plugin\System\ColorpackShield\SiteManager\Config},
 * this key is entered by the admin (there is no sibling plugin to borrow it from), so there is no
 * file to read here - the caller passes the plugin's own params straight in.
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
     * @return self|null  null when the feature is off, or no key is configured - the caller then
     *                      treats the Gemini advisor as entirely absent (no HTTP call, no button).
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
