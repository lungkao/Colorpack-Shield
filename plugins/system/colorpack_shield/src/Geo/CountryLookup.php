<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Geo;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Resolves an IP to an ISO country code from a local MaxMind GeoLite2 database.
 *
 * Reads the .mmdb through {@see \MaxMind\Db\Reader}, which is provided by EITHER
 * the `maxminddb` PHP extension OR the pure-PHP `geoip2/geoip2` Composer package
 * (both expose the same class). We deliberately do NOT bundle a hand-rolled MMDB
 * parser — the binary format is fiddly and the MaxMind reader is battle-tested.
 *
 * The lookup is LOCAL (no per-request network call — that would be a fleet-scale
 * latency tax) and fails OPEN: if the reader class is missing, the DB path is
 * unreadable, or a lookup throws, country() returns null and the {@see GeoPolicy}
 * treats the request as unknown rather than erroring out the site.
 */
final class CountryLookup
{
    private ?object $reader = null;

    private bool $resolved = false;

    public function __construct(private readonly string $dbPath)
    {
    }

    /** True when a usable reader is available (DB present + reader class loaded). */
    public function isAvailable(): bool
    {
        return $this->reader() !== null;
    }

    public function country(string $ip): ?string
    {
        $reader = $this->reader();

        if ($reader === null || $ip === '') {
            return null;
        }

        try {
            $record = $reader->get($ip);
        } catch (\Throwable) {
            return null;
        }

        if (\is_array($record) && isset($record['country']['iso_code'])) {
            return (string) $record['country']['iso_code'];
        }

        return null;
    }

    private function reader(): ?object
    {
        if ($this->resolved) {
            return $this->reader;
        }

        $this->resolved = true;

        if (
            $this->dbPath === ''
            || !is_readable($this->dbPath)
            || !class_exists('\\MaxMind\\Db\\Reader')
        ) {
            return null;
        }

        try {
            $class        = '\\MaxMind\\Db\\Reader';
            $this->reader = new $class($this->dbPath);
        } catch (\Throwable) {
            $this->reader = null;
        }

        return $this->reader;
    }
}
