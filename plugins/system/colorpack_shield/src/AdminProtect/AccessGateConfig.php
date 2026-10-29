<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

use Colorpack\Plugin\System\ColorpackShield\Net\IpAllowList;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Settings of the administrator access key (A4) and the administrator address list (A5)
 * (PLAN-ADMIN-PROTECTION.md §3). Anything unusable switches the feature OFF, never on:
 * a gate with no valid key, or an address list with no valid entry, would lock everybody out,
 * so each is simply inactive until it is complete.
 */
final class AccessGateConfig
{
    public const MIN_KEY = 10;

    /** No look-alike characters (0/o, 1/l/i): a key is read aloud and typed on phones. */
    public const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    public const GENERATED_LENGTH = 12;
    public const MAX_KEY = 128;

    /**
     * @param  string[]  $ipList  valid entries only
     */
    private function __construct(
        public readonly bool $gateActive,
        public readonly string $key,
        public readonly int $cookieHours,
        public readonly bool $ipActive,
        public readonly array $ipList,
        public readonly bool $keyMissing,
        public readonly bool $listEmpty
    ) {
    }

    /**
     * @param  array<string,mixed>  $p  plugin parameters
     */
    public static function fromArray(array $p): self
    {
        $bool = static fn (mixed $v): bool => filter_var($v, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === true;

        $key = $p['gate_key'] ?? '';
        $key = \is_string($key) ? trim($key) : '';
        $key = \strlen($key) >= self::MIN_KEY && \strlen($key) <= self::MAX_KEY && preg_match('/^[A-Za-z0-9_-]+$/', $key) === 1 ? $key : '';

        $hours = $p['gate_cookie_hours'] ?? null;
        $hours = is_numeric($hours) ? max(1, min(168, (int) $hours)) : 12;

        $list = IpAllowList::fromText(\is_string($p['admin_ip_list'] ?? null) ? $p['admin_ip_list'] : '')->entries();

        $gateWanted = $bool($p['gate_enabled'] ?? false);
        $ipWanted   = $bool($p['admin_ip_enforce'] ?? false);

        return new self(
            $gateWanted && $key !== '',
            $key,
            $hours,
            $ipWanted && $list !== [],
            $list,
            $gateWanted && $key === '',
            $ipWanted && $list === []
        );
    }

    /** A new random key (12 characters, about 60 bits) from an alphabet without look-alikes. */
    public static function generateKey(): string
    {
        $out = '';

        for ($i = 0; $i < self::GENERATED_LENGTH; $i++) {
            $out .= self::ALPHABET[random_int(0, \strlen(self::ALPHABET) - 1)];
        }

        return $out;
    }

    /** True when neither protection is in force. */
    public function off(): bool
    {
        return !$this->gateActive && !$this->ipActive;
    }
}
