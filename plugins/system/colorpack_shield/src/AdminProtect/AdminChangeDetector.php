<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Decides whether saving a user gave somebody Super User powers
 * (PLAN-ADMIN-PROTECTION.md A2): after a break-in, creating or promoting an
 * administrator is often the first thing an attacker does.
 *
 * "Super" is whatever the caller says it is (Joomla: a group allowed
 * `core.admin`); this class only compares group lists.
 */
final class AdminChangeDetector
{
    public const CREATED  = 'created';
    public const PROMOTED = 'promoted';

    /**
     * @param  array<int|string,mixed>|null  $oldGroups  groups before the save (null/[] for a new user)
     * @param  array<int|string,mixed>|null  $newGroups  groups after the save; null = the save did not carry groups
     * @param  callable(int):bool            $isSuper    does this group give Super User powers?
     *
     * @return string|null  CREATED (a new user holding a super group), PROMOTED (an existing user gained one), else null
     */
    public static function change(?array $oldGroups, ?array $newGroups, bool $isNew, callable $isSuper): ?string
    {
        if ($newGroups === null) {
            return null;
        }

        $new = self::ids($newGroups);
        $old = self::ids($oldGroups ?? []);

        $gained = array_values(array_filter(
            $isNew ? $new : array_diff($new, $old),
            static fn (int $g): bool => $isSuper($g)
        ));

        if ($gained === []) {
            return null;
        }

        return $isNew ? self::CREATED : self::PROMOTED;
    }

    /**
     * @param  array<int|string,mixed>  $groups
     *
     * @return int[]
     */
    private static function ids(array $groups): array
    {
        return array_values(array_unique(array_filter(
            array_map(static fn ($g): int => \is_scalar($g) && is_numeric($g) ? (int) $g : 0, $groups),
            static fn (int $g): bool => $g > 0
        )));
    }
}
