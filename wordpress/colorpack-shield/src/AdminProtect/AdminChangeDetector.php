<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\AdminProtect;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Decides whether saving a user gave somebody administrator-level powers
 * (PLAN-ADMIN-PROTECTION.md A2): after a break-in, creating or promoting an
 * administrator is often the first thing an attacker does.
 *
 * Not a straight port: the Joomla edition's own `AdminChangeDetector` compares integer
 * access-group ids (Joomla's own role model), which doesn't exist on this side - WordPress
 * roles are string slugs, and a user normally holds exactly one. The algorithm (did this save
 * add a role the caller considers "super" that the user didn't already hold?) carries over
 * unchanged; only the id type does not. "Super" is whatever the caller says it is - see
 * `Wiring::isSuperRole()`, which checks the `manage_options` capability rather than hardcoding
 * the 'administrator' slug, so a custom role a plugin grants that capability to still counts.
 *
 * Out of scope: multisite network Super Admin grants (`grant_super_admin`/`revoke_super_admin`)
 * are a separate, network-level privilege with their own hooks, not a role at all - this class
 * only ever looks at a single site's roles, the same single-site scope as the rest of this port.
 */
final class AdminChangeDetector
{
    public const CREATED  = 'created';
    public const PROMOTED = 'promoted';

    /**
     * @param  string[]            $oldRoles  roles before the save (empty for a brand-new user)
     * @param  string[]             $newRoles  roles after the save
     * @param  callable(string):bool  $isSuper  does this role grant administrator-level powers?
     *
     * @return string|null  CREATED (a new user holding a super role), PROMOTED (an existing user gained one), else null
     */
    public static function change(array $oldRoles, array $newRoles, bool $isNew, callable $isSuper): ?string
    {
        $gained = array_values(array_filter(
            $isNew ? $newRoles : array_diff($newRoles, $oldRoles),
            $isSuper
        ));

        if ($gained === []) {
            return null;
        }

        return $isNew ? self::CREATED : self::PROMOTED;
    }
}
