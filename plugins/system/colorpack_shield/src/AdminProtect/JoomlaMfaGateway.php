<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The only place that touches Joomla's multi-factor authentication classes
 * (Users\Administrator\Helper\Mfa, com_users options, the application's own list
 * of MFA pages), so the rest of A3 stays testable. Every method answers
 * "no / unknown" instead of throwing.
 */
final class JoomlaMfaGateway
{
    private const HELPER = 'Joomla\\Component\\Users\\Administrator\\Helper\\Mfa';

    /** Is there any multi-factor method a user could set up? (Joomla 4.2+ with a multifactorauth plugin enabled.) */
    public static function available(): bool
    {
        try {
            $h = self::HELPER;

            return class_exists($h) && !empty($h::getMfaMethods());
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Does the user have a method that Joomla would really ask for at login?
     * (Same rule as Joomla's captive page: a record whose method is enabled; backup codes alone do not count.)
     */
    public static function userHasMfa(int $userId): bool
    {
        try {
            $h = self::HELPER;

            if (!class_exists($h) || $userId <= 0) {
                return false;
            }

            // Joomla hands the methods back as arrays or as ArrayAccess objects, keyed by method name.
            $active = [];

            foreach ((array) $h::getMfaMethods() as $m) {
                $active[] = (string) (\is_array($m) || $m instanceof \ArrayAccess ? ($m['name'] ?? '') : ($m->name ?? ''));
            }

            foreach ((array) $h::getUserMfaRecords($userId) as $record) {
                if (\in_array((string) ($record->method ?? ''), $active, true)) {
                    return true;
                }
            }

            return false;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * @return int[]
     */
    public static function userGroups(object $user): array
    {
        try {
            $groups = method_exists($user, 'getAuthorisedGroups') ? $user->getAuthorisedGroups() : ($user->groups ?? []);

            return array_values(array_unique(array_filter(array_map('intval', array_values((array) $groups)), static fn (int $g): bool => $g > 0)));
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Groups Joomla itself exempts from multi-factor authentication ("Disable Multi-factor Authentication").
     *
     * @return int[]
     */
    public static function neverGroups(): array
    {
        try {
            $g = \Joomla\CMS\Component\ComponentHelper::getParams('com_users')->get('neverMFAUserGroups', []);

            return \is_array($g) ? array_values(array_filter(array_map('intval', $g), static fn (int $x): bool => $x > 0)) : [];
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * Pages that must stay reachable for a user without MFA: the MFA setup and
     * captive pages (Joomla's own list, the one it uses for its mandatory-MFA
     * redirect), logout, and the finalisation step of a Joomla update.
     */
    public static function isExemptPage(object $app): bool
    {
        try {
            if (method_exists($app, 'isMultiFactorAuthenticationPage') && $app->isMultiFactorAuthenticationPage(false)) {
                return true;
            }

            $input  = $app->getInput();
            $option = strtolower((string) $input->getCmd('option', ''));
            $task   = strtolower((string) $input->getCmd('task', ''));

            return ($option === 'com_login' && $task === 'logout')
                || ($option === 'com_joomlaupdate' && \in_array($task, ['update.finalise', 'update.cleanup', 'update.finaliseconfirm'], true));
        } catch (\Throwable) {
            return true;   // when in doubt, leave the page alone
        }
    }

    /**
     * Where the user sets multi-factor authentication up: a relative address,
     * which a browser (for the reminder link) and Joomla's redirect() (which
     * resolves it against the current request) both complete correctly for every
     * installation folder. No router or base-address helper is involved, so
     * nothing can double the "/administrator" part.
     */
    public static function setupUrl(): string
    {
        return 'index.php?option=com_users&view=methods';
    }
}
