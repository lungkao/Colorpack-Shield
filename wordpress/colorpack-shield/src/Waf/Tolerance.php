<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * How much a trusted editor may get away with, by how dangerous the matched rule is.
 *
 * Text pasted into an article is full of things that look like attacks but are not (SQL-style comments, a
 * stylesheet @import, an iframe). Those rules are tolerated for people we can vouch for. Rules that describe
 * code which would actually run (script tags, event handlers, javascript: links, UNION SELECT, path traversal,
 * stream wrappers, remote includes) are never tolerated for anyone. Nothing here switches a shield off: a
 * tolerated rule is skipped only on form fields (POST or JSON), and every other rule still runs on that field.
 */
final class Tolerance
{
    public const NONE = 0;

    public const LOW = 1;

    public const MEDIUM = 2;

    /** Rule ids that are common in ordinary pasted text. */
    private const LOW_RULES = ['sql_comment', 'boolean_tautology', 'css_expr'];

    /** Rule ids that are common in pasted web content from a trusted editor. */
    private const MEDIUM_RULES = ['risky_tag'];

    /**
     * @return string[]  the rule ids tolerated at this level
     */
    public static function rulesFor(int $level): array
    {
        return match (true) {
            $level >= self::MEDIUM => array_merge(self::LOW_RULES, self::MEDIUM_RULES),
            $level >= self::LOW    => self::LOW_RULES,
            default                => [],
        };
    }

    /**
     * The level a visitor earns. Fails closed: anything missing means a lower level.
     *
     * @param  bool      $enabled         the site turned "trusted editors" on
     * @param  bool      $adminClient     the request is for the administrator area
     * @param  bool      $loggedInEditor  a signed-in user allowed to manage the site
     * @param  bool      $gateOn          the secret entry address is required on this site
     * @param  bool      $mfaEnforced     two-step sign-in is enforced on this site
     * @param  bool      $userHasMfa      this user has set up two-step sign-in
     * @param  bool|null $countryOk       true/false = the visitor's country matches the allowed list; null = no country rule
     */
    public static function level(bool $enabled, bool $adminClient, bool $loggedInEditor, bool $gateOn, bool $mfaEnforced, bool $userHasMfa, ?bool $countryOk): int
    {
        if (!$enabled || !$adminClient || !$loggedInEditor) {
            return self::NONE;
        }

        return $gateOn && $mfaEnforced && $userHasMfa && $countryOk !== false ? self::MEDIUM : self::LOW;
    }
}
