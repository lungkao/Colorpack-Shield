<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Rules;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * The single table behind URL-path inspection: rule id, class, default mode
 * and pattern.
 *
 * Classes: A integrity (see PathNormalizer), B injection, C PHP execution in
 * upload/cache folders, D direct PHP in plugin/theme/core-includes code
 * folders, E WordPress leftovers (wp-config backups, dumps, logs), F foreign
 * scanner probes.
 *
 * Unlike the Joomla edition, wp-admin/wp-content/wp-includes/wp-login.php/
 * wp-json are this platform's OWN real paths, not signs of a misdirected
 * scanner — they are never treated as probes here. Class F instead looks for
 * signatures of OTHER software (phpMyAdmin, other CMSes, generic webshells,
 * infra scanners) that have no legitimate reason to exist on a WordPress site.
 *
 * Defaults: A traversal / control bytes / overlong UTF-8 and all of B block;
 * everything else is log-only until real traffic shows it is safe to promote
 * (same conservative default as the Joomla edition).
 */
final class PathRules
{
    public const CLASS_A = 'A';
    public const CLASS_B = 'B';
    public const CLASS_C = 'C';
    public const CLASS_D = 'D';
    public const CLASS_E = 'E';
    public const CLASS_F = 'F';

    /** Rule id => [class, default mode]. */
    public const RULES = [
        // A — integrity flags raised by PathNormalizer
        'path_traversal'       => [self::CLASS_A, 'block'],
        'path_ctrl'            => [self::CLASS_A, 'block'],
        'path_overlong_utf8'   => [self::CLASS_A, 'block'],
        'path_param_trick'     => [self::CLASS_A, 'log'],
        'path_double_encoded'  => [self::CLASS_A, 'log'],
        'path_bad_utf8'        => [self::CLASS_A, 'log'],
        'path_backslash'       => [self::CLASS_A, 'log'],
        'path_double_slash'    => [self::CLASS_A, 'log'],
        'path_oversize'        => [self::CLASS_A, 'log'],
        // B — injection
        'path_php_tag'         => [self::CLASS_B, 'block'],
        'path_jndi'            => [self::CLASS_B, 'block'],
        'path_wrapper'         => [self::CLASS_B, 'block'],
        'path_sqli'            => [self::CLASS_B, 'block'],
        'path_xss'             => [self::CLASS_B, 'block'],
        // C–F — location based
        'php_in_data_dir'      => [self::CLASS_C, 'log'],
        'direct_php_in_code'   => [self::CLASS_D, 'log'],
        'wp_leftover'          => [self::CLASS_E, 'log'],
        'scanner_probe'        => [self::CLASS_F, 'log'],
        'admin_tool_probe'     => [self::CLASS_F, 'log'],
        // operator's own deny list
        'path_extra_deny'      => [self::CLASS_C, 'block'],
    ];

    /**
     * Folders in which no PHP file should ever be requested (class C) — the
     * single most common webshell dropzone on WordPress is an upload path.
     */
    public const DATA_DIRS = 'wp-content/uploads|wp-content/cache|wp-content/upgrade|wp-content/backup[^/]*';

    /** Code folders (class D) — PHP here is the plugin/theme/core code itself. wp-admin is deliberately excluded: its PHP files are legitimate direct entry points. */
    public const CODE_DIRS = 'wp-content/plugins|wp-content/themes|wp-includes';

    /** PHP-type extensions Apache/FPM will hand to the interpreter. */
    public const PHP_EXT = 'php\d*|phtml|phar|pht|phps|inc';

    /** Backup / dump / archive extensions refused at the web root. */
    public const LEFTOVER_ROOT_EXT = 'sql|bak|old|orig|save|swp|zip|tar|gz|tgz|7z|rar';

    /** Log files anywhere. */
    public const LOG_FILES = 'error_log|php_errorlog|debug\.log|[^/]*\.log';

    /** Default tools that live under a site's own domain on DirectAdmin/HestiaCP/cPanel. */
    public const DEFAULT_TOOLS_EXEMPT = ['phpmyadmin', 'webmail', 'roundcube', 'pma'];

    /**
     * Class B: matched against the decoded view (characters as sent, lower-case).
     *
     * @return array<string,string>  rule => PCRE
     */
    public static function injectionPatterns(): array
    {
        return [
            'path_php_tag' => '/<\?(?:php|=)/',
            'path_jndi'    => '/\$\{\s*(?:jndi|lower|upper|env|sys|java|date|ctx|main|bundle|k8s|docker|log4j|spring|sd|web|\$\{|:|-)/',
            'path_wrapper' => '~(?:php|phar|expect|zip|glob|file|input|filter)://|(?:^|[/=\s"\'])(?:javascript|vbscript):|(?:^|[/=\s"\'])data:(?:text|application|image)/~',
            // "--" and quotes are deliberately NOT used: they occur in real slugs and file names.
            'path_sqli'    => '/\bunion[\s\/*+]+(?:all[\s\/*+]+)?select\b|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|;\s*(?:drop|truncate|shutdown)\s|\binformation_schema\b|\b(?:updatexml|extractvalue)\s*\(/',
            'path_xss'     => '/<\s*\/?\s*(?:script|svg|iframe|object|embed)\b|<\s*(?:img|body|details|video|audio|input)[\s\/]|["\'\s]on(?:error|load|click|mouse(?:over|out|enter)|focus|blur|toggle|begin|start|submit|change|key(?:down|up|press)|animation(?:start|end))\s*=/',
        ];
    }

    /**
     * Class C–F patterns, matched against the canonical path.
     *
     * @return array<string,string>  rule => PCRE
     */
    public static function locationPatterns(): array
    {
        return [
            // C: x.php, x.PHP., x.php/extra, x.phtml, and the double-extension trick x.php.jpg
            'php_in_data_dir'    => '~^/(?:' . self::DATA_DIRS . ')/(?:.*/)?[^/]*\.(?:' . self::PHP_EXT . ')(?:\.[a-z0-9]{1,6})?[. ]*(?:/|$)~',
            // D: any direct .php request in a plugin/theme/core-includes folder
            'direct_php_in_code' => '~^/(?:' . self::CODE_DIRS . ')/(?:.*/)?[^/]*\.php\d*[. ]*(?:/|$)~',
            // E: wp-config leftovers/backups, readme/license, and logs anywhere
            'wp_leftover'        => '~^/(?:wp-config(?:-sample)?\.php[^/]*|readme\.html|license\.txt|composer\.(?:json|lock)|package(?:-lock)?\.json|[^/]+\.(?:' . self::LEFTOVER_ROOT_EXT . '))$|(?:^|/)(?:' . self::LOG_FILES . ')$~',
            // F: other-CMS and generic infra/webshell scanners — never this platform's own paths
            'scanner_probe'      => '~(?:^|/)\.[^/]+'
                . '|(?:^|/)(?:administrator|configuration\.php|joomla\.xml)(?:/|$)'
                . '|(?:^|/)(?:sites/default/files|user/login|CHANGELOG\.txt)(?:/|$)'
                . '|(?:^|/)(?:typo3|typo3conf)(?:/|$)'
                . '|(?:^|/)(?:phpinfo|info|test|shell|c99|r57|wso|alfa|adminer|uploader|webshell|bypass|eval)\.php\d*$'
                . '|(?:^|/)vendor/(?:phpunit|composer|bin)(?:/|$)|(?:^|/)vendor/autoload\.php$|(?:^|/)node_modules/'
                . '|(?:^|/)(?:cgi-bin|actuator|jmx-console|web-console|web-inf|meta-inf|server-status|server-info|hnap1|boaform|nmaplowercheck\d*)(?:/|$)'
                . '|(?:^|/)manager/html(?:/|$)|(?:^|/)owa/auth|(?:^|/)ecp/default\.aspx|(?:^|/)autodiscover/autodiscover\.xml|(?:^|/)remote/login(?:/|$)'
                . '|(?:^|/)(?:backup|backups|dump|database|db|www|public_html|website|site|old|bak|html)(?:\.tar)?\.(?:zip|tar|gz|tgz|rar|7z|sql|bak)$'
                . '|\.(?:sql|bak|orig|swp)$|\~$~',
            // F, tools: matched separately so that the operator's exemption list can apply
            'admin_tool_probe'   => '~(?:^|/)(phpmyadmin[^/]*|pma|myadmin|mysqladmin|sqladmin|dbadmin|pgadmin[^/]*|webmail|roundcube[^/]*)(?:/|$)~',
        ];
    }

    /**
     * Never inspected by classes C–F (class A and B always apply). WordPress's
     * own front controller and REST API need no entry: no rule here matches
     * wp-admin, wp-login.php, wp-content, wp-includes, or wp-json.
     *
     * @return string[]  PCRE patterns on the canonical path
     */
    public static function exemptions(): array
    {
        return [
            '~^/\.well-known/~',
            '~^/(?:robots\.txt|sitemap[^/]*\.xml(?:\.gz)?|favicon\.ico|ads\.txt|humans\.txt)$~',
        ];
    }

    /**
     * Legitimate direct requests to PHP files; exempt from classes D and E only.
     * None needed yet on the WordPress side (wp-admin is already excluded from
     * CODE_DIRS, so its own entry points need no separate exemption).
     *
     * @return string[]
     */
    public static function directEntryPoints(): array
    {
        return [];
    }
}
