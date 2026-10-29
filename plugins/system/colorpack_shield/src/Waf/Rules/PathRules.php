<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf\Rules;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * The single table behind URL-path inspection (PLAN-WAF-PATH-P2.md §3.4):
 * rule id, class, default mode and pattern. The future server-config exporter
 * and the admin component read this same table.
 *
 * Classes: A integrity (see PathNormalizer), B injection, C PHP in data folders,
 * D direct PHP in code folders, E Joomla internals / leftovers, F scanner probes.
 *
 * Defaults in this release: A traversal / control bytes / overlong UTF-8 and all
 * of B block; everything else is log-only until real traffic (waf_replay.php)
 * shows it is safe to promote.
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
        'joomla_internal'      => [self::CLASS_E, 'log'],
        'scanner_probe'        => [self::CLASS_F, 'log'],
        'admin_tool_probe'     => [self::CLASS_F, 'log'],
        // operator's own deny list
        'path_extra_deny'      => [self::CLASS_C, 'block'],
    ];

    /** Folders in which no PHP file should ever be requested (class C). */
    public const DATA_DIRS = 'images|tmp|cache|logs|administrator/(?:cache|logs|tmp)';

    /** Code folders (class D). */
    public const CODE_DIRS = 'components|modules|plugins|templates|media|libraries|layouts|language|includes|administrator/(?:components|modules|plugins|templates|language|includes)';

    /** PHP-type extensions Apache/FPM will hand to the interpreter. */
    public const PHP_EXT = 'php\d*|phtml|phar|pht|phps|inc';

    /** Joomla internals at the web root, as a regular expression fragment (server-config exporters). */
    public const LEFTOVER_ROOT_FILES = 'configuration\.php(?:[-~.].*)?|htaccess\.txt|web\.config\.txt|README\.(?:txt|md)|LICENSE\.txt|joomla\.xml|composer\.(?:json|lock)|package(?:-lock)?\.json';

    /** Backup / dump / archive extensions refused at the web root. */
    public const LEFTOVER_ROOT_EXT = 'sql|bak|old|orig|save|swp|zip|tar|gz|tgz|7z|rar';

    /** Log files anywhere. */
    public const LOG_FILES = 'error_log|php_errorlog|[^/]*\.log';

    /** Legitimate direct requests to PHP files (relative to the web root); the server-config exporter uses this list too. */
    public const ENTRY_POINT_FILES = [
        'administrator/components/com_joomlaupdate/extract.php',
        'administrator/components/com_joomlaupdate/restore.php',
        'administrator/components/com_joomlaupdate/finalisation.php',
        'administrator/components/com_akeebabackup/restore.php',
        'administrator/components/com_akeeba/restore.php',
    ];

    /** Default tools that live under a site's own domain on DirectAdmin/HestiaCP. */
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
            // D: any direct .php request in a code folder (exceptions are applied by the shield)
            'direct_php_in_code' => '~^/(?:' . self::CODE_DIRS . ')/(?:.*/)?[^/]*\.php\d*[. ]*(?:/|$)~',
            // E: Joomla internals, leftovers, backups and logs
            'joomla_internal'    => '~^/(?:configuration\.php[^/]*|htaccess\.txt|web\.config\.txt|readme\.(?:txt|md)|license\.txt|joomla\.xml|composer\.(?:json|lock)|package(?:-lock)?\.json|[^/]+\.(?:sql|bak|old|orig|save|swp|zip|tar|gz|tgz|7z|rar))$|^/administrator/manifests/|(?:^|/)(?:error_log|php_errorlog|[^/]*\.log)$~',
            // F: scanners and bots looking for something else
            'scanner_probe'      => '~(?:^|/)\.[^/]+'
                . '|(?:^|/)(?:wp-login\.php|wp-admin|wp-content|wp-includes|wp-json|wp-config\.php|xmlrpc\.php|wlwmanifest\.xml)(?:/|$)'
                . '|(?:^|/)(?:phpinfo|info|test|shell|cmd|c99|r57|wso|alfa|adminer|uploader|webshell|bypass|eval)\.php\d*$'
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
     * Never inspected by classes C–F (class A and B always apply). The Joomla front
     * controllers need no entry: no rule matches them.
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
     *
     * @return string[]
     */
    public static function directEntryPoints(): array
    {
        return ['~^/(?:' . implode('|', array_map(static fn (string $f): string => preg_quote($f, '~'), self::ENTRY_POINT_FILES)) . ')$~'];
    }
}
