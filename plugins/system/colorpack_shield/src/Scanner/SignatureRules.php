<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Scanner;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * What the file scanner looks for INSIDE a file. Deliberately a short list of combinations that
 * legitimate Joomla code does not contain (a code-running function fed straight from the request, a
 * decode-then-run chain, well-known web-shell names), not a long treadmill of malware signatures:
 * it finds the common backdoors left by attacks, it does not replace a full anti-virus scan.
 * Every pattern is bounded so that a hostile file cannot make the scan slow.
 */
final class SignatureRules
{
    public const HIGH   = 'high';
    public const MEDIUM = 'medium';
    public const LOW    = 'low';

    /** Rule id => [severity, PCRE]. For PHP-type files. */
    public const PHP = [
        'eval_decode'        => [self::HIGH, '/\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|convert_uudecode|hex2bin)\s*\(/i'],
        'exec_request'       => [self::HIGH, '/\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
        'include_request'    => [self::HIGH, '/\b(?:include|require)(?:_once)?\s*\(?\s*@?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
        'preg_replace_e'     => [self::HIGH, '/preg_replace\s*\(\s*([\'"])[^\'"\n]{1,200}\/[a-z]*e[a-z]*\1\s*,/i'],
        'webshell_name'      => [self::HIGH, '/\b(?:c99shell|r57shell|wso\s*shell|filesman|b374k|alfa\s*shell|indoxploit|weevely|china\s*chopper|php\s*shell\s*by|priv8\s*shell)\b/i'],
        'callback_request'   => [self::MEDIUM, '/\$[a-z_][a-z0-9_]{0,40}\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
        'write_request'      => [self::MEDIUM, '/\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
        'create_function'    => [self::MEDIUM, '/\bcreate_function\s*\(/i'],
        'eval_variable'      => [self::MEDIUM, '/\beval\s*\(\s*\$[a-z_]/i'],
        'long_base64'        => [self::MEDIUM, '/[\'"][A-Za-z0-9+\/]{1500,}={0,2}[\'"]/'],
        'hex_blob'           => [self::MEDIUM, '/(?:\\\\x[0-9a-f]{2}){25,}/i'],
        'chr_chain'          => [self::MEDIUM, '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){10,}/i'],
        // Mined from the PHP Malware Finder ruleset (jvoisin/php-malware-finder, data/php.yar) and
        // re-checked by hand against Joomla 6's own core + extensions (8,500+ files) for zero false
        // positives before being added here - a YARA rule that reads cleanly does not mean it reads
        // cleanly as a plain PCRE against real code; several of theirs (e.g. "${$var}", ini_get()
        // read-only checks) do not survive that check and were left out for that reason.
        'extract_request'    => [self::HIGH, '/\bextract\s*\(\s*@?\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i'],
        'callback_decode'    => [self::HIGH, '/\b(?:array_filter|array_walk(?:_recursive)?|usort|uasort|uksort|preg_replace_callback|iterator_apply|assert_options)\s*\([^,]+,\s*@?[\'"]?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|pack|getenv)\b/i'],
        'unsafe_ini_tamper'  => [self::HIGH, '/\bini_(?:set|restore)\s*\(\s*[\'"](?:safe_mode|open_basedir|disable_functions|disable_classes|safe_mode_exec_dir|safe_mode_include_dir)\b/i'],
        'ld_preload'         => [self::HIGH, '/\bLD_PRELOAD\b/'],
        'exploit_site_ref'   => [self::MEDIUM, '/\b(?:1337day\.com|milw0rm\.com|pentestmonkey\.net|mumaasp\.com|ccteam\.ru|antichat\.ru|darkc0de)\b/i'],
        // Mined from a real incident (asianpa.org, 2026-10-30): every pattern below was verified
        // against the actual malicious files found there - each one evades every rule above by
        // never spelling out the function/superglobal name it needs as a plain substring, instead
        // building it at runtime (octal/hex escapes, XOR, chr(), string concatenation, arithmetic).
        'cookie_superglobal_octal' => [self::HIGH, '/\$\s*\{\s*["\'](?:\\\\(?:1[0-7]{2}|x[0-9a-f]{2}))+["\']/i'],
        'xor_string_obfuscation'   => [self::HIGH, "/(?:'[^'\\n]{6,}'\\s*\\^\\s*\\\$\\w+\\s*;.{0,200}){3}/is"],
        'concat_func_name_exec'    => [self::HIGH, '/\$\w+\s*=\s*["\'][a-z_]{2,}["\']\s*\.\s*["\'][a-z_]{2,}["\'].{0,40}\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/is'],
        'chr_built_eval'           => [self::HIGH, '/chr\s*\(\s*101\s*\)\s*\.\s*["\']val\(|\.\s*chr\s*\(\s*122\s*\)\s*\.\s*["\']inflate/i'],
        'charmap_index_obfuscation'=> [self::HIGH, '/(?:\$\w+\[\w+\]\[\d+\]\s*\.\s*){6,}/'],
        'split_base64_decode'      => [self::HIGH, '/[\'"]base[\'"]\s*\.\s*\(?[\d\s*\/+]+\)?\s*\.\s*[\'"]_de[\'"]|[\'"]ba[\'"]?\s*\.\s*[\'"]se64_d|[\'"]base64_de[\'"]\s*\.\s*[\'"]code[\'"]/i'],
        'upload_probe'             => [self::LOW, '/echo\s+["\']jm["\']\s*\.\s*["\']te["\']/i'],
    ];

    /** For .htaccess files found in folders where nothing should run. */
    public const HTACCESS_DATA = [
        'htaccess_php_handler' => [self::HIGH, '/^\s*(?:AddHandler|SetHandler|AddType)\s+[^\n#]*(?:php|x-httpd)/mi'],
        'htaccess_prepend'     => [self::HIGH, '/^\s*php_value\s+auto_(?:prepend|append)_file\b/mi'],
    ];

    /** For any .htaccess. */
    public const HTACCESS_ANY = [
        'htaccess_prepend' => [self::MEDIUM, '/^\s*php_value\s+auto_(?:prepend|append)_file\b/mi'],
        // Also from the asianpa.org incident: a cloaking rule that rewrites search-engine visitors
        // (by user-agent/referer, or by Googlebot's own address range) to a different PHP file -
        // no legitimate Joomla site or extension does this.
        'seo_cloaking_bot_redirect' => [self::HIGH, '~RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}\s+\(?[^\n]*(?:google|bing|yahoo)[\s\S]{0,2500}RewriteRule\s+\S+\s+/?(?!index\.php)[\w/.-]+\.php~is'],
        'googlebot_ip_condition'    => [self::MEDIUM, '~RewriteCond\s+%\{REMOTE_ADDR\}[^\n]*66\\\\\.249~i'],
    ];

    /**
     * A PHP open tag inside a file that claims to be an image or a document - "<?php", "<?=", or a
     * bare "<?" (the short_open_tag form, still honoured on some shared hosts and deliberately used
     * to dodge a "<?php"-only check), but not an XML prolog ("<?xml").
     *
     * A plain "<?" byte match alone is too weak: compressed binary image data (PNG/WEBP) hits it by
     * pure coincidence often enough to make the rule useless in practice - confirmed while porting
     * this scanner to the WordPress edition, which flagged 14 of wp-admin's, Akismet's, and a
     * bundled theme's own image files as "high severity" with the old pattern (the same regex, so
     * the same weakness applies here). Real hidden PHP is followed by actual PHP syntax, not random
     * bytes, so this now also requires a variable sigil or an identifier-then-"(" shortly after the
     * tag - every real sample (plain "<?php", the short-tag "<? $a=...", and a backdoor appended
     * after 20KB of image data) still matches; no genuine planted backdoor needs anything looser
     * than this to run.
     */
    public const PHP_IN_IMAGE = '/<\?(?!xml\b)(?:php\b)?\s*(?:\$[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\s*\()/i';

    /**
     * @param  array<string,array{0:string,1:string}>  $rules
     *
     * @return string[]  ids of the rules that match
     */
    public static function scan(string $content, array $rules = self::PHP): array
    {
        $hits = [];

        foreach ($rules as $id => [, $pattern]) {
            if (@preg_match($pattern, $content) === 1) {
                $hits[] = $id;
            }
        }

        return $hits;
    }

    /**
     * @param  array<string,array{0:string,1:string}>  $rules
     */
    public static function severity(string $id, array $rules = self::PHP): string
    {
        return ($rules[$id][0] ?? self::LOW);
    }
}
