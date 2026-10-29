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
    ];

    /** For .htaccess files found in folders where nothing should run. */
    public const HTACCESS_DATA = [
        'htaccess_php_handler' => [self::HIGH, '/^\s*(?:AddHandler|SetHandler|AddType)\s+[^\n#]*(?:php|x-httpd)/mi'],
        'htaccess_prepend'     => [self::HIGH, '/^\s*php_value\s+auto_(?:prepend|append)_file\b/mi'],
    ];

    /** For any .htaccess. */
    public const HTACCESS_ANY = [
        'htaccess_prepend' => [self::MEDIUM, '/^\s*php_value\s+auto_(?:prepend|append)_file\b/mi'],
    ];

    /** A PHP open tag inside a file that claims to be an image or a document. */
    public const PHP_IN_IMAGE = '/<\?(?:php|=)/i';

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
