<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Server-side request forgery signatures: a request value that points the server at itself, at the
 * private network, at a cloud metadata service, or uses a scheme only an attacker would ask for.
 *
 * An internal address only counts when it is the start of the value (a URL parameter), so text that
 * merely mentions 127.0.0.1 is left alone.
 */
final class SsrfShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'ssrf';
    }

    protected function patterns(): array
    {
        return [
            'internal_url'     => '~^\s*(?:https?|ftp)://(?:[^/@\s]*@)?(?:localhost|0\.0\.0\.0|0x7f[0-9a-f]*|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|\[(?:::1?|::ffff:[0-9a-f.:]+)\])(?::\d+)?(?:[/?#]|$)~',
            'metadata_service' => '~169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254~',
            'risky_scheme'     => '~\b(?:gopher|dict|tftp|ldap|ldaps|sftp|jar|netdoc)://~',
            'file_scheme'      => '~\bfile:///?[a-z]~',
        ];
    }
}
