<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf\Shield;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Operating-system command injection signatures.
 *
 * A bare word such as "id" or "cat" is ordinary text, so a command only counts when it follows a
 * shell separator AND is followed by an option, a path, a variable or the end of the value
 * ("; ls -la", "| whoami"), or when it is wrapped in $(...) or backticks.
 */
final class CmdiShield extends AbstractRegexShield
{
    public function id(): string
    {
        return 'cmdi';
    }

    protected function patterns(): array
    {
        $cmd = '(?:cat|ls|id|whoami|uname|pwd|ifconfig|ping|wget|curl|nc|ncat|netcat|bash|sh|zsh|python3?|perl|php|powershell|sleep)';

        return [
            'chained_command'  => '~(?:;|\|\|?|&&|\n|`)\s*' . $cmd . '(?:\s+(?:-{1,2}\w|[/\~$.][\w/.\~-]*)|\s*(?:$|[;&|`]))~',
            'command_subst'    => '~\$\(\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|echo|sleep|ping)\b~',
            'backtick_command' => '~`\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|sleep|ping)\b[^`]{0,100}`~',
            'shell_path'       => '~/(?:usr/)?bin/(?:ba|z|da|k)?sh\b|/bin/(?:nc|ncat|netcat)\b~',
            'download_exec'    => '~\b(?:wget|curl)\b[^|;]{0,200}\|\s*(?:ba)?sh\b~',
            'reverse_shell'    => '~bash\s+-i\s*>&|/dev/tcp/\d|\bnc\s+-[a-z]*e\s~',
            'ifs_evasion'      => '~\$\{?ifs\}?~',
        ];
    }
}
