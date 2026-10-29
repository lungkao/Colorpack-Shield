<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Waf;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Immutable verdict for one uploaded file that failed the {@see UploadScanner}.
 *
 * $reason is a stable machine token (e.g. "double_extension") for the log; the
 * human-readable "why" is derived from it. $detail carries the specific offender
 * (the bad extension, the real MIME, the matched marker) for triage.
 */
final class UploadThreat
{
    public function __construct(
        public readonly string $file,
        public readonly string $reason,
        public readonly string $detail = ''
    ) {
    }
}
