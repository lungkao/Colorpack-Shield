<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Waf;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * What a blocked visitor is shown: a short reference code and what to do with it.
 *
 * Deliberately says nothing about the product, the rule or the field that matched, so a scanner learns
 * nothing it did not already know (a 403). The code is also written to the Activity log, which is where
 * the site administrator finds the rule and can allow it for that one field.
 */
final class BlockPage
{
    /** A new 8-character code, e.g. 8F3A2C1D. */
    public static function newRef(): string
    {
        try {
            return strtoupper(bin2hex(random_bytes(4)));
        } catch (\Throwable) {
            return strtoupper(substr(md5(uniqid('', true)), 0, 8));
        }
    }

    public static function isRef(string $text): bool
    {
        return preg_match('/^[0-9A-F]{8}$/', $text) === 1;
    }

    public static function wantsHtml(string $accept): bool
    {
        return stripos($accept, 'text/html') !== false;
    }

    public static function text(string $ref): string
    {
        return "Forbidden\nReference: " . $ref . "\n";
    }

    public static function html(string $ref): string
    {
        $ref = htmlspecialchars($ref, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<meta name="robots" content="noindex,nofollow"><title>403</title>'
            . '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8;color:#16202a;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}'
            . 'main{max-width:34rem;margin:1.5rem;padding:1.75rem 2rem;background:#fff;border:1px solid #d8dee4;border-radius:12px}'
            . 'h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:.5rem 0}code{display:inline-block;padding:.15rem .6rem;border-radius:6px;background:#eef1f4;font:600 1.15rem/1.6 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.06em}'
            . '.s{color:#5a6773;font-size:.9rem}</style></head><body><main>'
            . '<h1>Request blocked / คำขอนี้ถูกบล็อก</h1>'
            . '<p>This request was blocked by the website\'s firewall. If you think this is a mistake, tell the site administrator this reference:</p>'
            . '<p>คำขอนี้ถูกบล็อกโดยไฟร์วอลล์ของเว็บไซต์ ถ้าคิดว่าผิดพลาด โปรดแจ้งผู้ดูแลเว็บไซต์พร้อมรหัสอ้างอิงนี้</p>'
            . '<p><code>' . $ref . '</code></p>'
            . '<p class="s">Site administrators: search this reference in the firewall\'s activity log to see what matched, and allow it for that one field if it is legitimate. / ผู้ดูแลเว็บ: ค้นรหัสนี้ในหน้า Activity ของไฟร์วอลล์ เพื่อดูว่าอะไรถูกจับ และอนุญาตเฉพาะช่องนั้นถ้าเป็นการใช้งานปกติ</p>'
            . '</main></body></html>';
    }
}
