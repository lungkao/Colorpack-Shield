<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\SiteManager;

use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\Scanner\ScanStore;

defined('ABSPATH') || die;

/** The site's health items for the Site Manager (Thai wording, plain language): pass / should_fix / must_fix. */
final class Health
{
    /** @return array{score:?int,items:array<int,array<string,mixed>>,shield_version:string} */
    public static function build(): array
    {
        $cfg   = Settings::get();
        $items = [];
        $add   = static function (string $key, string $status, string $title, string $detail = '', string $fix = '', bool $auto = false) use (&$items): void {
            $items[] = ['key' => $key, 'status' => $status, 'title' => $title] + ($detail !== '' ? ['detail' => $detail] : []) + ($fix !== '' ? ['fix' => $fix] : []) + ['can_autofix' => $auto];
        };

        $cfg['login_protect_enabled'] && $cfg['login_lockout']
            ? $add('lockout', 'pass', 'ล็อกบัญชีเมื่อถูกเดารหัส เปิดอยู่')
            : $add('lockout', 'must_fix', 'ยังไม่ล็อกบัญชีเมื่อถูกเดารหัส', 'ผู้โจมตีลองรหัสผ่านได้ไม่จำกัดครั้ง', 'เปิด “การป้องกันการเข้าสู่ระบบ” ในหน้าตั้งค่า Colorpack Shield');

        $cfg['waf_enabled']
            ? $add('waf', 'pass', 'ไฟร์วอลล์ปิดกั้นคำขอที่เป็นอันตราย เปิดอยู่')
            : $add('waf', 'should_fix', 'ไฟร์วอลล์ยังปิดอยู่', 'ยังไม่ตรวจและปิดกั้นคำขอที่เป็นอันตราย', 'เปิด “ไฟร์วอลล์” ในหน้าตั้งค่า Colorpack Shield');

        (defined('WP_DEBUG') && WP_DEBUG && (!defined('WP_DEBUG_DISPLAY') || WP_DEBUG_DISPLAY))
            ? $add('debug', 'must_fix', 'เปิดโหมด Debug และแสดงข้อผิดพลาดอยู่', 'แสดงข้อมูลภายในของเว็บให้ผู้เข้าชม', 'ตั้ง WP_DEBUG เป็น false ใน wp-config.php')
            : $add('debug', 'pass', 'ปิดการแสดงข้อผิดพลาดต่อผู้เข้าชม');

        is_ssl() || str_starts_with((string) home_url(), 'https://')
            ? $add('https', 'pass', 'เว็บใช้ HTTPS')
            : $add('https', 'must_fix', 'เว็บยังไม่ใช้ HTTPS', 'ข้อมูลและรหัสผ่านวิ่งผ่านเครือข่ายแบบไม่เข้ารหัส', 'เปิดใช้ใบรับรอง SSL และตั้งที่อยู่เว็บเป็น https');

        get_user_by('login', 'admin')
            ? $add('admin_user', 'should_fix', 'มีผู้ใช้ชื่อ “admin”', 'ชื่อนี้ถูกเดารหัสบ่อยที่สุด', 'สร้างผู้ดูแลชื่อใหม่แล้วลบบัญชี admin')
            : $add('admin_user', 'pass', 'ไม่มีผู้ใช้ชื่อ “admin”');

        defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT
            ? $add('file_edit', 'pass', 'ปิดการแก้ไขไฟล์ธีม/ปลั๊กอินจากหลังบ้าน')
            : $add('file_edit', 'should_fix', 'ยังแก้ไฟล์ธีม/ปลั๊กอินจากหลังบ้านได้', 'ถ้าบัญชีผู้ดูแลถูกยึด ผู้โจมตีฝังโค้ดได้ทันที', "เพิ่ม define('DISALLOW_FILE_EDIT', true); ใน wp-config.php");

        PHP_VERSION_ID >= 80100
            ? $add('php', 'pass', 'ใช้ PHP รุ่นที่ยังได้รับการสนับสนุน')
            : $add('php', PHP_VERSION_ID >= 80000 ? 'should_fix' : 'must_fix', 'PHP รุ่นเก่า (' . PHP_VERSION . ')', 'รุ่นเก่าไม่ได้รับแพตช์ความปลอดภัย', 'ให้โฮสต์เปลี่ยนเป็น PHP 8.2 ขึ้นไป');

        $scan = (new ScanStore(trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/scan'))->read('result');
        $at   = is_array($scan) ? (int) ($scan['finished'] ?? 0) : 0;
        $age  = $at > 0 ? (time() - $at) / 86400 : null;
        $high = is_array($scan) ? (int) ($scan['count']['high'] ?? 0) : 0;

        if ($high > 0) {
            $add('scan', 'must_fix', "สแกนไฟล์พบไฟล์น่าสงสัยระดับสูง $high ไฟล์", 'อาจเป็นโค้ดอันตรายที่ถูกฝังไว้', 'เปิดหน้า Colorpack Shield › Files แล้วตรวจรายการ');
        } elseif ($age === null || $age > 14) {
            $add('scan', 'should_fix', 'ยังไม่ได้สแกนไฟล์ในช่วง 14 วันที่ผ่านมา', '', 'เปิดหน้า Colorpack Shield › Files แล้วกดสแกน');
        } else {
            $add('scan', 'pass', 'สแกนไฟล์ล่าสุดไม่พบไฟล์น่าสงสัยระดับสูง');
        }

        return ['shield_version' => COLORPACK_SHIELD_WP_VERSION, 'score' => null, 'items' => $items];
    }
}
