<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Maps {@see ScoreCalculator}'s output to the "health" shape the Colorpack Site Manager
 * integration expects (docs/shield-integration.md, S6): `ok/warn/bad` -> `pass/should_fix/must_fix`.
 *
 * Titles and details are fixed Thai text ("ข้อความภาษาไทยที่คนไม่ใช่สายเทคนิคอ่านเข้าใจ" - the spec
 * requires Thai regardless of the administrator's own chosen UI language), mirrored from this
 * component's own th-TH language file rather than loaded through Joomla's Language class, so the
 * output never depends on which language the viewer happens to have selected. Keep these strings
 * in sync with `COM_COLORPACK_SHIELD_ITEM_*` in `com_colorpack_shield/admin/language/th-TH/com_colorpack_shield.ini`
 * if that file's wording changes.
 *
 * `unknown` items are left out entirely - there is no honest pass/should_fix/must_fix equivalent
 * for "not tested yet", and {@see ScoreCalculator} already excludes them from the score itself.
 */
final class HealthReport
{
    private const MAX_ITEMS = 80;

    /** Ids that already have a one-click "open the right settings field" action on the Dashboard. */
    private const AUTOFIXABLE = ['admin_login', 'shields', 'coverage', 'rate_limit'];

    private const TITLE = [
        'protection'        => 'ระบบป้องกันเปิดอยู่',
        'real_ip'           => 'IP จริงของผู้เข้าชม',
        'cloudflare_ranges' => 'รายชื่อ IP ของ Cloudflare',
        'lockout_safety'    => 'กันตัวเองถูกล็อกออก',
        'shields'           => 'การตรวจคำขอที่เข้ามา',
        'coverage'          => 'จุดที่ครอบคลุม',
        'rate_limit'        => 'จำกัดจำนวนคำขอถี่เกินไป',
        'server_rules'      => 'กฎระดับเซิร์ฟเวอร์',
        'admin_login'       => 'การเข้าสู่ระบบหลังบ้าน',
        'admin_door'        => 'ประตูหลังบ้าน',
        'file_scan'         => 'สแกนไฟล์',
    ];

    /** [id][status] => detail text; only warn/bad need one (pass items speak for themselves via the title). */
    private const DETAIL = [
        'protection'        => ['warn' => null, 'bad' => 'ไม่พบตัวป้องกัน หรือถูกปิดอยู่ หรือมีไฟล์ปิดฉุกเฉินทำให้ระบบป้องกันหยุดทำงาน'],
        'real_ip'           => ['warn' => 'ผลทดสอบล่าสุดที่ผ่านนั้นมีอายุเกิน 90 วันแล้ว ควรทดสอบซ้ำอีกครั้ง', 'bad' => 'ผลทดสอบล่าสุดพบว่า มีคนปลอม IP ของตัวเองผ่านทางเว็บนี้ได้'],
        'cloudflare_ranges' => ['warn' => 'ยังใช้รายชื่อเดิมที่ติดมากับปลั๊กอิน หรือรายชื่อที่เคยอัปเดตไว้เก่าเกิน 30 วันแล้ว', 'bad' => null],
        'lockout_safety'    => ['warn' => 'ยังขาดตัวช่วยอย่างหนึ่งจากสองอย่าง คือ IP ที่เชื่อถือได้ หรือรหัสลับสำหรับปิดฉุกเฉิน', 'bad' => 'ยังไม่มีทั้ง IP ที่เชื่อถือได้และรหัสลับฉุกเฉินเลย ถ้าตั้งค่าผิดอาจเข้าเว็บตัวเองไม่ได้'],
        'shields'           => ['warn' => 'มีการตรวจบางด้านถูกปิดอยู่', 'bad' => 'การตรวจทุกด้านถูกปิดอยู่'],
        'coverage'          => ['warn' => 'มีบางจุดที่ยังไม่ครอบคลุม', 'bad' => 'ยังไม่ครอบคลุมจุดใดเลย'],
        'rate_limit'        => ['warn' => 'ปิดอยู่ ถ้าเว็บถูกยิงคำขอรัว ๆ บ่อย ๆ ควรเปิดใช้งาน', 'bad' => 'เปิดอยู่ แต่เซิร์ฟเวอร์นี้ไม่มี APCu จึงนับไม่ได้ และฟีเจอร์นี้ไม่ทำงานจริง'],
        'server_rules'      => ['warn' => null, 'bad' => 'เว็บเซิร์ฟเวอร์ยังส่งไฟล์ที่ควรปฏิเสธออกไปให้คนนอกอยู่'],
        'admin_login'       => ['warn' => 'เปิดระบบล็อกเมื่อใส่รหัสผิดบ่อยแล้ว แต่ยังไม่ได้บังคับยืนยันตัวตนสองขั้นตอน', 'bad' => 'ยังไม่ได้เปิดระบบล็อกเมื่อใส่รหัสผิดบ่อย'],
        'admin_door'        => ['warn' => 'ตอนนี้ใครก็เปิดหน้าล็อกอินหลังบ้านเห็นได้', 'bad' => null],
        'file_scan'         => ['warn' => 'สแกนล่าสุดผ่านมาเกิน 30 วันแล้ว ควรสแกนซ้ำอีกครั้ง', 'bad' => 'สแกนล่าสุดพบสิ่งร้ายแรง กรุณาเปิดหน้าสแกนไฟล์เพื่อดูรายละเอียด'],
    ];

    /**
     * @param  array{score:?int,items:array<int,array{id:string,weight:int,status:string}>}  $score  {@see ScoreCalculator::calculate()}'s output
     *
     * @return array{shield_version:string,score:?int,items:array<int,array{key:string,status:string,title:string,detail?:string,can_autofix?:bool}>}
     */
    public static function build(array $score, string $shieldVersion): array
    {
        $items = [];

        foreach ($score['items'] as $it) {
            if (\count($items) >= self::MAX_ITEMS) {
                break;
            }

            $status = match ($it['status']) {
                'ok'    => 'pass',
                'warn'  => 'should_fix',
                'bad'   => 'must_fix',
                default => null, // 'unknown' (or anything unrecognised): no honest equivalent, omit
            };

            if ($status === null) {
                continue;
            }

            $row = ['key' => $it['id'], 'status' => $status, 'title' => self::TITLE[$it['id']] ?? $it['id']];

            $detail = self::DETAIL[$it['id']][$it['status']] ?? null;

            if ($detail !== null) {
                $row['detail'] = $detail;
            }

            if (\in_array($it['id'], self::AUTOFIXABLE, true)) {
                $row['can_autofix'] = true;
            }

            $items[] = $row;
        }

        return ['shield_version' => $shieldVersion, 'score' => $score['score'], 'items' => $items];
    }
}
