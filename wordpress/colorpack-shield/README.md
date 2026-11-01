<div align="center">

# Colorpack Shield for WordPress

**The WordPress port of [Colorpack Shield](https://github.com/lungkao/Colorpack-Shield) — WAF core + AI advisor + admin login protection + a full file scanner + a dashboard + MFA wired up, not ready for a real site yet.**

[![Status](https://img.shields.io/badge/status-waf%20%2B%20ai%20%2B%20login--protect%20%2B%20scan%20%2B%20dashboard%20%2B%20mfa-orange)](CHANGELOG.md)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-1f5fa8)](LICENSE.txt)
[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-1f5fa8)](https://wordpress.org)

[English](#english) · [ภาษาไทย](#ภาษาไทย)

</div>

---

## English

### Status

**The WAF core is ported and tested, and the Gemini AI advisor is now wired up — both still off by
default.** Activate the plugin, then go to **Colorpack Shield > Settings** in `wp-admin` to turn
protection on (the old `colorpack_shield_waf_enabled` filter from `wp-config.php`/a mu-plugin
still works too, as an override on top of the stored setting):

```php
add_filter('colorpack_shield_waf_enabled', '__return_true');
```

With WAF protection on, every request (front end and `wp-admin`) is inspected for SQL injection,
XSS, local/remote file inclusion, and suspicious paths/headers before WordPress routes it; a
blocking hit is refused with a plain 403 and recorded to a structured log
(`wp-content/uploads/colorpack-shield/activity.log`).

**Colorpack Shield > Activity** lists that log, and - once Gemini is enabled with your own API key
on the Settings screen - an "Analyze with AI" button explains what happened, in your own WordPress
profile language, the same way the Joomla edition's Activity screen does (a single latest result,
not a history list; no scheduled digest here yet).

**Admin login protection** (also off by default, its own Settings card) locks out an address after
repeated failed logins, limits login attempts per minute, and - advanced, with an on-screen
lockout-risk warning - an access-key "door" that can gate `wp-login.php`/`wp-admin` behind
`?cpskey=...` and/or a listed address.

**Colorpack Shield > Files** runs a chunked, resumable backdoor/web-shell scan and lists what it
finds (name/location/content signatures). Each finding can be viewed/edited in a dialog (a
`PhpSyntax` check runs before saving, with an explicit override), marked safe, or deleted
(confirm-by-typing-the-filename) - alone or in bulk - with a copy kept automatically before any
change and a "Copies kept before a change" section to restore or discard them. An optional
WP-Cron background scan (off by default) runs twice a day and emails the site admin about new
high-severity findings.

**Colorpack Shield > Dashboard** (now the first/top-level menu item) shows a plain-language score
ring plus an ordered "worth doing next" list, built from the same facts as the screens above -
whether the WAF is on, whether login lock-out is on, whether the admin door is set up, and the
last file scan's result and age. Only what this port can genuinely verify is counted; an untested
item is shown grey, never scored as good or bad.

**Colorpack Shield > MFA** sets up this port's own TOTP second factor (compatible with Google
Authenticator and any standard TOTP app) - always reachable, for any administrator, regardless of
the site-wide policy. Once confirmed, it is required at that administrator's own login; the
**Settings > Two-Factor Authentication** card only controls whether (and how firmly, after what
grace period) administrators who have *not* enrolled are reminded.

### Plan

Same design goals as the Joomla edition — a generic request firewall, admin login protection,
and a file-integrity scanner, built for ordinary shared hosting (no server administrator rights,
maybe no shell) — ported in this order:

1. **WAF core** (SQL injection / XSS / local & remote file inclusion, path and header
   inspection) — **done.** Ported from the Joomla edition's WAF classes
   (`pkg_colorpack_shield/plugins/system/colorpack_shield/src/Waf/`), which were already plain PHP
   with no Joomla dependency. The path/header location rules (`src/Waf/Rules/PathRules.php`) were
   rewritten for WordPress's own folder layout — `wp-admin`, `wp-content`, `wp-includes`,
   `wp-login.php`, and `wp-json` are this platform's real paths and are never treated as scanner
   probes, unlike on the Joomla edition where those same paths indicate a misdirected bot.
2. **Admin login protection** — **done.** Lock-out after repeated failed logins, a login speed
   limit, and the access-key "door" (`AdminProtect/`, ported from the Joomla edition - 12 of its
   14 classes needed only a namespace swap, no Joomla dependency to begin with). New-admin/
   promotion alerts are wired too (`AdminChangeDetector`, re-worked for WordPress's string role
   slugs instead of Joomla's integer group ids - the algorithm carries over unchanged).
3. **File scanner** — **done.** The same backdoor/web-shell signature scan, adapted to
   WordPress's folder layout (`wp-content/plugins`, `wp-content/uploads`, etc. instead of
   Joomla's `images/`/`administrator/`/`cache/`), plus the full action surface - view/edit with a
   `PhpSyntax` check, delete, bulk actions, quarantine/restore, and an optional WP-Cron background
   scan. Porting it surfaced a real false-positive bug in `SignatureRules::PHP_IN_IMAGE` shared
   with the Joomla edition (fixed there too, 0.10.7) and a request-dispatch bug in the bulk-action
   form (two different `action` values on one request) - both confirmed and fixed by running real
   scans/actions against a real WordPress install before calling each round done, not just against
   synthetic test fixtures. Not ported: a syntax-highlighting editor (plain `<textarea>` only) and
   accepting a scan as a new baseline/diff view (`FileScanner` already supports this, unused).
4. **Dashboard** — **done.** A `wp-admin` score/overview page (now the top-level menu item),
   plain-language explanations over raw numbers. Not a port of the Joomla edition's 11-item
   `ScoreCalculator` - four of its items score subsystems this port never built (no real-IP prober,
   no rate limiter, no server-rule checker) and two more are redundant here (this port's WAF has
   one `waf_enabled` switch, not Joomla's per-shield/per-scope toggles) - so a new, WordPress-
   specific `ScoreCalculator` scores only the 4 items this port genuinely has independent signals
   for. `DashboardPlanner` (the pure ranking/banding logic behind "what to fix next") is ported
   as-is from the Joomla edition.
5. **MFA** — **done.** A self-contained TOTP second factor (`Mfa\Totp`), not a bridge to a host
   API the way the Joomla edition's `JoomlaMfaGateway` is - WordPress has nothing of its own to
   bridge to, so this port ships its own: a **Colorpack Shield > MFA** screen (set up, confirm,
   regenerate backup codes, disable - always reachable, self-service, independent of policy), a
   login-time challenge, and a Settings policy (off/warn/enforce, with a grace period) for
   administrators who have not enrolled, reusing `AdminProtect\MfaPolicy` (ported in an earlier
   round, wired up for the first time here).

Nothing here is a commitment to exact parity with the Joomla edition on day one — each phase
lands as its own, fully tested round, the same way every Joomla-edition feature has. There is no
remaining gap from the Joomla edition's own AdminProtect feature set at this point.

### Requirements (planned)

- WordPress 6.0+
- PHP 8.1+ (matches the Joomla edition, so the ported WAF code can be reused close to as-is)

### Development

No build step and no Composer `vendor/` to install — classes autoload via a small PSR-4-style
loader registered in `colorpack-shield.php`, under the namespace `Colorpack\WP\ColorpackShield\`,
mapped to `src/`. This mirrors the Joomla edition's own manual-autoloader convention in its test
harness, kept deliberately dependency-free so the shipped zip stays self-contained on shared
hosting.

### License

GNU General Public License v3.0 or later — see [LICENSE.txt](LICENSE.txt).

---

## ภาษาไทย

### สถานะ

**แกนหลักของ WAF, ตัวช่วย AI Gemini, และระบบป้องกันการล็อกอินแอดมิน ย้ายมาและใช้งานได้จริงแล้ว — ทุกอย่างยังปิดอยู่โดยปริยาย (off by default)** เปิดใช้งาน (Activate) ปลั๊กอินแล้วเข้าเมนู
**Colorpack Shield > Settings** ใน `wp-admin` เพื่อเปิดระบบป้องกันแต่ละตัว (filter เดิมจาก
`wp-config.php`/mu-plugin ยังใช้ได้เหมือนเดิม เป็นตัว override ทับค่าที่บันทึกไว้):

```php
add_filter('colorpack_shield_waf_enabled', '__return_true');
```

เมื่อเปิด WAF แล้ว ทุก request (ทั้งหน้าเว็บทั่วไปและ `wp-admin`) จะถูกตรวจหา SQL injection, XSS,
การรวมไฟล์จากภายใน-ภายนอก, และ path/header ที่น่าสงสัย ก่อนที่ WordPress จะ route คำขอนั้น
คำขอที่โดนบล็อกจะได้รับ 403 ธรรมดา และถูกบันทึกลง log แบบมีโครงสร้าง
(`wp-content/uploads/colorpack-shield/activity.log`)

**Colorpack Shield > Activity** แสดง log นั้น และเมื่อเปิด Gemini พร้อมใส่ API key ของตัวเองแล้ว
ปุ่ม "Analyze with AI" จะอธิบายเหตุการณ์ด้วยภาษาที่ใช้งาน wp-admin ของแอดมินเอง (ยังไม่มี history
list หรือสรุปผลอัตโนมัติตามรอบเวลาในฝั่งนี้)

**ระบบป้องกันการล็อกอินแอดมิน** (ปิดอยู่โดยปริยายเช่นกัน มีการ์ดตั้งค่าของตัวเอง) ล็อกเอาท์ที่อยู่
หลังลองรหัสผิดซ้ำๆ, จำกัดจำนวนครั้งล็อกอินต่อนาที และ (ขั้นสูง พร้อมคำเตือนความเสี่ยงล็อกตัวเองออก
บนหน้าจอ) "ประตู" กุญแจเข้าถึงที่ปิดกั้น `wp-login.php`/`wp-admin` ด้วย `?cpskey=...` และ/หรือ
รายชื่อที่อยู่ที่อนุญาต ยังไม่มีตัวสแกนไฟล์และหน้าแดชบอร์ดคะแนนรวม — ดู **แผนงาน** ด้านล่าง

### แผนงาน

เป้าหมายการออกแบบเดียวกันกับเวอร์ชัน Joomla — ไฟร์วอลล์ป้องกันคำขอแบบทั่วไป, การป้องกันหน้าล็อกอินแอดมิน,
และตัวสแกนตรวจสอบความถูกต้องของไฟล์ ออกแบบมาเพื่อ shared hosting ทั่วไป (ไม่มีสิทธิ์ผู้ดูแลเซิร์ฟเวอร์
อาจไม่มี shell) — จะทำตามลำดับนี้:

1. **แกนหลัก WAF** (SQL injection / XSS / การรวมไฟล์จากภายใน-ภายนอก, ตรวจ path และ header) —
   **เสร็จแล้ว** ย้ายมาจากคลาส WAF ของเวอร์ชัน Joomla
   (`pkg_colorpack_shield/plugins/system/colorpack_shield/src/Waf/`) ซึ่งเป็น PHP ธรรมดาไม่ผูกกับ
   Joomla อยู่แล้ว ส่วนกฎตรวจ path/header ตามตำแหน่งไฟล์ (`src/Waf/Rules/PathRules.php`)
   เขียนใหม่ให้ตรงกับโครงสร้างโฟลเดอร์ของ WordPress — `wp-admin`, `wp-content`, `wp-includes`,
   `wp-login.php`, และ `wp-json` คือ path จริงของแพลตฟอร์มนี้ จึงไม่ถูกมองว่าเป็น scanner probe
   ต่างจากเวอร์ชัน Joomla ที่ path เดียวกันนี้บ่งบอกว่าเป็นบอทที่สแกนผิดเว็บ
2. **ป้องกันล็อกอินแอดมิน** — **เสร็จแล้ว** ล็อกเอาท์เมื่อลองรหัสผิดซ้ำๆ, จำกัดความเร็วการล็อกอิน,
   และ "ประตู" กุญแจเข้าถึง (`AdminProtect/` ย้ายมาจากเวอร์ชัน Joomla — 12 จาก 14 คลาสแค่สลับ
   namespace ก็ใช้ได้เลย เพราะไม่ผูกกับ Joomla อยู่แล้ว) รวมถึงการแจ้งเตือนแอดมินใหม่/เลื่อนขั้นแล้ว
   (`AdminChangeDetector` ปรับให้ใช้ role แบบ string ของ WordPress แทน group id แบบ Joomla)
3. **สแกนไฟล์** — **เสร็จแล้ว** สแกนหาแบ็คดอร์/เว็บเชลล์แบบเดียวกัน ปรับให้เข้ากับโครงสร้างโฟลเดอร์ของ
   WordPress (`wp-content/plugins`, `wp-content/uploads` ฯลฯ แทนโครงสร้างของ Joomla) พร้อมดู/แก้ไข/
   ลบ/กักกัน/กู้คืนไฟล์ และสแกนตามตารางเวลาผ่าน WP-Cron
4. **หน้าแดชบอร์ด** — **เสร็จแล้ว** หน้าคะแนนความปลอดภัยและรายการ "สิ่งที่ควรทำต่อ" เป็นเมนูบนสุด
5. **MFA** — **เสร็จแล้ว** รหัสยืนยันตัวตนสองชั้นแบบ TOTP ของปลั๊กอินเอง (ไม่พึ่ง API ของ WordPress
   เพราะ WordPress เองไม่มีระบบ MFA ในตัว) เปิดใช้ได้เองที่เมนู MFA พร้อมรหัสสำรองใช้ครั้งเดียว และ
   นโยบายเตือน/บังคับสำหรับแอดมินที่ยังไม่ได้ตั้งค่าในหน้า Settings

ไม่มีข้อผูกมัดว่าต้องเหมือนเวอร์ชัน Joomla ทุกอย่างตั้งแต่วันแรก — แต่ละเฟสจะทยอยออกเป็นรอบของตัวเอง
ทดสอบครบเหมือนที่ทำกับทุกฟีเจอร์ของเวอร์ชัน Joomla

### ความต้องการของระบบ (ตามแผน)

- WordPress 6.0 ขึ้นไป
- PHP 8.1 ขึ้นไป (ให้ตรงกับเวอร์ชัน Joomla เพื่อย้ายโค้ด WAF มาใช้ได้โดยแก้น้อยที่สุด)

### การพัฒนา

ไม่มีขั้นตอน build และไม่ต้องติดตั้ง Composer `vendor/` — คลาสต่างๆ โหลดอัตโนมัติผ่าน autoloader
สไตล์ PSR-4 เล็กๆ ที่ลงทะเบียนไว้ใน `colorpack-shield.php` ภายใต้ namespace
`Colorpack\WP\ColorpackShield\` ชี้ไปที่ `src/` ซึ่งเป็นแนวทางเดียวกับที่เวอร์ชัน Joomla ใช้ใน
test harness ของตัวเอง ตั้งใจให้ไม่มี dependency ภายนอกเลย เพื่อให้ไฟล์ zip ที่แจกออกไปใช้งานได้ครบ
ในตัวบน shared hosting

### สัญญาอนุญาต

GNU General Public License v3.0 หรือใหม่กว่า — ดู [LICENSE.txt](LICENSE.txt)
