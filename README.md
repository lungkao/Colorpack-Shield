<div align="center">

# Colorpack Shield

**Fleet-hardening security for Joomla 4 / 5 / 6 — built for shared hosting.**

[![Version](https://img.shields.io/badge/version-0.10.6-1f5fa8)](CHANGELOG.md)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-1f5fa8)](LICENSE.txt)
[![Joomla](https://img.shields.io/badge/Joomla-4%20%7C%205%20%7C%206-1f5fa8)](https://www.joomla.org)

[English](#english) · [ภาษาไทย](#ภาษาไทย) · [☕ Buy Me a Coffee](https://buymeacoffee.com/cheuachatchai)

</div>

---

## English

### Download

| Platform | |
|---|---|
| **Joomla** 4 / 5 / 6 | [![Download for Joomla](https://img.shields.io/badge/Download-Joomla-1f5fa8?logo=joomla&logoColor=white)](https://github.com/lungkao/Colorpack-Shield/releases/latest) |
| WordPress | _coming soon_ |

`/releases/latest` always points at the newest release — no need to update this link by hand.

### What it is

Colorpack Shield is a Joomla security package: a generic request firewall (WAF), administrator
login protection, and a file-integrity scanner — designed from the start to work on **ordinary
shared hosting**, where you may have no server administrator rights and no shell access. Every
server-level measure it offers is an optional extra; the web screens and the plugin stand on
their own without one.

### Features

- **Web Application Firewall** covering the site, administrator, and API applications: SQL
  injection, XSS, local/remote file inclusion, malformed or hostile HTTP headers, and URL-path
  inspection (traversal, injected code, scanner/CVE probes, foreign-CMS paths).
- **Targeted-attack IP ban**: a request for an old-CVE path, another CMS's files (WordPress's
  `/wp-login.php`, `/xmlrpc.php`, …), or a well-known web-shell name can block *and ban* the
  address outright for a configurable number of hours — built on a file-backed store, so it
  needs no APCu.
- **Administrator protection**: login lock-out with escalating bans, a login speed limit, an
  access-key "door" that 404s the admin login without the right cookie, an administrator address
  list, and alerts on new Super Users or new administrator addresses.
- **File scan**: walks the site in short, resumable steps looking for PHP hidden in images,
  PHP dropped in upload/cache folders, decode-and-run and request-driven code, well-known
  web-shell names, and odd `.htaccess` files. View, edit (with PHP syntax checking), delete, or
  restore a flagged file from quarantine, right from the admin screen. A baseline tracks new,
  changed, and removed PHP files between scans.
- **Rate limiting** (APCu-backed, fails open without it) and **GeoIP** allow/deny, Cloudflare-aware
  real-visitor-address resolution.
- **Shell-free rescue**: every lock-out has an FTP/file-manager way out (`colorpack_shield.disable`,
  `cache/colorpack_shield/gate.off`) — you are never one mistake away from being locked out of
  your own site.
- **Thai and English** as first-class, independent languages: use the component in Thai while
  the Joomla administrator stays in English, or the other way round — a personal choice, not a
  site-wide setting.
- A dashboard with a security score, a prioritized "do next" list, and reports for activity,
  file scan, and back-end login — each with a plain-language explanation, not just a number.

### Requirements

- Joomla 4, 5, or 6
- PHP 8.1+
- No special PHP extensions required (APCu is used opportunistically for rate limiting; the
  plugin works correctly, with that one feature quietly disabled, when it is absent)

### Installation

**Via Joomla's own updater (recommended, from 0.7.1 on):** once you have 0.7.1 or later
installed, Joomla's Extensions → Manage → Update screen finds new versions on its own — no FTP,
no manual download.

**Manual install (first time, or any earlier version):**

1. Download the latest `pkg_colorpack_shield-X.Y.Z.zip` from
   [Releases](https://github.com/lungkao/Colorpack-Shield/releases).
2. Joomla administrator → **System → Install → Extensions**, upload the zip.
3. Open **Components → Colorpack Shield → Quick setup** and follow the steps.

### Documentation

- [CHANGELOG.md](CHANGELOG.md) — every release, in plain language, including what was fixed and why.
- The admin component's own screens (Dashboard, Settings, Activity, File scan, Network & IP,
  Server rules, Tools) carry their own explanations throughout — there is no separate manual.

### License

GNU General Public License v3.0 or later — see [LICENSE.txt](LICENSE.txt).

### Support the project

If Colorpack Shield is protecting a site that matters to you, consider buying the maintainer a
coffee: **[buymeacoffee.com/cheuachatchai](https://buymeacoffee.com/cheuachatchai)**

---

## ภาษาไทย

### ดาวน์โหลด

| แพลตฟอร์ม | |
|---|---|
| **Joomla** 4 / 5 / 6 | [![ดาวน์โหลดสำหรับ Joomla](https://img.shields.io/badge/ดาวน์โหลด-Joomla-1f5fa8?logo=joomla&logoColor=white)](https://github.com/lungkao/Colorpack-Shield/releases/latest) |
| WordPress | _เร็วๆ นี้_ |

ลิงก์ `/releases/latest` จะชี้ไปที่เวอร์ชันล่าสุดเสมอ ไม่ต้องแก้ลิงก์นี้เองทุกครั้งที่ออกเวอร์ชันใหม่

### คืออะไร

Colorpack Shield คือชุดความปลอดภัยสำหรับ Joomla: ไฟร์วอลล์ป้องกันคำขอ (WAF) แบบทั่วไป,
การป้องกันหน้าล็อกอินผู้ดูแลระบบ และตัวสแกนตรวจสอบความถูกต้องของไฟล์ — ออกแบบมาตั้งแต่ต้น
เพื่อใช้งานได้บน **shared hosting ทั่วไป** ที่อาจไม่มีสิทธิ์ผู้ดูแลเซิร์ฟเวอร์และไม่มี shell
มาตรการระดับเซิร์ฟเวอร์ทุกอย่างที่มีให้เป็นเพียงตัวเสริมทางเลือก ตัวปลั๊กอินและหน้าเว็บทำงานได้ครบ
โดยไม่ต้องพึ่งมันเลย

### ฟีเจอร์

- **Web Application Firewall** ครอบคลุมทั้งหน้าเว็บ, ผู้ดูแลระบบ และ API: SQL injection, XSS,
  การรวมไฟล์จากภายใน/ภายนอก (LFI/RFI), header ที่ผิดรูปแบบหรือเป็นอันตราย และการตรวจสอบที่อยู่เว็บ
  (path traversal, โค้ดที่ถูกแทรก, การสอดส่องหาช่องโหว่/CVE เก่า, path ของ CMS อื่น)
- **บล็อกและแบน IP สำหรับการโจมตีที่ตั้งใจ**: คำขอ path ช่องโหว่เก่า, ไฟล์ของ CMS อื่น
  (`/wp-login.php`, `/xmlrpc.php` ของ WordPress ฯลฯ) หรือชื่อเว็บเชลล์ที่รู้จักกันดี
  สามารถบล็อก**และแบน IP นั้นไปเลย**เป็นระยะเวลาที่ตั้งได้ — ใช้ระบบเก็บข้อมูลแบบไฟล์
  จึงไม่ต้องพึ่ง APCu
- **ป้องกันผู้ดูแลระบบ**: ล็อกเอาท์เมื่อลองรหัสผิดซ้ำๆ (เพิ่มเวลาทวีคูณ), จำกัดความเร็วการล็อกอิน,
  "ประตู" กุญแจเข้าถึงที่ทำให้หน้า admin ขึ้น 404 ถ้าไม่มีคุกกี้ที่ถูกต้อง, รายการที่อยู่ผู้ดูแลระบบ,
  และแจ้งเตือนเมื่อมี Super User ใหม่หรือที่อยู่ผู้ดูแลระบบใหม่
- **File scan**: เดินสำรวจทั้งเว็บเป็นขั้นสั้นๆ ที่หยุดพักต่อได้ มองหา PHP ที่ซ่อนในรูปภาพ,
  PHP ที่แอบวางในโฟลเดอร์อัปโหลด/แคช, โค้ดแบบถอดรหัสแล้วรัน, ชื่อเว็บเชลล์ที่รู้จักกันดี และไฟล์
  `.htaccess` ที่ผิดปกติ เปิดดู แก้ไข (ตรวจ syntax PHP ก่อนบันทึก), ลบ หรือกู้คืนไฟล์ที่ถูกตั้งข้อสงสัย
  จากหน้าเว็บผู้ดูแลได้โดยตรง มี baseline ติดตามไฟล์ PHP ที่เพิ่ม/เปลี่ยน/หายไปในแต่ละรอบสแกน
- **จำกัดความถี่คำขอ** (ใช้ APCu ถ้ามี ถ้าไม่มีก็ยังทำงานได้ปกติเฉพาะส่วนนี้ปิดไปเงียบๆ) และ
  **GeoIP** อนุญาต/ปฏิเสธตามประเทศ รองรับ Cloudflare หา IP ผู้เข้าชมจริง
- **กู้คืนได้โดยไม่ต้องใช้ shell**: ทุกจุดที่อาจถูกล็อกมีทางออกผ่าน FTP/File manager เสมอ
  (`colorpack_shield.disable`, `cache/colorpack_shield/gate.off`) — ไม่มีทางที่พลาดครั้งเดียว
  แล้วเข้าเว็บตัวเองไม่ได้
- **ภาษาไทยและอังกฤษเท่าเทียมกัน**: ใช้ส่วนประกอบเป็นภาษาไทยได้ขณะที่ผู้ดูแล Joomla เป็นภาษาอังกฤษ
  หรือสลับกัน — เป็นความชอบส่วนบุคคล ไม่ใช่การตั้งค่าทั้งเว็บ
- แดชบอร์ดพร้อมคะแนนความปลอดภัย, รายการ "สิ่งที่ควรทำต่อ" เรียงลำดับความสำคัญ, และรายงานกิจกรรม/
  การสแกนไฟล์/การล็อกอินฝั่งหลังบ้าน — อธิบายด้วยภาษาธรรมดา ไม่ใช่แค่ตัวเลข

### ความต้องการของระบบ

- Joomla 4, 5 หรือ 6
- PHP 8.1 ขึ้นไป
- ไม่ต้องมี PHP extension พิเศษใดๆ (ใช้ APCu เสริมสำหรับจำกัดความถี่คำขอ ถ้าไม่มีปลั๊กอินยังทำงาน
  ถูกต้อง เพียงแค่ฟีเจอร์นี้ปิดไปเงียบๆ)

### การติดตั้ง

**ผ่านระบบอัปเดตของ Joomla เอง (แนะนำ ตั้งแต่เวอร์ชัน 0.7.1 เป็นต้นไป):** เมื่อติดตั้ง 0.7.1
ขึ้นไปแล้ว หน้า Extensions → Manage → Update ของ Joomla จะหาเวอร์ชันใหม่ให้เองอัตโนมัติ
ไม่ต้องใช้ FTP หรือโหลดไฟล์เอง

**ติดตั้งแบบ manual (ครั้งแรก หรือเวอร์ชันเก่ากว่านี้):**

1. ดาวน์โหลด `pkg_colorpack_shield-X.Y.Z.zip` เวอร์ชันล่าสุดจาก
   [Releases](https://github.com/lungkao/Colorpack-Shield/releases)
2. เข้าหน้าผู้ดูแล Joomla → **System → Install → Extensions** แล้วอัปโหลดไฟล์ zip
3. เปิด **Components → Colorpack Shield → Quick setup** แล้วทำตามขั้นตอน

### เอกสาร

- [CHANGELOG.md](CHANGELOG.md) — ทุกเวอร์ชันที่ออก อธิบายด้วยภาษาธรรมดา รวมถึงแก้อะไรและทำไม
- หน้าจอต่างๆ ของส่วนประกอบผู้ดูแล (Dashboard, Settings, Activity, File scan, Network & IP,
  Server rules, Tools) มีคำอธิบายในตัวอยู่แล้วทุกหน้า ไม่มีคู่มือแยกต่างหาก

### สัญญาอนุญาต

GNU General Public License v3.0 หรือใหม่กว่า — ดู [LICENSE.txt](LICENSE.txt)

### สนับสนุนโปรเจกต์นี้

ถ้า Colorpack Shield ช่วยป้องกันเว็บที่สำคัญกับคุณอยู่ เลี้ยงกาแฟผู้ดูแลโปรเจกต์สักแก้วได้ที่:
**[buymeacoffee.com/cheuachatchai](https://buymeacoffee.com/cheuachatchai)**
