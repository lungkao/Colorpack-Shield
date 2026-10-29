# Colorpack Shield — changelog

Everything here is built for **shared hosting** (no server administrator rights, maybe no shell). Server-level
measures are always optional extras; the plugin and the web screens stand on their own.

## 0.7.1

- **Joomla's own Extension Manager can now check for updates.** Added `<updateservers>` to the package manifest, pointing at `update.xml` in this (now public) repository, with the zip served from a GitHub Release. This needed the repository to go from private to public, since Joomla's updater fetches both with a plain, unauthenticated HTTP request — the trade-off: the plugin's source, including its WAF rules, is now publicly readable, in exchange for sites no longer needing a manual FTP/Extensions→Install round every release. A site must install this version (0.7.1) or later at least once, the normal way, before Joomla registers the update site and "Check for updates" starts finding anything.

## 0.7.0

- **File scan: five new backdoor signatures**, mined from the open-source PHP Malware Finder (PMF) YARA ruleset and converted to plain PCRE - `extract_request` (turning a visitor's request straight into variables), `callback_decode` (feeding a decoded value into an array function as the code to run), `unsafe_ini_tamper` (turning off `disable_functions`/`open_basedir` at runtime), `ld_preload` (a local-root privilege-escalation technique), `exploit_site_ref` (a known exploit-sharing/web-shell site mentioned in the file). Each was re-checked by hand against Joomla 6's own core plus its bundled extensions and YOOtheme (8,500+ real files) for false positives before being added; a few PMF rules that do not survive that check as plain PCRE (`${$var}`, read-only `ini_get()` checks) were deliberately left out.

## 0.6.0

- **New: "Scanner probes" can block and ban the address, not just the one request.** Settings → URL path → Scanner probes gained a fourth option, "Block and ban the address" (off by default): a request for an old-CVE path, another CMS's files (WordPress's `/wp-login.php`, `/xmlrpc.php`, plugin paths, …), or a well-known webshell/exploit name is never a visitor mistake — only attack tooling sends these. Once caught, every later request from that address is rejected outright for a configurable number of hours (default 24), not just the one that matched. Admin-tool probes (phpMyAdmin etc.) are deliberately excluded from banning — they exist to flag a coexistence problem with the host's own tools, not an attacker. Built on the same file-backed store as the admin login lock-out, so it needs no APCu (confirmed elsewhere in this project as sometimes missing on shared hosting). A fully trusted address (the operator's own `allow_ips`) is never banned, and bypasses even an existing one.
- **Activity: hover a rule name to see what it means.** "union_select", "scanner_probe" and every other rule id the WAF can report now carries a plain-language explanation on hover — found live: a rule name alone didn't say anything to someone not already familiar with these terms.
- **Severity badges (File scan) look sharper and never wrap mid-word**: bolder weight, a ringed dot, no border — found live: "ปานกลาง" (Medium) was breaking onto two lines inside its own badge at narrower widths, in both Thai and English.

## 0.5.1

- Fixed (found by live user-testing while running an OWASP ZAP scan): the Activity and Back-end login timelines showed every event's time in UTC with no label, which reads as flatly wrong to anyone not in that time zone (off by the local UTC offset). Times now render in the viewer's own device time zone via JavaScript — correct wherever the admin actually is, not wherever Joomla's Global Configuration happens to be set — and fall back to the site's configured time zone when JavaScript is off.
- Clarified: a "Request blocked" row in Activity means only that one request was rejected — the address itself is not banned and can reach the site again immediately. Found live: a person watching a ZAP scan saw dozens of "ถูกบล็อก" rows for their own address and, reasonably, read that as their IP being banned. The label now reads "Request blocked" (was "Blocked"), and every status badge carries an on-hover explanation of what it does and doesn't do.
- **File scan screen decluttered**: the "Last scan" card directly below the summary ring used to repeat the same date, file count and severity badges already shown in the ring card above it. That duplicate card is gone; only the details that weren't shown yet (files marked safe, files skipped, and the one alert that applies) still appear, and only when there's something to say.
- Activity and File-scan tables now highlight the row under the pointer and alternate a faint tint row to row, so a wide table with many columns is easier to track by eye.

## 0.5.0

- **Settings: "Show advanced settings" is now an obvious switch**, not a small button that could be mistaken for plain text — a real on/off track-and-knob, a chevron that turns, a shadow that lifts on hover, in a full-width banner.
- **Dashboard recommendations jump straight to the field they are about**: "Open settings" opens the right tab, reveals Advanced if needed, scrolls to the field and draws a thick, pulsing orange outline around it three times — not just a background tint — so it cannot be missed, instead of landing on the Settings screen and leaving the field to be found by hand.
- Fixed: the "Request rate limit" recommendation always pointed at the same on/off switch, even when that switch was already on — its "bad" status means the switch is on but the server has no APCu to count with, which nothing in Settings can fix. That recommendation no longer offers a dead-end "Open settings" button; the status text (ask the host to add the APCu extension) stands on its own.
- Fixed (found by live user-testing): `Settings::HtmlView` used `Form::getField($name)` with no group to validate the Dashboard's jump-to-field request; that call never matches a field inside a named `<fields>` group (every field here is), so the jump silently did nothing. Now walks the fieldsets the same way the template does.
- Fixed (found by live user-testing): on an already-installed site, Joomla reads a component's/plugin's language strings from the centralized `administrator/language/<tag>/` files, not from the extension's own `language/` folder — a handful of newly-added strings (the File scan filter/search placeholder, the bulk-by-filter buttons) showed as raw language keys until those centralized files were updated too. The Joomla installer package copies both locations correctly on its own; a plain FTP file-by-file update must copy language files to `administrator/language/<tag>/`, not (only) to the extension's own `language/` folder.

## 0.4.0

- **File scan** (new screen, scheduled task, e-mail): walks the site in short resumable steps and looks for PHP hidden in pictures, PHP in `images/`/`tmp/`, decode-and-run and request-driven code (a short list of backdoor patterns), well-known web-shell names, odd `.htaccess` files in upload folders. A real Joomla 6 tree (10,000 files) is scanned in about 4 s with no serious false positive. "Mark as safe" (by path and fingerprint), a **baseline** that lists new / changed / gone PHP files, and a dashboard item.
- **Optional `.htaccess` block** on Server rules: puts the path rules and browser security headers between two marker lines at the top of the site's `.htaccess`, checks the live site before and after and **puts the original back at once if any answer changes**; keeps `.htaccess.cps-backup`; says so when the host ignores `.htaccess`. Never uses directives that need server administrator rights.
- **Quick setup step 4: close the administrator door** (access key in one click) and a dashboard item for it; the key is checked while typed, minimum 10 characters, generated keys are 12 characters without look-alikes.
- **Language buttons** (ไทย / English) in the component header: use the component in Thai while the administrator is in English, or the other way round. A personal choice kept in a small cookie; works even when Thai is not installed in Joomla (the texts travel with the extension); also switches the plugin's settings labels.
- Settings are in **tabs**.
- **Proxy test from the browser** (no command line); the command stays as an option, with this site's values filled in.
- Every rescue works with FTP or a file manager (`colorpack_shield.disable`, `cache/colorpack_shield/gate.off`).
- **File scan: view, edit, delete.** Open a flagged file with the suspicious lines highlighted, edit it (PHP syntax is checked before saving), delete it (type the file name; several at once), and put back or drop the copies kept in quarantine. Only files the last scan reported can be touched; `configuration.php` and this package's own folders never can; every action is written to the log.
- **Redesigned screens:** Dashboard with a score ring, "do next" list, three report cards (activity, file scan, back-end) and a collapsible checklist; Activity with tiles (change against the week before) and a 14-day chart; File scan with a summary ring; new **Back-end login** report (door status, daily chart, two-step coverage, latest events).
- **Security audit fixes** (source review with the Cloudflare security-audit method, one pass): restoring a copy can no longer overwrite protected files; the kill-switch token is hidden from view-only users; the import preview shows whole values; an exception of just `/` is refused in the `.htaccess` block; the login speed limit now recognises `LOGIN`/`display.login` like Joomla does; very long values and floods of fields are inspected in pieces instead of being cut off; a JSON body sent with a form content type is decoded and inspected.
- **File scan findings: tabs, search and act-on-the-filter.** The findings table is now tabbed by severity (all / serious / medium / minor, each with a count) and paged (100 per page) instead of one long list. A path search box narrows the table live; "act on everything matching this filter" buttons delete or mark-safe every matching finding in one click — useful when the same file (e.g. a stray `.htaccess`) is dropped in many folders — without ticking rows one by one.
- Admin component icon: a Colorpack Shield logo now shows next to the component in the sidebar menu and Components list.
- Live-verified against a running Joomla 6 site with real HTTP traffic: all 7 of the audit fixes above, plus a classic SQLi/XSS/LFI/RFI attack sweep.

## 0.3.0

- Administrator **access key** (404 without the key cookie; redirect that removes the key from the address) and **administrator address list**, with lock-out safeguards, shell-free rescue, print-only server snippet.

## 0.2.0

- Admin component: Dashboard, Quick setup, Settings, Activity, Rules, Network & IP, Server rules, Tools (export/import).
- Administrator protection: login lock-out, speed limit, alerts (new Super User, new address, lock-outs), two-step login enforcement with grace period.
- Path and header shields; Cloudflare-aware real visitor address; scheduled refresh of the Cloudflare list.

## Known limits (audit, not fixed)

- Requests that reach a Cloudflare-proxied site through a Cloudflare Worker on another account share one egress address that cannot be told apart from other visitors; the address list, lock-out and speed limit then only observe. The access key (cookie, not address) is not affected. Needs a live Cloudflare test.

## Not yet verified (all versions)

Joomla 4.4 / 5.x, PHP 8.1, Cloudflare or a real proxy in front of a live site, nginx- and LiteSpeed-only hosts,
passkeys with the access key, the ColorPack font licence file (`OFL.txt` to be added to
`com_colorpack_shield/media/fonts/`), keyboard-only and screen-reader use.
