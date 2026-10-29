# Colorpack Shield — changelog

Everything here is built for **shared hosting** (no server administrator rights, maybe no shell). Server-level
measures are always optional extras; the plugin and the web screens stand on their own.

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
- Settings screen: "Show advanced settings" is now a full-width banner instead of a small button easy to miss. A Dashboard recommendation's "Open settings" link now jumps straight to the field it is about — opens the right tab, reveals Advanced if needed, scrolls to the field and flashes it briefly — instead of landing on the screen and leaving the field to be found by hand.
- Fixed (found by live user-testing): `Settings::HtmlView` used `Form::getField($name)` with no group to validate the Dashboard's jump-to-field request; that call never matches a field inside a named `<fields>` group (every field here is), so the jump silently did nothing. Now walks the fieldsets the same way the template does.
- Fixed (found by live user-testing): on an already-installed site, Joomla reads a component's/plugin's language strings from the centralized `administrator/language/<tag>/` files, not from the extension's own `language/` folder — a handful of newly-added strings (the File scan filter/search placeholder, the bulk-by-filter buttons) showed as raw language keys until those centralized files were updated too. The Joomla installer package copies both locations correctly on its own; a plain FTP file-by-file update must copy language files to `administrator/language/<tag>/`, not (only) to the extension's own `language/` folder.

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
