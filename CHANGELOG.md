# Colorpack Shield — changelog

Everything here is built for **shared hosting** (no server administrator rights, maybe no shell). Server-level
measures are always optional extras; the plugin and the web screens stand on their own.

## 0.10.5

- The AI advisor answered twice on every call (a Thai section, then the same content again in
  English) - too verbose for a result most admins only read in one language. It now answers once,
  in the admin's own current interface language (`Factory::getApplication()->getLanguage()->getTag()`
  - the language-switcher's setting, not the site's front-end default), falling back to English
  for any language this isn't taught to ask for yet. `PromptBuilder::forWafActivity()`/
  `forScanFindings()` take a new `string $lang = 'en'` parameter.

## 0.10.4

- The AI advisor's result box showed Gemini's reply as raw text: literal `###`, `**bold**`, and
  `- bullet` markers instead of real headings/bold/lists, inside a `<p style="white-space:pre-wrap">`
  that didn't constrain width, so long unbroken lines pushed the whole admin screen into
  horizontal scroll. Added `SimpleMarkdown` (`com_colorpack_shield/admin/src/Core/`): escapes the
  reply first (it's free text from an external API, never trusted as HTML), then renders a narrow,
  fixed set of patterns back to markup - headings, bold/italic/inline code, bullet/numbered lists,
  fenced code blocks, horizontal rules, paragraphs. Wired into both the Activity screen's and the
  Scanner screen's "latest AI analysis" panel, with matching CSS (`.cps-ai-answer`) that wraps long
  tokens and caps line length for readability.
- The Gemini prompts (`PromptBuilder::PREAMBLE_WAF` / `PREAMBLE_SCAN`) now ask for the reply twice
  - a Thai section first, then the same content in English - instead of English only.

## 0.10.3

- Changed the default Gemini model from `gemini-2.5-flash` to `gemini-3.5-flash-lite`.
  `gemini-2.5-flash`'s Free Tier quota turned out to be as low as 20 requests/day on a newly
  created API key/project - easy to exhaust from normal admin use (let alone testing), after
  which every call returns HTTP 429 and `Client::ask()` fails exactly the same way it fails for
  any other non-2xx reply: a generic "The call to Gemini failed - try again later" with no
  detail, because the client is deliberately fail-open and never surfaces transport-level error
  detail to the end user. `gemini-3.5-flash-lite` is a separate, currently-uncapped free model on
  the same key and was confirmed working end to end (`PromptBuilder` → `Client::ask()` → a real
  Gemini reply) against a key whose `gemini-2.5-flash` quota was already exhausted. This only
  changes the *default* - an admin who already saved a custom model keeps whatever they set and
  needs to update the Model field themselves if they want to switch.
- This is a one-time pick based on what currently has free quota; Google's free-tier model
  lineup and limits change over time, so a future round may need to revisit the default again.

## 0.10.2

- Fixed the real cause of "The call to Gemini failed - try again later" showing up even with a
  working API key and a reachable network: `PromptBuilder::clean()` truncated every sample/path
  field with a plain, byte-counted `substr()`. A real attack sample can contain raw bytes that
  are not valid UTF-8 (url-decoded binary, overlong sequences meant to evade filters), and even
  an otherwise-clean sample could have a multibyte character land right on that 300-byte cut
  point, slicing it in half. Either way, `Client::ask()`'s `json_encode()` call fails *silently*
  (returns `false`) the instant any invalid UTF-8 reaches it - which looks exactly like "the call
  failed", except no HTTP request was ever sent, so there was nothing to find in a transport-level
  log no matter how closely it was watched. Fixed `clean()` to repair invalid UTF-8 and truncate
  by character (`mb_substr`) instead of by byte; added `JSON_INVALID_UTF8_SUBSTITUTE` to
  `Client::ask()`'s own `json_encode()` call as a second line of defence. New regression test
  reproduces the exact truncated-multibyte and raw-invalid-byte cases.

## 0.10.1

- Fixed the Activity screen's "analyse with AI" button leaving a bogus "The security token did
  not match" message next to every real result, success or failure. `ActivityController::analyze()`
  rebuilt its redirect target from the whole GET query array, which still contained the
  `task=activity.analyze` the button's own form action URL carries (needed so `checkToken()` has
  a query context to resolve against). Left in, that redirect sent the browser's next, token-less
  GET navigation straight back into the same `analyze()` task, which correctly failed its token
  check and queued a second, spurious message - stacking on top of the real one every single
  time. Reproduced locally with a full login + POST replay against a disposable Joomla instance;
  fixed by stripping `option`/`task`/`view` out of the redirect query before rebuilding it.

## Update feed fix (no package version change)

- Fixed two bugs in `update.xml` that together hid every available update from every site since
  0.7.1 (when the update feed was first wired up):
  1. `<targetplatform version="6.0" />` was matched as a regex against the site's Joomla
     major.minor version, so it only ever matched a site running exactly Joomla 6.0.x and
     filtered the update out on Joomla 4.x, 5.x, or any 6.1+/6.2+ site, even though the plugin
     has always supported Joomla 4/5/6. Changed to `version="(4|5|6)\.[0-9]+"`.
  2. No `<client>` tag was present. Joomla's updater defaults an unset `<client>` to
     `client_id = 1` ("administrator"), but `pkg_colorpack_shield` is a `type="package"`
     extension with `client_id = 0` ("site") in `#__extensions`. The mismatch meant the parsed
     update could never be matched back to the installed extension record - Joomla stored it in
     `#__updates` with `extension_id = 0` and the Extensions: Update screen silently excludes
     those rows, so admins saw "no updates available" even though Joomla *had* successfully
     fetched and parsed the feed. Added `<client>site</client>` to match the package's real
     `client_id`.
  Both fields are only read from the live `update.xml` fetched from GitHub on every check, so
  fixing them needs no new package release - sites already on any version from 0.7.1 onward will
  see this fix the next time they check for updates. If Joomla still doesn't pick it up, the
  check itself is time-cached: reset it via System → Update Sites → select the row → Rebuild (or,
  on a site with phpMyAdmin access, `UPDATE #__update_sites SET last_check_timestamp = 0 WHERE
  name = 'Colorpack Shield Update Server'`) before checking again.

## 0.10.0

- **AI advisor: Google Gemini can now explain WAF activity and file-scan findings in plain
  language, and suggest new detection rules — entirely off by default, using an admin's own
  Gemini API key.** New `Gemini/` namespace: `Config`, `HttpTransport`/`CurlTransport` (same
  curl-first/stream-fallback house style as every other outbound call in this plugin),
  `PromptBuilder`, `Client`, `AnalysisHistory`.
- **Privacy by construction, not by filter**: `PromptBuilder` is an allowlist, not a blocklist -
  only the fields it explicitly reads (rule, shield, client, the matched sample text, a request
  path; for scan findings: path, matched rule ids, severity, size, mtime, hash) ever reach a
  prompt. A visitor's IP address, the request-parameter name/source that carried an attack, and
  raw file content are never read for this feature at all, so a future log field can never
  silently start leaking. Scan-finding analysis sends metadata only - file contents are never
  read or sent, by the admin's own explicit choice.
- **Two ways to ask**: an "analyse with AI" button on the Activity screen (recent WAF hits) and
  the File scan screen (recent findings), plus an optional scheduled digest of the last day's WAF
  activity - its own separate toggle, throttled to a configurable interval (`AlertThrottle`) so a
  short Task Scheduler interval can never call a billable API more often than the admin asked
  for. Every analysis (on-demand or scheduled) is kept in a small local history, read back by
  each screen - nothing is pushed anywhere; a separate Colorpack Site Manager, if the admin runs
  one, is expected to come read it on its own.
- New Settings fieldset "AI (Gemini)": a master off-by-default switch, the API key (this
  project's first `type="password"` field - hidden from non-Super-Users and excluded from
  settings export/import, the same treatment as the existing access-key and kill-switch-token
  fields), the model name (defaults to a fast, inexpensive one), and the digest schedule.
- 23 new tests (`tests/gemini_tests.php`): config validation, a privacy sweep over realistic
  fixtures containing real-looking IPs/usernames/file content (asserting none of it reaches the
  built prompt), `Client` against a fake transport, and `AnalysisHistory`'s kind-filtered
  history. 1,900 assertions pass in all.

## 0.9.0

- **File scan: ten new backdoor/cloaking signatures, mined from a real incident** (a different Joomla site, asianpa.org, compromised 2026-10-30 - every pattern below was verified against the attacker's own files, not written speculatively):
  - Content: a superglobal name (`$_COOKIE`, …) spelled out in octal/hex escapes inside `${"..."}`; a decode routine built from repeated `'text' ^ $var` XOR operations; a function name assembled from two short string pieces and immediately called with a visitor's request; `eval`/`gzinflate` spelled out letter-by-letter with `chr()`; text built one character at a time by indexing into a string; `base64_decode` assembled from separate text pieces plus an arithmetic expression (`'base'.(128/2).'_de'.'code'`); and a known upload-probe string attack tooling leaves behind (`"jm"."te"."st"`).
  - `.htaccess`: a rewrite that redirects search-engine visitors (by user-agent/referer, or by Googlebot's own address range) to a different PHP file - a cloaking technique with no legitimate Joomla equivalent.
  - Filenames: a literal `?` character anywhere in a stored file name (a disguised-extension trick used on several of the attacker's own files, e.g. `photo.jpg?.php`); a file a host's own security tool already renamed to `.suspected` but never removed; and the PHP-extension check now accepts any `php` + digit suffix (`.php56`, …) instead of an enumerated list.
  - A hidden-PHP-in-an-image check that only matched `<?php`/`<?=` now also catches a bare `<?` (the `short_open_tag` form, deliberately used on one sample to dodge that exact check) - while still not mistaking an `<?xml` prolog for one.
  - Also widened: "PHP in images/" is now checked at any depth, not just the top level (a real sample was nested under `media/mailto/images/`).
  - Every pattern was re-checked against this project's own ~150 PHP source files for zero false positives, the same discipline as every previous signature batch.

## 0.8.0

- **New: optional integration with Colorpack Site Manager.** A fourth switch, off by default ("Send health reports and events to Colorpack Site Manager", under the plugin's new "Site Manager" tab), lets a site push its security score and a few account-protection events to a separate Colorpack Site Manager install, over the same signed channel the companion Agent plugin (`plg_system_colorpack`) already uses — no new credential to manage. Built from a frozen integration spec (`docs/shield-integration.md` in the Site Manager project), approved by its designer.
  - **Health (daily)**: the Dashboard's existing security score, mapped to pass / should-fix / must-fix, with a short Thai explanation for each item — the same score shown here, just forwarded.
  - **Events**: a `lockout` event every time an address gets locked out from repeated failed logins, and a `login_burst` event (higher severity) when 3 or more accounts lock out inside 10 minutes — both carry a count and a fixed, parameter-free Thai sentence only, by construction: there is no code path where a username, address, email, or password could reach either event.
  - Sends only from the scheduled task (never from a visitor or admin page load, so a slow or unreachable Site Manager can never slow the site itself), fails open on any problem (missing Agent config, network failure, a non-2xx reply) — nothing is ever logged or sent twice by design, and the feature does nothing at all, not even reading a file, unless the switch above is turned on.
  - This covers phases P3 (lockout), P4 (login burst) and P6 (health) of the spec. P5 (`password_breached`, `account_suspended`) are new security features in their own right, not wiring, and are planned for a later release.

## 0.7.2

- **Server rules: optional SameSite=Lax on cookies.** The `.htaccess` block's header section gained a fourth checkbox ("Also add SameSite=Lax to any cookie that does not already set one") — off by default. Found live: an OWASP ZAP scan flagged "Cookie without SameSite Attribute" on the live site. Only appends the attribute when a `Set-Cookie` response does not already carry one (checked by regex, right in Apache — Joomla's own session cookie or another extension's choice is left exactly as it is), and Lax was chosen over Strict so it never breaks a normal cross-site link or a payment gateway's return redirect. A generic Content-Security-Policy stays deliberately out of this block — fitting one to a specific theme's inline scripts without live-testing it would risk breaking the site, the one thing this feature promises never to do.

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
