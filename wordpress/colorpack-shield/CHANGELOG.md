# Changelog

## 0.11.0-dev

- **New-administrator / promotion alerts**, wired up for the first time on this side -
  `AdminProtect\AdminChangeDetector` is re-worked for WordPress's string role slugs (the Joomla
  edition's own version compares integer access-group ids, which don't exist here; the algorithm
  carries over, only the id type does not) and hooked onto `user_register`/`profile_update`, the
  WordPress equivalents of the Joomla edition's `onUserBeforeSave`/`onUserAfterSave` pair.
  WordPress hands `profile_update` the user's pre-update state directly (`$old_user_data`), so -
  unlike the Joomla plugin - no separate "remember the roles before the save" step is needed.
- "Super" is decided by the `manage_options` capability, not a hardcoded `administrator` slug, so
  a custom role a plugin grants that capability to is still caught - the WordPress equivalent of
  the Joomla edition's own `Access::checkGroup($id, 'core.admin')` check.
- New **Settings > Email the site admin about > "A new administrator, or someone promoted to
  one"** checkbox (on by default, same as the existing lockout/new-address alerts); mailed to
  `admin_email`, throttled to once per five minutes per user id via the existing `AlertThrottle`.
- 7 new tests (`admin_protect_tests.php`) covering creation, promotion, demotion (no alert - losing
  power is never a threat), a no-op re-save, and a caller-supplied "super" predicate for a custom
  role - suite now 396 tests, all green.
- Verified against the real local WordPress install: a real `wp_insert_user()` with the
  administrator role, a real promotion and demotion via `wp_update_user()`, a real email-only
  re-save confirmed to stay silent (distinguished from WordPress core's own unrelated "Email
  Changed" notice), the `alert_new_admin` toggle confirmed to suppress the alert when off, and
  `Wiring::isSuperRole()` checked against the real `administrator`/`subscriber` roles - plus a
  direct check that both hooks are actually registered once the plugin boots.

## 0.10.0-dev

- **MFA: a self-contained TOTP second factor** (`Mfa\Totp`), not a bridge to a host API the way
  the Joomla edition's `JoomlaMfaGateway` is - WordPress core has nothing of its own to bridge to,
  and the project's convention is to ship dependency-free. SHA-1/6-digit/30-second, compatible
  with Google Authenticator and any standard TOTP app; no QR code (no bundled QR library) - a
  manual-entry key and an `otpauth://` link are shown instead.
- New **Colorpack Shield > MFA** screen: set up, confirm (with 8 one-time backup codes shown once),
  regenerate backup codes, or disable - self-service, always reachable, independent of the
  site-wide policy below (a user's own enrollment, once confirmed, is always required at their own
  login, the same way any personal second factor works).
- New **Settings > Two-Factor Authentication** card: off/warn/enforce policy for administrators who
  have *not* enrolled, with a grace period (days) - reuses `AdminProtect\MfaPolicy`, ported
  unmodified in an earlier round and wired up for the first time this round. "Warn" shows an
  admin-notice reminder; "enforce" redirects (or, for an ajax/json request, refuses) wp-admin
  access once the grace period runs out, the WordPress equivalent of the Joomla edition's captive
  page, except for the MFA screen itself.
- Login flow: an administrator with confirmed MFA is challenged for a code (or a backup code)
  after their password succeeds, via the `authenticate` filter - a pending-token ticket
  (`Mfa\MfaChallenge`, built on the same `StateStore` the lockout/alert classes already use) and a
  custom code-entry form that replaces wp-login.php's own form in place, reusing its header/footer/
  error display and "remember me"/redirect_to handling rather than reinventing them. Code guesses
  are rate-limited (8/minute per address) independently of the general login rate limit, since this
  is a sensitive enough surface to protect even when an operator has left that off.
- `ScoreCalculator`'s `admin_login` item now matches the Joomla edition's own three-state shape:
  lock-out off is still a failure; lock-out on without MFA enforced is a recommendation, not a
  failure; lock-out on with MFA enforced is fully ok.
- 25 new tests (`mfa_tests.php`, including `MfaPolicy`'s own grace-period assertions, ported
  unmodified from the Joomla edition's `admin_mfa_tests.php` and never previously covered on this
  side) plus updated `dashboard_tests.php` fixtures for the new three-state `admin_login` scoring -
  suite now 389 tests, all green. The HOTP core is checked directly against the RFC 4226 Appendix D
  test vectors, and the base32 encoder against an independently-written cross-check, rather than
  trusting hand-recalled RFC 6238 time-based vectors.
- Verified against the real local WordPress install: a real secret enrolled, confirmed and
  verified through `MfaStore`/`Totp`, a real backup code consumed through `BackupCodes`, a real
  challenge ticket round-tripped through the real file-backed `StateStore`, `ScoreCalculator`
  checked against real `Settings`/`MfaStore` state, and `MfaPolicy`'s redirect decision checked
  past a real grace period - plus a visual check of all three MFA-screen states, the new Settings
  card, and the login challenge form (confirming it correctly hides wp-login.php's own form).

## 0.9.0-dev

- **New Dashboard landing page** (now the top-level menu item, taking the place Settings used to
  hold): a score ring plus an ordered "worth doing next" list - the WordPress equivalent of the
  Joomla edition's Dashboard screen.
- New `ScoreCalculator` - a WordPress-specific rewrite, not a port, of the Joomla edition's
  11-item checklist. Four Joomla items (`real_ip`, `cloudflare_ranges`, `rate_limit`,
  `server_rules`) score subsystems this port never built; two more (`shields`, `coverage`) are
  redundant here because the WAF port has one all-or-nothing `waf_enabled` switch instead of
  Joomla's per-shield/per-scope toggles. Passing WordPress through the Joomla calculator unmodified
  would have surfaced permanent, unfixable recommendations pointing at Settings fields that don't
  exist on this side. Instead, only the four items this port genuinely has an independent signal
  for are scored - `protection` (WAF on), `admin_login` (lockout on), `admin_door` (access key or
  address list - a recommendation, not a failure, when off), `file_scan` (last scan's high-severity
  count and age) - re-weighted to still sum to 100.
- `DashboardPlanner` ported from the Joomla edition near-verbatim (pure ranking/banding logic, no
  Joomla dependency); its `FIX`/`FIELD`/`PRIORITY` maps trimmed to this port's 4 items and 2 real
  screens (Settings, Files).
- 11 new tests (`dashboard_tests.php`) covering the score calculator's weighting/unknown handling
  and the planner's ranking/banding - full suite now 361 tests, all green.
- Verified against the real local WordPress install before calling this round done: toggled
  Settings and scan-store state through several real combinations (all off, all on, a high-severity
  finding, an old clean scan, a fresh clean scan) and confirmed the real `DashboardPage::facts()`
  code path produces the right score/band/todo every time; visually checked the rendered ring and
  todo list in a browser against the real `cps.css`.

## 0.8.0-dev

- **Finished the file scanner**: view/edit a flagged file, delete it, bulk delete/mark-safe, and
  quarantine-before-change copies with restore - the parts Round 2 (0.7.0-dev) explicitly
  deferred. Ported `Quarantine`, `PhpSyntax`, `LineMarker` near-verbatim (confirmed zero Joomla
  dependency, same as everything else in `Scanner/`).
- New Files-screen actions, all going through the same `FileGuard` checks the Joomla edition's
  `ScanModel` uses: a view/edit dialog (plain `<textarea>`, the first real use of the `cps.css`
  `dialog.cps-dialog` styles shipped in Round 1) with a `PhpSyntax` pre-save check and an explicit
  "save anyway" override, confirm-by-typing-the-filename delete, bulk delete/mark-safe across
  checked rows, and a quarantine-copies section with restore/discard. Every action is quarantined
  before it touches a file and logged to the Activity screen (`ActivityLog`, reused as-is).
- Fixed a request-dispatch bug found while building the bulk-actions table: a per-row "Mark safe"
  button using `formaction` to post to a different handler than its enclosing bulk form would have
  put two different `action` values on the same request (one in the query string, one in the
  form's own POST body) - which handler fires then depends on PHP's `variables_order`. Removed the
  form-level `action` field entirely; every button (including the bulk ones) now declares its own
  `formaction` explicitly, so only one `action` value is ever submitted at a time.
- New scheduled background scan (WP-Cron, `twicedaily`, off by default - a new Settings toggle):
  reuses the exact same `FileScanner::step()`/`result()` pair and `ScanStore` location as the
  on-demand button, saves its `state` after every step so an interrupted run resumes on the next
  firing instead of restarting, and emails the site admin (throttled via `AdminProtect\AlertThrottle`,
  already ported in Round 1 - the first real cross-feature reuse on this side) when a run finds a
  genuinely new high-severity item.
- Verified end to end against the real local WordPress install before calling this round done: a
  planted test backdoor was viewed, edited (confirming the quarantine-copy-first behavior and that
  the re-scan picks up the cleaned file), deleted, and restored correctly through the real code
  path; `FileGuard`/`Quarantine` correctly refused a forged restore targeting `wp-config.php` and
  the plugin's own files; the WP-Cron toggle correctly scheduled and unscheduled the real event.
- Still not ported: a syntax-highlighting editor (plain `<textarea>` only), accepting a scan as a
  new baseline and the diff view against it (`FileScanner` already supports this, unused).

## 0.7.0-dev

- **Ported the file scanner (detection only)** from the Joomla edition's `Scanner/`: `FileScanner`,
  `ScanStore`, `SignatureRules` ported near-verbatim (content-based, no path assumptions).
  `LocationRules` and `FileGuard` were rewritten, not just namespace-swapped - the Joomla
  edition's `foreign_cms_file` rule flags `wp-*.php` as suspicious, which is backwards here
  (those are WordPress's own real files); the inverse (`foreign_configphp`, a stray Joomla
  `configuration.php`) replaces it. `images/`/`tmp/`/`administrator/` path anchors became
  `wp-content/uploads/`/`wp-content/tmp/`/WordPress's own folder layout throughout, including
  three hardcoded Joomla paths baked directly into `FileScanner.php` itself (its own-cache skip,
  its own-rule-file skip, and the `.htaccess` "data dir" check) that a plain namespace swap would
  have missed.
- New "Colorpack Shield > Files" screen (`Admin\ScanPage`): a chunked, resumable scan
  (`admin-ajax.php`, budgeted steps, lock-guarded against double-clicks - the WordPress
  equivalent of the Joomla edition's `ScanModel::step()`/`budget()`), a findings table, "Mark
  safe" per finding, and "Analyze with AI" reusing the exact pattern from the Activity screen.
  Detection only this round: no file view/edit/delete, no quarantine/restore, no scheduled
  background scan (WP-Cron) - see README "Plan" for what's deferred to a proposed next round.
- **Found and fixed a real false-positive bug** (not WP-specific - the same fix was shipped to
  the Joomla edition too, 0.10.7) by running a real scan against a real WordPress install before
  calling this round done: `SignatureRules::PHP_IN_IMAGE` matched a bare `<?` byte anywhere in
  image/document content, which compressed binary image data hits by pure coincidence often
  enough to be practically useless - 17 of 20 findings on a clean install were WordPress's own
  core/plugin/theme images and library files, not backdoors. Tightened the signature to require
  actual PHP-looking syntax after the tag, and added a narrow, evidence-based allowlist
  (`FileScanner::KNOWN_CORE_FILES`) for two specific WordPress-bundled library files whose real,
  legitimate content still tripped other rules (`shell.php` - a diff-engine class, nothing to do
  with a webshell; a `sodium_compat` cryptographic constant that looked like an obfuscated hex
  blob). Re-verified end to end after the fix: the same real scan went from 20 findings to 2 (one
  coincidental comment match, one genuinely loose file permission), while a planted test backdoor
  was still caught correctly throughout.
- 69 new tests (`tests/file_scanner_tests.php`, ported from the Joomla edition's equivalent,
  including the real-world "asianpa.org incident" regression fixtures, with the
  `LocationRules`/`FileGuard` assertions adjusted for WordPress's paths) - 322/322 total pass.

## 0.6.0-dev

- **Ported admin login protection** from the Joomla edition's `AdminProtect/` (12 of its 14
  classes are pure PHP with no Joomla dependency - copied near-verbatim, namespace/cache-path
  swap only): `LockoutPolicy`, `LoginRateLimit`, `AccessGate`/`AccessGateConfig`, `KnownIps`,
  `AdminChangeDetector`, `AlertThrottle`, `AdminProtectConfig`, `StateStore`/`FileStateStore`/
  `MemoryStateStore`, `MfaPolicy`. Also ported their shared dependencies `Net\ClientIp`,
  `Net\IpAllowList`, `Net\CloudflareRanges`, `Geo\CidrMatcher` (same reasoning: pure PHP, no
  Joomla touchpoints beyond the include guard).
- New `AdminProtect\Wiring` connects these to WordPress's own login lifecycle (the WordPress
  equivalent of the Joomla edition's login-protection code in `Extension\ColorpackShield`):
  `authenticate` (blocks an already-locked address regardless of password correctness),
  `wp_login_failed`/`wp_login` (record failures/successes, known-address learning, new-address
  alerts via `wp_mail()`), and `login_init`/`admin_init` (the access-key "door" - same
  allow/deny/exchange/observe decision as the Joomla edition, with a plain 404 on deny so a door
  is never revealed to exist). Off by default, same as every other server-facing feature here.
- Settings screen gained two new cards: **Admin Login Protection** (lockout thresholds, rate
  limit, alert toggles) and **Administrator Door** (the access key + address list, with an
  explicit on-screen warning about the lockout risk before anyone turns it on).
- 160 new tests (`tests/admin_protect_tests.php`, `tests/admin_gate_tests.php`, both ported from
  the Joomla edition's equivalents) - 253/253 total pass. Verified end to end against the real
  local WordPress install: a scripted 3-strikes lockout correctly blocked the offending address
  via the real `authenticate` filter while leaving a different address untouched, then was
  reverted and cleaned up.
- **Not ported this round**: MFA enforcement (`JoomlaMfaGateway` has no 1:1 WordPress API to
  bridge to - `MfaPolicy` itself is ported and ready, just not wired to anything, same "library
  ported, not wired" pattern as Gemini in 0.3.0-dev) and new-admin/promotion alerts
  (`AdminChangeDetector`'s group-id model doesn't fit WordPress's string role slugs without
  rework that would need its own round rather than a half-adapted shim here).

## 0.5.0-dev

- **Ported the Colorpack design system** (`cps.css`, 297 lines + 3 bundled ColorPack webfont
  files) from the Joomla edition's `media/css/cps.css` - dropped the two Atum
  `data-bs-theme` dark-mode rules (WordPress has no equivalent explicit toggle; auto dark mode via
  `prefers-color-scheme` still works) and the three Joomla-field-harmonization rules. New
  `Admin\Assets` enqueues it on this plugin's own `wp-admin` pages only. Rewrote `SettingsPage`
  and `ActivityPage` to use the `cps-*` markup (cards, pill radio toggles, `cps-table`) inside a
  shared `<div id="cps-app">` (every `cps.css` rule is scoped under that id) instead of
  WordPress's native `form-table`/`widefat` styling, plus a new `Admin\Nav` for the shared
  `cps-head`/`cps-nav` banner. Visually verified against the real
  `/Users/pisan/Sites/wordpress` install before and after.
- `assets/js/cps.js` is enqueued but intentionally near-empty for now - nothing built on this side
  yet needs any of the Joomla edition's JS (tab groups, the Basic/Advanced toggle, the file-scan
  step runner); it'll gain behavior alongside the features that need it.

## 0.4.0-dev

- **Wired the Gemini AI advisor up for real** - the 0.3.0-dev round's library-only classes now
  have a `wp-admin` screen to drive them. New top-level "Colorpack Shield" menu:
  - **Settings**: WAF on/off (the `colorpack_shield_waf_enabled` filter still works as an override
    on top of the stored setting) and the Gemini advisor's own on/off + API key + model, stored in
    one `colorpack_shield_settings` option (`src/Admin/Settings.php`).
  - **Activity**: lists the WAF log and, once Gemini is enabled with a key, an "Analyze with AI"
    button - the same on-demand round trip as the Joomla edition's
    `ActivityModel::analyzeWithAi()` (`PromptBuilder::forWafActivity()` -> `Client::ask()`), with
    the result rendered through `SimpleMarkdown` (ported from the Joomla edition's 0.10.4 round)
    instead of raw Markdown text. Stores only the single latest result
    (`colorpack_shield_ai_latest`) - no history list or scheduled digest this round; the Joomla
    edition's `AnalysisHistory`/`FileStateStore` weren't ported, since nothing here needs a
    history yet.
- `Bootstrap::block()` now writes a structured log line (`src/Admin/ActivityLog.php`, the exact
  wire format the Joomla edition's own `text_file` logger uses) to
  `wp-content/uploads/colorpack-shield/activity.log`, instead of a plain `error_log()` call - there
  was nothing for the Activity screen to read before this. Ported `LogReader`/`LogFilter`
  near-verbatim from the Joomla edition's Core classes (they were already Joomla-free).
- The admin-post handler for the "Analyze with AI" button redirects back with a plain GET and no
  leftover POST-only params - deliberately avoiding the exact shape of the Joomla edition's 0.10.1
  CSRF-chain bug (a redirect target that still carried `action`/token values, re-triggering the
  same handler on the browser's next GET).
- 11 new tests in `tests/admin_tests.php` (`ActivityLog` -> `LogReader` -> `LogFilter` round trip,
  including that a hostile value can't forge a second log line, plus `SimpleMarkdown`) — 88/88
  total pass.
- **Still out of scope**: admin login protection, the file scanner, scan-finding analysis, a
  scheduled digest, and an analysis history list. See README "Plan".

## 0.3.0-dev

- Ported the Gemini AI advisor library from the Joomla edition's `Gemini/` namespace: `Config`,
  `HttpTransport`/`CurlTransport` (same curl-first/stream-fallback house style as the WAF core's
  own HTTP code), `PromptBuilder` (the allowlist-based redaction that keeps visitor IPs, request-
  parameter names, and raw file content out of every prompt), and `Client`.
- **Library only, not wired to anything.** There is no WordPress Settings screen, Activity log
  reader, or file scanner yet to drive this from, and building one here would be scope creep
  beyond what was asked. See the Joomla edition's 0.10.0 round for the full feature (on-demand
  button, scheduled digest, Settings toggle) this library is meant to eventually support here too.
- 17 new tests in `tests/gemini_tests.php` (config validation, the privacy-sweep pattern over
  realistic fixtures, and `Client` against a fake transport) — 77/77 total pass.
- Changed `Config::DEFAULT_MODEL` from `gemini-2.5-flash` to `gemini-3.5-flash-lite`, matching the
  Joomla edition's 0.10.3 fix: a fresh Gemini API key's Free Tier quota for `gemini-2.5-flash` was
  confirmed as low as 20 requests/day, while `gemini-3.5-flash-lite` worked end to end on the same,
  already-exhausted key. Since this library isn't wired to a Settings screen here yet, this only
  matters once something actually calls `Config::fromParams()` with a blank model.
- `PromptBuilder`'s two preambles now ask for the reply twice - a Thai section first, then the
  same content in English - matching the Joomla edition's 0.10.4 change. The companion
  `SimpleMarkdown` renderer from that round is **not** ported here: it's a Joomla-component
  template helper with nothing to render into on this side yet (no Activity/Scanner screen exists
  here), so porting it now would be dead code.

## 0.2.0-dev

- Ported the WAF core from the Joomla edition: request normalization (`Normalizer`,
  `PathNormalizer`), the bounded request flattener (`RequestData`), a content-type-aware body
  parser for JSON/REST payloads (`BodyParser`), the generic signature shields (SQLi, XSS, LFI,
  RFI), the header shield, the path shield, and the orchestrating `WafEngine`.
- Rewrote the path/header location rules (`src/Waf/Rules/PathRules.php`,
  `src/Waf/Rules/HeaderRules.php`) for WordPress's own folder layout: `wp-admin`, `wp-content`,
  `wp-includes`, `wp-login.php`, and `wp-json` are this platform's real paths and are never
  treated as scanner probes; PHP execution in `wp-content/uploads` (the most common webshell
  dropzone on WordPress) is flagged the way Joomla's `images/`/`tmp/` are.
- Wired the engine into WordPress's request lifecycle via `src/Waf/Bootstrap.php`, hooked on
  `plugins_loaded`. Off by default — nothing runs until a site adds
  `add_filter('colorpack_shield_waf_enabled', '__return_true')`.
- Added a minimal `Net\ClientIpResolver::normalise()` (IP-string validation only; full
  Cloudflare/trusted-proxy resolution is deferred to the admin-login/rate-limiting round).
- 60 tests in `tests/run.php` / `tests/waf_tests.php`, covering every shield, the WordPress-
  specific path rules, and engine scoping.

## 0.1.0-dev

- Initial scaffold: plugin bootstrap, `uninstall.php`, bilingual README, LICENSE. No feature
  code.
