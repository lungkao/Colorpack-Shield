<?php
/**
 * Colorpack Shield (WordPress) — WAF core standalone test harness (no WordPress required).
 *
 * Run:  php pkg_colorpack_shield_wp/tests/run.php
 * Exits 0 if every fixture behaves, 1 otherwise.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

define('COLORPACK_SHIELD_WP_TEST', 1);

$waf = __DIR__ . '/../colorpack-shield/src/Waf';
require $waf . '/WafResult.php';
require $waf . '/Normalizer.php';
require $waf . '/PathNormalizer.php';
require $waf . '/RequestData.php';
require $waf . '/BodyParser.php';
require $waf . '/RequestMeta.php';
require $waf . '/Shield/ShieldInterface.php';
require $waf . '/Shield/MultiResultShield.php';
require $waf . '/Shield/AbstractRegexShield.php';
require $waf . '/Shield/SqliShield.php';
require $waf . '/Shield/XssShield.php';
require $waf . '/Shield/LfiShield.php';
require $waf . '/Shield/RfiShield.php';
require $waf . '/Shield/HeaderShield.php';
require $waf . '/Shield/PathShield.php';
require $waf . '/Rules/HeaderRules.php';
require $waf . '/Rules/PathRules.php';
require $waf . '/WafEngine.php';
require __DIR__ . '/../colorpack-shield/src/Net/ClientIpResolver.php';
require __DIR__ . '/../colorpack-shield/src/Net/ClientIp.php';
require __DIR__ . '/../colorpack-shield/src/Net/CloudflareRanges.php';
require __DIR__ . '/../colorpack-shield/src/Geo/CidrMatcher.php';
require __DIR__ . '/../colorpack-shield/src/Net/IpAllowList.php';
require __DIR__ . '/../colorpack-shield/src/Net/IpCountry.php';

$gemini = __DIR__ . '/../colorpack-shield/src/Gemini';
require $gemini . '/HttpTransport.php';
require $gemini . '/CurlTransport.php';
require $gemini . '/Config.php';
require $gemini . '/PromptBuilder.php';
require $gemini . '/Client.php';

$admin = __DIR__ . '/../colorpack-shield/src/Admin';
require $admin . '/LogReader.php';
require $admin . '/LogFilter.php';
require $admin . '/ActivityLog.php';
require $admin . '/SimpleMarkdown.php';

$ap = __DIR__ . '/../colorpack-shield/src/AdminProtect';
require $ap . '/StateStore.php';
require $ap . '/FileStateStore.php';
require $ap . '/MemoryStateStore.php';
require $ap . '/LockDecision.php';
require $ap . '/LockoutPolicy.php';
require $ap . '/LoginRateLimit.php';
require $ap . '/AccessGateConfig.php';
require $ap . '/AccessGate.php';
require $ap . '/KnownIps.php';
require $ap . '/AdminChangeDetector.php';
require $ap . '/AlertThrottle.php';
require $ap . '/AdminProtectConfig.php';
require $ap . '/MfaPolicy.php';

$scanner = __DIR__ . '/../colorpack-shield/src/Scanner';
require $scanner . '/SignatureRules.php';
require $scanner . '/LocationRules.php';
require $scanner . '/FileScanner.php';
require $scanner . '/ScanStore.php';
require $scanner . '/FileGuard.php';
require $scanner . '/Quarantine.php';
require $scanner . '/PhpSyntax.php';
require $scanner . '/LineMarker.php';

$admin2 = __DIR__ . '/../colorpack-shield/src/Admin';
require $admin2 . '/ScoreCalculator.php';
require $admin2 . '/DashboardPlanner.php';

$mfa = __DIR__ . '/../colorpack-shield/src/Mfa';
require $mfa . '/Totp.php';
require $mfa . '/BackupCodes.php';
require $mfa . '/MfaChallenge.php';

$pass = 0;
$fail = 0;

/** Shared by every test file included below. */
function ok(string $label, bool $condition): void
{
    global $pass, $fail;

    if ($condition) {
        $pass++;
    } else {
        $fail++;
        echo "FAIL: $label\n";
    }
}

require __DIR__ . '/waf_tests.php';
require __DIR__ . '/gemini_tests.php';
require __DIR__ . '/admin_tests.php';
require __DIR__ . '/admin_protect_tests.php';
require __DIR__ . '/admin_gate_tests.php';
require __DIR__ . '/file_scanner_tests.php';
require __DIR__ . '/scanner_actions_tests.php';
require __DIR__ . '/dashboard_tests.php';
require __DIR__ . '/mfa_tests.php';
require __DIR__ . '/ip_country_tests.php';

echo "\n$pass passed, $fail failed.\n";
exit($fail === 0 ? 0 : 1);
