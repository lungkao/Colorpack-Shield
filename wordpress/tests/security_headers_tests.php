<?php
/**
 * HTTP security headers: which headers each context gets, the HTTPS-only HSTS rule and the
 * header-injection guard. Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Admin\Settings;
use Colorpack\WP\ColorpackShield\Headers\SecurityHeaders;

echo "\n== HTTP security headers ==\n";

$defaults = Settings::normalise([]);

check('off by default: nothing is sent', SecurityHeaders::build($defaults, true) === []);

$on = Settings::normalise(['sec_headers_enabled' => '1']);
$h  = SecurityHeaders::build($on, true);

check('switched on with the defaults: nosniff, same-origin framing, referrer and permissions policy', $h === [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options'        => 'SAMEORIGIN',
    'Referrer-Policy'        => 'strict-origin-when-cross-origin',
    'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=()',
]);
check('HSTS and CSP are never on unless chosen', !isset($h['Strict-Transport-Security']) && !isset($h['Content-Security-Policy']));

$hsts = Settings::normalise(['sec_headers_enabled' => '1', 'sec_hsts' => 'y1', 'sec_hsts_subdomains' => '1']);

check('HSTS: max-age and includeSubDomains over HTTPS', SecurityHeaders::build($hsts, true)['Strict-Transport-Security'] === 'max-age=31536000; includeSubDomains');
check('HSTS is never sent over plain HTTP', !isset(SecurityHeaders::build($hsts, false)['Strict-Transport-Security']));
check('HSTS without sub-domains', SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_hsts' => 'm6'], true)['Strict-Transport-Security'] === 'max-age=15552000');

$csp = Settings::normalise(['sec_headers_enabled' => '1', 'sec_csp' => "upgrade-insecure-requests;\r\nframe-ancestors 'self'", 'sec_csp_report_only' => '1']);
$hc  = SecurityHeaders::build($csp, true);

check('CSP set to report-only goes out under the report-only name', ($hc['Content-Security-Policy-Report-Only'] ?? '') === "upgrade-insecure-requests; frame-ancestors 'self'" && !isset($hc['Content-Security-Policy']));
check('CSP enforced when report-only is off', isset(SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_csp' => "default-src 'self'", 'sec_csp_report_only' => false], true)['Content-Security-Policy']));

$admin = SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_nosniff' => true, 'sec_frame' => 'deny', 'sec_referrer' => 'no-referrer', 'sec_csp' => "default-src 'none'", 'sec_csp_report_only' => false], true, SecurityHeaders::ADMIN);

check('wp-admin and the login page get no CSP and no frame header (WordPress and the admin need their own)', !isset($admin['Content-Security-Policy']) && !isset($admin['X-Frame-Options']) && $admin['Referrer-Policy'] === 'no-referrer' && $admin['X-Content-Type-Options'] === 'nosniff');
check('a frame setting of "deny" is sent as DENY on the public site', SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_frame' => 'deny'], true)['X-Frame-Options'] === 'DENY');
check('each header can be switched off', SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_nosniff' => false, 'sec_frame' => 'off', 'sec_referrer' => 'off', 'sec_permissions' => ''], true) === []);

$evil = SecurityHeaders::build(['sec_headers_enabled' => true, 'sec_permissions' => "camera=()\r\nSet-Cookie: x=1\0"], true);

check('a value cannot start a second header', !preg_match('/[\r\n\0]/', $evil['Permissions-Policy']));
check('control characters collapse to one space, long values are capped', SecurityHeaders::clean("a\t\r\n b") === 'a b' && strlen(SecurityHeaders::clean(str_repeat('x', 9000))) === 4000);
check('an unknown frame, referrer or HSTS choice falls back to the default', Settings::clean(['sec_frame' => 'x', 'sec_referrer' => 'x', 'sec_hsts' => 'x'])['sec_frame'] === 'sameorigin' && Settings::clean(['sec_hsts' => 'x'])['sec_hsts'] === 'off');
