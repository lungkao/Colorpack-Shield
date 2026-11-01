<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Every setting, grouped into the same tabs as the Joomla edition's plugin form
 * (plugins/system/colorpack_shield/colorpack_shield.xml), plus the few switches that only exist
 * on WordPress. The settings screen, the stored-value reader and the saver all read this one list,
 * so a setting added here appears everywhere. Label/description values are language-file keys.
 */
final class SettingsSchema
{
    /** The settings most sites ever touch; everything else is "Advanced" (same list as the Joomla edition). */
    public const BASIC = [
        'waf_enabled', 'cover_site', 'cover_admin', 'cover_api', 'allow_ips', 'alert_email', 'killswitch_token', 'auto_allow_admin',
        'trust_cloudflare', 'header_mode', 'path_mode', 'login_lockout', 'mfa_enforce',
    ];

    /** Defaults that differ from the Joomla form because WordPress fleet sites start protected. */
    private const DEFAULT_OVERRIDES = [
        'login_lockout' => '1', 'site_manager_enabled' => '1',
    ];

    private const GENERATED = [
        'basic' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_COVERAGE',
            'fields' => [
                'cover_site' => ['name' => 'cover_site', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_SITE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_SITE_DESC', 'default' => '1'],
                'cover_admin' => ['name' => 'cover_admin', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_ADMIN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_ADMIN_DESC', 'default' => '1'],
                'cover_api' => ['name' => 'cover_api', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_API_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_COVER_API_DESC', 'default' => '1'],
                'admin_allowlist' => ['name' => 'admin_allowlist', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_ALLOWLIST_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_ALLOWLIST_DESC', 'default' => 'com_colorpack_shield', 'rows' => '4'],
            ],
        ],
        'safety' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_SAFETY',
            'fields' => [
                'allow_ips' => ['name' => 'allow_ips', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALLOW_IPS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALLOW_IPS_DESC', 'default' => '', 'rows' => '5'],
                'killswitch_token' => ['name' => 'killswitch_token', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_KILLSWITCH_TOKEN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_KILLSWITCH_TOKEN_DESC', 'default' => ''],
                'alert_email' => ['name' => 'alert_email', 'type' => 'email', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_EMAIL_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_EMAIL_DESC', 'default' => ''],
                'auto_allow_admin' => ['name' => 'auto_allow_admin', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_AUTO_ALLOW_ADMIN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_AUTO_ALLOW_ADMIN_DESC', 'default' => '1'],
            ],
        ],
        'clientip' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_CLIENTIP',
            'fields' => [
                'trust_cloudflare' => ['name' => 'trust_cloudflare', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_TRUST_CLOUDFLARE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_TRUST_CLOUDFLARE_DESC', 'default' => '1'],
                'trusted_proxies' => ['name' => 'trusted_proxies', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_TRUSTED_PROXIES_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_TRUSTED_PROXIES_DESC', 'default' => '', 'rows' => '3'],
                'override_remote_addr' => ['name' => 'override_remote_addr', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_OVERRIDE_REMOTE_ADDR_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_OVERRIDE_REMOTE_ADDR_DESC', 'default' => '0'],
            ],
        ],
        'shields' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_SHIELDS',
            'fields' => [
                'shield_sqli' => ['name' => 'shield_sqli', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SHIELD_SQLI_LABEL', 'desc' => '', 'default' => '1'],
                'shield_xss' => ['name' => 'shield_xss', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SHIELD_XSS_LABEL', 'desc' => '', 'default' => '1'],
                'shield_lfi' => ['name' => 'shield_lfi', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SHIELD_LFI_LABEL', 'desc' => '', 'default' => '1'],
                'shield_rfi' => ['name' => 'shield_rfi', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SHIELD_RFI_LABEL', 'desc' => '', 'default' => '1'],
            ],
        ],
        'headers' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_HEADERS',
            'fields' => [
                'header_scan' => ['name' => 'header_scan', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_SCAN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_SCAN_DESC', 'default' => '1'],
                'header_mode' => ['name' => 'header_mode', 'type' => 'list', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_MODE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_MODE_DESC', 'default' => 'default', 'showon' => 'header_scan:1', 'options' => ['default' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_MODE_DEFAULT', 'log' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_MODE_LOG', 'block' => 'PLG_SYSTEM_COLORPACK_SHIELD_HEADER_MODE_BLOCK']],
                'extra_scan_headers' => ['name' => 'extra_scan_headers', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_EXTRA_HEADERS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_EXTRA_HEADERS_DESC', 'default' => '', 'rows' => '3', 'showon' => 'header_scan:1'],
                'ignored_headers' => ['name' => 'ignored_headers', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_IGNORED_HEADERS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_IGNORED_HEADERS_DESC', 'default' => '', 'rows' => '3', 'showon' => 'header_scan:1'],
            ],
        ],
        'paths' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_PATHS',
            'fields' => [
                'path_scan' => ['name' => 'path_scan', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_SCAN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_SCAN_DESC', 'default' => '1'],
                'path_mode' => ['name' => 'path_mode', 'type' => 'list', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_MODE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_MODE_DESC', 'default' => 'recommended', 'showon' => 'path_scan:1', 'options' => ['recommended' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_MODE_RECOMMENDED', 'log' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_MODE_LOG', 'block' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_MODE_BLOCK']],
                'path_probe_mode' => ['name' => 'path_probe_mode', 'type' => 'list', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_DESC', 'default' => 'log', 'showon' => 'path_scan:1', 'options' => ['off' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_OFF', 'log' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_LOG', 'block' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_BLOCK', 'ban' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_BAN']],
                'path_probe_ban_hours' => ['name' => 'path_probe_ban_hours', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_BAN_HOURS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_PROBE_BAN_HOURS_DESC', 'default' => '24', 'min' => '1', 'max' => '720', 'showon' => 'path_scan:1[AND]path_probe_mode:ban'],
                'path_tools_exempt' => ['name' => 'path_tools_exempt', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_TOOLS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_TOOLS_DESC', 'default' => 'phpmyadmin
    webmail
    roundcube
    pma', 'rows' => '3', 'showon' => 'path_scan:1'],
                'path_allow' => ['name' => 'path_allow', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_ALLOW_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_ALLOW_DESC', 'default' => '', 'rows' => '4', 'showon' => 'path_scan:1'],
                'path_extra_deny' => ['name' => 'path_extra_deny', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_DENY_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_PATH_DENY_DESC', 'default' => '', 'rows' => '4', 'showon' => 'path_scan:1'],
            ],
        ],
        'adminprotect' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_ADMINPROTECT',
            'fields' => [
                'login_lockout' => ['name' => 'login_lockout', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCKOUT_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCKOUT_DESC', 'default' => '1'],
                'login_max_failures' => ['name' => 'login_max_failures', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_MAX_FAILURES_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_MAX_FAILURES_DESC', 'default' => '5', 'min' => '1', 'max' => '100', 'step' => '1', 'showon' => 'login_lockout:1'],
                'login_failure_window' => ['name' => 'login_failure_window', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_FAILURE_WINDOW_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_FAILURE_WINDOW_DESC', 'default' => '600', 'min' => '60', 'max' => '86400', 'step' => '60', 'showon' => 'login_lockout:1'],
                'login_lock_minutes' => ['name' => 'login_lock_minutes', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCK_MINUTES_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCK_MINUTES_DESC', 'default' => '15', 'min' => '1', 'max' => '1440', 'step' => '1', 'showon' => 'login_lockout:1'],
                'login_lock_max_hours' => ['name' => 'login_lock_max_hours', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCK_MAX_HOURS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_LOCK_MAX_HOURS_DESC', 'default' => '24', 'min' => '1', 'max' => '168', 'step' => '1', 'showon' => 'login_lockout:1'],
                'login_rate_per_minute' => ['name' => 'login_rate_per_minute', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_RATE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_LOGIN_RATE_DESC', 'default' => '10', 'min' => '0', 'max' => '600', 'step' => '1'],
                'alert_new_admin' => ['name' => 'alert_new_admin', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_NEW_ADMIN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_NEW_ADMIN_DESC', 'default' => '1'],
                'alert_new_ip' => ['name' => 'alert_new_ip', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_NEW_IP_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_NEW_IP_DESC', 'default' => '1'],
                'alert_lockouts' => ['name' => 'alert_lockouts', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_LOCKOUTS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ALERT_LOCKOUTS_DESC', 'default' => '1'],
                'mfa_enforce' => ['name' => 'mfa_enforce', 'type' => 'list', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_ENFORCE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_ENFORCE_DESC', 'default' => 'off', 'options' => ['off' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_ENFORCE_OFF', 'warn' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_ENFORCE_WARN', 'enforce' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_ENFORCE_ENFORCE']],
                'mfa_grace_days' => ['name' => 'mfa_grace_days', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_GRACE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_MFA_GRACE_DESC', 'default' => '7', 'min' => '0', 'max' => '90', 'step' => '1', 'showon' => 'mfa_enforce:warn,enforce'],
                'gate_enabled' => ['name' => 'gate_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_ENABLED_DESC', 'default' => '0'],
                'gate_key' => ['name' => 'gate_key', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_KEY_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_KEY_DESC', 'default' => '', 'showon' => 'gate_enabled:1'],
                'gate_cookie_hours' => ['name' => 'gate_cookie_hours', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_COOKIE_HOURS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GATE_COOKIE_HOURS_DESC', 'default' => '12', 'min' => '1', 'max' => '168', 'step' => '1', 'showon' => 'gate_enabled:1'],
                'admin_ip_enforce' => ['name' => 'admin_ip_enforce', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_ENFORCE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_ENFORCE_DESC', 'default' => '0'],
                'admin_ip_list' => ['name' => 'admin_ip_list', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_LIST_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_ADMIN_IP_LIST_DESC', 'default' => '', 'rows' => '4', 'showon' => 'admin_ip_enforce:1'],
            ],
        ],
        'geoip' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_GEOIP',
            'fields' => [
                'geo_enabled' => ['name' => 'geo_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_ENABLED_DESC', 'default' => '0'],
                'geo_db_path' => ['name' => 'geo_db_path', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_DB_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_DB_DESC', 'default' => '', 'showon' => 'geo_enabled:1'],
                'geo_mode' => ['name' => 'geo_mode', 'type' => 'list', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_MODE_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_MODE_DESC', 'default' => 'deny', 'showon' => 'geo_enabled:1', 'options' => ['deny' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_MODE_DENY', 'allow' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_MODE_ALLOW']],
                'geo_countries' => ['name' => 'geo_countries', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_COUNTRIES_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_COUNTRIES_DESC', 'default' => '', 'showon' => 'geo_enabled:1'],
                'geo_unknown_allow' => ['name' => 'geo_unknown_allow', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_UNKNOWN_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_UNKNOWN_DESC', 'default' => '1', 'showon' => 'geo_enabled:1[AND]geo_mode:allow'],
                'geo_allow_ips' => ['name' => 'geo_allow_ips', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_ALLOW_IPS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_ALLOW_IPS_DESC', 'default' => '', 'rows' => '3', 'showon' => 'geo_enabled:1'],
                'geo_deny_ips' => ['name' => 'geo_deny_ips', 'type' => 'textarea', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_DENY_IPS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEO_DENY_IPS_DESC', 'default' => '', 'rows' => '3', 'showon' => 'geo_enabled:1'],
            ],
        ],
        'ratelimit' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_RATELIMIT',
            'fields' => [
                'rate_enabled' => ['name' => 'rate_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_ENABLED_DESC', 'default' => '0'],
                'rate_window' => ['name' => 'rate_window', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_WINDOW_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_WINDOW_DESC', 'default' => '60', 'min' => '1', 'showon' => 'rate_enabled:1'],
                'rate_limit' => ['name' => 'rate_limit', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_LIMIT_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_LIMIT_DESC', 'default' => '120', 'min' => '1', 'showon' => 'rate_enabled:1'],
                'rate_ban_threshold' => ['name' => 'rate_ban_threshold', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_THRESHOLD_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_THRESHOLD_DESC', 'default' => '5', 'min' => '0', 'showon' => 'rate_enabled:1'],
                'rate_ban_window' => ['name' => 'rate_ban_window', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_WINDOW_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_WINDOW_DESC', 'default' => '300', 'min' => '1', 'showon' => 'rate_enabled:1'],
                'rate_ban_duration' => ['name' => 'rate_ban_duration', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_DURATION_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_RATE_BAN_DURATION_DESC', 'default' => '3600', 'min' => '1', 'showon' => 'rate_enabled:1'],
            ],
        ],
        'advanced' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_ADVANCED',
            'fields' => [
                'scan_body' => ['name' => 'scan_body', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SCAN_BODY_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_SCAN_BODY_DESC', 'default' => '1'],
                'scan_uploads' => ['name' => 'scan_uploads', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SCAN_UPLOADS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_SCAN_UPLOADS_DESC', 'default' => '1'],
                'upload_max_bytes' => ['name' => 'upload_max_bytes', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_UPLOAD_MAX_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_UPLOAD_MAX_DESC', 'default' => '10485760', 'min' => '0', 'showon' => 'scan_uploads:1'],
                'upload_allowlist' => ['name' => 'upload_allowlist', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_UPLOAD_ALLOWLIST_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_UPLOAD_ALLOWLIST_DESC', 'default' => '', 'showon' => 'scan_uploads:1'],
                'block_silent' => ['name' => 'block_silent', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_BLOCK_SILENT_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_BLOCK_SILENT_DESC', 'default' => '0'],
            ],
        ],
        'sitemanager' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_SITEMANAGER',
            'fields' => [
                'site_manager_enabled' => ['name' => 'site_manager_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_SITE_MANAGER_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_SITE_MANAGER_ENABLED_DESC', 'default' => '0'],
            ],
        ],
        'gemini' => [
            'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_FS_GEMINI',
            'fields' => [
                'gemini_enabled' => ['name' => 'gemini_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_ENABLED_DESC', 'default' => '0'],
                'gemini_api_key' => ['name' => 'gemini_api_key', 'type' => 'password', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_API_KEY_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_API_KEY_DESC', 'default' => '', 'showon' => 'gemini_enabled:1'],
                'gemini_model' => ['name' => 'gemini_model', 'type' => 'text', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_MODEL_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_MODEL_DESC', 'default' => 'gemini-3.5-flash-lite', 'showon' => 'gemini_enabled:1'],
                'gemini_schedule_enabled' => ['name' => 'gemini_schedule_enabled', 'type' => 'switch', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_SCHEDULE_ENABLED_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_SCHEDULE_ENABLED_DESC', 'default' => '0', 'showon' => 'gemini_enabled:1'],
                'gemini_schedule_hours' => ['name' => 'gemini_schedule_hours', 'type' => 'number', 'label' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_SCHEDULE_HOURS_LABEL', 'desc' => 'PLG_SYSTEM_COLORPACK_SHIELD_GEMINI_SCHEDULE_HOURS_DESC', 'default' => '24', 'min' => '1', 'max' => '168', 'step' => '1', 'showon' => 'gemini_schedule_enabled:1'],
            ],
        ],
    ];

    /**
     * @return array<string,array{label:string,fields:array<string,array<string,mixed>>}>
     */
    public static function fieldsets(): array
    {
        $sets = self::GENERATED;

        // WordPress-only switches.
        $sets['basic']['fields'] = [
            'waf_enabled' => ['name' => 'waf_enabled', 'type' => 'switch', 'label' => 'WPS_WAF_ENABLED_LABEL', 'desc' => 'WPS_WAF_ENABLED_DESC', 'default' => '0'],
        ] + $sets['basic']['fields'];
        $sets['sitemanager']['fields'] += [
            'fleet_ban' => ['name' => 'fleet_ban', 'type' => 'switch', 'label' => 'WPS_FLEET_BAN_LABEL', 'desc' => 'WPS_FLEET_BAN_DESC', 'default' => '1', 'showon' => 'site_manager_enabled:1'],
            'scan_schedule_enabled' => ['name' => 'scan_schedule_enabled', 'type' => 'switch', 'label' => 'WPS_SCAN_SCHEDULE_LABEL', 'desc' => 'WPS_SCAN_SCHEDULE_DESC', 'default' => '1'],
            'ip_country_lookup' => ['name' => 'ip_country_lookup', 'type' => 'switch', 'label' => 'WPS_IP_COUNTRY_LABEL', 'desc' => 'WPS_IP_COUNTRY_DESC', 'default' => '1'],
        ];

        foreach ($sets as $name => $set) {
            foreach ($set['fields'] as $key => $field) {
                if (isset(self::DEFAULT_OVERRIDES[$key])) {
                    $sets[$name]['fields'][$key]['default'] = self::DEFAULT_OVERRIDES[$key];
                }
            }
        }

        return $sets;
    }

    /**
     * @return array<string,array<string,mixed>>  every field by name
     */
    public static function fields(): array
    {
        $all = [];

        foreach (self::fieldsets() as $set) {
            $all += $set['fields'];
        }

        return $all;
    }
}
