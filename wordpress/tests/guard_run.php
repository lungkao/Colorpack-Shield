<?php
/**
 * Runs ONE request through the WordPress guard (Waf\Bootstrap) with a tiny stand-in for the WordPress
 * functions it calls, in its own process because a blocked request ends with exit.
 *
 * Usage: php guard_run.php '<json: {"settings":{...},"server":{...},"get":{...},"post":{...},"files":{...},"dir":"..."}>'
 * Prints "PASSED" when the request was let through; a blocked one prints what the guard answered.
 */

define('COLORPACK_SHIELD_WP_TEST', 1);
define('ABSPATH', '/nonexistent-abspath/');

if (isset(json_decode((string) ($argv[1] ?? '{}'), true)['content'])) {
    define('WP_CONTENT_DIR', json_decode((string) $argv[1], true)['content']);
}

$in = json_decode((string) ($argv[1] ?? '{}'), true) ?: [];

spl_autoload_register(static function (string $class): void {
    $prefix = 'Colorpack\\WP\\ColorpackShield\\';

    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/../colorpack-shield/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

        if (is_file($file)) {
            require_once $file;
        }
    }
});

$GLOBALS['cps_options'] = ['colorpack_shield_settings' => $in['settings'] ?? []];
$GLOBALS['cps_dir']     = $in['dir'] ?? sys_get_temp_dir();

function add_action(...$a): void {}
function apply_filters(string $tag, $value) { return $value; }
function get_option(string $k, $d = false) { return $GLOBALS['cps_options'][$k] ?? $d; }
function update_option(string $k, $v): bool { $GLOBALS['cps_options'][$k] = $v; return true; }
function delete_option(string $k): bool { return true; }
function wp_unslash($v) { return $v; }
function is_admin(): bool { return !empty($GLOBALS['cps_is_admin']); }
function trailingslashit(string $s): string { return rtrim($s, '/') . '/'; }
function wp_upload_dir(): array { return ['basedir' => $GLOBALS['cps_dir']]; }
function get_user_locale(): string { return 'en_US'; }
function wp_mail(...$a): bool { return true; }

$_SERVER = array_merge(['REMOTE_ADDR' => '198.51.100.20', 'REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET'], $in['server'] ?? []);
$_GET    = $in['get'] ?? [];
$_POST   = $in['post'] ?? [];
$_FILES  = $in['files'] ?? [];
$GLOBALS['cps_is_admin'] = !empty($in['admin']);

register_shutdown_function(static function (): void {
    // A guard that blocks calls exit; anything printed before then is its answer.
});

\Colorpack\WP\ColorpackShield\Waf\Bootstrap::maybeInspect();

echo 'PASSED';
