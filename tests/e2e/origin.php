<?php
/**
 * Router for `php -S`: the "origin" web server. Runs the real plugin class
 * (with Joomla stand-ins) for every request. Env: CPS_E2E_SECRET, CPS_E2E_PARAMS (JSON).
 * Used only by tests/e2e_proxy_probe.php.
 */

\define('_JEXEC', 1);
\define('JPATH_ROOT', sys_get_temp_dir() . '/cps-e2e-nonexistent-root');
\define('JPATH_ADMINISTRATOR', JPATH_ROOT . '/administrator');
\define('JPATH_CACHE', JPATH_ROOT . '/cache');

require_once __DIR__ . '/../stubs/joomla.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'Colorpack\\Plugin\\System\\ColorpackShield\\';

    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/../../plugins/system/colorpack_shield/src/' . str_replace('\\', '/', substr($class, \strlen($prefix))) . '.php';

        if (is_file($file)) {
            require_once $file;
        }
    }
});

$subject = new stdClass();
$plugin  = new Colorpack\Plugin\System\ColorpackShield\Extension\ColorpackShield(
    $subject,
    ['params' => json_decode((string) getenv('CPS_E2E_PARAMS'), true) ?: []]
);
$plugin->setApplication(new Colorpack\Tests\FakeApp('site', ['secret' => (string) getenv('CPS_E2E_SECRET')]));

try {
    $plugin->onAfterInitialise(new Joomla\Event\Event('onAfterInitialise'));
    echo 'NOT-A-PROBE';
} catch (Colorpack\Tests\RequestEnded $e) {
    // the plugin ended the request; its JSON is already echoed
}
