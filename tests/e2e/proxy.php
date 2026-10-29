<?php
/**
 * Router for `php -S`: emulates an nginx-style reverse proxy in front of the
 * origin — appends the connecting address to X-Forwarded-For
 * ($proxy_add_x_forwarded_for) and sets X-Real-IP itself.
 *
 * Env: CPS_E2E_ORIGIN (host:port of the origin); CPS_E2E_CLIENT (optional) —
 * pretend the connecting client had this address, to emulate a tester coming
 * from outside the server (a real nginx would see its real peer).
 * Used only by tests/e2e_proxy_probe.php.
 */

$client = getenv('CPS_E2E_CLIENT') ?: ($_SERVER['REMOTE_ADDR'] ?? '');
$origin = (string) getenv('CPS_E2E_ORIGIN');

$headers = [];

foreach (getallheaders() as $name => $value) {
    $lower = strtolower($name);

    if (\in_array($lower, ['x-forwarded-for', 'x-real-ip', 'host', 'content-length', 'connection'], true)) {
        continue;
    }

    $headers[] = "$name: $value";
}

$incoming  = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$headers[] = 'X-Forwarded-For: ' . ($incoming !== '' ? $incoming . ', ' : '') . $client;
$headers[] = 'X-Real-IP: ' . $client;

$ch = curl_init('http://' . $origin . ($_SERVER['REQUEST_URI'] ?? '/'));
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 10]);
echo (string) curl_exec($ch);
unset($ch);
