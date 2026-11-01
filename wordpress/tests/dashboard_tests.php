<?php
/**
 * ScoreCalculator (WordPress-specific, not a port - see its own docblock for why) and
 * DashboardPlanner (ported from the Joomla edition, pure ranking/wording logic, its FIX/FIELD/
 * PRIORITY maps trimmed to the 4 items this port scores). New tests rather than a port of the
 * Joomla edition's DashboardPlanner assertions in component_core_tests.php: those exercise
 * Joomla-only item ids (real_ip, rate_limit, shields, coverage, lockout_safety) that don't exist
 * in this port's trimmed maps, so the exact old expectations don't carry over - the underlying
 * ranking/banding logic being tested is unchanged, just exercised against this port's own item
 * set. Included by run.php.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Admin\DashboardPlanner;
use Colorpack\WP\ColorpackShield\Admin\ScoreCalculator;

echo "== Dashboard: score calculator ==\n";

$sc = static fn (array $f): array => ScoreCalculator::calculate($f);

ok('all four on/clean, MFA enforced -> 100, everything tested', $sc(['waf_enabled' => true, 'login_lockout' => true, 'mfa_enforce' => 'enforce', 'admin_door' => true, 'file_scan' => ['high' => 0, 'age' => 1]]) === ['score' => 100, 'tested' => 4, 'total' => 4, 'items' => [
    ['id' => 'protection', 'weight' => 30, 'status' => 'ok'],
    ['id' => 'admin_login', 'weight' => 30, 'status' => 'ok'],
    ['id' => 'admin_door', 'weight' => 15, 'status' => 'ok'],
    ['id' => 'file_scan', 'weight' => 25, 'status' => 'ok'],
]]);

ok('admin_login: lock-out off is bad regardless of MFA; lock-out on without MFA enforced is a warning, not a failure; lock-out on with MFA enforced is ok', $sc(['login_lockout' => false, 'mfa_enforce' => 'enforce'])['items'][1]['status'] === 'bad'
    && $sc(['login_lockout' => true, 'mfa_enforce' => 'off'])['items'][1]['status'] === 'warn'
    && $sc(['login_lockout' => true, 'mfa_enforce' => 'warn'])['items'][1]['status'] === 'warn'
    && $sc(['login_lockout' => true, 'mfa_enforce' => 'enforce'])['items'][1]['status'] === 'ok');

ok('everything off/missing -> low score, file_scan unknown (never scanned) so not counted against it', (static function () use ($sc): bool {
    $r = $sc(['waf_enabled' => false, 'login_lockout' => false, 'admin_door' => false, 'file_scan' => null]);

    return $r['tested'] === 3 && $r['score'] === 0 && array_column($r['items'], 'status', 'id') === ['protection' => 'bad', 'admin_login' => 'bad', 'admin_door' => 'warn', 'file_scan' => 'unknown'];
})());

ok('admin_door is a warning (recommended), not a failure, when off', $sc(['waf_enabled' => true, 'login_lockout' => true, 'admin_door' => false, 'file_scan' => ['high' => 0, 'age' => 1]])['items'][2] === ['id' => 'admin_door', 'weight' => 15, 'status' => 'warn']);

ok('file_scan: a high-severity finding is bad regardless of age; an old clean scan is a warning; a recent clean scan is ok', $sc(['waf_enabled' => true, 'login_lockout' => true, 'admin_door' => true, 'file_scan' => ['high' => 1, 'age' => 0]])['items'][3]['status'] === 'bad'
    && $sc(['waf_enabled' => true, 'login_lockout' => true, 'admin_door' => true, 'file_scan' => ['high' => 0, 'age' => 31]])['items'][3]['status'] === 'warn'
    && $sc(['waf_enabled' => true, 'login_lockout' => true, 'admin_door' => true, 'file_scan' => ['high' => 0, 'age' => 30]])['items'][3]['status'] === 'ok');

ok('no facts at all -> every item falls back to its "off" default, nothing is ever unknown except file_scan', $sc([])['score'] === 0 && $sc([])['items'][3]['status'] === 'unknown');

echo "== Dashboard: planner ==\n";

$items = static fn (array $st): array => array_map(static fn (string $id, string $s): array => ['id' => $id, 'weight' => 10, 'status' => $s], array_keys($st), array_values($st));

$pl = DashboardPlanner::plan(['score' => 60, 'items' => $items(['protection' => 'ok', 'admin_login' => 'warn', 'admin_door' => 'warn', 'file_scan' => 'bad'])]);
ok('todo holds only things not ok, bad before warn, protection-weighted priority within the same severity', array_column($pl['todo'], 'id') === ['file_scan', 'admin_login', 'admin_door'] && $pl['counts'] === ['ok' => 1, 'warn' => 2, 'bad' => 1, 'unknown' => 0]);

ok('a critical item comes before a warning, whatever its usual priority order', array_column(DashboardPlanner::plan(['score' => 70, 'items' => $items(['admin_door' => 'bad', 'admin_login' => 'warn'])])['todo'], 'id') === ['admin_door', 'admin_login']);

ok('band: good needs a high number and nothing critical; one critical item caps it; low numbers are risk; no score is "none"', DashboardPlanner::plan(['score' => 90, 'items' => $items(['protection' => 'ok'])])['band'] === 'good'
    && DashboardPlanner::plan(['score' => 90, 'items' => $items(['protection' => 'bad'])])['band'] === 'watch' && DashboardPlanner::plan(['score' => 70, 'items' => $items(['protection' => 'bad'])])['band'] === 'risk'
    && DashboardPlanner::plan(['score' => 40, 'items' => $items(['protection' => 'ok'])])['band'] === 'risk' && DashboardPlanner::plan(['score' => 60, 'items' => $items(['protection' => 'warn'])])['band'] === 'watch'
    && DashboardPlanner::plan(['score' => null, 'items' => []])['band'] === 'none');

ok('an all-good list has an empty todo; an unknown item id still gets a screen (the default "settings")', DashboardPlanner::plan(['score' => 100, 'items' => $items(['protection' => 'ok'])])['todo'] === []
    && DashboardPlanner::plan(['score' => 50, 'items' => [['id' => 'mystery', 'weight' => 1, 'status' => 'warn']]])['todo'][0]['screen'] === 'settings');

ok('each of the 4 known items maps to a screen and (where relevant) a field', DashboardPlanner::action('protection', 'bad') === ['screen' => 'settings', 'field' => 'waf_enabled']
    && DashboardPlanner::action('admin_login', 'bad') === ['screen' => 'settings', 'field' => 'login_protect_enabled']
    && DashboardPlanner::action('admin_door', 'warn') === ['screen' => 'settings', 'field' => 'gate_enabled']
    && DashboardPlanner::action('file_scan', 'bad') === ['screen' => 'scan', 'field' => null]);

ok('the maximum is respected (at least one)', count(DashboardPlanner::plan(['score' => 50, 'items' => $items(['a' => 'warn', 'b' => 'warn', 'c' => 'warn', 'd' => 'warn'])], 2)['todo']) === 2
    && count(DashboardPlanner::plan(['score' => 50, 'items' => $items(['a' => 'warn', 'b' => 'warn'])], 0)['todo']) === 1);
