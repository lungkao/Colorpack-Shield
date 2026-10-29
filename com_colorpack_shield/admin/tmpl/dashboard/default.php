<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Dashboard\HtmlView $this */
$s      = $this->summary;
$link   = ['protection' => 'settings', 'real_ip' => 'setup', 'cloudflare_ranges' => 'network', 'lockout_safety' => 'setup', 'shields' => 'settings', 'coverage' => 'settings', 'rate_limit' => 'settings', 'admin_login' => 'settings', 'admin_door' => 'setup', 'file_scan' => 'scan', 'server_rules' => 'server'];
$field  = ['admin_login' => 'login_lockout', 'shields' => 'shield_sqli', 'coverage' => 'cover_site', 'rate_limit' => 'rate_enabled'];
$go     = static fn (string $screen, ?string $f = null): string => Route::_('index.php?option=com_colorpack_shield&view=' . $screen . ($f !== null ? '&field=' . $f : ''));
$number = static fn (int $n): string => number_format($n);
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <?php if (!$s['installed']) : ?>
            <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <?php if (!$s['enabled']) : ?>
                <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_DISABLED'); ?></div>
            <?php endif; ?>
            <?php if (!$s['php_ok']) : ?>
                <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_PHP_OLD', $this->escape(PHP_VERSION)); ?></div>
            <?php endif; ?>
            <?php if (!$s['log']['readable']) : ?>
                <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_NONE'); ?></div>
            <?php elseif ($s['log']['truncated']) : ?>
                <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_TRUNCATED'); ?></div>
            <?php endif; ?>

            <?php if ($s['score'] !== null) :
                $sc    = $s['score'];
                $plan  = $s['plan'];
                $pct   = (int) ($sc['score'] ?? 0);
                $ringC = ['good' => 'ok', 'watch' => 'warn', 'risk' => 'bad', 'none' => 'none'][$plan['band']];
                $left  = $plan['counts']['warn'] + $plan['counts']['bad'] + $plan['counts']['unknown'];
                $first = $plan['todo'][0] ?? null;
                $dot   = ['ok' => 'cps-dot-ok', 'warn' => 'cps-dot-warn', 'bad' => 'cps-dot-bad', 'unknown' => ''];
                ?>
                <section class="cps-card" aria-labelledby="cps-score-h">
                    <div class="cps-hero">
                        <div class="cps-ring cps-ring-<?php echo $ringC; ?>" style="--p:<?php echo $pct; ?>" role="img" aria-label="<?php echo $pct; ?> / 100"><i><b><?php echo $pct; ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_RING_OF'); ?></span></i></div>
                        <div class="cps-hero-text">
                            <p class="cps-eyebrow"><?php echo Text::_('COM_COLORPACK_SHIELD_SCORE_TITLE'); ?> · <?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCORE_TESTED', (int) $sc['tested'], (int) $sc['total']); ?></p>
                            <h2 id="cps-score-h"><?php echo Text::_('COM_COLORPACK_SHIELD_BAND_' . strtoupper($plan['band'])); ?></h2>
                            <?php if ($left > 0) : ?><span class="cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_TODO_LEFT', $left); ?></span><?php endif; ?>
                            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCORE_NOTE'); ?></p>
                        </div>
                    </div>
                    <?php if ($first !== null) : $fid = strtoupper($first['id']); ?>
                        <div class="cps-next">
                            <span class="cps-badge cps-badge-warn"><?php echo Text::_('COM_COLORPACK_SHIELD_TODO_TITLE'); ?></span>
                            <strong><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $fid); ?></strong>
                            <span class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $fid . '_' . strtoupper($first['status'])); ?></span>
                            <a class="cps-btn cps-btn-primary" href="<?php echo $go($first['screen'], $first['field']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_' . strtoupper($first['screen'])); ?></a>
                        </div>
                    <?php endif; ?>
                </section>

                <?php if (\count($plan['todo']) > 1) : ?>
                    <section class="cps-card" aria-labelledby="cps-todo-h">
                        <h2 class="cps-h3" id="cps-todo-h"><?php echo Text::_('COM_COLORPACK_SHIELD_TODO_TITLE'); ?></h2>
                        <div>
                            <?php foreach (\array_slice($plan['todo'], 1) as $n => $t) : $tid = strtoupper($t['id']); ?>
                                <div class="cps-todo">
                                    <span class="cps-marker <?php echo $t['status'] === 'bad' ? 'cps-marker-red' : ($t['status'] === 'warn' ? 'cps-marker-orange' : ''); ?>" aria-hidden="true"><?php echo $n + 2; ?></span>
                                    <div class="cps-todo-t"><h3><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $tid); ?></h3><span class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $tid . '_' . strtoupper($t['status'])); ?></span></div>
                                    <a class="cps-btn" href="<?php echo $go($t['screen'], $t['field']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_' . strtoupper($t['screen'])); ?></a>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </section>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($s['day'] !== null) :
                $peak = max(1, ...array_map(static fn (array $d): int => $d['blocked'] + $d['detected'], $s['daily']));
                $bar  = static fn (int $n): int => $n > 0 ? max(4, (int) round($n / $peak * 120)) : 0;
                $scan = $s['scan'];
                $adm  = $s['admin'];
                ?>
                <div class="cps-reports">
                    <section class="cps-card" aria-labelledby="cps-rp-act">
                        <p class="cps-eyebrow"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_ACTIVITY'); ?></p>
                        <h2 class="cps-h3" id="cps-rp-act" style="color:var(--ink)"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_REPORT_BLOCKED_N', $number($s['week']['blocked'])); ?></h2>
                        <div class="cps-chart" role="img" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>">
                            <?php foreach ($s['daily'] as $d) : ?>
                                <div class="cps-col"><div class="cps-stack-bars"><i class="cps-bar-log" style="height:<?php echo $bar($d['detected']); ?>px"></i><i style="height:<?php echo $bar($d['blocked']); ?>px"></i></div><small><?php echo $this->escape(substr($d['date'], 8, 2)); ?></small></div>
                            <?php endforeach; ?>
                        </div>
                        <div class="cps-legend"><span><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span class="cps-lg-log"><?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></span></div>
                        <div class="cps-card-foot"><a class="cps-btn cps-btn-sm" href="<?php echo $go('activity'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_ACTIVITY'); ?></a></div>
                    </section>

                    <section class="cps-card" aria-labelledby="cps-rp-scan">
                        <p class="cps-eyebrow"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_SCAN'); ?></p>
                        <h2 class="cps-h3" id="cps-rp-scan" style="color:var(--ink)"><?php echo $scan === null ? Text::_('COM_COLORPACK_SHIELD_REPORT_SCAN_NEVER') : Text::sprintf('COM_COLORPACK_SHIELD_REPORT_SCAN_WHEN', gmdate('Y-m-d H:i', $scan['finished']) . ' UTC'); ?></h2>
                        <?php if ($scan !== null) : ?>
                            <div class="cps-mini">
                                <div><b style="color:<?php echo $scan['high'] > 0 ? 'var(--red-deep)' : 'var(--green-deep)'; ?>"><?php echo $number($scan['high']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_HIGH'); ?></span></div>
                                <div><b style="color:var(--orange-deep)"><?php echo $number($scan['medium']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM'); ?></span></div>
                                <div><b><?php echo $number($scan['changed']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_CHANGED'); ?></span></div>
                            </div>
                        <?php endif; ?>
                        <div class="cps-card-foot"><a class="cps-btn cps-btn-sm cps-btn-primary" href="<?php echo $go('scan'); ?>"><?php echo Text::_($scan === null ? 'COM_COLORPACK_SHIELD_SCAN_START' : 'COM_COLORPACK_SHIELD_ACTION_SCAN'); ?></a></div>
                    </section>

                    <section class="cps-card" aria-labelledby="cps-rp-adm">
                        <p class="cps-eyebrow"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_LOGIN'); ?></p>
                        <h2 class="cps-h3" id="cps-rp-adm" style="color:var(--ink)"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_LOGIN_TITLE'); ?></h2>
                        <div class="cps-mini">
                            <div><b><?php echo $number($adm['blockedAdmin']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_BLOCKED_ADMIN'); ?></span></div>
                            <div><b><?php echo $number($adm['locks']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_LOCKOUTS'); ?></span></div>
                            <div><b><?php echo $number($adm['newIp']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWIP'); ?></span></div>
                        </div>
                        <div class="cps-card-foot"><a class="cps-btn cps-btn-sm" href="<?php echo $go('login'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_LOGIN'); ?></a></div>
                    </section>
                </div>

                <div class="cps-grid">
                    <?php foreach (['topRules' => 'COM_COLORPACK_SHIELD_TOP_RULES', 'topPaths' => 'COM_COLORPACK_SHIELD_TOP_PATHS'] as $key => $label) : ?>
                        <section class="cps-card">
                            <h3 class="cps-h3"><?php echo Text::_($label); ?> · <?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></h3>
                            <?php if ($s['week'][$key] === []) : ?>
                                <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                            <?php else : ?>
                                <ul class="cps-list">
                                    <?php foreach ($s['week'][$key] as $name => $count) : ?>
                                        <li><code class="cps-grow"><?php echo $this->escape((string) $name); ?></code><strong><?php echo $number((int) $count); ?></strong></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                        </section>
                    <?php endforeach; ?>
                    <section class="cps-card">
                        <h3 class="cps-h3"><?php echo Text::_('COM_COLORPACK_SHIELD_BY_APP'); ?></h3>
                        <?php if ($s['week']['byClient'] === []) : ?>
                            <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                        <?php else : ?>
                            <ul class="cps-list">
                                <?php foreach ($s['week']['byClient'] as $client => $c) : ?>
                                    <li><span class="cps-grow"><?php echo Text::_('COM_COLORPACK_SHIELD_CLIENT_' . strtoupper($client)); ?></span><span><?php echo $number($c['blocked']); ?> / <?php echo $number($c['detected']); ?></span></li>
                                <?php endforeach; ?>
                            </ul>
                            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_BY_APP_NOTE'); ?></p>
                        <?php endif; ?>
                    </section>
                </div>
            <?php endif; ?>

            <?php if ($s['score'] !== null) : ?>
                <details class="cps-card">
                    <summary><?php echo Text::_('COM_COLORPACK_SHIELD_CHECKS_ALL'); ?>
                        <span class="cps-badge cps-badge-ok"><?php echo (int) $s['plan']['counts']['ok']; ?></span>
                        <span class="cps-badge cps-badge-warn"><?php echo (int) ($s['plan']['counts']['warn'] + $s['plan']['counts']['bad']); ?></span>
                        <span class="cps-badge"><?php echo (int) $s['plan']['counts']['unknown']; ?></span></summary>
                    <div>
                        <?php foreach ($s['score']['items'] as $it) : $id = strtoupper($it['id']); $st = $it['status']; ?>
                            <div class="cps-row" style="align-items:flex-start;flex-wrap:wrap">
                                <span class="cps-dot <?php echo $dot[$st] ?? ''; ?>" style="margin-top:8px" aria-hidden="true"></span>
                                <div style="flex:1 1 260px;min-width:0"><strong><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $id); ?></strong> · <span class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_STATUS_' . strtoupper($st)); ?></span><div class="cps-small"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $id . '_' . strtoupper($st)); ?></div></div>
                                <?php if ($st !== 'ok' && isset($link[$it['id']])) : ?>
                                    <a class="cps-btn cps-btn-sm" href="<?php echo $go($link[$it['id']], $field[$it['id']] ?? null); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_' . strtoupper($link[$it['id']])); ?></a>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </details>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
