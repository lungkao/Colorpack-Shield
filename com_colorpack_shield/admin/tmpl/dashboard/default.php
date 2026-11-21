<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\DashboardPlanner;
use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Dashboard\HtmlView $this */
$s      = $this->summary;
$go     = static fn (string $screen, ?string $f = null): string => Route::_('index.php?option=com_colorpack_shield&view=' . $screen . ($f !== null ? '&field=' . $f : ''));
$number = static fn (int $n): string => number_format($n);
$tone   = ['ok' => 'ok', 'warn' => 'warn', 'bad' => 'bad', 'unknown' => ''];

// The answer: the headline of the checklist band, or why there is none.
$cpsLead = !$s['installed'] ? Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING') : Text::_('COM_COLORPACK_SHIELD_BAND_' . strtoupper($s['plan']['band'] ?? 'none'));
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <?php if (!$s['installed']) : ?>
            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
        <?php else : ?>
            <?php if (!$s['enabled']) : ?>
                <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_DISABLED')); ?>
            <?php endif; ?>
            <?php if (!$s['php_ok']) : ?>
                <?php echo Ui::callout('bad', '', Text::sprintf('COM_COLORPACK_SHIELD_PHP_OLD', PHP_VERSION)); ?>
            <?php endif; ?>
            <?php if (!$s['log']['readable']) : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_LOG_NONE')); ?>
            <?php elseif ($s['log']['truncated']) : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_LOG_TRUNCATED')); ?>
            <?php endif; ?>

            <?php if ($s['score'] !== null) :
                $sc    = $s['score'];
                $plan  = $s['plan'];
                $pct   = (int) ($sc['score'] ?? 0);
                $ringC = ['good' => 'ok', 'watch' => 'warn', 'risk' => 'bad', 'none' => ''][$plan['band']];
                $left  = $plan['counts']['warn'] + $plan['counts']['bad'] + $plan['counts']['unknown'];
                $title = $left > 0 ? Text::sprintf('COM_COLORPACK_SHIELD_TODO_LEFT', $left) : Text::_($plan['band'] === 'none' ? 'COM_COLORPACK_SHIELD_BAND_NONE' : 'COM_COLORPACK_SHIELD_TODO_NONE');
                ?>
                <div class="cp-split">
                    <section class="cp-card" aria-labelledby="cps-score-h">
                        <h2 class="cp-card__title" id="cps-score-h"><?php echo Text::_('COM_COLORPACK_SHIELD_SCORE_TITLE'); ?></h2>
                        <p class="cp-card__lead"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCORE_TESTED', (int) $sc['tested'], (int) $sc['total']); ?></p>
                        <div class="cps-hero">
                            <?php echo Ui::ring($pct, $ringC, (string) $pct, Text::_('COM_COLORPACK_SHIELD_RING_OF'), $pct . ' / 100'); ?>
                            <div class="cps-hero-text">
                                <?php echo Ui::callout($ringC !== '' ? $ringC : 'info', $title, Text::_('COM_COLORPACK_SHIELD_SCORE_NOTE')); ?>
                            </div>
                        </div>
                    </section>

                    <?php if ($plan['todo'] !== []) : ?>
                        <section class="cp-card" aria-labelledby="cps-todo-h">
                            <h2 class="cp-card__title" id="cps-todo-h"><?php echo Text::_('COM_COLORPACK_SHIELD_TODO_TITLE'); ?></h2>
                            <ol class="cp-todo">
                                <?php foreach ($plan['todo'] as $n => $t) : $tid = strtoupper($t['id']); ?>
                                    <li<?php echo $t['status'] === 'bad' ? ' data-state="bad"' : ($t['status'] === 'warn' ? '' : ' data-state="info"'); ?>>
                                        <div>
                                            <p class="cp-todo__title"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $tid); ?></p>
                                            <p class="cp-todo__text"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $tid . '_' . strtoupper($t['status'])); ?></p>
                                        </div>
                                        <?php if ($t['screen'] !== null) : ?>
                                            <div class="cp-todo__act"><a class="btn btn-sm <?php echo $n === 0 ? 'btn-primary' : 'btn-outline-secondary'; ?>" href="<?php echo $go($t['screen'], $t['field']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_' . strtoupper($t['screen'])); ?></a></div>
                                        <?php endif; ?>
                                    </li>
                                <?php endforeach; ?>
                            </ol>
                        </section>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if ($s['day'] !== null) :
                $scan = $s['scan'];
                $adm  = $s['admin'];
                $days = array_map(static fn (array $d): array => ['label' => substr($d['date'], 8, 2), 'a' => (int) $d['blocked'], 'b' => (int) $d['detected']], $s['daily']);
                ?>
                <div class="cp-grid cps-reports">
                    <section class="cp-card cp-stat" aria-labelledby="cps-rp-act">
                        <div class="cp-stat__head"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_ACTIVITY'); ?></span></div>
                        <h2 class="cp-card__title" id="cps-rp-act"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_REPORT_BLOCKED_N', $number($s['week']['blocked'])); ?></h2>
                        <?php echo Ui::bars($days, Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>
                        <p class="cp-legend"><span><i></i><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span><i class="cps-lg-log"></i><?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></span></p>
                        <div class="cp-card__foot"><a class="btn btn-sm btn-outline-secondary" href="<?php echo $go('activity'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_ACTIVITY'); ?></a></div>
                    </section>

                    <section class="cp-card cp-stat" aria-labelledby="cps-rp-scan">
                        <div class="cp-stat__head"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_SCAN'); ?></span></div>
                        <h2 class="cp-card__title" id="cps-rp-scan"><?php echo $scan === null ? Text::_('COM_COLORPACK_SHIELD_REPORT_SCAN_NEVER') : Text::sprintf('COM_COLORPACK_SHIELD_REPORT_SCAN_WHEN', gmdate('Y-m-d H:i', $scan['finished']) . ' UTC'); ?></h2>
                        <?php if ($scan !== null) : ?>
                            <div class="cps-mini">
                                <div data-state="<?php echo $scan['high'] > 0 ? 'bad' : 'ok'; ?>"><b><?php echo $number($scan['high']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_HIGH'); ?></span></div>
                                <div<?php echo $scan['medium'] > 0 ? ' data-state="warn"' : ''; ?>><b><?php echo $number($scan['medium']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM'); ?></span></div>
                                <div><b><?php echo $number($scan['changed']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_CHANGED'); ?></span></div>
                            </div>
                        <?php endif; ?>
                        <div class="cp-card__foot"><a class="btn btn-sm btn-outline-secondary" href="<?php echo $go('scan'); ?>"><?php echo Text::_($scan === null ? 'COM_COLORPACK_SHIELD_SCAN_START' : 'COM_COLORPACK_SHIELD_ACTION_SCAN'); ?></a></div>
                    </section>

                    <section class="cp-card cp-stat" aria-labelledby="cps-rp-adm">
                        <div class="cp-stat__head"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_LOGIN'); ?></span></div>
                        <h2 class="cp-card__title" id="cps-rp-adm"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_LOGIN_TITLE'); ?></h2>
                        <div class="cps-mini">
                            <div><b><?php echo $number($adm['blockedAdmin']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_BLOCKED_ADMIN'); ?></span></div>
                            <div><b><?php echo $number($adm['locks']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_LOCKOUTS'); ?></span></div>
                            <div><b><?php echo $number($adm['newIp']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWIP'); ?></span></div>
                        </div>
                        <div class="cp-card__foot"><a class="btn btn-sm btn-outline-secondary" href="<?php echo $go('login'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_LOGIN'); ?></a></div>
                    </section>
                </div>

                <div class="cp-grid">
                    <?php foreach (['topRules' => 'COM_COLORPACK_SHIELD_TOP_RULES', 'topPaths' => 'COM_COLORPACK_SHIELD_TOP_PATHS'] as $key => $label) : ?>
                        <section class="cp-card">
                            <h3 class="cp-card__title"><?php echo Text::_($label); ?> · <?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></h3>
                            <?php if ($s['week'][$key] === []) : ?>
                                <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                            <?php else : ?>
                                <ul class="cps-list">
                                    <?php foreach ($s['week'][$key] as $name => $count) : ?>
                                        <li><code class="cps-grow"><?php echo $this->escape((string) $name); ?></code><strong class="cp-num"><?php echo $number((int) $count); ?></strong></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                        </section>
                    <?php endforeach; ?>
                    <section class="cp-card">
                        <h3 class="cp-card__title"><?php echo Text::_('COM_COLORPACK_SHIELD_BY_APP'); ?></h3>
                        <?php if ($s['week']['byClient'] === []) : ?>
                            <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                        <?php else : ?>
                            <ul class="cps-list">
                                <?php foreach ($s['week']['byClient'] as $client => $c) : ?>
                                    <li><span class="cps-grow"><?php echo Text::_('COM_COLORPACK_SHIELD_CLIENT_' . strtoupper($client)); ?></span><span class="cp-num"><?php echo $number($c['blocked']); ?> / <?php echo $number($c['detected']); ?></span></li>
                                <?php endforeach; ?>
                            </ul>
                            <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_BY_APP_NOTE'); ?></p>
                        <?php endif; ?>
                    </section>
                </div>
            <?php endif; ?>

            <?php $vel = $s['vulnerable']; ?>
            <section class="cp-card" aria-labelledby="cps-vel-h">
                <p class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_VEL_EYEBROW'); ?></p>
                <h2 class="cp-card__title" id="cps-vel-h"><?php echo $vel === null ? Text::_('COM_COLORPACK_SHIELD_VEL_NEVER') : ($vel['count'] === 0 ? Text::_('COM_COLORPACK_SHIELD_VEL_NONE') : Text::sprintf('COM_COLORPACK_SHIELD_VEL_SOME', $vel['count'])); ?></h2>
                <?php if ($vel !== null && $vel['found'] !== []) : ?>
                    <ul class="cps-list">
                        <?php foreach ($vel['found'] as $f) : ?>
                            <li>
                                <span class="cps-grow"><strong><?php echo $this->escape($f['name']); ?></strong> <span class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_VEL_INSTALLED', $this->escape($f['installed'])); ?> · <?php echo $f['fixed'] !== null ? Text::sprintf('COM_COLORPACK_SHIELD_VEL_FIXED_IN', $this->escape($f['fixed'])) : Text::_('COM_COLORPACK_SHIELD_VEL_NOFIX'); ?></span></span>
                                <?php echo Ui::badge($f['sev'] === 'medium' ? 'warn' : 'bad', Text::_('COM_COLORPACK_SHIELD_VEL_SEV_' . strtoupper($f['sev']))); ?>
                                <a class="btn btn-sm btn-outline-secondary" href="<?php echo $this->escape($f['url']); ?>" target="_blank" rel="noopener noreferrer"><?php echo Text::_('COM_COLORPACK_SHIELD_VEL_DETAILS'); ?></a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
                <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_VEL_NOTE'); ?><?php echo $vel !== null ? ' ' . Text::sprintf('COM_COLORPACK_SHIELD_VEL_CHECKED', gmdate('Y-m-d H:i', $vel['at'])) : ''; ?></p>
                <form class="cp-card__foot" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=dashboard.checkVulnerable'); ?>" method="post">
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_VEL_CHECK_NOW'); ?></button>
                    <?php echo HTMLHelper::_('form.token'); ?>
                </form>
            </section>

            <?php if ($s['score'] !== null) : ?>
                <details class="cp-card cps-details">
                    <summary><?php echo Text::_('COM_COLORPACK_SHIELD_CHECKS_ALL'); ?>
                        <?php echo Ui::badge('ok', Text::_('COM_COLORPACK_SHIELD_STATUS_OK') . ' ' . (int) $s['plan']['counts']['ok']); ?>
                        <?php echo Ui::badge('warn', Text::_('COM_COLORPACK_SHIELD_STATUS_WARN') . ' ' . (int) ($s['plan']['counts']['warn'] + $s['plan']['counts']['bad'])); ?>
                        <?php echo Ui::badge('', Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN') . ' ' . (int) $s['plan']['counts']['unknown']); ?></summary>
                    <div>
                        <?php foreach ($s['score']['items'] as $it) : $id = strtoupper($it['id']); $st = $it['status']; $act = DashboardPlanner::action($it['id'], $st); ?>
                            <div class="cps-row">
                                <?php echo Ui::badge($tone[$st] ?? '', Text::_('COM_COLORPACK_SHIELD_STATUS_' . strtoupper($st))); ?>
                                <div class="cps-grow"><strong><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $id); ?></strong><div class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_ITEM_' . $id . '_' . strtoupper($st)); ?></div></div>
                                <?php if ($st !== 'ok' && $act['screen'] !== null) : ?>
                                    <a class="btn btn-sm btn-outline-secondary" href="<?php echo $go($act['screen'], $act['field']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_' . strtoupper($act['screen'])); ?></a>
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
