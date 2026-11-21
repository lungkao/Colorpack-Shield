<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Network\HtmlView $this */
$n = $this->net;
$cpsLead = $n['installed'] ? Text::_('COM_COLORPACK_SHIELD_NET_DIAG_' . strtoupper($n['diag']['code'])) : Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING');
$level   = ['ok' => 'ok', 'warn' => 'warn', 'bad' => 'bad'][$n['diag']['level'] ?? ''] ?? 'info';
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <?php if (!$n['installed']) : ?>
            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
        <?php else : ?>
            <section class="cp-card" aria-labelledby="cps-net-seen">
                <h2 class="cp-card__title" id="cps-net-seen"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_SEEN'); ?></h2>
                <p><?php echo Ui::badge($level === 'info' ? '' : $level, Text::_('COM_COLORPACK_SHIELD_STATUS_' . (['ok' => 'OK', 'warn' => 'WARN', 'bad' => 'BAD'][$level] ?? 'UNKNOWN'))); ?></p>
                <dl class="cp-kv">
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_REMOTE'); ?></dt><dd class="cps-mono"><?php echo $this->escape($n['seen']['remote'] ?: '—'); ?></dd>
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_VISITOR'); ?></dt><dd class="cps-mono"><strong><?php echo $this->escape($n['seen']['resolved'] ?: '—'); ?></strong></dd>
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_VIA'); ?></dt><dd class="cps-mono"><?php echo $this->escape($n['seen']['via'] ?: '—'); ?></dd>
                </dl>
                <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_SEEN_NOTE'); ?></p>
            </section>

            <section class="cp-card" aria-labelledby="cps-net-probe">
                <h2 class="cp-card__title" id="cps-net-probe"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_PROBE'); ?></h2>
                <?php if ($n['probe'] === null) : ?>
                    <p><?php echo Ui::badge('', Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN')); ?></p>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_UNTESTED'); ?></p>
                    <?php $cpsProbeUi = $n['probeUi'] ?? null; $cpsReturn = 'network'; require __DIR__ . '/../probe.php'; ?>
                <?php else : ?>
                    <?php $v = $n['probe']['verdict']; ?>
                    <p><?php echo Ui::badge(['safe' => 'ok', 'no_proxy' => 'ok', 'spoofable' => 'bad'][$v] ?? '', Text::_('COM_COLORPACK_SHIELD_PROBE_V_' . strtoupper($v))); ?></p>
                    <p><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_PROBE_AGE', (int) $n['probe']['age']); ?></p>
                    <?php if ($v === 'spoofable') : ?><p><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_SPOOFABLE'); ?></p><?php endif; ?>
                    <?php $cpsProbeUi = $n['probeUi'] ?? null; $cpsReturn = 'network'; require __DIR__ . '/../probe.php'; ?>
                <?php endif; ?>
                <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_PROBE_NOTE'); ?></p>
            </section>

            <section class="cp-card" aria-labelledby="cps-net-cf">
                <h2 class="cp-card__title" id="cps-net-cf"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF'); ?></h2>
                <?php if (!$n['trustCloudflare']) : ?>
                    <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_NET_CF_OFF')); ?>
                <?php endif; ?>
                <dl class="cp-kv">
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SOURCE'); ?></dt><dd><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SRC_' . strtoupper($n['ranges']['source'])); ?></dd>
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_DATE'); ?></dt><dd><?php echo $n['ranges']['date'] !== null ? $this->escape($n['ranges']['date']) . ' · ' . Text::sprintf('COM_COLORPACK_SHIELD_NET_CF_AGE', (int) $n['ranges']['ageDays']) : '—'; ?></dd>
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_COUNT'); ?></dt><dd><?php echo (int) $n['ranges']['count']; ?></dd>
                    <dt><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_TASK'); ?></dt><dd>
                        <?php if ($n['scheduled'] === null) : ?>
                            <?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_TASK_UNKNOWN'); ?>
                        <?php else : ?>
                            <?php echo Ui::badge($n['scheduled'] ? 'ok' : 'warn', Text::_($n['scheduled'] ? 'COM_COLORPACK_SHIELD_NET_CF_TASK_YES' : 'COM_COLORPACK_SHIELD_NET_CF_TASK_NO')); ?>
                        <?php endif; ?>
                    </dd>
                </dl>
                <div class="cp-card__foot">
                    <?php if ($this->canChange && $n['ranges']['canSign']) : ?>
                        <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=network.refresh'); ?>" method="post">
                            <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_REFRESH'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                    <a class="btn btn-outline-secondary" href="<?php echo Route::_('index.php?option=com_scheduler&view=tasks'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SCHEDULER'); ?></a>
                </div>
                <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_NOTE'); ?></p>
            </section>

            <section class="cp-card" aria-labelledby="cps-net-lists">
                <h2 class="cp-card__title" id="cps-net-lists"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_LISTS'); ?></h2>
                <?php foreach (['proxies' => 'COM_COLORPACK_SHIELD_NET_PROXIES', 'allow' => 'COM_COLORPACK_SHIELD_NET_ALLOW'] as $k => $label) : ?>
                    <div>
                        <h3 class="cps-label"><?php echo Text::_($label); ?></h3>
                        <?php if ($n[$k]['entries'] === []) : ?>
                            <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_EMPTY'); ?></p>
                        <?php else : ?>
                            <p><?php foreach ($n[$k]['entries'] as $e) : ?><code><?php echo $this->escape($e); ?></code> <?php endforeach; ?></p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
                <?php if (($n['proxies']['invalid'] ?? 0) > 0) : ?>
                    <?php echo Ui::callout('warn', '', Text::sprintf('COM_COLORPACK_SHIELD_NET_INVALID', (int) $n['proxies']['invalid'])); ?>
                <?php endif; ?>
                <div class="cp-card__foot"><a class="btn btn-outline-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETTINGS'); ?></a></div>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
