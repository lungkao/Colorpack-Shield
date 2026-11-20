<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Network\HtmlView $this */
$n = $this->net;
?>
<div id="cps-app" class="j-main-container">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="d-flex flex-column gap-3">
        <?php if (!$n['installed']) : ?>
            <div class="alert alert-danger" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <section class="card card-body" aria-labelledby="cps-net-seen">
                <h2 class="h5" id="cps-net-seen"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_SEEN'); ?></h2>
                <div class="alert alert-<?php echo ['ok' => 'success', 'warn' => 'warning', 'bad' => 'danger'][$n['diag']['level']] ?? 'info'; ?>">
                    <div><?php echo Text::_('COM_COLORPACK_SHIELD_NET_DIAG_' . strtoupper($n['diag']['code'])); ?></div>
                </div>
                <table class="table">
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_REMOTE'); ?></td><td class="font-monospace"><?php echo $this->escape($n['seen']['remote'] ?: '—'); ?></td></tr>
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_VISITOR'); ?></td><td class="font-monospace"><strong><?php echo $this->escape($n['seen']['resolved'] ?: '—'); ?></strong></td></tr>
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_VIA'); ?></td><td class="font-monospace"><?php echo $this->escape($n['seen']['via'] ?: '—'); ?></td></tr>
                </table>
                <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_SEEN_NOTE'); ?></p>
            </section>

            <section class="card card-body" aria-labelledby="cps-net-probe">
                <h2 class="h5" id="cps-net-probe"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_PROBE'); ?></h2>
                <?php if ($n['probe'] === null) : ?>
                    <span class="badge"><?php echo Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN'); ?></span>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_UNTESTED'); ?></p>
                    <?php $cpsProbeUi = $n['probeUi'] ?? null; $cpsReturn = 'network'; require __DIR__ . '/../probe.php'; ?>
                <?php else : ?>
                    <?php $v = $n['probe']['verdict']; ?>
                    <span class="badge <?php echo ['safe' => 'bg-success', 'no_proxy' => 'bg-success', 'spoofable' => 'bg-danger'][$v] ?? ''; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_V_' . strtoupper($v)); ?></span>
                    <p><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_PROBE_AGE', (int) $n['probe']['age']); ?></p>
                    <?php if ($v === 'spoofable') : ?><p><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_SPOOFABLE'); ?></p><?php endif; ?>
                    <?php $cpsProbeUi = $n['probeUi'] ?? null; $cpsReturn = 'network'; require __DIR__ . '/../probe.php'; ?>
                <?php endif; ?>
                <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_PROBE_NOTE'); ?></p>
            </section>

            <section class="card card-body" aria-labelledby="cps-net-cf">
                <h2 class="h5" id="cps-net-cf"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF'); ?></h2>
                <?php if (!$n['trustCloudflare']) : ?>
                    <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_OFF'); ?></div>
                <?php endif; ?>
                <table class="table">
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SOURCE'); ?></td><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SRC_' . strtoupper($n['ranges']['source'])); ?></td></tr>
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_DATE'); ?></td><td><?php echo $n['ranges']['date'] !== null ? $this->escape($n['ranges']['date']) . ' · ' . Text::sprintf('COM_COLORPACK_SHIELD_NET_CF_AGE', (int) $n['ranges']['ageDays']) : '—'; ?></td></tr>
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_COUNT'); ?></td><td><?php echo (int) $n['ranges']['count']; ?></td></tr>
                    <tr><td><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_TASK'); ?></td><td>
                        <?php if ($n['scheduled'] === null) : ?>
                            <?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_TASK_UNKNOWN'); ?>
                        <?php else : ?>
                            <span class="badge <?php echo $n['scheduled'] ? 'bg-success' : 'bg-warning text-dark'; ?>"><?php echo Text::_($n['scheduled'] ? 'COM_COLORPACK_SHIELD_NET_CF_TASK_YES' : 'COM_COLORPACK_SHIELD_NET_CF_TASK_NO'); ?></span>
                        <?php endif; ?>
                    </td></tr>
                </table>
                <div class="d-flex flex-wrap gap-2 align-items-center mt-3">
                    <?php if ($this->canChange && $n['ranges']['canSign']) : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=network.refresh'); ?>" method="post">
                            <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_REFRESH'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                    <a class="btn btn-secondary" href="<?php echo Route::_('index.php?option=com_scheduler&view=tasks'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_SCHEDULER'); ?></a>
                </div>
                <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_CF_NOTE'); ?></p>
            </section>

            <section class="card card-body" aria-labelledby="cps-net-lists">
                <h2 class="h5" id="cps-net-lists"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_LISTS'); ?></h2>
                <?php foreach (['proxies' => 'COM_COLORPACK_SHIELD_NET_PROXIES', 'allow' => 'COM_COLORPACK_SHIELD_NET_ALLOW'] as $k => $label) : ?>
                    <div>
                        <p class="cps-label text-muted"><?php echo Text::_($label); ?></p>
                        <?php if ($n[$k]['entries'] === []) : ?>
                            <p class="text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NET_EMPTY'); ?></p>
                        <?php else : ?>
                            <p><?php foreach ($n[$k]['entries'] as $e) : ?><code><?php echo $this->escape($e); ?></code> <?php endforeach; ?></p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
                <?php if (($n['proxies']['invalid'] ?? 0) > 0) : ?>
                    <div class="alert alert-warning"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_INVALID', (int) $n['proxies']['invalid']); ?></div>
                <?php endif; ?>
                <div class="d-flex flex-wrap gap-2 align-items-center mt-3"><a class="btn btn-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETTINGS'); ?></a></div>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
