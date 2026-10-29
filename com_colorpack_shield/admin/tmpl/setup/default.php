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

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Setup\HtmlView $this */
$plan    = $this->plan;
$markers = [1 => '', 2 => ' cps-marker-green', 3 => ' cps-marker-orange', 4 => ' cps-marker-red', 5 => ''];
$show    = static function ($v): string {
    if (\is_bool($v)) {
        return $v ? '1' : '0';
    }

    return \is_scalar($v) ? (string) $v : '';
};
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <?php if (!$plan['installed']) : ?>
        <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
    <?php else : ?>
        <div class="cps-stack">
            <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_INTRO'); ?></p>
            <?php if (!$this->canChange) : ?>
                <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY'); ?></div>
            <?php endif; ?>

            <?php foreach ($plan['steps'] as $n => $step) : ?>
                <section class="cps-card" aria-labelledby="cps-step-<?php echo (int) $n; ?>">
                    <div class="cps-step">
                        <span class="cps-marker<?php echo $markers[$n]; ?>" aria-hidden="true"><?php echo (int) $n; ?></span>
                        <div class="cps-stack" style="gap:8px;flex:1;min-width:0">
                            <h2 class="cps-h3" id="cps-step-<?php echo (int) $n; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP' . (int) $n . '_TITLE'); ?></h2>
                            <p><?php echo Text::_('COM_COLORPACK_SHIELD_STEP' . (int) $n . '_TEXT'); ?></p>

                            <?php if ($n === 4) : ?>
                                <?php if ($step['advice'] === 'already') : ?>
                                    <span class="cps-badge cps-badge-ok"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_ALREADY'); ?></span>
                                    <?php if ($plan['gateLink'] !== null) : ?>
                                        <div class="cps-alert cps-alert-info"><div>
                                            <?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_ON'); ?>
                                            <pre class="cps-log" id="cps-gate-link" tabindex="0" style="margin-top:8px"><?php echo $this->escape($plan['gateLink']); ?></pre>
                                            <div style="margin-top:8px"><button type="button" class="cps-btn cps-btn-sm" data-cps-copy="cps-gate-link" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button></div>
                                            <span class="cps-small"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_ON_NOTE'); ?></span>
                                        </div></div>
                                    <?php endif; ?>
                                <?php else : ?>
                                    <div class="cps-alert cps-alert-warn"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_SAFE'); ?></div>
                                <?php endif; ?>
                            <?php endif; ?>

                            <?php if ($n === 1) : ?>
                                <div class="cps-alert cps-alert-<?php echo in_array($step['advice'], ['safe', 'no_proxy'], true) ? 'ok' : ($step['advice'] === 'spoofable' ? 'bad' : 'info'); ?>">
                                    <div>
                                        <?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_' . strtoupper($step['advice'])); ?>
                                        <?php if ($step['advice'] === 'untested' || $step['advice'] === 'spoofable') : ?>
                                            <div style="margin-top:8px"><?php $cpsProbeUi = $plan['probeUi'] ?? null; $cpsReturn = 'setup'; require __DIR__ . '/../probe.php'; ?></div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if ($step['patch'] === []) : ?>
                                <?php if ($n !== 4) : ?><span class="cps-badge cps-badge-ok"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_NOTHING'); ?></span><?php endif; ?>
                            <?php else : ?>
                                <table class="cps-diff" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_DIFF')); ?>">
                                    <?php foreach ($step['patch'] as $key => $value) : ?>
                                        <tr>
                                            <td><?php echo $this->escape($key); ?></td>
                                            <td class="cps-muted"><?php echo $key === 'gate_key' ? (isset($step['current'][$key]) && $step['current'][$key] !== '' ? '•••' : '—') : ($this->escape($show($step['current'][$key] ?? '')) ?: '—'); ?></td>
                                            <td aria-hidden="true">→</td>
                                            <td><strong><?php echo $key === 'gate_key' ? $this->escape(Text::_('COM_COLORPACK_SHIELD_STEP4_NEWKEY')) : ($this->escape($show($value)) ?: '—'); ?></strong></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </table>
                                <?php if ($this->canChange) : ?>
                                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=setup.apply'); ?>" method="post">
                                        <input type="hidden" name="step" value="<?php echo (int) $n; ?>">
                                        <button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_APPLY'); ?></button>
                                        <?php echo HTMLHelper::_('form.token'); ?>
                                    </form>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </section>
            <?php endforeach; ?>

            <section class="cps-card">
                <div class="cps-step">
                    <span class="cps-marker" aria-hidden="true">5</span>
                    <div class="cps-stack" style="gap:8px">
                        <h2 class="cps-h3"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP5_TITLE'); ?></h2>
                        <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP5_TEXT'); ?></p>
                        <span class="cps-badge"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP5_LATER'); ?></span>
                    </div>
                </div>
            </section>
        </div>
    <?php endif; ?>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
