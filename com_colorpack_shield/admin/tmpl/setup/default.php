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

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Setup\HtmlView $this */
$plan = $this->plan;
$show = static function ($v): string {
    if (\is_bool($v)) {
        return $v ? '1' : '0';
    }

    return \is_scalar($v) ? (string) $v : '';
};
$cpsLead = Text::_($plan['installed'] ? 'COM_COLORPACK_SHIELD_SETUP_INTRO' : 'COM_COLORPACK_SHIELD_PLUGIN_MISSING');
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <?php if (!$plan['installed']) : ?>
        <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
    <?php else : ?>
        <div class="cps-flow">
            <?php if (!$this->canChange) : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY')); ?>
            <?php endif; ?>

            <ol class="cps-steps">
            <?php foreach ($plan['steps'] as $n => $step) : ?>
                <li class="cp-card">
                    <div class="cps-step">
                        <span class="cps-marker" aria-hidden="true"><?php echo (int) $n; ?></span>
                        <div class="cp-stack">
                            <h2 class="cp-card__title" id="cps-step-<?php echo (int) $n; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP' . (int) $n . '_TITLE'); ?></h2>
                            <p><?php echo Text::_('COM_COLORPACK_SHIELD_STEP' . (int) $n . '_TEXT'); ?></p>

                            <?php if ($n === 4) : ?>
                                <?php if ($step['advice'] === 'already') : ?>
                                    <p><?php echo Ui::badge('ok', Text::_('COM_COLORPACK_SHIELD_STEP4_ALREADY')); ?></p>
                                    <?php if ($plan['gateLink'] !== null) : ?>
                                        <?php echo Ui::calloutStart('info'); ?>
                                            <p class="cp-callout__text"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_ON'); ?></p>
                                            <pre class="cp-code" id="cps-gate-link" tabindex="0"><?php echo $this->escape($plan['gateLink']); ?></pre>
                                            <div><button type="button" class="btn btn-sm btn-outline-secondary" data-cps-copy="cps-gate-link" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button></div>
                                            <p class="cp-callout__text cp-small"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP4_ON_NOTE'); ?></p>
                                        <?php echo Ui::calloutEnd(); ?>
                                    <?php endif; ?>
                                <?php else : ?>
                                    <?php echo Ui::callout('warn', '', Text::_('COM_COLORPACK_SHIELD_STEP4_SAFE')); ?>
                                <?php endif; ?>
                            <?php endif; ?>

                            <?php if ($n === 1) : ?>
                                <?php echo Ui::calloutStart(in_array($step['advice'], ['safe', 'no_proxy'], true) ? 'ok' : ($step['advice'] === 'spoofable' ? 'bad' : 'info')); ?>
                                    <p class="cp-callout__text"><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_' . strtoupper($step['advice'])); ?></p>
                                    <?php if ($step['advice'] === 'untested' || $step['advice'] === 'spoofable') : ?>
                                        <div class="cp-stack"><?php $cpsProbeUi = $plan['probeUi'] ?? null; $cpsReturn = 'setup'; require __DIR__ . '/../probe.php'; ?></div>
                                    <?php endif; ?>
                                <?php echo Ui::calloutEnd(); ?>
                            <?php endif; ?>

                            <?php if ($step['patch'] === []) : ?>
                                <?php if ($n !== 4) : ?><p><?php echo Ui::badge('ok', Text::_('COM_COLORPACK_SHIELD_SETUP_NOTHING')); ?></p><?php endif; ?>
                            <?php else : ?>
                                <div class="cp-tablewrap" role="region" tabindex="0" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_DIFF')); ?>">
                                    <table class="cps-diff" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_DIFF')); ?>">
                                        <?php foreach ($step['patch'] as $key => $value) : ?>
                                            <tr>
                                                <td><?php echo $this->escape($key); ?></td>
                                                <td class="cp-muted"><?php echo $key === 'gate_key' ? (isset($step['current'][$key]) && $step['current'][$key] !== '' ? '•••' : '—') : ($this->escape($show($step['current'][$key] ?? '')) ?: '—'); ?></td>
                                                <td aria-hidden="true">→</td>
                                                <td><strong><?php echo $key === 'gate_key' ? $this->escape(Text::_('COM_COLORPACK_SHIELD_STEP4_NEWKEY')) : ($this->escape($show($value)) ?: '—'); ?></strong></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </table>
                                </div>
                                <?php if ($this->canChange) : ?>
                                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=setup.apply'); ?>" method="post">
                                        <input type="hidden" name="step" value="<?php echo (int) $n; ?>">
                                        <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_APPLY'); ?></button>
                                        <?php echo HTMLHelper::_('form.token'); ?>
                                    </form>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </li>
            <?php endforeach; ?>

                <li class="cp-card">
                    <div class="cps-step">
                        <span class="cps-marker" aria-hidden="true">5</span>
                        <div class="cp-stack">
                            <h2 class="cp-card__title" id="cps-step-5"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP5_TITLE'); ?></h2>
                            <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_STEP5_TEXT'); ?></p>
                            <p><?php echo Ui::badge('', Text::_('COM_COLORPACK_SHIELD_STEP5_LATER')); ?></p>
                        </div>
                    </div>
                </li>
            </ol>
        </div>
    <?php endif; ?>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
