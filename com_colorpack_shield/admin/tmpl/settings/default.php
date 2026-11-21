<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Model\SettingsModel;
use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Settings\HtmlView $this */
$basic   = array_flip(SettingsModel::BASIC);
$cpsLead = Text::_($this->form === null ? 'COM_COLORPACK_SHIELD_PLUGIN_MISSING' : 'COM_COLORPACK_SHIELD_SETTINGS_NOTE');
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <?php if ($this->form === null) : ?>
        <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
    <?php else : ?>
        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=settings.save'); ?>" method="post" id="cps-settings-form" class="cps-flow"<?php echo $this->jumpField !== '' ? ' data-cps-jump="' . $this->escape($this->jumpField) . '"' : ''; ?>>
            <?php if (!$this->canChange) : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY')); ?>
            <?php endif; ?>

            <button type="button" class="cps-adv-toggle" id="cps-toggle-advanced" aria-pressed="false"
                    data-show="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SHOW_ADVANCED')); ?>"
                    data-hide="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_HIDE_ADVANCED')); ?>">
                <span class="cps-adv-toggle-switch" aria-hidden="true"><i></i></span>
                <span class="cps-adv-toggle-text">
                    <span class="cps-adv-toggle-label"><?php echo Text::_('COM_COLORPACK_SHIELD_SHOW_ADVANCED'); ?></span>
                </span>
                <span class="cps-adv-toggle-chev" aria-hidden="true">▾</span>
            </button>

            <?php if ($this->canChange && filter_var($this->params['gate_enabled'] ?? false, FILTER_VALIDATE_BOOLEAN) && \Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig::fromArray(['gate_enabled' => '1', 'gate_key' => $this->params['gate_key'] ?? ''])->gateActive) : ?>
                <?php echo Ui::calloutStart('info'); ?>
                    <p class="cp-callout__text"><?php echo Text::_('COM_COLORPACK_SHIELD_GATE_LINK'); ?></p>
                    <pre class="cp-code" tabindex="0"><?php echo $this->escape(rtrim(\Joomla\CMS\Uri\Uri::root(), '/') . '/administrator/?cpskey=' . $this->params['gate_key']); ?></pre>
                    <p class="cp-callout__text cp-small"><?php echo Text::_('COM_COLORPACK_SHIELD_GATE_LINK_NOTE'); ?></p>
                <?php echo Ui::calloutEnd(); ?>
            <?php endif; ?>

            <?php
            // One tab per group of settings; a group with only advanced settings is a tab that shows with "Show advanced".
            $tabs = [];

            foreach ($this->form->getFieldsets() as $name => $fieldset) {
                $fields   = $this->form->getFieldset($name);
                $anyBasic = false;
                $hasError = false;

                foreach ($fields as $f) {
                    $anyBasic = $anyBasic || isset($basic[$f->fieldname]);
                    $hasError = $hasError || isset($this->fieldErrors[$f->fieldname]);
                }

                $tabs[$name] = ['fieldset' => $fieldset, 'fields' => $fields, 'basic' => $anyBasic, 'error' => $hasError];
            }
            ?>
            <div class="cps-tablist" role="tablist" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_NAV_SETTINGS')); ?>" data-cps-tabs>
                <?php foreach ($tabs as $name => $t) : ?>
                    <button type="button" role="tab" class="cps-tab<?php echo $t['basic'] ? '' : ' cps-adv'; ?><?php echo $t['error'] ? ' has-error' : ''; ?>" id="cps-tab-<?php echo $this->escape($name); ?>"
                            aria-controls="cps-panel-<?php echo $this->escape($name); ?>" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-<?php echo $this->escape($name); ?>"><?php echo Text::_($t['fieldset']->label); ?></button>
                <?php endforeach; ?>
            </div>

            <fieldset <?php echo $this->canChange ? '' : 'disabled'; ?> class="cps-flow">
                <?php foreach ($tabs as $name => $t) : $fields = $t['fields']; ?>
                    <section class="cp-card cps-panel<?php echo $t['basic'] ? '' : ' cps-adv'; ?>" role="tabpanel" id="cps-panel-<?php echo $this->escape($name); ?>" aria-labelledby="cps-tab-<?php echo $this->escape($name); ?>">
                        <h2 class="cp-card__title"><?php echo Text::_($t['fieldset']->label); ?></h2>
                        <?php foreach ($fields as $f) : ?>
                            <?php if (\in_array($f->fieldname, ['gate_key', 'killswitch_token', 'gemini_api_key'], true) && !$this->canChange) { continue; } ?>
                            <?php $err = $this->fieldErrors[$f->fieldname] ?? null; ?>
                            <div class="cps-fieldwrap<?php echo isset($basic[$f->fieldname]) ? '' : ' cps-adv'; ?><?php echo $err ? ' is-error' : ''; ?>" id="cps-f-<?php echo $this->escape($f->fieldname); ?>">
                                <?php echo $f->renderField(); ?>
                                <?php if ($f->fieldname === 'gate_key') : ?>
                                    <div id="cps-gate-helper" class="cp-small cps-gate-helper" role="status" aria-live="polite"
                                         data-min="<?php echo \Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig::MIN_KEY; ?>" data-max="<?php echo \Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig::MAX_KEY; ?>"
                                         data-alphabet="<?php echo \Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig::ALPHABET; ?>" data-length="<?php echo \Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig::GENERATED_LENGTH; ?>"
                                         data-ok="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_OK')); ?>" data-short="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_SHORT')); ?>"
                                         data-long="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_LONG')); ?>" data-chars="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_CHARS')); ?>"
                                         data-empty="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_EMPTY')); ?>" data-button="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_KEY_GENERATE')); ?>"></div>
                                <?php endif; ?>
                                <?php if ($err) : ?>
                                    <p class="cps-fielderr cp-small" role="alert"><?php echo Ui::icon('bad'); ?><span><?php echo Text::sprintf('COM_COLORPACK_SHIELD_ERR_' . strtoupper($err), $this->escape($f->fieldname), ''); ?></span></p>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </section>
                <?php endforeach; ?>
            </fieldset>

            <?php if ($this->canChange) : ?>
                <div class="cp-savebar cps-savebar">
                    <span class="cp-muted cp-small"><?php echo Text::_('COM_COLORPACK_SHIELD_SAVE_NOTE'); ?></span>
                    <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SAVE'); ?></button>
                </div>
            <?php endif; ?>
            <?php echo HTMLHelper::_('form.token'); ?>
        </form>
    <?php endif; ?>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
