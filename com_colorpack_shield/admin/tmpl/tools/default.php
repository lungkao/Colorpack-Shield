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

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Tools\HtmlView $this */
$t = $this->tools;
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <div class="cps-tablist" role="tablist" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_NAV_TOOLS')); ?>" data-cps-tabs data-cps-key="tools">
            <button type="button" role="tab" class="cps-tab" id="cps-tab-tools-general" aria-controls="cps-panel-tools-general" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-tools-general"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_TAB_GENERAL'); ?></button>
            <button type="button" role="tab" class="cps-tab" id="cps-tab-tools-ai" aria-controls="cps-panel-tools-ai" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-tools-ai"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_TAB_AI'); ?><?php echo $t['ai'] !== [] ? ' (' . \count($t['ai']) . ')' : ''; ?></button>
        </div>

        <div class="cps-stack cps-panel" role="tabpanel" id="cps-panel-tools-general" aria-labelledby="cps-tab-tools-general">
        <section class="cps-card" aria-labelledby="cps-tl-ver">
            <h2 class="cps-h3" id="cps-tl-ver"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_VERSIONS'); ?></h2>
            <table class="cps-table">
                <tr><td>Colorpack Shield (<?php echo Text::_('COM_COLORPACK_SHIELD_TL_PLUGIN'); ?>)</td><td class="cps-mono"><?php echo $this->escape($t['versions']['plugin'] ?: '—'); ?></td></tr>
                <tr><td>Colorpack Shield (<?php echo Text::_('COM_COLORPACK_SHIELD_TL_COMPONENT'); ?>)</td><td class="cps-mono"><?php echo $this->escape($t['versions']['component'] ?: '—'); ?></td></tr>
                <tr><td>Joomla</td><td class="cps-mono"><?php echo $this->escape($t['versions']['joomla']); ?></td></tr>
                <tr><td>PHP</td><td class="cps-mono"><?php echo $this->escape($t['versions']['php']); ?></td></tr>
            </table>
        </section>

        <?php if ($t['installed']) : ?>
            <section class="cps-card" aria-labelledby="cps-tl-port">
                <h2 class="cps-h3" id="cps-tl-port"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_PORT'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_TL_PORT_TEXT'); ?></p>
                <?php if (!$this->canChange) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY'); ?></div>
                <?php else : ?>
                    <div class="cps-card-foot"><a class="cps-btn" href="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.export'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_EXPORT'); ?></a></div>

                    <?php if ($t['pending'] !== null) : $p = $t['pending']; ?>
                        <h3 class="cps-h3"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_PREVIEW'); ?></h3>
                        <?php if ($p['diff'] === []) : ?>
                            <span class="cps-badge cps-badge-ok"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_NOTHING'); ?></span>
                        <?php else : ?>
                            <div class="cps-scroll"><table class="cps-diff" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_DIFF')); ?>">
                                <?php foreach ($p['diff'] as $key => $d) : ?>
                                    <tr><td><?php echo $this->escape($key); ?></td><td class="cps-muted"><div style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:200px;overflow:auto"><?php echo $this->escape($d['old']) ?: '—'; ?></div></td><td aria-hidden="true">→</td><td><strong><div style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:200px;overflow:auto"><?php echo $this->escape($d['new']) ?: '—'; ?></div></strong></td></tr>
                                <?php endforeach; ?>
                            </table></div>
                        <?php endif; ?>
                        <?php if ($p['ignored'] !== []) : ?>
                            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_IGNORED'); ?> <?php foreach ($p['ignored'] as $i) : ?><code><?php echo $this->escape($i); ?></code> <?php endforeach; ?></p>
                        <?php endif; ?>
                        <div class="cps-card-foot">
                            <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.apply'); ?>" method="post">
                                <button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SETUP_APPLY'); ?></button>
                                <?php echo HTMLHelper::_('form.token'); ?>
                            </form>
                            <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.discard'); ?>" method="post">
                                <button type="submit" class="cps-btn"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_DISCARD'); ?></button>
                                <?php echo HTMLHelper::_('form.token'); ?>
                            </form>
                        </div>
                    <?php else : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.preview'); ?>" method="post" enctype="multipart/form-data" class="cps-stack" style="gap:12px">
                            <div class="cps-field">
                                <label for="cps-imp-file"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_IMPORT_FILE'); ?></label>
                                <input type="file" id="cps-imp-file" name="settings_file" accept="application/json,.json">
                            </div>
                            <div class="cps-field">
                                <label for="cps-imp-text"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_IMPORT_TEXT'); ?></label>
                                <textarea id="cps-imp-text" name="settings_text" rows="4" maxlength="65536"></textarea>
                                <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_IMPORT_HELP'); ?></span>
                            </div>
                            <div><button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_CHECK'); ?></button></div>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>
            </section>
        <?php endif; ?>

        <section class="cps-card" aria-labelledby="cps-tl-replay">
            <h2 class="cps-h3" id="cps-tl-replay"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_REPLAY'); ?></h2>
            <p><?php echo Text::_('COM_COLORPACK_SHIELD_TL_REPLAY_TEXT'); ?></p>
            <pre class="cps-log" tabindex="0">php <?php echo $this->escape($t['root']); ?>/plugins/system/colorpack_shield/cli/waf_replay.php --scope=paths --min-count=5 /PATH/TO/YOUR/ACCESS.LOG</pre>
            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_REPLAY_NOTE'); ?></p>
        </section>

        <section class="cps-card" aria-labelledby="cps-tl-kill">
            <h2 class="cps-h3" id="cps-tl-kill"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_KILL'); ?></h2>
            <p><?php echo Text::_('COM_COLORPACK_SHIELD_TL_KILL_TEXT'); ?></p>
            <pre class="cps-log" tabindex="0"><?php echo $this->escape($t['root']); ?>/colorpack_shield.disable
<?php echo $this->escape($t['root']); ?>/administrator/colorpack_shield.disable</pre>
            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_KILL_NOTE'); ?></p>
            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_LOGFILE'); ?> <code><?php echo $this->escape($t['logFile']); ?></code></p>
        </section>
        </div>

        <div class="cps-stack cps-panel" role="tabpanel" id="cps-panel-tools-ai" aria-labelledby="cps-tab-tools-ai">
            <section class="cps-card" aria-labelledby="cps-tl-ai-ask">
                <h2 class="cps-h3" id="cps-tl-ai-ask"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_CARD_TITLE'); ?></h2>
                <?php if (!$t['aiAvailable']) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_OFF'); ?></div>
                <?php elseif (!$this->canChange) : ?>
                    <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY'); ?></p>
                <?php else : ?>
                    <p class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_ASK_NOTE'); ?></p>
                    <div class="cps-row" style="display:flex;flex-wrap:wrap;gap:10px">
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.analyzeActivity'); ?>" method="post">
                            <button type="submit" class="cps-btn"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_ASK_ACTIVITY'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.analyzeScan'); ?>" method="post">
                            <button type="submit" class="cps-btn"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_ASK_SCAN'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    </div>
                <?php endif; ?>
            </section>

            <section class="cps-card" aria-labelledby="cps-tl-ai">
                <div class="cps-card-head">
                    <h2 class="cps-h3" id="cps-tl-ai"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_TITLE'); ?></h2>
                    <?php if ($t['ai'] !== [] && $this->canChange) : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=tools.clearAi'); ?>" method="post">
                            <button type="submit" class="cps-btn cps-btn-sm" data-cps-confirm="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_TL_AI_CLEAR_ASK')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_CLEAR'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                </div>
                <p class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_NOTE'); ?></p>
                <?php if ($t['ai'] === []) : ?>
                    <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TL_AI_EMPTY'); ?></p>
                    <div class="cps-card-foot">
                        <a class="cps-btn cps-btn-sm" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=activity'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NAV_ACTIVITY'); ?></a>
                        <a class="cps-btn cps-btn-sm" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=scan'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NAV_SCAN'); ?></a>
                    </div>
                <?php else : ?>
                    <?php foreach ($t['ai'] as $i => $a) : ?>
                        <details class="cps-ai-entry"<?php echo $i === 0 ? ' open' : ''; ?>>
                            <summary>
                                <time datetime="<?php echo gmdate('c', $a['when']); ?>" data-cps-localtime><?php echo gmdate('Y-m-d H:i', $a['when']); ?> UTC</time>
                                · <span class="cps-badge"><?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_TL_AI_KIND_' . strtoupper((string) $a['kind']))); ?></span>
                            </summary>
                            <?php if (($a['answer'] ?? '') !== '' && $a['answer'] !== null) : ?>
                                <div class="cps-ai-answer"><?php echo \Colorpack\Component\ColorpackShield\Administrator\Core\SimpleMarkdown::toHtml((string) $a['answer']); ?></div>
                            <?php else : ?>
                                <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_FAILED'); ?></p>
                            <?php endif; ?>
                        </details>
                    <?php endforeach; ?>
                <?php endif; ?>
            </section>
        </div>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
