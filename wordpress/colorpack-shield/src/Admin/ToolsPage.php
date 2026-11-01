<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > Tools" - two tabs like the Joomla edition's Tools screen once the AI tab
 * is added: general information, and "Analyse with AI", where every kept analysis can be read again
 * and all of them cleared with one button.
 */
final class ToolsPage
{
    public const ACTION_CLEAR_AI = 'colorpack_shield_clear_ai';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html(Lang::t('WPS_NOT_ADMIN')));
        }

        $ai = AiStore::history()->recent(time(), 30);
        global $wp_version;
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-tools'); ?>

                <?php if (isset($_GET['cleared'])) : ?>
                    <div class="cps-alert cps-alert-ok" role="status"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_CLEARED', (int) $_GET['cleared'])); ?></div>
                <?php endif; ?>

                <div class="cps-stack">
                    <div class="cps-tablist" role="tablist" aria-label="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_NAV_TOOLS')); ?>" data-cps-tabs data-cps-key="tools">
                        <button type="button" role="tab" class="cps-tab" id="cps-tab-tools-general" aria-controls="cps-panel-tools-general" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-tools-general"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_TAB_GENERAL')); ?></button>
                        <button type="button" role="tab" class="cps-tab" id="cps-tab-tools-ai" aria-controls="cps-panel-tools-ai" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-tools-ai"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_TAB_AI') . ($ai !== [] ? ' (' . \count($ai) . ')' : '')); ?></button>
                    </div>

                    <div class="cps-stack cps-panel" role="tabpanel" id="cps-panel-tools-general" aria-labelledby="cps-tab-tools-general">
                        <section class="cps-card" aria-labelledby="cps-tl-ver">
                            <h2 class="cps-h3" id="cps-tl-ver"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_VERSIONS')); ?></h2>
                            <table class="cps-table">
                                <tr><td>Colorpack Shield</td><td class="cps-mono"><?php echo esc_html(COLORPACK_SHIELD_WP_VERSION); ?></td></tr>
                                <tr><td>WordPress</td><td class="cps-mono"><?php echo esc_html((string) $wp_version); ?></td></tr>
                                <tr><td>PHP</td><td class="cps-mono"><?php echo esc_html(PHP_VERSION); ?></td></tr>
                            </table>
                        </section>
                        <section class="cps-card" aria-labelledby="cps-tl-kill">
                            <h2 class="cps-h3" id="cps-tl-kill"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_KILL')); ?></h2>
                            <p class="cps-help"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_KILL_TEXT')); ?> <code><?php echo esc_html(\Colorpack\WP\ColorpackShield\Safety\KillSwitch::FILENAME); ?></code></p>
                            <p class="cps-help"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_KILL_NOTE')); ?></p>
                        </section>
                    </div>

                    <div class="cps-stack cps-panel" role="tabpanel" id="cps-panel-tools-ai" aria-labelledby="cps-tab-tools-ai">
                        <section class="cps-card" aria-labelledby="cps-tl-ai-ask">
                            <h2 class="cps-h3" id="cps-tl-ai-ask"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_AI_CARD_TITLE')); ?></h2>
                            <?php if (Settings::geminiConfig() === null) : ?>
                                <div class="cps-alert cps-alert-info"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_AI_OFF')); ?></div>
                            <?php else : ?>
                                <p class="cps-help"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_ASK_NOTE')); ?></p>
                                <div style="display:flex;flex-wrap:wrap;gap:10px">
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="<?php echo esc_attr(ActivityPage::AI_ACTION); ?>">
                                        <?php wp_nonce_field(ActivityPage::AI_ACTION); ?>
                                        <button type="submit" class="cps-btn"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_ASK_ACTIVITY')); ?></button>
                                    </form>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="<?php echo esc_attr(ScanPage::AJAX_AI_ANALYZE); ?>">
                                        <?php wp_nonce_field(ScanPage::NONCE); ?>
                                        <button type="submit" class="cps-btn"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_ASK_SCAN')); ?></button>
                                    </form>
                                </div>
                            <?php endif; ?>
                        </section>
                        <section class="cps-card" aria-labelledby="cps-tl-ai">
                            <div class="cps-card-head">
                                <h2 class="cps-h3" id="cps-tl-ai"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_TITLE')); ?></h2>
                                <?php if ($ai !== []) : ?>
                                    <form action="<?php echo esc_url(admin_url('admin-post.php')); ?>" method="post">
                                        <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_CLEAR_AI); ?>">
                                        <?php wp_nonce_field(self::ACTION_CLEAR_AI); ?>
                                        <button type="submit" class="cps-btn cps-btn-sm" data-cps-confirm="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_TL_AI_CLEAR_ASK')); ?>"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_CLEAR')); ?></button>
                                    </form>
                                <?php endif; ?>
                            </div>
                            <p class="cps-help"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_NOTE')); ?></p>
                            <?php if ($ai === []) : ?>
                                <p class="cps-muted"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_EMPTY')); ?></p>
                                <div class="cps-card-foot">
                                    <a class="cps-btn cps-btn-sm" href="<?php echo esc_url(admin_url('admin.php?page=colorpack-shield-activity')); ?>"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_NAV_ACTIVITY')); ?></a>
                                    <a class="cps-btn cps-btn-sm" href="<?php echo esc_url(admin_url('admin.php?page=colorpack-shield-scan')); ?>"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_NAV_SCAN')); ?></a>
                                </div>
                            <?php else : ?>
                                <?php foreach ($ai as $i => $a) : ?>
                                    <details class="cps-ai-entry"<?php echo $i === 0 ? ' open' : ''; ?>>
                                        <summary>
                                            <time datetime="<?php echo esc_attr(gmdate('c', $a['when'])); ?>"><?php echo esc_html(gmdate('Y-m-d H:i', $a['when'])); ?> UTC</time>
                                            · <span class="cps-badge"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_TL_AI_KIND_' . strtoupper($a['kind']))); ?></span>
                                        </summary>
                                        <?php if (($a['answer'] ?? '') !== '' && $a['answer'] !== null) : ?>
                                            <div class="cps-ai-answer"><?php echo SimpleMarkdown::toHtml((string) $a['answer']); // escaped inside SimpleMarkdown ?></div>
                                        <?php else : ?>
                                            <p class="cps-muted"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_AI_FAILED')); ?></p>
                                        <?php endif; ?>
                                    </details>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </section>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /** admin-post.php handler: delete every kept AI analysis and go back to the AI tab. */
    public static function handleClearAi(): void
    {
        check_admin_referer(self::ACTION_CLEAR_AI);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        wp_safe_redirect(add_query_arg('cleared', AiStore::clear(), admin_url('admin.php?page=colorpack-shield-tools')) . '#ai');
        exit;
    }
}
