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

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Scan\HtmlView $this */
$s    = $this->scan;
$r    = $s['result'];
$sev  = ['high' => 'cps-badge-bad', 'medium' => 'cps-badge-warn', 'low' => ''];
$day  = static fn (int $t): string => $t > 0 ? gmdate('Y-m-d H:i', $t) . ' UTC' : '—';
$fl   = $s['findList'];
$fc   = $fl['criteria'] ?? ['sev' => '', 'text' => ''];
$flQ  = array_filter(['option' => 'com_colorpack_shield', 'view' => 'scan', 'sev' => $fc['sev'], 'q' => $fc['text']], static fn ($v) => $v !== '' && $v !== []);
$flUrl = static fn (array $extra): string => Route::_('index.php?' . http_build_query($extra + $flQ));
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <section class="cps-card" aria-labelledby="cps-scan-h">
            <h2 class="cps-h3" id="cps-scan-h"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TITLE'); ?></h2>
            <p><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TEXT'); ?></p>
            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_LIMITS'); ?></p>

            <?php if ($this->canChange) : ?>
                <div class="cps-actions" style="position:static;padding:0">
                    <button type="button" class="cps-btn cps-btn-primary" id="cps-scan-btn" data-cps-scan
                            data-start="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.start&format=json', false)); ?>"
                            data-step="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.step&format=json', false)); ?>"
                            data-resume="<?php echo $s['running'] !== null ? '1' : '0'; ?>"
                            data-token="<?php echo $this->escape(\Joomla\CMS\Session\Session::getFormToken()); ?>"
                            data-msg-run="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_RUNNING')); ?>"
                            data-msg-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_DONE')); ?>"
                            data-msg-fail="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_JSFAIL')); ?>"
                            data-msg-files="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_PROGRESS')); ?>"><?php echo Text::_($s['running'] !== null ? 'COM_COLORPACK_SHIELD_SCAN_CONTINUE' : 'COM_COLORPACK_SHIELD_SCAN_START'); ?></button>
                    <span id="cps-scan-status" class="cps-small" role="status" aria-live="polite"></span>
                </div>
                <div class="cps-progress" id="cps-scan-bar" hidden style="margin-top:8px"><i style="width:100%;opacity:.5"></i></div>
            <?php else : ?>
                <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY'); ?></div>
            <?php endif; ?>
            <?php if ($s['running'] !== null) : ?>
                <p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_UNFINISHED', (int) $s['running']['seen']); ?></p>
            <?php endif; ?>
        </section>

        <?php if ($r === null) : ?>
            <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_NONE'); ?></div>
        <?php else : ?>
            <section class="cps-card" aria-labelledby="cps-scan-hero">
                <div class="cps-hero">
                    <div class="cps-ring cps-ring-<?php echo $r['count']['high'] > 0 ? 'bad' : 'ok'; ?>" style="--p:100" role="img" aria-label="<?php echo (int) $r['count']['high']; ?> <?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SC_RING_SERIOUS')); ?>"><i><b><?php echo (int) $r['count']['high']; ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SC_RING_SERIOUS'); ?></span></i></div>
                    <div class="cps-hero-text">
                        <p class="cps-eyebrow"><?php echo $day((int) $r['finished']); ?> · <?php echo (int) $r['seen']; ?> · PHP: <?php echo (int) $r['php']; ?></p>
                        <h2 id="cps-scan-hero"><?php echo Text::_($r['count']['high'] > 0 ? 'COM_COLORPACK_SHIELD_SC_HERO_HIGH' : 'COM_COLORPACK_SHIELD_SC_HERO_NONE'); ?></h2>
                        <div style="display:flex;gap:8px;flex-wrap:wrap">
                            <span class="cps-badge <?php echo $r['count']['high'] > 0 ? 'cps-badge-bad' : 'cps-badge-ok'; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_HIGH'); ?>: <?php echo (int) $r['count']['high']; ?></span>
                            <span class="cps-badge cps-badge-warn"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM'); ?>: <?php echo (int) $r['count']['medium']; ?></span>
                            <span class="cps-badge"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_LOW'); ?>: <?php echo (int) $r['count']['low']; ?></span>
                        </div>
                    </div>
                </div>
            </section>
            <?php
                // The ring card above already carries when/files/severity counts - repeating them
                // here as a second table was pure duplication. This card now holds only what isn't
                // shown yet: the safe/skipped counts and the one alert that applies.
                $hasSafe    = $r['ignored'] > 0 || $s['ignored'] > 0;
                $hasSkipped = $r['links'] > 0 || $r['unreadable'] > 0;
                $hasAlert   = $r['count']['high'] > 0 || $r['findings'] === [];
                $miniCols   = ($hasSafe ? 1 : 0) + ($hasSkipped ? 1 : 0);
            ?>
            <?php if ($hasSafe || $hasSkipped || $hasAlert) : ?>
                <section class="cps-card">
                    <?php if ($hasAlert) : ?>
                        <?php if ($r['count']['high'] > 0) : ?>
                            <div class="cps-alert cps-alert-bad" role="alert"><div><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_HIGH_HELP'); ?></div></div>
                        <?php else : ?>
                            <div class="cps-alert cps-alert-ok"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_CLEAN'); ?></div>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($hasSafe || $hasSkipped) : ?>
                        <div class="cps-mini" style="grid-template-columns:repeat(<?php echo $miniCols; ?>,minmax(0,1fr));max-width:<?php echo $miniCols * 200; ?>px">
                            <?php if ($hasSafe) : ?><div><b><?php echo (int) $s['ignored']; ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_SAFE'); ?></span></div><?php endif; ?>
                            <?php if ($hasSkipped) : ?><div><b><?php echo (int) ($r['links'] + $r['unreadable']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_SKIPPED'); ?></span></div><?php endif; ?>
                        </div>
                        <?php if ($hasSkipped) : ?><p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_SKIPPED_V', (int) $r['links'], (int) $r['unreadable']); ?></p><?php endif; ?>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <?php if ($r['findings'] !== []) : ?>
                <section class="cps-card" aria-labelledby="cps-scan-find">
                    <h2 class="cps-h3" id="cps-scan-find"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FINDINGS'); ?></h2>
                    <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FINDINGS_NOTE'); ?></p>

                    <nav class="cps-sevtabs" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_TABS')); ?>">
                        <a class="cps-sevtab<?php echo $fc['sev'] === '' ? ' is-on' : ''; ?>" href="<?php echo $flUrl(['sev' => null, 'page' => null]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_ALL'); ?> <span class="cps-badge"><?php echo (int) $fl['total']; ?></span></a>
                        <a class="cps-sevtab<?php echo $fc['sev'] === 'high' ? ' is-on' : ''; ?>" href="<?php echo $flUrl(['sev' => 'high', 'page' => null]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_HIGH'); ?> <span class="cps-badge cps-badge-bad"><?php echo (int) $fl['counts']['high']; ?></span></a>
                        <a class="cps-sevtab<?php echo $fc['sev'] === 'medium' ? ' is-on' : ''; ?>" href="<?php echo $flUrl(['sev' => 'medium', 'page' => null]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM'); ?> <span class="cps-badge cps-badge-warn"><?php echo (int) $fl['counts']['medium']; ?></span></a>
                        <a class="cps-sevtab<?php echo $fc['sev'] === 'low' ? ' is-on' : ''; ?>" href="<?php echo $flUrl(['sev' => 'low', 'page' => null]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_LOW'); ?> <span class="cps-badge"><?php echo (int) $fl['counts']['low']; ?></span></a>
                    </nav>

                    <form action="<?php echo Route::_('index.php'); ?>" method="get" class="cps-scan-filter">
                        <input type="hidden" name="option" value="com_colorpack_shield">
                        <input type="hidden" name="view" value="scan">
                        <?php if ($fc['sev'] !== '') : ?><input type="hidden" name="sev" value="<?php echo $this->escape($fc['sev']); ?>"><?php endif; ?>
                        <label for="cps-scan-q" class="cps-sr"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FILTER_PH'); ?></label>
                        <input type="text" id="cps-scan-q" name="q" maxlength="100" placeholder="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_FILTER_PH')); ?>" value="<?php echo $this->escape($fc['text']); ?>">
                        <button type="submit" class="cps-btn cps-btn-sm"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_APPLY'); ?></button>
                        <?php if ($fc['sev'] !== '' || $fc['text'] !== '') : ?><a class="cps-btn cps-btn-sm" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=scan'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RESET'); ?></a><?php endif; ?>
                    </form>

                    <?php if ($fl['list']['rows'] === []) : ?>
                        <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_NOMATCH'); ?></p>
                    <?php else : ?>
                    <div class="cps-scroll">
                        <table class="cps-table">
                            <thead><tr>
                                <?php if ($this->canChange) : ?><th scope="col"><input type="checkbox" id="cps-pick-all" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_SELECT')); ?>"></th><?php endif; ?>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_LEVEL'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_FILE'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_WHY'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_MODIFIED'); ?></th>
                                <th scope="col"></th>
                            </tr></thead>
                            <tbody>
                                <?php foreach ($fl['list']['rows'] as $f) : ?>
                                    <tr>
                                        <?php if ($this->canChange) : ?><td><input type="checkbox" class="cps-pick" value="<?php echo $this->escape($f['path']); ?>" aria-label="<?php echo $this->escape($f['path']); ?>"></td><?php endif; ?>
                                        <td><span class="cps-badge <?php echo $sev[$f['sev']] ?? ''; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_' . strtoupper($f['sev'])); ?></span></td>
                                        <td><code><?php echo $this->escape($f['path']); ?></code><div class="cps-small cps-muted"><?php echo (int) $f['size']; ?> B</div></td>
                                        <td><?php foreach ($f['rules'] as $rule) : ?><div class="cps-small"><?php echo Text::_('COM_COLORPACK_SHIELD_SCANRULE_' . strtoupper(preg_replace('/[^a-z_]/', '', (string) $rule))); ?></div><?php endforeach; ?></td>
                                        <td class="cps-mono"><?php echo $day((int) $f['mtime']); ?></td>
                                        <td>
                                            <?php if ($this->canChange) : ?>
                                                <button type="button" class="cps-btn cps-btn-sm cps-btn-primary" data-cps-code="<?php echo $this->escape($f['path']); ?>" style="margin-bottom:6px"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_OPEN'); ?></button>
                                                <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.safe'); ?>" method="post">
                                                    <input type="hidden" name="path" value="<?php echo $this->escape($f['path']); ?>">
                                                    <input type="hidden" name="hash" value="<?php echo $this->escape($f['hash']); ?>">
                                                    <button type="submit" class="cps-btn cps-btn-sm"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_MARK'); ?></button>
                                                    <?php echo HTMLHelper::_('form.token'); ?>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($fl['list']['pages'] > 1) : ?>
                        <nav class="cps-actions" style="position:static" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PAGES')); ?>">
                            <?php if ($fl['list']['page'] > 1) : ?><a class="cps-btn" href="<?php echo $flUrl(['page' => $fl['list']['page'] - 1]); ?>"><?php echo Text::_('JPREV'); ?></a><?php endif; ?>
                            <span><?php echo Text::sprintf('COM_COLORPACK_SHIELD_PAGE_OF', (int) $fl['list']['page'], (int) $fl['list']['pages']); ?></span>
                            <?php if ($fl['list']['page'] < $fl['list']['pages']) : ?><a class="cps-btn" href="<?php echo $flUrl(['page' => $fl['list']['page'] + 1]); ?>"><?php echo Text::_('JNEXT'); ?></a><?php endif; ?>
                        </nav>
                    <?php endif; ?>
                    <?php if ($this->canChange) : ?>
                        <div class="cps-actions" style="position:static;padding:0;flex-wrap:wrap">
                            <button type="button" class="cps-btn cps-btn-sm" id="cps-bulk" disabled data-confirm="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_BULK_CONFIRM')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_DELETE'); ?></button>
                            <button type="button" class="cps-btn cps-btn-sm" id="cps-bulk-safe" disabled><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_SAFE'); ?></button>
                            <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_NOTE'); ?></span>
                        </div>
                        <?php if ($fc['text'] !== '' || $fc['sev'] !== '') : ?>
                            <div class="cps-actions" style="position:static;padding:0;flex-wrap:wrap" id="cps-scan-filterbulk"
                                 data-url="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.bulkbyfilter&format=json', false)); ?>"
                                 data-token="<?php echo $this->escape(\Joomla\CMS\Session\Session::getFormToken()); ?>"
                                 data-sev="<?php echo $this->escape($fc['sev']); ?>" data-q="<?php echo $this->escape($fc['text']); ?>">
                                <button type="button" class="cps-btn cps-btn-sm cps-btn-danger" data-cps-filterbulk="delete" data-confirm="<?php echo $this->escape(Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_DEL_CONFIRM', (int) $fl['list']['total'])); ?>"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_DEL', (int) $fl['list']['total']); ?></button>
                                <button type="button" class="cps-btn cps-btn-sm" data-cps-filterbulk="safe"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_SAFE', (int) $fl['list']['total']); ?></button>
                                <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTERBULK_NOTE'); ?></span>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($r['more'] > 0) : ?><p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_MORE', (int) $r['more']); ?></p><?php endif; ?>
                    <?php if ($this->canChange && $s['ignored'] > 0) : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.clearsafe'); ?>" method="post">
                            <button type="submit" class="cps-btn cps-btn-sm"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_CLEARSAFE'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <section class="cps-card" aria-labelledby="cps-scan-chg">
                <h2 class="cps-h3" id="cps-scan-chg"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_CHANGES'); ?></h2>
                <?php if (!$r['tracked']) : ?>
                    <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TOOMANY'); ?></p>
                <?php elseif ($r['changes'] === null) : ?>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_NOBASE'); ?></p>
                <?php else : $c = $r['changes']; ?>
                    <p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_BASEAT', $day((int) $r['baselineAt'])); ?></p>
                    <?php if ($c['new'] === [] && $c['changed'] === [] && $c['removed'] === []) : ?>
                        <span class="cps-badge cps-badge-ok"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_NOCHANGE'); ?></span>
                    <?php endif; ?>
                    <?php foreach (['new' => 'COM_COLORPACK_SHIELD_SCAN_NEW', 'changed' => 'COM_COLORPACK_SHIELD_SCAN_CHANGED', 'removed' => 'COM_COLORPACK_SHIELD_SCAN_REMOVED'] as $k => $label) : ?>
                        <?php if ($c[$k] !== []) : ?>
                            <p class="cps-label cps-muted"><?php echo Text::_($label); ?> (<?php echo count($c[$k]); ?>)</p>
                            <ul class="cps-list"><?php foreach ($c[$k] as $p) : ?><li><code class="cps-grow"><?php echo $this->escape((string) $p); ?></code><?php if ($this->canChange && $k !== 'removed') : ?><button type="button" class="cps-btn cps-btn-sm" data-cps-code="<?php echo $this->escape((string) $p); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_OPEN'); ?></button><?php endif; ?></li><?php endforeach; ?></ul>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <?php if ($c['more'] > 0) : ?><p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_MORE', (int) $c['more']); ?></p><?php endif; ?>
                <?php endif; ?>
                <?php if ($this->canChange && $s['canAccept'] && $r['tracked']) : ?>
                    <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_ACCEPT_TEXT'); ?></p>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.accept'); ?>" method="post">
                        <button type="submit" class="cps-btn"><?php echo Text::_($r['baseline'] ? 'COM_COLORPACK_SHIELD_SCAN_ACCEPT_AGAIN' : 'COM_COLORPACK_SHIELD_SCAN_ACCEPT'); ?></button>
                        <?php echo HTMLHelper::_('form.token'); ?>
                    </form>
                <?php endif; ?>
            </section>
        <?php endif; ?>
    </div>


    <?php if ($this->canChange) : ?>
        <?php
        $ruleText = [];

        foreach (['eval_decode','exec_request','include_request','preg_replace_e','webshell_name','callback_request','write_request','create_function','eval_variable','long_base64','hex_blob','chr_chain','extract_request','callback_decode','unsafe_ini_tamper','ld_preload','exploit_site_ref','htaccess_php_handler','htaccess_prepend','php_in_image','php_in_uploads','php_in_tmp','double_extension','hidden_php','shell_name','foreign_cms_file','world_writable'] as $rid) {
            $ruleText[$rid] = Text::_('COM_COLORPACK_SHIELD_SCANRULE_' . strtoupper($rid));
        }

        $errText = [];

        foreach (['not_in_scan', 'bad_path', 'outside', 'not_a_file', 'protected', 'entry_point', 'too_big', 'unreadable', 'binary', 'changed', 'syntax', 'no_backup', 'write_failed', 'permission', 'confirm', 'failed', 'exists', 'not_found'] as $e) {
            $errText[$e] = Text::_('COM_COLORPACK_SHIELD_CODE_ERR_' . strtoupper($e));
        }

        $str = [];

        foreach (['SAVED', 'SAVING', 'LOADING', 'NO_MARKS', 'LINE', 'SYNTAX', 'BINARY', 'READONLY', 'NETWORK', 'RESTORED', 'RESTORE_OVERWRITE', 'DROP_CONFIRM', 'COPY_DROP_CONFIRM'] as $k) {
            $str[strtolower($k)] = Text::_('COM_COLORPACK_SHIELD_CODE_' . $k);
        }
        ?>
        <dialog id="cps-code" class="cps-dialog" aria-labelledby="cps-code-title"
                data-token="<?php echo $this->escape(\Joomla\CMS\Session\Session::getFormToken()); ?>"
                data-url-view="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.view&format=json', false)); ?>"
                data-url-save="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.save&format=json', false)); ?>"
                data-url-delete="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.delete&format=json', false)); ?>"
                data-url-bulk="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.bulkdelete&format=json', false)); ?>"
                data-url-bulksafe="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.bulksafe&format=json', false)); ?>"
                data-url-restore="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.restore&format=json', false)); ?>"
                data-url-drop="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.dropcopy&format=json', false)); ?>"
                data-rules="<?php echo $this->escape(json_encode($ruleText, JSON_UNESCAPED_UNICODE)); ?>"
                data-errs="<?php echo $this->escape(json_encode($errText, JSON_UNESCAPED_UNICODE)); ?>"
                data-str="<?php echo $this->escape(json_encode($str, JSON_UNESCAPED_UNICODE)); ?>">
            <div class="cps-dialog-in">
                <header class="cps-dialog-head">
                    <div style="min-width:0"><h2 id="cps-code-title" class="cps-h3" style="overflow-wrap:anywhere"></h2><span class="cps-small cps-muted" id="cps-code-meta"></span></div>
                    <button type="button" class="cps-btn cps-btn-sm" id="cps-code-close"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_CLOSE'); ?></button>
                </header>
                <div id="cps-code-marks" class="cps-small" role="list"></div>
                <div id="cps-code-syntax" class="cps-alert cps-alert-warn" role="alert" hidden></div>
                <div class="cps-editor">
                    <pre id="cps-code-nums" class="cps-nums" aria-hidden="true"></pre>
                    <textarea id="cps-code-text" spellcheck="false" wrap="off" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CODE_AREA')); ?>"></textarea>
                </div>
                <div id="cps-code-msg" class="cps-small" role="status" aria-live="polite"></div>
                <footer class="cps-dialog-foot">
                    <button type="button" class="cps-btn cps-btn-primary" id="cps-code-save"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_SAVE'); ?></button>
                    <label class="cps-check cps-small" id="cps-code-force-wrap" hidden><input type="checkbox" id="cps-code-force"> <?php echo Text::_('COM_COLORPACK_SHIELD_CODE_FORCE'); ?></label>
                    <span style="flex:1"></span>
                    <button type="button" class="cps-btn cps-btn-danger" id="cps-code-del"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE'); ?></button>
                </footer>
                <div id="cps-code-delbox" class="cps-alert cps-alert-bad" hidden>
                    <div style="flex:1;display:flex;flex-direction:column;gap:8px">
                        <span><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE_HELP'); ?></span>
                        <div class="cps-field" style="margin:0"><label for="cps-code-confirm"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_TYPE_NAME'); ?></label><input type="text" id="cps-code-confirm" autocomplete="off"></div>
                        <div><button type="button" class="cps-btn cps-btn-danger" id="cps-code-del-go" disabled><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE_GO'); ?></button></div>
                    </div>
                </div>
            </div>
        </dialog>

        <?php if ($s['copies'] !== []) : ?>
            <section class="cps-card" aria-labelledby="cps-q-h" id="cps-copies">
                <h2 class="cps-h3" id="cps-q-h"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_TITLE'); ?></h2>
                <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_TEXT'); ?></p>
                <div class="cps-scroll">
                    <table class="cps-table">
                        <thead><tr><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_TIME'); ?></th><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_FILE'); ?></th><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_WHAT'); ?></th><th scope="col"></th></tr></thead>
                        <tbody>
                            <?php foreach ($s['copies'] as $cp) : ?>
                                <tr>
                                    <td class="cps-mono"><?php echo $day((int) $cp['time']); ?></td>
                                    <td><code><?php echo $this->escape($cp['path']); ?></code><div class="cps-small cps-muted"><?php echo (int) $cp['size']; ?> B</div></td>
                                    <td><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_' . strtoupper(preg_replace('/[^a-z_]/', '', $cp['action']))); ?></td>
                                    <td>
                                        <button type="button" class="cps-btn cps-btn-sm" data-cps-restore="<?php echo $this->escape($cp['id']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_RESTORE'); ?></button>
                                        <button type="button" class="cps-btn cps-btn-sm" data-cps-drop="<?php echo $this->escape($cp['id']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_DROP'); ?></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        <?php endif; ?>
    <?php endif; ?>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
