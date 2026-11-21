<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\SimpleMarkdown;
use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Scan\HtmlView $this */
$s    = $this->scan;
$r    = $s['result'];
$sev  = ['high' => 'bad', 'medium' => 'warn', 'low' => ''];
$day  = static fn (int $t): string => $t > 0 ? gmdate('Y-m-d H:i', $t) . ' UTC' : '—';
$fl   = $s['findList'];
$fc   = $fl['criteria'] ?? ['sev' => '', 'text' => ''];
$flQ  = array_filter(['option' => 'com_colorpack_shield', 'view' => 'scan', 'sev' => $fc['sev'], 'q' => $fc['text']], static fn ($v) => $v !== '' && $v !== []);
$flUrl = static fn (array $extra): string => Route::_('index.php?' . http_build_query($extra + $flQ));
$cpsLead = Text::_($r === null ? 'COM_COLORPACK_SHIELD_SCAN_TITLE' : ($r['count']['high'] > 0 ? 'COM_COLORPACK_SHIELD_SC_HERO_HIGH' : 'COM_COLORPACK_SHIELD_SC_HERO_NONE'));
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <section class="cp-card" aria-labelledby="cps-scan-h">
            <h2 class="cp-card__title" id="cps-scan-h"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TITLE'); ?></h2>
            <p><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TEXT'); ?></p>
            <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_LIMITS'); ?></p>

            <?php if ($this->canChange) : ?>
                <div class="cp-row">
                    <button type="button" class="btn btn-primary" id="cps-scan-btn" data-cps-scan
                            data-start="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.start&format=json', false)); ?>"
                            data-step="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.step&format=json', false)); ?>"
                            data-resume="<?php echo $s['running'] !== null ? '1' : '0'; ?>"
                            data-token="<?php echo $this->escape(\Joomla\CMS\Session\Session::getFormToken()); ?>"
                            data-msg-run="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_RUNNING')); ?>"
                            data-msg-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_DONE')); ?>"
                            data-msg-fail="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_JSFAIL')); ?>"
                            data-msg-files="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_PROGRESS')); ?>"><?php echo Text::_($s['running'] !== null ? 'COM_COLORPACK_SHIELD_SCAN_CONTINUE' : 'COM_COLORPACK_SHIELD_SCAN_START'); ?></button>
                    <span id="cps-scan-status" class="cp-small" role="status" aria-live="polite"></span>
                </div>
                <progress class="cp-progress cp-progress--wide" id="cps-scan-bar" max="100" aria-labelledby="cps-scan-status" hidden></progress>
            <?php else : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_VIEW_ONLY')); ?>
            <?php endif; ?>
            <?php if ($s['running'] !== null) : ?>
                <p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_UNFINISHED', (int) $s['running']['seen']); ?></p>
            <?php endif; ?>
        </section>

        <?php if ($r === null) : ?>
            <?php echo Ui::empty(Text::_('COM_COLORPACK_SHIELD_SCAN_NONE'), Text::_('COM_COLORPACK_SHIELD_SCAN_NONE_HELP')); ?>
        <?php else : ?>
            <section class="cp-card" aria-labelledby="cps-scan-hero">
                <div class="cps-hero">
                    <?php echo Ui::ring(100, $r['count']['high'] > 0 ? 'bad' : 'ok', (string) (int) $r['count']['high'], Text::_('COM_COLORPACK_SHIELD_SC_RING_SERIOUS'), (int) $r['count']['high'] . ' ' . Text::_('COM_COLORPACK_SHIELD_SC_RING_SERIOUS')); ?>
                    <div class="cps-hero-text">
                        <p class="cp-small cp-muted"><?php echo $day((int) $r['finished']); ?> · <?php echo (int) $r['seen']; ?> · PHP: <?php echo (int) $r['php']; ?></p>
                        <h2 class="cp-card__title" id="cps-scan-hero"><?php echo Text::_($r['count']['high'] > 0 ? 'COM_COLORPACK_SHIELD_SC_HERO_HIGH' : 'COM_COLORPACK_SHIELD_SC_HERO_NONE'); ?></h2>
                        <ul class="cp-badges">
                            <li><?php echo Ui::badge($r['count']['high'] > 0 ? 'bad' : 'ok', Text::_('COM_COLORPACK_SHIELD_SEV_HIGH') . ': ' . (int) $r['count']['high']); ?></li>
                            <li><?php echo Ui::badge('warn', Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM') . ': ' . (int) $r['count']['medium']); ?></li>
                            <li><?php echo Ui::badge('', Text::_('COM_COLORPACK_SHIELD_SEV_LOW') . ': ' . (int) $r['count']['low']); ?></li>
                        </ul>
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
            ?>
            <?php if ($hasSafe || $hasSkipped || $hasAlert) : ?>
                <section class="cp-card">
                    <?php if ($hasAlert) : ?>
                        <?php if ($r['count']['high'] > 0) : ?>
                            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_SCAN_HIGH_HELP')); ?>
                        <?php else : ?>
                            <?php echo Ui::callout('ok', '', Text::_('COM_COLORPACK_SHIELD_SCAN_CLEAN')); ?>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($hasSafe || $hasSkipped) : ?>
                        <div class="cps-mini cps-mini--fit">
                            <?php if ($hasSafe) : ?><div><b><?php echo (int) $s['ignored']; ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_SAFE'); ?></span></div><?php endif; ?>
                            <?php if ($hasSkipped) : ?><div><b><?php echo (int) ($r['links'] + $r['unreadable']); ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_SKIPPED'); ?></span></div><?php endif; ?>
                        </div>
                        <?php if ($hasSkipped) : ?><p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_SKIPPED_V', (int) $r['links'], (int) $r['unreadable']); ?></p><?php endif; ?>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <?php if ($r['findings'] !== []) : ?>
                <section class="cp-card" aria-labelledby="cps-scan-find">
                    <h2 class="cp-card__title" id="cps-scan-find"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FINDINGS'); ?></h2>
                    <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FINDINGS_NOTE'); ?></p>

                    <div class="cps-scan-toolbar">
                        <nav class="cps-seg" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_TABS')); ?>">
                            <a href="<?php echo $flUrl(['sev' => null, 'page' => null]); ?>"<?php echo $fc['sev'] === '' ? ' aria-current="page"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_ALL'); ?> <span class="cp-tab__count"><?php echo (int) $fl['total']; ?></span></a>
                            <a href="<?php echo $flUrl(['sev' => 'high', 'page' => null]); ?>"<?php echo $fc['sev'] === 'high' ? ' aria-current="page"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_HIGH'); ?> <span class="cp-tab__count"<?php echo (int) $fl['counts']['high'] > 0 ? ' data-state="bad"' : ''; ?>><?php echo (int) $fl['counts']['high']; ?></span></a>
                            <a href="<?php echo $flUrl(['sev' => 'medium', 'page' => null]); ?>"<?php echo $fc['sev'] === 'medium' ? ' aria-current="page"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_MEDIUM'); ?> <span class="cp-tab__count"<?php echo (int) $fl['counts']['medium'] > 0 ? ' data-state="warn"' : ''; ?>><?php echo (int) $fl['counts']['medium']; ?></span></a>
                            <a href="<?php echo $flUrl(['sev' => 'low', 'page' => null]); ?>"<?php echo $fc['sev'] === 'low' ? ' aria-current="page"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_SEV_LOW'); ?> <span class="cp-tab__count"><?php echo (int) $fl['counts']['low']; ?></span></a>
                        </nav>

                        <form action="<?php echo Route::_('index.php'); ?>" method="get" class="cp-filter" role="search">
                            <input type="hidden" name="option" value="com_colorpack_shield">
                            <input type="hidden" name="view" value="scan">
                            <?php if ($fc['sev'] !== '') : ?><input type="hidden" name="sev" value="<?php echo $this->escape($fc['sev']); ?>"><?php endif; ?>
                            <div class="cp-filter__field cp-filter__field--grow">
                                <label for="cps-scan-q"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FILTER_PH'); ?></label>
                                <input type="text" id="cps-scan-q" name="q" maxlength="100" value="<?php echo $this->escape($fc['text']); ?>" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-outline-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_APPLY'); ?></button>
                            <?php if ($fc['sev'] !== '' || $fc['text'] !== '') : ?><a class="btn btn-outline-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=scan'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RESET'); ?></a><?php endif; ?>
                        </form>
                    </div>

                    <?php if ($this->canChange && $fl['list']['rows'] !== []) : ?>
                        <div class="cps-bulkbar">
                            <button type="button" class="btn btn-sm btn-outline-danger" id="cps-bulk" disabled data-confirm="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_BULK_CONFIRM')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_DELETE'); ?></button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="cps-bulk-safe" disabled><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_SAFE'); ?></button>
                            <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_BULK_NOTE'); ?></span>
                        </div>
                        <?php if ($fc['text'] !== '' || $fc['sev'] !== '') : ?>
                            <div class="cps-bulkbar" id="cps-scan-filterbulk"
                                 data-url="<?php echo $this->escape(Route::_('index.php?option=com_colorpack_shield&task=scan.bulkbyfilter&format=json', false)); ?>"
                                 data-token="<?php echo $this->escape(\Joomla\CMS\Session\Session::getFormToken()); ?>"
                                 data-sev="<?php echo $this->escape($fc['sev']); ?>" data-q="<?php echo $this->escape($fc['text']); ?>">
                                <button type="button" class="btn btn-sm btn-outline-danger" data-cps-filterbulk="delete" data-confirm="<?php echo $this->escape(Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_DEL_CONFIRM', (int) $fl['list']['total'])); ?>"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_DEL', (int) $fl['list']['total']); ?></button>
                                <button type="button" class="btn btn-sm btn-outline-secondary" data-cps-filterbulk="safe"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_FILTERBULK_SAFE', (int) $fl['list']['total']); ?></button>
                                <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTERBULK_NOTE'); ?></span>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php if ($fl['list']['rows'] === []) : ?>
                        <?php echo Ui::empty(Text::_('COM_COLORPACK_SHIELD_SCAN_NOMATCH'), '', '<a class="btn btn-sm btn-outline-secondary" href="' . Route::_('index.php?option=com_colorpack_shield&view=scan') . '">' . Text::_('COM_COLORPACK_SHIELD_FILTER_RESET') . '</a>'); ?>
                    <?php else : ?>
                    <div class="cp-tablewrap" role="region" tabindex="0" aria-labelledby="cps-scan-find">
                        <table class="table cp-table">
                            <caption class="visually-hidden"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_FINDINGS'); ?></caption>
                            <thead><tr>
                                <?php if ($this->canChange) : ?><th scope="col"><input type="checkbox" id="cps-pick-all" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SCAN_SELECT')); ?>"></th><?php endif; ?>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_LEVEL'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_FILE'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_WHY'); ?></th>
                                <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_MODIFIED'); ?></th>
                                <th scope="col"><span class="visually-hidden"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_ACTION'); ?></span></th>
                            </tr></thead>
                            <tbody>
                                <?php foreach ($fl['list']['rows'] as $f) : ?>
                                    <tr>
                                        <?php if ($this->canChange) : ?><td><input type="checkbox" class="cps-pick" value="<?php echo $this->escape($f['path']); ?>" aria-label="<?php echo $this->escape($f['path']); ?>"></td><?php endif; ?>
                                        <td><?php echo Ui::badge($sev[$f['sev']] ?? '', Text::_('COM_COLORPACK_SHIELD_SEV_' . strtoupper($f['sev']))); ?></td>
                                        <td class="cp-wrap"><code><?php echo $this->escape($f['path']); ?></code><div class="cp-small cp-muted"><?php echo (int) $f['size']; ?> B</div></td>
                                        <td><?php foreach ($f['rules'] as $rule) : ?><div class="cp-small"><?php echo Text::_('COM_COLORPACK_SHIELD_SCANRULE_' . strtoupper(preg_replace('/[^a-z_]/', '', (string) $rule))); ?></div><?php endforeach; ?></td>
                                        <td class="cp-nowrap"><?php echo $day((int) $f['mtime']); ?></td>
                                        <td>
                                            <?php if ($this->canChange) : ?>
                                                <div class="cp-row">
                                                    <button type="button" class="btn btn-sm btn-outline-secondary" data-cps-code="<?php echo $this->escape($f['path']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_OPEN'); ?></button>
                                                    <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.safe'); ?>" method="post">
                                                        <input type="hidden" name="path" value="<?php echo $this->escape($f['path']); ?>">
                                                        <input type="hidden" name="hash" value="<?php echo $this->escape($f['hash']); ?>">
                                                        <button type="submit" class="btn btn-sm btn-outline-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_MARK'); ?></button>
                                                        <?php echo HTMLHelper::_('form.token'); ?>
                                                    </form>
                                                </div>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($fl['list']['pages'] > 1) : ?>
                        <nav aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PAGES')); ?>">
                            <ul class="pagination">
                                <?php if ($fl['list']['page'] > 1) : ?><li class="page-item"><a class="page-link" href="<?php echo $flUrl(['page' => $fl['list']['page'] - 1]); ?>"><?php echo Text::_('JPREV'); ?></a></li><?php endif; ?>
                                <li class="page-item disabled"><span class="page-link"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_PAGE_OF', (int) $fl['list']['page'], (int) $fl['list']['pages']); ?></span></li>
                                <?php if ($fl['list']['page'] < $fl['list']['pages']) : ?><li class="page-item"><a class="page-link" href="<?php echo $flUrl(['page' => $fl['list']['page'] + 1]); ?>"><?php echo Text::_('JNEXT'); ?></a></li><?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($r['more'] > 0) : ?><p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_MORE', (int) $r['more']); ?></p><?php endif; ?>
                    <?php if ($this->canChange && $s['ignored'] > 0) : ?>
                        <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.clearsafe'); ?>" method="post">
                            <button type="submit" class="btn btn-sm btn-outline-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_CLEARSAFE'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <section class="cp-card" aria-labelledby="cps-scan-chg">
                <h2 class="cp-card__title" id="cps-scan-chg"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_CHANGES'); ?></h2>
                <?php if (!$r['tracked']) : ?>
                    <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_TOOMANY'); ?></p>
                <?php elseif ($r['changes'] === null) : ?>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_NOBASE'); ?></p>
                <?php else : $c = $r['changes']; ?>
                    <p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_BASEAT', $day((int) $r['baselineAt'])); ?></p>
                    <?php if ($c['new'] === [] && $c['changed'] === [] && $c['removed'] === []) : ?>
                        <p><?php echo Ui::badge('ok', Text::_('COM_COLORPACK_SHIELD_SCAN_NOCHANGE')); ?></p>
                    <?php endif; ?>
                    <?php foreach (['new' => 'COM_COLORPACK_SHIELD_SCAN_NEW', 'changed' => 'COM_COLORPACK_SHIELD_SCAN_CHANGED', 'removed' => 'COM_COLORPACK_SHIELD_SCAN_REMOVED'] as $k => $label) : ?>
                        <?php if ($c[$k] !== []) : ?>
                            <h3 class="cps-label"><?php echo Text::_($label); ?> (<?php echo count($c[$k]); ?>)</h3>
                            <ul class="cps-list"><?php foreach ($c[$k] as $p) : ?><li><code class="cps-grow cp-wrap"><?php echo $this->escape((string) $p); ?></code><?php if ($this->canChange && $k !== 'removed') : ?><button type="button" class="btn btn-sm btn-outline-secondary" data-cps-code="<?php echo $this->escape((string) $p); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_OPEN'); ?></button><?php endif; ?></li><?php endforeach; ?></ul>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <?php if ($c['more'] > 0) : ?><p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_SCAN_MORE', (int) $c['more']); ?></p><?php endif; ?>
                <?php endif; ?>
                <?php if ($this->canChange && $s['canAccept'] && $r['tracked']) : ?>
                    <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SCAN_ACCEPT_TEXT'); ?></p>
                    <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=scan.accept'); ?>" method="post">
                        <button type="submit" class="btn btn-outline-secondary"><?php echo Text::_($r['baseline'] ? 'COM_COLORPACK_SHIELD_SCAN_ACCEPT_AGAIN' : 'COM_COLORPACK_SHIELD_SCAN_ACCEPT'); ?></button>
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
                    <div class="cps-grow"><h2 id="cps-code-title" class="cp-card__title cp-wrap"></h2><span class="cp-small cp-muted" id="cps-code-meta"></span></div>
                    <button type="button" class="btn btn-sm btn-outline-secondary" id="cps-code-close"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_CLOSE'); ?></button>
                </header>
                <div id="cps-code-marks" class="cp-small" role="list"></div>
                <div id="cps-code-syntax" class="cps-note" data-state="warn" role="alert" hidden></div>
                <div class="cps-editor">
                    <pre id="cps-code-nums" class="cps-nums" aria-hidden="true"></pre>
                    <textarea id="cps-code-text" spellcheck="false" wrap="off" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CODE_AREA')); ?>" class="form-control"></textarea>
                </div>
                <div id="cps-code-msg" class="cp-small" role="status" aria-live="polite"></div>
                <footer class="cps-dialog-foot">
                    <button type="button" class="btn btn-primary" id="cps-code-save"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_SAVE'); ?></button>
                    <div class="form-check cp-small" id="cps-code-force-wrap" hidden><input class="form-check-input" type="checkbox" id="cps-code-force"><label class="form-check-label" for="cps-code-force"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_FORCE'); ?></label></div>
                    <span class="cps-spacer"></span>
                    <button type="button" class="btn btn-outline-danger" id="cps-code-del"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE'); ?></button>
                </footer>
                <div id="cps-code-delbox" class="cp-callout" data-state="bad" role="alert" hidden>
                    <span class="cp-callout__icon" aria-hidden="true"><?php echo Ui::icon('bad'); ?></span>
                    <div class="cp-callout__body">
                        <p class="cp-callout__text"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE_HELP'); ?></p>
                        <div class="cps-field"><label for="cps-code-confirm"><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_TYPE_NAME'); ?></label><input type="text" id="cps-code-confirm" autocomplete="off" class="form-control"></div>
                        <div><button type="button" class="btn btn-outline-danger" id="cps-code-del-go" disabled><?php echo Text::_('COM_COLORPACK_SHIELD_CODE_DELETE_GO'); ?></button></div>
                    </div>
                </div>
            </div>
        </dialog>

        <?php if ($s['copies'] !== []) : ?>
            <section class="cp-card" aria-labelledby="cps-q-h" id="cps-copies">
                <h2 class="cp-card__title" id="cps-q-h"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_TITLE'); ?></h2>
                <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_TEXT'); ?></p>
                <div class="cp-tablewrap" role="region" tabindex="0" aria-labelledby="cps-q-h">
                    <table class="table cp-table">
                        <caption class="visually-hidden"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_TITLE'); ?></caption>
                        <thead><tr><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_TIME'); ?></th><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_FILE'); ?></th><th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COPIES_WHAT'); ?></th><th scope="col"><span class="visually-hidden"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_ACTION'); ?></span></th></tr></thead>
                        <tbody>
                            <?php foreach ($s['copies'] as $cp) : ?>
                                <tr>
                                    <td class="cp-nowrap"><?php echo $day((int) $cp['time']); ?></td>
                                    <td class="cp-wrap"><code><?php echo $this->escape($cp['path']); ?></code><div class="cp-small cp-muted"><?php echo (int) $cp['size']; ?> B</div></td>
                                    <td><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_' . strtoupper(preg_replace('/[^a-z_]/', '', $cp['action']))); ?></td>
                                    <td><div class="cp-row">
                                        <button type="button" class="btn btn-sm btn-outline-secondary" data-cps-restore="<?php echo $this->escape($cp['id']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_RESTORE'); ?></button>
                                        <button type="button" class="btn btn-sm btn-outline-danger" data-cps-drop="<?php echo $this->escape($cp['id']); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_COPY_DROP'); ?></button>
                                    </div></td>
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
