<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Gemini\Client;
use Colorpack\WP\ColorpackShield\Gemini\PromptBuilder;
use Colorpack\WP\ColorpackShield\Scanner\FileGuard;
use Colorpack\WP\ColorpackShield\Scanner\FileScanner;
use Colorpack\WP\ColorpackShield\Scanner\LineMarker;
use Colorpack\WP\ColorpackShield\Scanner\LocationRules;
use Colorpack\WP\ColorpackShield\Scanner\PhpSyntax;
use Colorpack\WP\ColorpackShield\Scanner\Quarantine;
use Colorpack\WP\ColorpackShield\Scanner\ScanStore;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > Files" screen: a chunked, resumable backdoor/web-shell scan, plus
 * the file actions a finding needs once found - view, edit (with a copy taken first and a
 * PHP-syntax check before saving), delete (confirm-by-typing-the-name), bulk delete/mark-safe,
 * and quarantine copies with restore. The WordPress equivalent of the Joomla edition's Scanner
 * screen and `ScanModel`'s full action surface. No code-highlighting editor, no accept-baseline/
 * diff view, and no scheduled scan (WP-Cron) yet - see CHANGELOG.
 */
final class ScanPage
{
    public const AJAX_START      = 'cps_scan_start';
    public const AJAX_STEP       = 'cps_scan_step';
    public const AJAX_VIEW       = 'cps_scan_view';
    public const AJAX_MARK_SAFE  = 'cps_scan_mark_safe';
    public const AJAX_AI_ANALYZE = 'cps_scan_ai_analyze';
    public const AJAX_SAVE       = 'cps_scan_save';
    public const AJAX_DELETE     = 'cps_scan_delete';
    public const AJAX_BULK       = 'cps_scan_bulk';
    public const AJAX_RESTORE    = 'cps_scan_restore';
    public const AJAX_DROP_COPY  = 'cps_scan_drop_copy';

    /** 2 MB, matches the Joomla edition's ScanModel::MAX_EDIT. */
    private const MAX_EDIT = 2097152;

    /** Matches the Joomla edition's ScanModel::MAX_BULK. */
    private const MAX_BULK = 200;

    private const NONCE = 'cps_scan';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        $store  = self::store();
        $result = $store->read('result');
        $state  = $store->read('state');
        $ignore = $store->read('ignore');
        $config = Settings::geminiConfig();
        $latest = get_option('colorpack_shield_scan_ai_latest', null);
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-scan'); ?>

                <section class="cps-card">
                    <h2 class="cps-h3"><?php esc_html_e('File Scan', 'colorpack-shield'); ?></h2>
                    <p class="cps-help"><?php esc_html_e('Looks for backdoors/web-shells by file name, location, and content signature. Nothing is changed on disk; this only reports what it finds.', 'colorpack-shield'); ?></p>
                    <div class="cps-card-foot">
                        <button type="button" class="cps-btn cps-btn-primary" id="cps-scan-start" data-nonce="<?php echo esc_attr(wp_create_nonce(self::NONCE)); ?>"<?php echo $state !== null ? ' disabled' : ''; ?>>
                            <?php esc_html_e('Start scan', 'colorpack-shield'); ?>
                        </button>
                        <span id="cps-scan-progress" class="cps-help"></span>
                    </div>
                </section>

                <?php if ($config !== null && $result !== null && ($result['findings'] ?? []) !== []) : ?>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="cps-card">
                        <input type="hidden" name="action" value="<?php echo esc_attr(self::AJAX_AI_ANALYZE); ?>">
                        <?php wp_nonce_field(self::NONCE); ?>
                        <div class="cps-card-foot">
                            <button type="submit" class="cps-btn"><?php esc_html_e('Analyze with AI', 'colorpack-shield'); ?></button>
                        </div>
                    </form>
                <?php endif; ?>

                <?php if (\is_array($latest) && \is_string($latest['answer'] ?? null)) : ?>
                    <section class="cps-card" aria-labelledby="cps-scan-ai-latest">
                        <h2 class="cps-h3" id="cps-scan-ai-latest">
                            <?php
                            printf(
                                /* translators: %s: human-readable time */
                                esc_html__('Latest AI analysis (%s)', 'colorpack-shield'),
                                esc_html(gmdate('Y-m-d H:i:s', (int) ($latest['when'] ?? 0)))
                            );
                            ?>
                        </h2>
                        <div class="cps-ai-answer"><?php echo SimpleMarkdown::toHtml($latest['answer']); ?></div>
                    </section>
                <?php endif; ?>

                <?php if ($result === null) : ?>
                    <div class="cps-alert cps-alert-info"><p><?php esc_html_e('No scan has run yet.', 'colorpack-shield'); ?></p></div>
                <?php else : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3">
                            <?php
                            printf(
                                /* translators: 1: high count, 2: medium count, 3: low count */
                                esc_html__('Findings: %1$d high, %2$d medium, %3$d low', 'colorpack-shield'),
                                (int) ($result['count']['high'] ?? 0),
                                (int) ($result['count']['medium'] ?? 0),
                                (int) ($result['count']['low'] ?? 0)
                            );
                            ?>
                        </h2>
                        <?php
                        // No form-level "action" field: every button below sets its own formaction
                        // (including the bulk ones) so admin-post.php's dispatch ($_REQUEST['action'])
                        // never sees two different action values submitted at once (one in the query
                        // string, one in the POST body) - that ambiguity would make the wrong handler
                        // fire depending on PHP's variables_order.
                        ?>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="cps-scan-bulk-form">
                            <?php wp_nonce_field(self::NONCE); ?>
                            <table class="cps-table">
                                <thead>
                                    <tr>
                                        <th><input type="checkbox" id="cps-scan-check-all"></th>
                                        <th><?php esc_html_e('Severity', 'colorpack-shield'); ?></th>
                                        <th><?php esc_html_e('Path', 'colorpack-shield'); ?></th>
                                        <th><?php esc_html_e('Rules', 'colorpack-shield'); ?></th>
                                        <th><?php esc_html_e('Size', 'colorpack-shield'); ?></th>
                                        <th><?php esc_html_e('Modified', 'colorpack-shield'); ?></th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (($result['findings'] ?? []) === []) : ?>
                                        <tr><td colspan="7" class="cps-muted"><?php esc_html_e('Nothing found.', 'colorpack-shield'); ?></td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($result['findings'] as $f) : ?>
                                        <tr>
                                            <td><input type="checkbox" name="paths[]" value="<?php echo esc_attr($f['path']); ?>" class="cps-scan-check"></td>
                                            <td><?php echo esc_html($f['sev']); ?></td>
                                            <td>
                                                <button type="button" class="cps-scan-view" data-path="<?php echo esc_attr($f['path']); ?>" style="background:none;border:0;padding:0;cursor:pointer;color:var(--action,#1f5fa8);text-decoration:underline">
                                                    <code><?php echo esc_html($f['path']); ?></code>
                                                </button>
                                            </td>
                                            <td><?php echo esc_html(implode(', ', $f['rules'])); ?></td>
                                            <td class="cps-num"><?php echo esc_html((string) $f['size']); ?></td>
                                            <td><?php echo esc_html(gmdate('Y-m-d H:i:s', $f['mtime'])); ?></td>
                                            <td>
                                                <button type="submit" formaction="<?php echo esc_url(admin_url('admin-post.php?action=' . self::AJAX_MARK_SAFE . '&path=' . rawurlencode($f['path']) . '&hash=' . rawurlencode($f['hash']))); ?>" class="cps-btn"><?php esc_html_e('Mark safe', 'colorpack-shield'); ?></button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php if (($result['findings'] ?? []) !== []) : ?>
                                <div class="cps-card-foot">
                                    <button type="submit" name="bulk_action" value="safe" formaction="<?php echo esc_url(admin_url('admin-post.php?action=' . self::AJAX_BULK)); ?>" class="cps-btn"><?php esc_html_e('Mark selected safe', 'colorpack-shield'); ?></button>
                                    <button type="submit" name="bulk_action" value="delete" formaction="<?php echo esc_url(admin_url('admin-post.php?action=' . self::AJAX_BULK)); ?>" class="cps-btn cps-btn-danger" onclick="return confirm(<?php echo esc_js(__('Delete every selected file? A copy of each is kept and can be restored below.', 'colorpack-shield')); ?>);"><?php esc_html_e('Delete selected', 'colorpack-shield'); ?></button>
                                </div>
                            <?php endif; ?>
                        </form>
                        <p class="cps-help">
                            <?php
                            printf(
                                /* translators: %d: number of findings marked safe */
                                esc_html__('%d marked safe (excluded from future scans unless the file changes).', 'colorpack-shield'),
                                \is_array($ignore) ? \count($ignore) : 0
                            );
                            ?>
                        </p>
                    </section>
                <?php endif; ?>

                <?php $copies = (new Quarantine(self::quarantineDir()))->items(100); ?>
                <?php if ($copies !== []) : ?>
                    <section class="cps-card">
                        <h2 class="cps-h3"><?php esc_html_e('Copies kept before a change', 'colorpack-shield'); ?></h2>
                        <p class="cps-help"><?php esc_html_e('A copy is taken automatically before any edit or delete. Nothing done on this screen is final while a copy still exists here.', 'colorpack-shield'); ?></p>
                        <table class="cps-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Path', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Action', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('When', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Size', 'colorpack-shield'); ?></th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($copies as $c) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($c['path']); ?></code></td>
                                        <td><?php echo esc_html($c['action']); ?></td>
                                        <td><?php echo esc_html(gmdate('Y-m-d H:i:s', $c['time'])); ?></td>
                                        <td class="cps-num"><?php echo esc_html((string) $c['size']); ?></td>
                                        <td style="display:flex;gap:8px">
                                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                <input type="hidden" name="action" value="<?php echo esc_attr(self::AJAX_RESTORE); ?>">
                                                <input type="hidden" name="id" value="<?php echo esc_attr($c['id']); ?>">
                                                <?php wp_nonce_field(self::NONCE); ?>
                                                <button type="submit" class="cps-btn" onclick="return confirm(<?php echo esc_js(__('Restore this file? If a file is there now, it will be kept as a new copy first.', 'colorpack-shield')); ?>);"><?php esc_html_e('Restore', 'colorpack-shield'); ?></button>
                                            </form>
                                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                <input type="hidden" name="action" value="<?php echo esc_attr(self::AJAX_DROP_COPY); ?>">
                                                <input type="hidden" name="id" value="<?php echo esc_attr($c['id']); ?>">
                                                <?php wp_nonce_field(self::NONCE); ?>
                                                <button type="submit" class="cps-btn"><?php esc_html_e('Discard copy', 'colorpack-shield'); ?></button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </section>
                <?php endif; ?>
            </div>
        </div>

        <dialog class="cps-dialog" id="cps-view-dialog">
            <div class="cps-dialog-in">
                <div class="cps-dialog-head">
                    <div>
                        <h3 id="cps-view-path"></h3>
                        <div id="cps-code-marks"></div>
                    </div>
                    <button type="button" class="cps-btn cps-btn-sm" id="cps-view-close"><?php esc_html_e('Close', 'colorpack-shield'); ?></button>
                </div>
                <div id="cps-view-alert"></div>
                <div class="cps-editor">
                    <pre class="cps-nums" id="cps-view-nums"></pre>
                    <textarea id="cps-view-textarea" spellcheck="false"></textarea>
                </div>
                <div class="cps-dialog-foot">
                    <button type="button" class="cps-btn cps-btn-primary" id="cps-view-save"><?php esc_html_e('Save', 'colorpack-shield'); ?></button>
                    <button type="button" class="cps-btn cps-btn-danger" id="cps-view-delete"><?php esc_html_e('Delete', 'colorpack-shield'); ?></button>
                    <span id="cps-view-status" class="cps-help"></span>
                </div>
            </div>
        </dialog>
        <script>
        (function () {
            var nonce   = <?php echo wp_json_encode(wp_create_nonce(self::NONCE)); ?>;
            var ajaxUrl = <?php echo wp_json_encode(admin_url('admin-ajax.php')); ?>;

            function post(action, extra) {
                var body = new URLSearchParams(Object.assign({ action: action, _wpnonce: nonce }, extra || {}));

                return fetch(ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body }).then(function (r) { return r.json(); });
            }

            // --- Start scan ---------------------------------------------------------------

            var btn = document.getElementById('cps-scan-start');
            var out = document.getElementById('cps-scan-progress');

            if (btn) {
                btn.addEventListener('click', function () {
                    btn.disabled = true;

                    function step() {
                        post(<?php echo wp_json_encode(self::AJAX_STEP); ?>).then(function (res) {
                            if (!res.success) {
                                out.textContent = <?php echo wp_json_encode(__('Scan failed.', 'colorpack-shield')); ?>;

                                return;
                            }

                            var d = res.data;

                            if (d.busy) {
                                setTimeout(step, 500);

                                return;
                            }

                            out.textContent = d.seen + ' ' + <?php echo wp_json_encode(__('files seen,', 'colorpack-shield')); ?> + ' ' + d.findings + ' ' + <?php echo wp_json_encode(__('findings so far', 'colorpack-shield')); ?>;

                            if (d.done) {
                                window.location.reload();
                            } else {
                                setTimeout(step, 50);
                            }
                        });
                    }

                    post(<?php echo wp_json_encode(self::AJAX_START); ?>).then(function () { step(); });
                });
            }

            // --- Select-all checkbox -------------------------------------------------------

            var checkAll = document.getElementById('cps-scan-check-all');

            if (checkAll) {
                checkAll.addEventListener('change', function () {
                    document.querySelectorAll('.cps-scan-check').forEach(function (c) { c.checked = checkAll.checked; });
                });
            }

            // --- View / edit / delete dialog ------------------------------------------------

            var dialog   = document.getElementById('cps-view-dialog');
            var pathEl   = document.getElementById('cps-view-path');
            var marksEl  = document.getElementById('cps-code-marks');
            var alertEl  = document.getElementById('cps-view-alert');
            var numsEl   = document.getElementById('cps-view-nums');
            var textEl   = document.getElementById('cps-view-textarea');
            var saveBtn  = document.getElementById('cps-view-save');
            var delBtn   = document.getElementById('cps-view-delete');
            var statusEl = document.getElementById('cps-view-status');
            var current  = { path: '', hash: '' };

            var L = {
                tooBig: <?php echo wp_json_encode(__('This file is too large to edit here.', 'colorpack-shield')); ?>,
                binary: <?php echo wp_json_encode(__('This file is binary - it cannot be shown as text.', 'colorpack-shield')); ?>,
                loadFailed: <?php echo wp_json_encode(__('Could not open this file.', 'colorpack-shield')); ?>,
                saved: <?php echo wp_json_encode(__('Saved.', 'colorpack-shield')); ?>,
                saveFailed: <?php echo wp_json_encode(__('Could not save.', 'colorpack-shield')); ?>,
                changedSince: <?php echo wp_json_encode(__('This file changed on disk since it was opened. Reopen it to see the latest version before saving.', 'colorpack-shield')); ?>,
                syntaxError: <?php echo wp_json_encode(__('This no longer looks like valid PHP (line %d: %s). Saving anyway may break the site.', 'colorpack-shield')); ?>,
                saveAnyway: <?php echo wp_json_encode(__('Save anyway', 'colorpack-shield')); ?>,
                deleteConfirm: <?php echo wp_json_encode(__('Type the file name to confirm deletion:', 'colorpack-shield')); ?>,
                deleteFailed: <?php echo wp_json_encode(__('Could not delete.', 'colorpack-shield')); ?>
            };

            function renderNums(content) {
                var n = content.split('\n').length;
                var lines = [];
                for (var i = 1; i <= n; i++) { lines.push(i); }
                numsEl.textContent = lines.join('\n');
            }

            function openView(path) {
                current = { path: path, hash: '' };
                pathEl.textContent = path;
                marksEl.innerHTML = '';
                alertEl.innerHTML = '';
                statusEl.textContent = '';
                textEl.value = '';
                textEl.disabled = true;
                saveBtn.disabled = true;
                delBtn.disabled = true;
                dialog.showModal();

                post(<?php echo wp_json_encode(self::AJAX_VIEW); ?>, { path: path }).then(function (res) {
                    if (!res.success) {
                        alertEl.innerHTML = '<div class="cps-alert cps-alert-bad">' + (res.data && res.data.err === 'too_big' ? L.tooBig : L.loadFailed) + '</div>';

                        return;
                    }

                    var d = res.data;
                    current.hash = d.hash;
                    textEl.value = d.content;
                    renderNums(d.content);
                    textEl.disabled = !d.canEdit;
                    saveBtn.disabled = !d.canEdit;
                    delBtn.disabled = !d.canDelete;

                    if (d.binary) {
                        alertEl.innerHTML = '<div class="cps-alert cps-alert-warn">' + L.binary + '</div>';
                    }

                    (d.marks || []).forEach(function (m) {
                        var b = document.createElement('span');
                        b.className = 'cps-mk';
                        b.textContent = m.rule + ' @' + m.line;
                        marksEl.appendChild(b);
                    });
                });
            }

            document.querySelectorAll('.cps-scan-view').forEach(function (b) {
                b.addEventListener('click', function () { openView(b.getAttribute('data-path')); });
            });

            document.getElementById('cps-view-close').addEventListener('click', function () { dialog.close(); });

            function doSave(force) {
                statusEl.textContent = '';
                post(<?php echo wp_json_encode(self::AJAX_SAVE); ?>, { path: current.path, content: textEl.value, base_hash: current.hash, force: force ? '1' : '' }).then(function (res) {
                    if (!res.success) {
                        var d = res.data || {};

                        if (d.err === 'changed') {
                            alertEl.innerHTML = '<div class="cps-alert cps-alert-bad">' + L.changedSince + '</div>';
                        } else if (d.err === 'syntax' && d.syntax) {
                            alertEl.innerHTML = '<div class="cps-alert cps-alert-warn">' + L.syntaxError.replace('%d', d.syntax.line).replace('%s', d.syntax.message) + ' <button type="button" class="cps-btn cps-btn-sm" id="cps-view-force-save">' + L.saveAnyway + '</button></div>';
                            document.getElementById('cps-view-force-save').addEventListener('click', function () { doSave(true); });
                        } else {
                            alertEl.innerHTML = '<div class="cps-alert cps-alert-bad">' + L.saveFailed + '</div>';
                        }

                        return;
                    }

                    current.hash = res.data.hash;
                    alertEl.innerHTML = '';
                    statusEl.textContent = L.saved;
                });
            }

            saveBtn.addEventListener('click', function () { doSave(false); });

            delBtn.addEventListener('click', function () {
                var name = current.path.split('/').pop();
                var typed = window.prompt(L.deleteConfirm + ' "' + name + '"');

                if (typed === null) {
                    return;
                }

                post(<?php echo wp_json_encode(self::AJAX_DELETE); ?>, { path: current.path, confirm: typed }).then(function (res) {
                    if (!res.success) {
                        alertEl.innerHTML = '<div class="cps-alert cps-alert-bad">' + L.deleteFailed + '</div>';

                        return;
                    }

                    window.location.reload();
                });
            });
        })();
        </script>
        <?php
    }

    public static function ajaxStart(): void
    {
        check_ajax_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }

        self::store()->write('state', FileScanner::newState(time()));
        wp_send_json_success(['ok' => true]);
    }

    public static function ajaxStep(): void
    {
        check_ajax_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }

        $store = self::store();
        $dir   = self::storeDir();

        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            wp_send_json_error(null, 500);
        }

        // One step at a time: a double click or a second tab must not run two steps over the same state.
        $lock = @fopen($dir . '/lock', 'c');

        if ($lock === false || !flock($lock, \LOCK_EX | \LOCK_NB)) {
            wp_send_json_success(['busy' => true]);
        }

        try {
            $state = $store->read('state');

            if ($state === null) {
                wp_send_json_error(null, 404);
            }

            $ignore = $store->read('ignore');
            $budget = self::budget();
            $state  = FileScanner::step($state, ABSPATH, microtime(true) + $budget, \is_array($ignore) ? array_map('strval', $ignore) : []);

            if ($state['done']) {
                $now  = time();
                $base = $store->read('baseline');
                $store->write('result', FileScanner::result($state, $base, $now));
                $store->write('lastfiles', ['at' => $now, 'files' => $state['tracked'] ? $state['files'] : null]);
                $store->delete('state');
            } else {
                $store->write('state', $state);
            }

            wp_send_json_success([
                'done'     => (bool) $state['done'],
                'seen'     => (int) $state['seen'],
                'php'      => (int) $state['php'],
                'findings' => \count($state['findings']),
            ]);
        } finally {
            flock($lock, \LOCK_UN);
            fclose($lock);
        }
    }

    public static function handleMarkSafe(): void
    {
        check_admin_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        // path/hash arrive via the "Mark safe" button's own formaction query string (the
        // surrounding bulk-select form's POST body carries unrelated fields - see the markup's
        // own comment on why nothing here reads $_REQUEST for "action" or these two fields).
        $path = \is_string($_GET['path'] ?? null) ? wp_unslash($_GET['path']) : '';
        $hash = \is_string($_GET['hash'] ?? null) ? wp_unslash($_GET['hash']) : '';

        if ($path !== '') {
            self::markSafe($path, $hash);
        }

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-scan'));
        exit;
    }

    /**
     * admin-post.php handler for the Scanner's "Analyze with AI" button - same pattern as
     * ActivityPage::handleAnalyze(), reusing PromptBuilder::forScanFindings() (metadata only,
     * file contents are never read or sent) and the admin's own interface language.
     */
    public static function handleAiAnalyze(): void
    {
        check_admin_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $config = Settings::geminiConfig();
        $result = self::store()->read('result');
        $target = admin_url('admin.php?page=colorpack-shield-scan');

        if ($config === null || $result === null || (($result['findings'] ?? []) === [])) {
            wp_safe_redirect($target);
            exit;
        }

        $lang   = substr(get_user_locale(), 0, 2);
        $prompt = (new PromptBuilder())->forScanFindings($result['findings'], $lang);
        $answer = (new Client())->ask($config, $prompt);

        update_option('colorpack_shield_scan_ai_latest', [
            'prompt' => $prompt,
            'answer' => $answer,
            'when'   => time(),
        ]);
        AiStore::history()->record('scan_ondemand', $prompt, $answer, time());

        wp_safe_redirect($target);
        exit;
    }

    /**
     * The code viewer's content for one file - the WordPress equivalent of the Joomla edition's
     * ScanModel::view(). AJAX (not admin-post) so the dialog can show the result without a page
     * reload.
     */
    public static function ajaxView(): void
    {
        check_ajax_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['err' => 'forbidden'], 403);
        }

        $rel = \is_string($_POST['path'] ?? null) ? wp_unslash($_POST['path']) : '';
        $g   = self::guard($rel, 'view');

        if (!$g['ok']) {
            wp_send_json_error(['err' => $g['err']]);
        }

        $real = $g['real'];
        $size = (int) @filesize($real);

        if ($size > self::MAX_EDIT) {
            wp_send_json_error(['err' => 'too_big', 'size' => $size]);
        }

        $raw = @file_get_contents($real);

        if ($raw === false) {
            wp_send_json_error(['err' => 'unreadable']);
        }

        $text    = !str_contains($raw, "\0") && preg_match('//u', $raw) === 1;
        $kind    = LineMarker::kindOf($rel);
        $inData  = preg_match('~^(?:' . LocationRules::DATA_DIRS . ')/~i', $rel) === 1;
        $allowed = self::allowed();
        $canEdit = FileGuard::check(ABSPATH, $rel, $allowed, 'edit')['code'] === FileGuard::OK;
        $delChk  = FileGuard::check(ABSPATH, $rel, $allowed, 'delete');
        $syntax  = $text && $kind === 'php' ? PhpSyntax::error($raw) : null;

        self::audit('view', $rel);

        wp_send_json_success([
            'path'      => $rel,
            'content'   => $text ? $raw : substr(mb_convert_encoding(substr($raw, 0, 65536), 'UTF-8', 'UTF-8'), 0, 65536),
            'binary'    => !$text,
            'size'      => $size,
            'hash'      => substr(sha1($raw), 0, 12),
            'marks'     => LineMarker::marks($text ? $raw : substr($raw, 0, 524288), $kind, $inData),
            'syntax'    => $syntax,
            'canEdit'   => $canEdit && $text,
            'canDelete' => $delChk['code'] === FileGuard::OK,
            'deleteWhy' => $delChk['code'] === FileGuard::OK ? '' : $delChk['code'],
        ]);
    }

    /**
     * Save an edit. The file is quarantined first; PHP that no longer parses is refused unless
     * $force. The WordPress equivalent of ScanModel::save().
     */
    public static function ajaxSave(): void
    {
        check_ajax_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['err' => 'forbidden'], 403);
        }

        $rel     = \is_string($_POST['path'] ?? null) ? wp_unslash($_POST['path']) : '';
        $content = \is_string($_POST['content'] ?? null) ? wp_unslash($_POST['content']) : '';
        $base    = \is_string($_POST['base_hash'] ?? null) ? wp_unslash($_POST['base_hash']) : '';
        $force   = !empty($_POST['force']);

        $g = self::guard($rel, 'edit');

        if (!$g['ok']) {
            wp_send_json_error(['err' => $g['err']]);
        }

        if (\strlen($content) > self::MAX_EDIT) {
            wp_send_json_error(['err' => 'too_big']);
        }

        $real = $g['real'];
        $now  = @file_get_contents($real);

        if ($now === false || str_contains($now, "\0") || preg_match('//u', $now) !== 1) {
            wp_send_json_error(['err' => 'binary']);
        }

        // Somebody (or the site) changed the file since it was opened: do not overwrite blindly.
        if ($base !== '' && !hash_equals(substr(sha1($now), 0, 12), $base)) {
            wp_send_json_error(['err' => 'changed']);
        }

        $kind = LineMarker::kindOf($rel);

        if (!$force && $kind === 'php' && ($syntax = PhpSyntax::error($content)) !== null) {
            wp_send_json_error(['err' => 'syntax', 'syntax' => $syntax]);
        }

        if ((new Quarantine(self::quarantineDir()))->store($real, $rel, 'edit') === null) {
            wp_send_json_error(['err' => 'no_backup']);
        }

        if (@file_put_contents($real, $content, \LOCK_EX) === false) {
            self::audit('save_failed', $rel);
            wp_send_json_error(['err' => 'write_failed']);
        }

        self::audit('save', $rel . ' (' . \strlen($content) . ' B)');
        self::refresh($rel);

        wp_send_json_success([
            'hash'   => substr(sha1($content), 0, 12),
            'marks'  => LineMarker::marks($content, $kind),
            'syntax' => $kind === 'php' ? PhpSyntax::error($content) : null,
        ]);
    }

    /** The WordPress equivalent of ScanModel::delete() - confirm-by-typing-the-filename. */
    public static function ajaxDelete(): void
    {
        check_ajax_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['err' => 'forbidden'], 403);
        }

        $rel     = \is_string($_POST['path'] ?? null) ? wp_unslash($_POST['path']) : '';
        $confirm = \is_string($_POST['confirm'] ?? null) ? wp_unslash($_POST['confirm']) : '';

        $g = self::guard($rel, 'delete');

        if (!$g['ok']) {
            wp_send_json_error(['err' => $g['err']]);
        }

        if ($confirm !== basename($rel)) {
            wp_send_json_error(['err' => 'confirm']);
        }

        $r = self::remove($rel, $g['real'], 'delete');

        if (!$r['ok']) {
            wp_send_json_error(['err' => $r['err'] ?? 'failed']);
        }

        wp_send_json_success([]);
    }

    /** Delete or mark-safe every checked finding at once (capped at MAX_BULK per call). */
    public static function handleBulk(): void
    {
        check_admin_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $action = \is_string($_POST['bulk_action'] ?? null) ? $_POST['bulk_action'] : '';
        $paths  = \is_array($_POST['paths'] ?? null) ? array_values(array_filter(wp_unslash($_POST['paths']), 'is_string')) : [];
        $paths  = \array_slice(array_values(array_unique($paths)), 0, self::MAX_BULK);

        if ($action === 'safe') {
            $res = self::store()->read('result');
            $hashes = [];

            foreach ((array) ($res['findings'] ?? []) as $f) {
                if (\is_string($f['path'] ?? null) && \is_string($f['hash'] ?? null)) {
                    $hashes[$f['path']] = $f['hash'];
                }
            }

            foreach ($paths as $rel) {
                if (isset($hashes[$rel])) {
                    self::markSafe($rel, $hashes[$rel]);
                }
            }
        } elseif ($action === 'delete') {
            foreach ($paths as $rel) {
                $g = self::guard($rel, 'delete');

                if ($g['ok']) {
                    self::remove($rel, $g['real'], 'bulk_delete');
                }
            }
        }

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-scan'));
        exit;
    }

    public static function handleRestore(): void
    {
        check_admin_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $id = \is_string($_POST['id'] ?? null) ? wp_unslash($_POST['id']) : '';
        $q  = new Quarantine(self::quarantineDir());
        $res = $q->restore($id, ABSPATH, true);
        self::audit($res === 'ok' ? 'restore' : 'restore_refused', $id . ' ' . $res);

        if ($res === 'ok') {
            foreach ($q->items(300) as $it) {
                if ($it['id'] === $id) {
                    self::refresh($it['path']);
                }
            }
        }

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-scan'));
        exit;
    }

    public static function handleDropCopy(): void
    {
        check_admin_referer(self::NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $id = \is_string($_POST['id'] ?? null) ? wp_unslash($_POST['id']) : '';
        self::audit('drop_copy', $id);
        (new Quarantine(self::quarantineDir()))->drop($id);

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-scan'));
        exit;
    }

    /**
     * Marks one finding safe - the shared core behind both the single "Mark safe" button
     * (handleMarkSafe()) and the bulk "safe" action.
     */
    private static function markSafe(string $path, string $hash): bool
    {
        if (preg_match('/^[0-9a-f]{12}$/', $hash) !== 1) {
            return false;
        }

        $store = self::store();
        $res   = $store->read('result');

        if ($res === null) {
            return false;
        }

        $found = false;

        foreach ((array) ($res['findings'] ?? []) as $f) {
            if (($f['path'] ?? null) === $path && ($f['hash'] ?? null) === $hash) {
                $found = true;

                break;
            }
        }

        if (!$found) {
            return false;
        }

        $ign = $store->read('ignore') ?? [];

        if (\count($ign) >= 500 && !isset($ign[$path])) {
            return false;
        }

        $ign[$path] = $hash;

        if (!$store->write('ignore', $ign)) {
            return false;
        }

        $res['findings'] = array_values(array_filter((array) $res['findings'], static fn (array $f): bool => !($f['path'] === $path && $f['hash'] === $hash)));
        $res['count']    = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($res['findings'] as $f) {
            $res['count'][$f['sev']]++;
        }

        $res['ignored'] = (int) ($res['ignored'] ?? 0) + 1;
        $store->write('result', $res);

        return true;
    }

    /** @return array{ok:bool,err?:string} */
    private static function remove(string $rel, string $real, string $label): array
    {
        if ((new Quarantine(self::quarantineDir()))->store($real, $rel, 'delete') === null) {
            return ['ok' => false, 'err' => 'no_backup'];
        }

        if (!@unlink($real)) {
            self::audit('delete_failed', $rel);

            return ['ok' => false, 'err' => 'permission'];
        }

        self::audit($label, $rel);
        self::refresh($rel);

        return ['ok' => true];
    }

    /** Paths this screen is allowed to touch: the last scan's findings plus its new/changed list. */
    private static function allowed(): array
    {
        $r   = self::store()->read('result');
        $out = [];

        foreach ((array) ($r['findings'] ?? []) as $f) {
            if (\is_string($f['path'] ?? null)) {
                $out[$f['path']] = 1;
            }
        }

        foreach (['new', 'changed'] as $k) {
            foreach ((array) ($r['changes'][$k] ?? []) as $p) {
                if (\is_string($p)) {
                    $out[$p] = 1;
                }
            }
        }

        return $out;
    }

    /** @return array{ok:bool,err?:string,real?:string} */
    private static function guard(string $rel, string $action): array
    {
        $g = FileGuard::check(ABSPATH, $rel, self::allowed(), $action);

        if ($g['code'] !== FileGuard::OK) {
            self::audit('denied', $action . ' ' . $g['code'] . ' ' . $rel);

            return ['ok' => false, 'err' => $g['code']];
        }

        return ['ok' => true, 'real' => (string) $g['real']];
    }

    /**
     * After a change: look at that one file again and update the shown result (findings, counts).
     * The WordPress equivalent of ScanModel::refresh().
     */
    private static function refresh(string $rel): void
    {
        $s   = self::store();
        $res = $s->read('result');

        if ($res === null) {
            return;
        }

        $ign  = $s->read('ignore');
        $one  = FileScanner::inspectFile(ABSPATH, $rel, \is_array($ign) ? array_map('strval', $ign) : []);
        $list = array_values(array_filter((array) ($res['findings'] ?? []), static fn (array $f): bool => ($f['path'] ?? '') !== $rel));

        if ($one !== null && \count($list) < FileScanner::MAX_FINDINGS) {
            $list[] = $one;
        }

        $rank = ['high' => 3, 'medium' => 2, 'low' => 1];
        usort($list, static fn (array $a, array $b): int => [$rank[$b['sev']], $a['path']] <=> [$rank[$a['sev']], $b['path']]);
        $res['findings'] = $list;
        $res['count']    = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($list as $f) {
            $res['count'][$f['sev']]++;
        }

        if (!is_file(ABSPATH . $rel) && \is_array($res['changes'] ?? null)) {
            foreach (['new', 'changed'] as $k) {
                $res['changes'][$k] = array_values(array_filter((array) ($res['changes'][$k] ?? []), static fn ($p): bool => $p !== $rel));
            }
        }

        $s->write('result', $res);
    }

    /** One line in the plugin's own Activity log: who did what to which file. */
    private static function audit(string $action, string $detail): void
    {
        $ip     = \Colorpack\WP\ColorpackShield\Net\ClientIpResolver::normalise((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        $detail = substr(preg_replace('/[\x00-\x1f\x7f]/', '?', $detail) ?? '', 0, 200);
        (new ActivityLog(ActivityLog::defaultPath()))->write('NOTE', [
            'client' => 'administrator',
            'kind'   => 'scan_action',
            'action' => $action,
            'user'   => (string) get_current_user_id(),
            'sample' => $detail,
        ], $ip);
    }

    private static function store(): ScanStore
    {
        return new ScanStore(self::storeDir());
    }

    private static function storeDir(): string
    {
        return trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/scan';
    }

    private static function quarantineDir(): string
    {
        return trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/quarantine';
    }

    /** Seconds one step may work: well inside the host's PHP time limit, never more than 6. */
    private static function budget(): float
    {
        $max = (int) ini_get('max_execution_time');

        return $max > 0 ? max(1.0, min(6.0, $max * 0.35)) : 6.0;
    }
}
