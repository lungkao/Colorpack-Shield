<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\IpMasker;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogFilter;
use Colorpack\Component\ColorpackShield\Administrator\Core\SimpleMarkdown;
use Colorpack\Component\ColorpackShield\Administrator\Core\TimeFormat;
use Joomla\CMS\Factory;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Activity\HtmlView $this */
$d    = $this->data;
$c    = $d['criteria'];
$tz   = (string) Factory::getApplication()->get('offset', 'UTC');
$when = static fn (int $ts): string => TimeFormat::local($ts, $tz);
$mask = (int) ($_GET['mask'] ?? 0) === 1;
$list = $d['list'];
$q    = array_filter([
    'option' => 'com_colorpack_shield', 'view' => 'activity', 'types' => $c['types'], 'client' => $c['client'], 'rule' => $c['rule'],
    'text' => $c['text'], 'days' => $c['days'], 'mask' => $mask ? 1 : 0,
], static fn ($v) => $v !== '' && $v !== []);
$url  = static fn (array $extra): string => Route::_('index.php?' . http_build_query($extra + $q));
$badge = ['BLOCK' => 'cps-badge-bad', 'DETECT' => 'cps-badge-warn', 'LOCK' => 'cps-badge-bad', 'OBSERVE' => 'cps-badge-info', 'ALERT' => 'cps-badge-info', 'NOTE' => ''];
$hint  = ['BLOCK', 'DETECT', 'LOCK', 'OBSERVE', 'ALERT'];
// Rule ids this screen can explain on hover - every WafResult::hit() rule id across the shields,
// plus the path-ban ones. An id not in this list (an upload reason, an admin kind=, …) gets no
// tooltip rather than a raw, un-translated language key.
$ruleHints = [
    'union_select', 'stacked_query', 'boolean_tautology', 'sql_comment', 'time_based', 'error_based', 'meta_tables', 'file_access',
    'script_tag', 'js_uri', 'vbscript_uri', 'event_handler', 'risky_tag', 'img_handler', 'data_html', 'css_expr',
    'deep_traversal', 'sensitive_file', 'php_wrapper', 'traversal_hit',
    'remote_script', 'remote_wrapper', 'null_terminate',
    'control_chars', 'jndi_lookup', 'malformed_content_type', 'malformed_forwarded', 'malformed_host', 'malformed_ip_header',
    'malformed_negotiation', 'oversize', 'php_object_injection', 'php_open_tag', 'shellshock', 'sqli_strict', 'xss_strict', 'traversal',
    'path_traversal', 'path_ctrl', 'path_overlong_utf8', 'path_param_trick', 'path_double_encoded', 'path_bad_utf8', 'path_backslash',
    'path_double_slash', 'path_oversize', 'path_php_tag', 'path_jndi', 'path_wrapper', 'path_sqli', 'path_xss',
    'php_in_data_dir', 'direct_php_in_code', 'joomla_internal', 'scanner_probe', 'admin_tool_probe', 'path_extra_deny', 'ip_banned',
];
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <?php if ($d['report'] !== null) :
            $rp    = $d['report'];
            $peak  = max(1, ...array_map(static fn (array $x): int => $x['blocked'] + $x['detected'], $rp['daily']));
            $bar   = static fn (int $n): int => $n > 0 ? max(4, (int) round($n / $peak * 150)) : 0;
            $trend = static function (?int $ch): string {
                if ($ch === null) {
                    return Text::_('COM_COLORPACK_SHIELD_CHANGE_NONE');
                }

                return $ch === 0 ? Text::_('COM_COLORPACK_SHIELD_CHANGE_SAME') : Text::sprintf($ch > 0 ? 'COM_COLORPACK_SHIELD_CHANGE_UP' : 'COM_COLORPACK_SHIELD_CHANGE_DOWN', abs($ch));
            };
            $nf    = static fn (int $n): string => number_format($n);
            ?>
            <div class="cps-tiles">
                <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?> · <?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></span><b><?php echo $nf($rp['week']['blocked']); ?></b><em class="<?php echo $rp['blocked'] === null ? '' : ($rp['blocked'] > 0 ? 'cps-up' : 'cps-down'); ?>"><?php echo $trend($rp['blocked']); ?></em></div>
                <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></span><b><?php echo $nf($rp['week']['detected']); ?></b><em><?php echo $trend($rp['logged']); ?></em></div>
                <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_UNIQUE_IPS'); ?></span><b><?php echo $nf($rp['unique']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
                <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_LOCKOUTS'); ?></span><b><?php echo $nf($rp['week']['locks']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
            </div>
            <section class="cps-card" aria-labelledby="cps-act-chart">
                <h2 class="cps-h3" id="cps-act-chart"><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?> / <?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></h2>
                <div class="cps-chart" role="img" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>">
                    <?php foreach ($rp['daily'] as $x) : ?>
                        <div class="cps-col"><div class="cps-stack-bars"><i class="cps-bar-log" style="height:<?php echo $bar($x['detected']); ?>px"></i><i style="height:<?php echo $bar($x['blocked']); ?>px"></i></div><small><?php echo $this->escape(substr($x['date'], 8, 2)); ?></small></div>
                    <?php endforeach; ?>
                </div>
                <div class="cps-legend"><span><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span class="cps-lg-log"><?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></span></div>
            </section>
        <?php endif; ?>

        <form action="<?php echo Route::_('index.php'); ?>" method="get" class="cps-card" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_FILTER')); ?>">
            <input type="hidden" name="option" value="com_colorpack_shield">
            <input type="hidden" name="view" value="activity">
            <div class="cps-fields">
                <div class="cps-field">
                    <label for="cps-f-text"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_TEXT'); ?></label>
                    <input type="text" id="cps-f-text" name="text" maxlength="100" value="<?php echo $this->escape($c['text']); ?>">
                </div>
                <div class="cps-field">
                    <label for="cps-f-rule"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RULE'); ?></label>
                    <input type="text" id="cps-f-rule" name="rule" maxlength="60" value="<?php echo $this->escape($c['rule']); ?>">
                </div>
                <div class="cps-field">
                    <label for="cps-f-client"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_AREA'); ?></label>
                    <select id="cps-f-client" name="client">
                        <option value=""><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_ALL'); ?></option>
                        <?php foreach (['site', 'administrator', 'api'] as $a) : ?>
                            <option value="<?php echo $a; ?>"<?php echo $c['client'] === $a ? ' selected' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_CLIENT_' . strtoupper($a)); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="cps-field">
                    <label for="cps-f-days"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_PERIOD'); ?></label>
                    <select id="cps-f-days" name="days">
                        <?php foreach ([1, 7, 30, 90] as $n) : ?>
                            <option value="<?php echo $n; ?>"<?php echo $c['days'] === $n ? ' selected' : ''; ?>><?php echo Text::plural('COM_COLORPACK_SHIELD_DAYS', $n); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <fieldset class="cps-field cps-wide">
                    <legend><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_TYPE'); ?></legend>
                    <div class="cps-radio">
                        <?php foreach (LogFilter::TYPES as $t) : ?>
                            <label><input type="checkbox" name="types[]" value="<?php echo $t; ?>"<?php echo in_array($t, $c['types'], true) ? ' checked' : ''; ?>> <?php echo Text::_('COM_COLORPACK_SHIELD_TYPE_' . $t); ?></label>
                        <?php endforeach; ?>
                    </div>
                </fieldset>
                <div class="cps-field cps-wide">
                    <div class="cps-radio"><label><input type="checkbox" name="mask" value="1"<?php echo $mask ? ' checked' : ''; ?>> <?php echo Text::_('COM_COLORPACK_SHIELD_MASK_IPS'); ?></label></div>
                </div>
            </div>
            <div class="cps-card-foot">
                <button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_APPLY'); ?></button>
                <a class="cps-btn" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=activity'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RESET'); ?></a>
                <?php if ($list['total'] > 0) : ?>
                    <a class="cps-btn" href="<?php echo $url(['task' => 'activity.export', 'view' => null, 'mask' => ($mask || !$this->canChange) ? 1 : 0]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_EXPORT_CSV'); ?></a>
                <?php endif; ?>
            </div>
            <?php if ($list['total'] > 0) : ?>
                <p class="cps-help"><?php echo Text::_($this->canChange ? 'COM_COLORPACK_SHIELD_EXPORT_NOTE_ADMIN' : 'COM_COLORPACK_SHIELD_EXPORT_NOTE'); ?></p>
            <?php endif; ?>
        </form>

        <?php if ($this->canChange && $d['aiAvailable'] && $d['list']['total'] > 0) : ?>
            <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=activity.analyze&' . http_build_query($q)); ?>" method="post" class="cps-card">
                <p class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_ANALYZE'); ?></p>
                <div class="cps-card-foot">
                    <button type="submit" class="cps-btn"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_ANALYZE'); ?></button>
                </div>
                <?php echo HTMLHelper::_('form.token'); ?>
            </form>
        <?php endif; ?>

        <?php if ($d['aiLatest'] !== null) : ?>
            <section class="cps-card" aria-labelledby="cps-ai-latest">
                <h2 class="cps-h3" id="cps-ai-latest"><?php echo Text::_('COM_COLORPACK_SHIELD_AI_LATEST'); ?> <small><?php echo Text::_('COM_COLORPACK_SHIELD_AI_LATEST_WHEN'); ?> <?php echo $this->escape($when($d['aiLatest']['when'])); ?></small></h2>
                <div class="cps-ai-answer"><?php echo SimpleMarkdown::toHtml((string) ($d['aiLatest']['answer'] ?? '')); ?></div>
            </section>
        <?php endif; ?>

        <?php if (!$d['readable']) : ?>
            <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_NONE'); ?></div>
        <?php else : ?>
            <?php if ($d['truncated']) : ?>
                <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_TRUNCATED'); ?></div>
            <?php endif; ?>

            <section class="cps-card">
                <h2 class="cps-h3"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_RESULTS', (int) $list['total']); ?></h2>
                <?php if ($list['rows'] === []) : ?>
                    <p class="cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                <?php else : ?>
                    <div class="cps-scroll">
                        <table class="cps-table">
                            <thead>
                                <tr>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_TIME'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_TYPE'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_AREA'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_RULE'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_IP'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_PATH'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($list['rows'] as $e) : $f = $e['f']; ?>
                                    <tr>
                                        <td class="cps-mono"><time datetime="<?php echo gmdate('c', $e['time']); ?>" data-cps-localtime data-cps-seconds><?php echo $when($e['time']); ?></time></td>
                                        <td><span class="cps-badge <?php echo $badge[$e['type']] ?? ''; ?>"<?php echo in_array($e['type'], $hint, true) ? ' title="' . $this->escape(Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type'] . '_HINT')) . '"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type']); ?></span></td>
                                        <td><?php echo isset($f['client']) ? $this->escape($f['client']) : '—'; ?></td>
                                        <?php $rule = LogFilter::ruleOf($e); $ruleHint = \in_array($rule, $ruleHints, true) ? Text::_('COM_COLORPACK_SHIELD_RULE_' . strtoupper($rule)) : ''; ?>
                                        <td><code<?php echo $ruleHint !== '' ? ' title="' . $this->escape($ruleHint) . '"' : ''; ?>><?php echo $this->escape($rule ?: '—'); ?></code><?php echo isset($f['reason']) ? ' <span class="cps-small cps-muted">' . $this->escape($f['reason']) . '</span>' : ''; ?></td>
                                        <td class="cps-mono"><?php echo isset($f['ip']) ? $this->escape($mask ? IpMasker::mask($f['ip']) : $f['ip']) : '—'; ?></td>
                                        <td>
                                            <?php $uri = $f['uri'] ?? ''; if ($mask && ($qpos = strpos($uri, '?')) !== false) { $uri = substr($uri, 0, $qpos); } ?>
                                            <code><?php echo $uri !== '' ? $this->escape(mb_substr($uri, 0, 160)) : '—'; ?></code>
                                            <?php if (!$mask && isset($f['sample']) && $f['sample'] !== '') : ?>
                                                <div class="cps-small cps-muted"><?php echo $this->escape(mb_substr($f['sample'], 0, 120)); ?></div>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($list['pages'] > 1) : ?>
                        <nav class="cps-actions" style="position:static" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PAGES')); ?>">
                            <?php if ($list['page'] > 1) : ?><a class="cps-btn" href="<?php echo $url(['page' => $list['page'] - 1]); ?>"><?php echo Text::_('JPREV'); ?></a><?php endif; ?>
                            <span><?php echo Text::sprintf('COM_COLORPACK_SHIELD_PAGE_OF', (int) $list['page'], (int) $list['pages']); ?></span>
                            <?php if ($list['page'] < $list['pages']) : ?><a class="cps-btn" href="<?php echo $url(['page' => $list['page'] + 1]); ?>"><?php echo Text::_('JNEXT'); ?></a><?php endif; ?>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
                <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TIME_NOTE'); ?></p>
                <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCK_NOTE'); ?></p>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
