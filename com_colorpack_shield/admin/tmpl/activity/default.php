<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\EventPresenter;
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
$cpsCountry = new \Colorpack\Component\ColorpackShield\Administrator\Service\CountryLabel();
$list = $d['list'];
$q    = array_filter([
    'option' => 'com_colorpack_shield', 'view' => 'activity', 'types' => $c['types'], 'client' => $c['client'], 'rule' => $c['rule'],
    'text' => $c['text'], 'days' => $c['days'], 'mask' => $mask ? 1 : 0,
], static fn ($v) => $v !== '' && $v !== []);
$url  = static fn (array $extra): string => Route::_('index.php?' . http_build_query($extra + $q));
$badge = ['BLOCK' => 'bg-danger', 'DETECT' => 'bg-warning text-dark', 'LOCK' => 'bg-danger', 'OBSERVE' => 'bg-info text-dark', 'ALERT' => 'bg-info text-dark', 'NOTE' => ''];
$hint  = ['BLOCK', 'DETECT', 'LOCK', 'OBSERVE', 'ALERT'];
$levelBadge = ['high' => 'bg-danger', 'medium' => 'bg-warning text-dark', 'low' => '', 'info' => 'bg-info text-dark'];
$levelLabel = ['high' => 'COM_COLORPACK_SHIELD_SEV_HIGH', 'medium' => 'COM_COLORPACK_SHIELD_SEV_MEDIUM', 'low' => 'COM_COLORPACK_SHIELD_SEV_LOW', 'info' => 'COM_COLORPACK_SHIELD_LEVEL_INFO'];
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
<div id="cps-app" class="j-main-container">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="d-flex flex-column gap-3">
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
            <section class="card card-body" aria-labelledby="cps-act-chart">
                <h2 class="h5" id="cps-act-chart"><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?> / <?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></h2>
                <div class="cps-chart" role="img" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>">
                    <?php foreach ($rp['daily'] as $x) : ?>
                        <div class="cps-col"><div class="cps-stack-bars"><i class="cps-bar-log" style="height:<?php echo $bar($x['detected']); ?>px"></i><i style="height:<?php echo $bar($x['blocked']); ?>px"></i></div><small><?php echo $this->escape(substr($x['date'], 8, 2)); ?></small></div>
                    <?php endforeach; ?>
                </div>
                <div class="cps-legend"><span><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span class="cps-lg-log"><?php echo Text::_('COM_COLORPACK_SHIELD_LOGGED_ONLY'); ?></span></div>
            </section>
        <?php endif; ?>

        <form action="<?php echo Route::_('index.php'); ?>" method="get" class="card card-body bg-body-tertiary" aria-labelledby="cps-act-filter">
            <input type="hidden" name="option" value="com_colorpack_shield">
            <input type="hidden" name="view" value="activity">
            <h2 class="h5" id="cps-act-filter"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER'); ?></h2>
            <div class="cps-fields">
                <div class="cps-field">
                    <label for="cps-f-client"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_AREA'); ?></label>
                    <select id="cps-f-client" name="client" class="form-select">
                        <option value=""><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_ALL'); ?></option>
                        <?php foreach (['site', 'administrator', 'api'] as $a) : ?>
                            <option value="<?php echo $a; ?>"<?php echo $c['client'] === $a ? ' selected' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_CLIENT_' . strtoupper($a)); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="cps-field">
                    <label for="cps-f-days"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_PERIOD'); ?></label>
                    <select id="cps-f-days" name="days" class="form-select">
                        <?php foreach ([1, 7, 30, 90] as $n) : ?>
                            <option value="<?php echo $n; ?>"<?php echo $c['days'] === $n ? ' selected' : ''; ?>><?php echo Text::plural('COM_COLORPACK_SHIELD_DAYS', $n); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <fieldset class="cps-field cps-wide">
                    <legend><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_TYPE'); ?></legend>
                    <div class="d-flex flex-wrap gap-3">
                        <?php foreach (LogFilter::TYPES as $t) : ?>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="types[]" id="cps-f-type-<?php echo strtolower($t); ?>" value="<?php echo $t; ?>"<?php echo in_array($t, $c['types'], true) ? ' checked' : ''; ?>>
                                <label class="form-check-label" for="cps-f-type-<?php echo strtolower($t); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_TYPE_' . $t); ?></label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </fieldset>
                <div class="cps-field">
                    <label for="cps-f-text"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_TEXT'); ?></label>
                    <input type="text" id="cps-f-text" name="text" maxlength="100" value="<?php echo $this->escape($c['text']); ?>" class="form-control">
                </div>
                <div class="cps-field">
                    <label for="cps-f-rule"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RULE'); ?></label>
                    <input type="text" id="cps-f-rule" name="rule" maxlength="60" value="<?php echo $this->escape($c['rule']); ?>" class="form-control">
                </div>
            </div>
            <div class="d-flex flex-wrap gap-2 align-items-center mt-3">
                <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_APPLY'); ?></button>
                <a class="btn btn-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=activity'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_FILTER_RESET'); ?></a>
                <span class="flex-grow-1"></span>
                <div class="form-check mb-0"><input class="form-check-input" type="checkbox" name="mask" id="cps-f-mask" value="1"<?php echo $mask ? ' checked' : ''; ?>><label class="form-check-label small" for="cps-f-mask"><?php echo Text::_('COM_COLORPACK_SHIELD_MASK_IPS'); ?></label></div>
                <?php if ($list['total'] > 0) : ?>
                    <a class="btn btn-secondary" href="<?php echo $url(['task' => 'activity.export', 'view' => null, 'mask' => ($mask || !$this->canChange) ? 1 : 0]); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_EXPORT_CSV'); ?></a>
                <?php endif; ?>
            </div>
            <?php if ($list['total'] > 0) : ?>
                <p class="form-text"><?php echo Text::_($this->canChange ? 'COM_COLORPACK_SHIELD_EXPORT_NOTE_ADMIN' : 'COM_COLORPACK_SHIELD_EXPORT_NOTE'); ?></p>
            <?php endif; ?>
        </form>

        <?php if (!$d['readable']) : ?>
            <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_NONE'); ?></div>
        <?php else : ?>
            <?php if ($d['truncated']) : ?>
                <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_TRUNCATED'); ?></div>
            <?php endif; ?>

            <section class="card card-body" aria-labelledby="cps-act-results">
                <h2 class="h5" id="cps-act-results"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_RESULTS', (int) $list['total']); ?></h2>
                <?php if ($list['rows'] === []) : ?>
                    <p class="text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NONE_YET'); ?></p>
                <?php else : ?>
                    <?php $showAction = $this->canChange && !$mask; $return = 'index.php?' . http_build_query($q + ['page' => (int) $list['page']]); ?>
                    <div class="table-responsive">
                        <table class="table cps-events">
                            <thead>
                                <tr>
                                    <?php if ($showAction) : ?><th scope="col" class="cps-act"><span class="visually-hidden"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_ACTION'); ?></span></th><?php endif; ?>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_LEVEL'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_TIME'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_IP'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_PATH'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_WHAT'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($list['rows'] as $e) :
                                    $f      = $e['f'];
                                    $ip     = (string) ($f['ip'] ?? '');
                                    $level  = EventPresenter::level($e);
                                    $rule   = LogFilter::ruleOf($e);
                                    $uri    = (string) ($f['uri'] ?? '');
                                    if ($mask && ($qpos = strpos($uri, '?')) !== false) {
                                        $uri = substr($uri, 0, $qpos);
                                    }
                                    $isBlocked = $ip !== '' && isset($d['blocked'][$ip]);
                                    ?>
                                    <tr>
                                        <?php if ($showAction) : ?>
                                            <td class="cps-act">
                                                <?php if ($ip !== '') : ?>
                                                    <form method="post" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=activity.' . ($isBlocked ? 'unblock' : 'block')); ?>">
                                                        <input type="hidden" name="ip" value="<?php echo $this->escape($ip); ?>">
                                                        <input type="hidden" name="return" value="<?php echo $this->escape($return); ?>">
                                                        <?php echo HTMLHelper::_('form.token'); ?>
                                                        <button type="submit" class="btn btn-sm <?php echo $isBlocked ? 'btn-primary' : 'btn-danger'; ?>" title="<?php echo $this->escape(Text::_($isBlocked ? 'COM_COLORPACK_SHIELD_ACT_UNBLOCK_HINT' : 'COM_COLORPACK_SHIELD_ACT_BLOCK_HINT')); ?>"><?php echo Text::_($isBlocked ? 'COM_COLORPACK_SHIELD_ACT_UNBLOCK' : 'COM_COLORPACK_SHIELD_ACT_BLOCK'); ?></button>
                                                    </form>
                                                <?php endif; ?>
                                            </td>
                                        <?php endif; ?>
                                        <td><span class="badge <?php echo $levelBadge[$level]; ?>"><?php echo Text::_($levelLabel[$level]); ?></span></td>
                                        <td class="font-monospace"><time datetime="<?php echo gmdate('c', $e['time']); ?>" data-cps-localtime data-cps-seconds><?php echo $when($e['time']); ?></time></td>
                                        <td class="font-monospace"><?php echo $ip !== '' ? $this->escape($mask ? IpMasker::mask($ip) : $ip) . $cpsCountry->html($ip, $mask) : '—'; ?></td>
                                        <td><code><?php echo $uri !== '' ? $this->escape(mb_substr($uri, 0, 120)) : '—'; ?></code></td>
                                        <td>
                                            <span class="cps-what"><?php echo Text::_(EventPresenter::descriptionKey($e, $ruleHints)); ?></span>
                                            <details class="cps-more">
                                                <summary><?php echo Text::_('COM_COLORPACK_SHIELD_ACT_DETAILS'); ?></summary>
                                                <div class="cps-more-body">
                                                    <div><span class="badge <?php echo $badge[$e['type']] ?? ''; ?>"<?php echo in_array($e['type'], $hint, true) ? ' title="' . $this->escape(Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type'] . '_HINT')) . '"' : ''; ?>><?php echo Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type']); ?></span>
                                                        <?php echo isset($f['client']) ? '<span class="small text-muted">' . Text::_('COM_COLORPACK_SHIELD_COL_AREA') . ': ' . $this->escape($f['client']) . '</span>' : ''; ?></div>
                                                    <?php if ($rule !== '') : ?><div class="small"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_RULE'); ?>: <code><?php echo $this->escape($rule); ?></code><?php echo isset($f['reason']) ? ' <span class="text-muted">' . $this->escape($f['reason']) . '</span>' : ''; ?></div><?php endif; ?>
                                                    <?php if ($uri !== '' && mb_strlen($uri) > 120) : ?><div class="small"><code><?php echo $this->escape(mb_substr($uri, 0, 400)); ?></code></div><?php endif; ?>
                                                    <?php if (!$mask && isset($f['sample']) && $f['sample'] !== '') : ?>
                                                        <div class="small text-muted"><?php echo $this->escape(mb_substr($f['sample'], 0, 200)); ?></div>
                                                    <?php endif; ?>
                                                    <?php if (isset($f['note']) && $f['note'] === 'tolerated') : ?>
                                                        <div class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NOTE_TOLERATED'); ?></div>
                                                    <?php endif; ?>
                                                    <?php if (($e['type'] === 'BLOCK' || ($e['type'] === 'DETECT' && ($f['note'] ?? '') === 'watch')) && isset($f['ref'])) : ?>
                                                        <?php if (($f['note'] ?? '') === 'watch') : ?><div class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_NOTE_WATCH'); ?></div><?php endif; ?>
                                                        <div class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_REF'); ?> <code><?php echo $this->escape($f['ref']); ?></code><?php if (isset($f['key']) && $f['key'] !== '') : ?> · <?php echo Text::_('COM_COLORPACK_SHIELD_FIELD'); ?> <code><?php echo $this->escape(mb_substr($f['key'], 0, 80)); ?></code><?php endif; ?></div>
                                                        <?php if (($f['src'] ?? '') === 'POST' && \Colorpack\Component\ColorpackShield\Administrator\Core\ExceptionLine::fromRow($f) !== null) : ?>
                                                            <div class="small cps-tip"><?php echo Text::_('COM_COLORPACK_SHIELD_TIP_PASTE'); ?></div>
                                                        <?php endif; ?>
                                                        <?php if ($this->canChange && \Colorpack\Component\ColorpackShield\Administrator\Core\ExceptionLine::fromRow($f) !== null) : ?>
                                                            <form method="post" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=activity.allow'); ?>" class="cps-inline-form">
                                                                <input type="hidden" name="ref" value="<?php echo $this->escape($f['ref']); ?>">
                                                                <?php echo HTMLHelper::_('form.token'); ?>
                                                                <button type="submit" class="btn btn-sm btn-secondary" title="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_ALLOW_HINT')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ALLOW'); ?></button>
                                                            </form>
                                                            <?php if ($e['type'] === 'BLOCK' && \Colorpack\Component\ColorpackShield\Administrator\Core\ExceptionLine::isWatchable($f['rule'] ?? '')) : ?>
                                                                <form method="post" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=activity.watch'); ?>" class="cps-inline-form">
                                                                    <input type="hidden" name="ref" value="<?php echo $this->escape($f['ref']); ?>">
                                                                    <?php echo HTMLHelper::_('form.token'); ?>
                                                                    <button type="submit" class="btn btn-sm btn-secondary" title="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_WATCH_HINT')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_WATCH'); ?></button>
                                                                </form>
                                                            <?php endif; ?>
                                                        <?php endif; ?>
                                                    <?php endif; ?>
                                                </div>
                                            </details>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($list['pages'] > 1) : ?>
                        <nav class="cps-pager" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PAGES')); ?>">
                            <?php if ($list['page'] > 1) : ?><a class="btn btn-secondary" href="<?php echo $url(['page' => $list['page'] - 1]); ?>"><?php echo Text::_('JPREV'); ?></a><?php endif; ?>
                            <span class="small text-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_PAGE_OF', (int) $list['page'], (int) $list['pages']); ?></span>
                            <?php if ($list['page'] < $list['pages']) : ?><a class="btn btn-secondary" href="<?php echo $url(['page' => $list['page'] + 1]); ?>"><?php echo Text::_('JNEXT'); ?></a><?php endif; ?>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
                <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_TIME_NOTE'); ?></p>
                <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCK_NOTE'); ?></p>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
