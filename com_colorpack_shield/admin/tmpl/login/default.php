<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\IpMasker;
use Colorpack\Component\ColorpackShield\Administrator\Core\TimeFormat;
use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

$cpsCountry = new \Colorpack\Component\ColorpackShield\Administrator\Service\CountryLabel();

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Login\HtmlView $this */
$r      = $this->report;
$go     = static fn (string $screen): string => Route::_('index.php?option=com_colorpack_shield&view=' . $screen);
$number = static fn (int $n): string => number_format($n);
$tz     = (string) Factory::getApplication()->get('offset', 'UTC');
$when   = static fn (int $ts): string => TimeFormat::local($ts, $tz, 'Y-m-d H:i');
$badge  = ['BLOCK' => 'bad', 'LOCK' => 'bad', 'ALERT' => 'info', 'OBSERVE' => 'warn'];
$cpsLead = !$r['installed'] ? Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING') : Text::_($r['door'] ? 'COM_COLORPACK_SHIELD_LG_DOOR_ON_TEXT' : 'COM_COLORPACK_SHIELD_LG_DOOR_OFF_TEXT');
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <?php if (!$r['installed']) : ?>
            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
        <?php else : ?>
            <section class="cp-card" aria-labelledby="cps-lg-door">
                <h2 class="cp-card__title" id="cps-lg-door"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_DOOR'); ?></h2>
                <div class="cp-grid">
                    <div class="cp-stack">
                        <p><?php echo Ui::badge($r['door'] ? 'ok' : 'warn', Text::_($r['door'] ? 'COM_COLORPACK_SHIELD_LG_DOOR_ON' : 'COM_COLORPACK_SHIELD_LG_DOOR_OFF')); ?></p>
                        <p class="cp-small cp-muted"><?php echo Text::_($r['door'] ? 'COM_COLORPACK_SHIELD_LG_DOOR_ON_TEXT' : 'COM_COLORPACK_SHIELD_LG_DOOR_OFF_TEXT'); ?></p>
                        <?php if (!$r['door']) : ?><div><a class="btn btn-sm btn-primary" href="<?php echo $go('setup'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETUP'); ?></a></div><?php endif; ?>
                    </div>
                    <div class="cp-stack">
                        <p><?php echo Ui::badge($r['list'] ? 'ok' : '', Text::_($r['list'] ? 'COM_COLORPACK_SHIELD_LG_ADDR_ON' : 'COM_COLORPACK_SHIELD_LG_ADDR_OFF')); ?></p>
                        <h3 class="cps-label"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ADDR'); ?></h3>
                        <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ADDR_TEXT'); ?></p>
                    </div>
                    <div class="cp-stack">
                        <p><?php echo Ui::badge('ok', Text::_('COM_COLORPACK_SHIELD_STATUS_OK')); ?></p>
                        <h3 class="cps-label"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_RESCUE'); ?></h3>
                        <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_RESCUE_TEXT'); ?></p>
                    </div>
                </div>
            </section>

            <?php if (!$r['readable']) : ?>
                <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_LOG_NONE')); ?>
            <?php else : $c = $r['counts']; ?>
                <div class="cp-grid">
                    <article class="cp-card cp-stat"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_BLOCKED_ADMIN'); ?></span><p class="cp-stat__value"><?php echo $number($c['blockedAdmin']); ?></p><p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></p></article>
                    <article class="cp-card cp-stat"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_LOCKOUTS'); ?></span><p class="cp-stat__value"><?php echo $number($c['locks']); ?></p><p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></p></article>
                    <article class="cp-card cp-stat"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWIP'); ?></span><p class="cp-stat__value"><?php echo $number($c['newIp']); ?></p><p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></p></article>
                    <article class="cp-card cp-stat"><span class="cp-stat__label"><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWADMIN'); ?></span><p class="cp-stat__value"><?php echo $number($c['newAdmin']); ?></p><p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></p></article>
                </div>

                <div class="cp-split">
                    <section class="cp-card" aria-labelledby="cps-lg-daily">
                        <h2 class="cp-card__title" id="cps-lg-daily"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_DAILY'); ?></h2>
                        <?php echo Ui::bars(array_map(static fn (array $d): array => ['label' => substr($d['date'], 8, 2), 'a' => (int) $d['blocked'], 'flag' => $d['locks'] > 0], $r['daily']), Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>
                        <p class="cp-legend"><span><i></i><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span><i data-state="bad"></i><?php echo Text::_('COM_COLORPACK_SHIELD_CHART_LOCKDAY'); ?></span></p>
                        <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_LOCKNOTE'); ?></p>
                    </section>

                    <section class="cp-card" aria-labelledby="cps-lg-mfa">
                        <h2 class="cp-card__title" id="cps-lg-mfa"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_MFA'); ?></h2>
                        <?php if ($r['mfa'] === null || $r['mfa']['total'] === 0) : ?>
                            <p class="cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_MFA_UNKNOWN'); ?></p>
                        <?php else : $m = $r['mfa']; $pct = (int) round($m['with'] / $m['total'] * 100); ?>
                            <div class="cps-hero">
                                <?php echo Ui::ring($pct, $pct === 100 ? 'ok' : 'warn', (int) $m['with'] . '/' . (int) $m['total'], Text::_('COM_COLORPACK_SHIELD_LG_MFA_PEOPLE'), (int) $m['with'] . ' / ' . (int) $m['total'], true); ?>
                                <div class="cps-hero-text"><p><?php echo Text::sprintf('COM_COLORPACK_SHIELD_LG_MFA_TEXT', (int) $m['with'], (int) $m['total'], Text::_('COM_COLORPACK_SHIELD_LG_MFA_' . strtoupper($r['mfaMode']))); ?></p></div>
                            </div>
                            <?php if ($m['missing'] !== []) : ?>
                                <?php echo Ui::calloutStart('warn'); ?><p class="cp-callout__text"><?php foreach ($m['missing'] as $u) : ?><code><?php echo $this->escape($u); ?></code> <?php endforeach; ?></p><?php echo Ui::calloutEnd(); ?>
                            <?php endif; ?>
                        <?php endif; ?>
                        <div class="cp-card__foot"><a class="btn btn-sm btn-outline-secondary" href="<?php echo $go('settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETTINGS'); ?></a></div>
                    </section>
                </div>

                <section class="cp-card" aria-labelledby="cps-lg-tl">
                    <h2 class="cp-card__title" id="cps-lg-tl"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_TIMELINE'); ?></h2>
                    <?php if ($r['events'] === []) : ?>
                        <?php echo Ui::empty(Text::_('COM_COLORPACK_SHIELD_LG_TIMELINE_NONE')); ?>
                    <?php else : ?>
                        <div>
                            <?php foreach ($r['events'] as $e) : $f = $e['f']; ?>
                                <div class="cps-row">
                                    <span class="cps-time"><time datetime="<?php echo gmdate('c', $e['time']); ?>" data-cps-localtime><?php echo $when($e['time']); ?></time></span>
                                    <?php echo Ui::badge($badge[$e['type']] ?? '', Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type'])); ?>
                                    <span class="cps-grow cp-wrap"><?php echo $this->escape(($f['rule'] ?? '') !== '' ? $f['rule'] : (isset($f['kind']) ? 'kind:' . $f['kind'] : '')); ?>
                                        <?php if (isset($f['ip']) && $f['ip'] !== '') : ?><span class="cps-mono cp-muted"> · <?php echo $this->escape(IpMasker::mask($f['ip'])); ?></span><?php echo $cpsCountry->html($f['ip'], true); ?><?php endif; ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <div class="cp-card__foot"><a class="btn btn-sm btn-outline-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=activity&client=administrator'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ALL_EVENTS'); ?></a></div>
                </section>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
