<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Core\IpMasker;
use Colorpack\Component\ColorpackShield\Administrator\Core\TimeFormat;
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
$badge  = ['BLOCK' => 'bg-danger', 'LOCK' => 'bg-danger', 'ALERT' => 'bg-info text-dark', 'OBSERVE' => 'bg-warning text-dark'];
?>
<div id="cps-app" class="j-main-container">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="d-flex flex-column gap-3">
        <?php if (!$r['installed']) : ?>
            <div class="alert alert-danger" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <section class="card card-body" aria-labelledby="cps-lg-door">
                <h2 class="h5" id="cps-lg-door"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_DOOR'); ?></h2>
                <div class="cps-reports">
                    <div class="d-flex flex-column gap-3">
                        <span class="badge <?php echo $r['door'] ? 'bg-success' : 'bg-warning text-dark'; ?>"><?php echo Text::_($r['door'] ? 'COM_COLORPACK_SHIELD_LG_DOOR_ON' : 'COM_COLORPACK_SHIELD_LG_DOOR_OFF'); ?></span>
                        <span class="small text-muted"><?php echo Text::_($r['door'] ? 'COM_COLORPACK_SHIELD_LG_DOOR_ON_TEXT' : 'COM_COLORPACK_SHIELD_LG_DOOR_OFF_TEXT'); ?></span>
                        <?php if (!$r['door']) : ?><div><a class="btn btn-sm btn-primary" href="<?php echo $go('setup'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETUP'); ?></a></div><?php endif; ?>
                    </div>
                    <div class="d-flex flex-column gap-3">
                        <span class="badge <?php echo $r['list'] ? 'bg-success' : ''; ?>"><?php echo Text::_($r['list'] ? 'COM_COLORPACK_SHIELD_LG_ADDR_ON' : 'COM_COLORPACK_SHIELD_LG_ADDR_OFF'); ?></span>
                        <h3 class="h6"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ADDR'); ?></h3>
                        <span class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ADDR_TEXT'); ?></span>
                    </div>
                    <div class="d-flex flex-column gap-3">
                        <span class="badge bg-success"><?php echo Text::_('COM_COLORPACK_SHIELD_STATUS_OK'); ?></span>
                        <h3 class="h6"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_RESCUE'); ?></h3>
                        <span class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_RESCUE_TEXT'); ?></span>
                    </div>
                </div>
            </section>

            <?php if (!$r['readable']) : ?>
                <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_LOG_NONE'); ?></div>
            <?php else : $c = $r['counts']; ?>
                <div class="cps-tiles">
                    <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_BLOCKED_ADMIN'); ?></span><b><?php echo $number($c['blockedAdmin']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
                    <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_LOCKOUTS'); ?></span><b><?php echo $number($c['locks']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
                    <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWIP'); ?></span><b><?php echo $number($c['newIp']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
                    <div class="cps-tile"><span><?php echo Text::_('COM_COLORPACK_SHIELD_REPORT_NEWADMIN'); ?></span><b><?php echo $number($c['newAdmin']); ?></b><em><?php echo Text::_('COM_COLORPACK_SHIELD_LAST_7D'); ?></em></div>
                </div>

                <div class="cps-grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
                    <section class="card card-body" aria-labelledby="cps-lg-daily">
                        <h2 class="h5" id="cps-lg-daily"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_DAILY'); ?></h2>
                        <?php $peak = max(1, ...array_map(static fn (array $d): int => $d['blocked'] + $d['locks'], $r['daily'])); ?>
                        <div class="cps-chart" role="img" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_CHART_LABEL')); ?>">
                            <?php foreach ($r['daily'] as $d) : $n = $d['blocked']; ?>
                                <div class="cps-col"><div class="cps-stack-bars"><i class="<?php echo $d['locks'] > 0 ? 'cps-bar-red' : ''; ?>" style="height:<?php echo $n > 0 ? max(4, (int) round($n / $peak * 120)) : 0; ?>px"></i></div><small><?php echo $this->escape(substr($d['date'], 8, 2)); ?></small></div>
                            <?php endforeach; ?>
                        </div>
                        <div class="cps-legend"><span><?php echo Text::_('COM_COLORPACK_SHIELD_BLOCKED'); ?></span><span class="cps-lg-red"><?php echo Text::_('COM_COLORPACK_SHIELD_CHART_LOCKDAY'); ?></span></div>
                        <p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_LOCKNOTE'); ?></p>
                    </section>

                    <section class="card card-body" aria-labelledby="cps-lg-mfa">
                        <h2 class="h5" id="cps-lg-mfa"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_MFA'); ?></h2>
                        <?php if ($r['mfa'] === null || $r['mfa']['total'] === 0) : ?>
                            <p class="text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_MFA_UNKNOWN'); ?></p>
                        <?php else : $m = $r['mfa']; $pct = (int) round($m['with'] / $m['total'] * 100); ?>
                            <div class="cps-hero">
                                <div class="cps-ring cps-ring-<?php echo $pct === 100 ? 'ok' : 'warn'; ?>" style="--p:<?php echo $pct; ?>;width:120px;height:120px" role="img" aria-label="<?php echo (int) $m['with']; ?> / <?php echo (int) $m['total']; ?>"><i style="width:90px;height:90px"><b style="font-size:28px;line-height:32px"><?php echo (int) $m['with']; ?>/<?php echo (int) $m['total']; ?></b><span><?php echo Text::_('COM_COLORPACK_SHIELD_LG_MFA_PEOPLE'); ?></span></i></div>
                                <div class="cps-hero-text"><span><?php echo Text::sprintf('COM_COLORPACK_SHIELD_LG_MFA_TEXT', (int) $m['with'], (int) $m['total'], Text::_('COM_COLORPACK_SHIELD_LG_MFA_' . strtoupper($r['mfaMode']))); ?></span></div>
                            </div>
                            <?php if ($m['missing'] !== []) : ?><div class="alert alert-warning"><span><?php foreach ($m['missing'] as $u) : ?><code><?php echo $this->escape($u); ?></code> <?php endforeach; ?></span></div><?php endif; ?>
                        <?php endif; ?>
                        <div class="d-flex flex-wrap gap-2 align-items-center mt-3"><a class="btn btn-sm btn-secondary" href="<?php echo $go('settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_ACTION_SETTINGS'); ?></a></div>
                    </section>
                </div>

                <section class="card card-body" aria-labelledby="cps-lg-tl">
                    <h2 class="h5" id="cps-lg-tl"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_TIMELINE'); ?></h2>
                    <?php if ($r['events'] === []) : ?>
                        <p class="text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_TIMELINE_NONE'); ?></p>
                    <?php else : ?>
                        <div>
                            <?php foreach ($r['events'] as $e) : $f = $e['f']; ?>
                                <div class="cps-row">
                                    <span class="font-monospace" style="min-width:150px"><time datetime="<?php echo gmdate('c', $e['time']); ?>" data-cps-localtime><?php echo $when($e['time']); ?></time></span>
                                    <span class="badge <?php echo $badge[$e['type']] ?? ''; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_TYPE_' . $e['type']); ?></span>
                                    <span style="flex:1 1 240px;min-width:0"><?php echo $this->escape(($f['rule'] ?? '') !== '' ? $f['rule'] : (isset($f['kind']) ? 'kind:' . $f['kind'] : '')); ?>
                                        <?php if (isset($f['ip']) && $f['ip'] !== '') : ?><span class="font-monospace text-muted"> · <?php echo $this->escape(IpMasker::mask($f['ip'])); ?></span><?php echo $cpsCountry->html($f['ip'], true); ?><?php endif; ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <div class="d-flex flex-wrap gap-2 align-items-center mt-3"><a class="btn btn-sm btn-secondary" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=activity&client=administrator'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_LG_ALL_EVENTS'); ?></a></div>
                </section>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
