<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Server\HtmlView $this */
$s = $this->server;
$cpsLead = $s['installed'] ? Text::_('COM_COLORPACK_SHIELD_SRV_GUESS_' . strtoupper($s['guess'])) : Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING');
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <?php if (!$s['installed']) : ?>
            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
        <?php else : ?>
            <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_SRV_BOTH')); ?>

            <form action="<?php echo Route::_('index.php'); ?>" method="get" class="cp-card" aria-labelledby="cps-srv-opt">
                <input type="hidden" name="option" value="com_colorpack_shield">
                <input type="hidden" name="view" value="server">
                <h2 class="cp-card__title" id="cps-srv-opt"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_OPTIONS'); ?></h2>
                <div class="cps-field">
                    <label for="cps-allow"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW'); ?></label>
                    <textarea id="cps-allow" name="allow" rows="4" maxlength="4000" class="form-control"><?php echo $this->escape($s['allowText']); ?></textarea>
                    <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW_HELP'); ?></span>
                </div>
                <?php if ($s['bad'] !== []) : ?>
                    <?php echo Ui::calloutStart('warn'); ?>
                        <p class="cp-callout__text"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_BAD'); ?></p>
                        <ul class="cps-bullets"><?php foreach ($s['bad'] as $b) : ?><li><code><?php echo $this->escape($b); ?></code></li><?php endforeach; ?></ul>
                    <?php echo Ui::calloutEnd(); ?>
                <?php endif; ?>
                <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-1" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>><label class="form-check-label" for="cps-srv-chk-1"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS_HELP'); ?></span>
                <div class="cp-card__foot"><button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_UPDATE'); ?></button></div>
            </form>

            <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                <section class="cp-card" aria-labelledby="cps-srv-<?php echo $t; ?>">
                    <h2 class="cp-card__title" id="cps-srv-<?php echo $t; ?>"><?php echo Text::_($label); ?></h2>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_HOW_' . strtoupper($t)); ?></p>
                    <pre class="cp-code" id="cps-text-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s[$t]); ?></pre>
                    <div class="cp-card__foot">
                        <button type="button" class="btn btn-outline-secondary" data-cps-copy="cps-text-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button>
                        <a class="btn btn-outline-secondary" href="<?php echo Route::_('index.php?' . http_build_query(['option' => 'com_colorpack_shield', 'task' => 'server.download', 'target' => $t, 'allow' => $s['allowText'], 'codedirs' => $s['codedirs'] ? 1 : 0])); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_DOWNLOAD'); ?></a>
                    </div>
                </section>
            <?php endforeach; ?>

            <section class="cp-card" aria-labelledby="cps-srv-hta">
                <h2 class="cp-card__title" id="cps-srv-hta"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TITLE'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TEXT'); ?></p>
                <?php $h = $s['htaccess']; ?>
                <?php if (!$h['exists']) : ?>
                    <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_HTA_NOFILE')); ?>
                <?php elseif (!$this->canChange) : ?>
                    <p><?php echo Ui::badge($h['hasBlock'] ? 'ok' : '', Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF')); ?></p>
                <?php elseif (!$h['writable']) : ?>
                    <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_HTA_READONLY')); ?>
                <?php elseif (!$h['canAsk']) : ?>
                    <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_HTA_CANNOTASK')); ?>
                <?php else : ?>
                    <p><?php echo Ui::badge($h['hasBlock'] ? 'ok' : '', Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF')); ?></p>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.htaccess'); ?>" method="post" class="cp-stack">
                        <input type="hidden" name="allow" value="<?php echo $this->escape($s['allowText']); ?>">
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-2" name="headers" value="1" checked><label class="form-check-label" for="cps-srv-chk-2"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HEADERS'); ?></label></div>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-3" name="hsts" value="1"><label class="form-check-label" for="cps-srv-chk-3"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS'); ?></label></div>
                        <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS_HELP'); ?></span>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-4" name="samesite" value="1"><label class="form-check-label" for="cps-srv-chk-4"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE'); ?></label></div>
                        <span class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE_HELP'); ?></span>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-5" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>><label class="form-check-label" for="cps-srv-chk-5"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                        <div class="cp-row"><button type="submit" class="btn btn-primary"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_UPDATE' : 'COM_COLORPACK_SHIELD_HTA_APPLY'); ?></button><?php echo HTMLHelper::_('form.token'); ?></div>
                    </form>
                    <?php if ($h['hasBlock']) : ?>
                        <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.unhtaccess'); ?>" method="post">
                            <button type="submit" class="btn btn-outline-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_REMOVE'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                    <?php if ($h['backup']) : ?><p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_BACKUP'); ?></p><?php endif; ?>
                <?php endif; ?>
            </section>

            <section class="cp-card" aria-labelledby="cps-srv-admin">
                <h2 class="cp-card__title" id="cps-srv-admin"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_TEXT'); ?></p>
                <?php if ($s['adminList']['apache']['count'] === 0) : ?>
                    <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_EMPTY')); ?>
                <?php else : ?>
                    <?php echo Ui::callout('warn', '', Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_WARN')); ?>
                    <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                        <h3 class="cps-label"><?php echo Text::_($label); ?></h3>
                        <pre class="cp-code" id="cps-admin-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s['adminList'][$t]['text']); ?></pre>
                        <div><button type="button" class="btn btn-outline-secondary" data-cps-copy="cps-admin-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button></div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </section>

            <section class="cp-card" aria-labelledby="cps-srv-verify">
                <h2 class="cp-card__title" id="cps-srv-verify"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY'); ?></h2>
                <?php if ($s['verify'] === null) : ?>
                    <p><?php echo Ui::badge('', Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN')); ?></p>
                <?php else : $r = $s['verify']['result']; ?>
                    <p><?php echo Ui::badge(['refused' => 'ok', 'open' => 'bad', 'unknown' => ''][$r], Text::_('COM_COLORPACK_SHIELD_VERIFY_V_' . strtoupper($r))); ?></p>
                    <p class="cp-small cp-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_PROBE_AGE', (int) $s['verify']['age']); ?></p>
                <?php endif; ?>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_TEXT'); ?></p>
                <?php if ($this->canChange) : ?>
                    <form class="cp-action" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.verify'); ?>" method="post">
                        <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_BTN'); ?></button>
                        <?php echo HTMLHelper::_('form.token'); ?>
                    </form>
                <?php endif; ?>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
