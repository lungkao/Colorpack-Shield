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

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Server\HtmlView $this */
$s = $this->server;
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <?php if (!$s['installed']) : ?>
            <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <div class="cps-alert cps-alert-info"><div>
                <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_GUESS_' . strtoupper($s['guess'])); ?>
                <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_BOTH'); ?>
            </div></div>

            <form action="<?php echo Route::_('index.php'); ?>" method="get" class="cps-card">
                <input type="hidden" name="option" value="com_colorpack_shield">
                <input type="hidden" name="view" value="server">
                <h2 class="cps-h3"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_OPTIONS'); ?></h2>
                <div class="cps-field">
                    <label for="cps-allow"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW'); ?></label>
                    <textarea id="cps-allow" name="allow" rows="4" maxlength="4000"><?php echo $this->escape($s['allowText']); ?></textarea>
                    <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW_HELP'); ?></span>
                </div>
                <?php if ($s['bad'] !== []) : ?>
                    <div class="cps-alert cps-alert-warn"><div><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_BAD'); ?>
                        <ul><?php foreach ($s['bad'] as $b) : ?><li><code><?php echo $this->escape($b); ?></code></li><?php endforeach; ?></ul></div></div>
                <?php endif; ?>
                <div class="cps-radio"><label><input type="checkbox" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>> <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS_HELP'); ?></span>
                <div class="cps-card-foot"><button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_UPDATE'); ?></button></div>
            </form>

            <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                <section class="cps-card" aria-labelledby="cps-srv-<?php echo $t; ?>">
                    <h2 class="cps-h3" id="cps-srv-<?php echo $t; ?>"><?php echo Text::_($label); ?></h2>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_HOW_' . strtoupper($t)); ?></p>
                    <pre class="cps-log" id="cps-text-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s[$t]); ?></pre>
                    <div class="cps-card-foot">
                        <button type="button" class="cps-btn" data-cps-copy="cps-text-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button>
                        <a class="cps-btn" href="<?php echo Route::_('index.php?' . http_build_query(['option' => 'com_colorpack_shield', 'task' => 'server.download', 'target' => $t, 'allow' => $s['allowText'], 'codedirs' => $s['codedirs'] ? 1 : 0])); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_DOWNLOAD'); ?></a>
                    </div>
                </section>
            <?php endforeach; ?>

            <section class="cps-card" aria-labelledby="cps-srv-hta">
                <h2 class="cps-h3" id="cps-srv-hta"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TITLE'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TEXT'); ?></p>
                <?php $h = $s['htaccess']; ?>
                <?php if (!$h['exists']) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_NOFILE'); ?></div>
                <?php elseif (!$this->canChange) : ?>
                    <span class="cps-badge <?php echo $h['hasBlock'] ? 'cps-badge-ok' : ''; ?>"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF'); ?></span>
                <?php elseif (!$h['writable']) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_READONLY'); ?></div>
                <?php elseif (!$h['canAsk']) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_CANNOTASK'); ?></div>
                <?php else : ?>
                    <span class="cps-badge <?php echo $h['hasBlock'] ? 'cps-badge-ok' : ''; ?>"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF'); ?></span>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.htaccess'); ?>" method="post" class="cps-stack" style="gap:12px">
                        <input type="hidden" name="allow" value="<?php echo $this->escape($s['allowText']); ?>">
                        <div class="cps-radio"><label><input type="checkbox" name="headers" value="1" checked> <?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HEADERS'); ?></label></div>
                        <div class="cps-radio"><label><input type="checkbox" name="hsts" value="1"> <?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS'); ?></label></div>
                        <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS_HELP'); ?></span>
                        <div class="cps-radio"><label><input type="checkbox" name="samesite" value="1"> <?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE'); ?></label></div>
                        <span class="cps-help"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE_HELP'); ?></span>
                        <div class="cps-radio"><label><input type="checkbox" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>> <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                        <div class="cps-card-foot"><button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_UPDATE' : 'COM_COLORPACK_SHIELD_HTA_APPLY'); ?></button><?php echo HTMLHelper::_('form.token'); ?></div>
                    </form>
                    <?php if ($h['hasBlock']) : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.unhtaccess'); ?>" method="post">
                            <button type="submit" class="cps-btn"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_REMOVE'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                    <?php if ($h['backup']) : ?><p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_BACKUP'); ?></p><?php endif; ?>
                <?php endif; ?>
            </section>

            <section class="cps-card" aria-labelledby="cps-srv-admin">
                <h2 class="cps-h3" id="cps-srv-admin"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_TEXT'); ?></p>
                <?php if ($s['adminList']['apache']['count'] === 0) : ?>
                    <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_EMPTY'); ?></div>
                <?php else : ?>
                    <div class="cps-alert cps-alert-warn"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_WARN'); ?></div>
                    <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                        <h3 class="cps-h3"><?php echo Text::_($label); ?></h3>
                        <pre class="cps-log" id="cps-admin-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s['adminList'][$t]['text']); ?></pre>
                        <div><button type="button" class="cps-btn" data-cps-copy="cps-admin-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button></div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </section>

            <section class="cps-card" aria-labelledby="cps-srv-verify">
                <h2 class="cps-h3" id="cps-srv-verify"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY'); ?></h2>
                <?php if ($s['verify'] === null) : ?>
                    <span class="cps-badge"><?php echo Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN'); ?></span>
                <?php else : $r = $s['verify']['result']; ?>
                    <span class="cps-badge <?php echo ['refused' => 'cps-badge-ok', 'open' => 'cps-badge-bad', 'unknown' => ''][$r]; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_VERIFY_V_' . strtoupper($r)); ?></span>
                    <p class="cps-small cps-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_PROBE_AGE', (int) $s['verify']['age']); ?></p>
                <?php endif; ?>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_TEXT'); ?></p>
                <?php if ($this->canChange) : ?>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.verify'); ?>" method="post">
                        <button type="submit" class="cps-btn cps-btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_BTN'); ?></button>
                        <?php echo HTMLHelper::_('form.token'); ?>
                    </form>
                <?php endif; ?>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
