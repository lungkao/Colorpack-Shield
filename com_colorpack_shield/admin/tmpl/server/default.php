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
<div id="cps-app" class="j-main-container">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="d-flex flex-column gap-3">
        <?php if (!$s['installed']) : ?>
            <div class="alert alert-danger" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <div class="alert alert-info"><div>
                <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_GUESS_' . strtoupper($s['guess'])); ?>
                <?php echo Text::_('COM_COLORPACK_SHIELD_SRV_BOTH'); ?>
            </div></div>

            <form action="<?php echo Route::_('index.php'); ?>" method="get" class="card card-body">
                <input type="hidden" name="option" value="com_colorpack_shield">
                <input type="hidden" name="view" value="server">
                <h2 class="h5"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_OPTIONS'); ?></h2>
                <div class="cps-field">
                    <label for="cps-allow"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW'); ?></label>
                    <textarea id="cps-allow" name="allow" rows="4" maxlength="4000" class="form-control"><?php echo $this->escape($s['allowText']); ?></textarea>
                    <span class="form-text"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ALLOW_HELP'); ?></span>
                </div>
                <?php if ($s['bad'] !== []) : ?>
                    <div class="alert alert-warning"><div><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_BAD'); ?>
                        <ul><?php foreach ($s['bad'] as $b) : ?><li><code><?php echo $this->escape($b); ?></code></li><?php endforeach; ?></ul></div></div>
                <?php endif; ?>
                <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-1" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>><label class="form-check-label" for="cps-srv-chk-1"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                <span class="form-text"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS_HELP'); ?></span>
                <div class="d-flex flex-wrap gap-2 align-items-center mt-3"><button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_UPDATE'); ?></button></div>
            </form>

            <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                <section class="card card-body" aria-labelledby="cps-srv-<?php echo $t; ?>">
                    <h2 class="h5" id="cps-srv-<?php echo $t; ?>"><?php echo Text::_($label); ?></h2>
                    <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_HOW_' . strtoupper($t)); ?></p>
                    <pre class="cps-log" id="cps-text-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s[$t]); ?></pre>
                    <div class="d-flex flex-wrap gap-2 align-items-center mt-3">
                        <button type="button" class="btn btn-secondary" data-cps-copy="cps-text-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button>
                        <a class="btn btn-secondary" href="<?php echo Route::_('index.php?' . http_build_query(['option' => 'com_colorpack_shield', 'task' => 'server.download', 'target' => $t, 'allow' => $s['allowText'], 'codedirs' => $s['codedirs'] ? 1 : 0])); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_DOWNLOAD'); ?></a>
                    </div>
                </section>
            <?php endforeach; ?>

            <section class="card card-body" aria-labelledby="cps-srv-hta">
                <h2 class="h5" id="cps-srv-hta"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TITLE'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_TEXT'); ?></p>
                <?php $h = $s['htaccess']; ?>
                <?php if (!$h['exists']) : ?>
                    <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_NOFILE'); ?></div>
                <?php elseif (!$this->canChange) : ?>
                    <span class="badge <?php echo $h['hasBlock'] ? 'bg-success' : ''; ?>"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF'); ?></span>
                <?php elseif (!$h['writable']) : ?>
                    <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_READONLY'); ?></div>
                <?php elseif (!$h['canAsk']) : ?>
                    <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_CANNOTASK'); ?></div>
                <?php else : ?>
                    <span class="badge <?php echo $h['hasBlock'] ? 'bg-success' : ''; ?>"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_ON' : 'COM_COLORPACK_SHIELD_HTA_OFF'); ?></span>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.htaccess'); ?>" method="post" class="d-flex flex-column gap-3">
                        <input type="hidden" name="allow" value="<?php echo $this->escape($s['allowText']); ?>">
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-2" name="headers" value="1" checked><label class="form-check-label" for="cps-srv-chk-2"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HEADERS'); ?></label></div>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-3" name="hsts" value="1"><label class="form-check-label" for="cps-srv-chk-3"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS'); ?></label></div>
                        <span class="form-text"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_HSTS_HELP'); ?></span>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-4" name="samesite" value="1"><label class="form-check-label" for="cps-srv-chk-4"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE'); ?></label></div>
                        <span class="form-text"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_SAMESITE_HELP'); ?></span>
                        <div class="form-check"><input class="form-check-input" type="checkbox" id="cps-srv-chk-5" name="codedirs" value="1"<?php echo $s['codedirs'] ? ' checked' : ''; ?>><label class="form-check-label" for="cps-srv-chk-5"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_CODEDIRS'); ?></label></div>
                        <div class="d-flex flex-wrap gap-2 align-items-center mt-3"><button type="submit" class="btn btn-primary"><?php echo Text::_($h['hasBlock'] ? 'COM_COLORPACK_SHIELD_HTA_UPDATE' : 'COM_COLORPACK_SHIELD_HTA_APPLY'); ?></button><?php echo HTMLHelper::_('form.token'); ?></div>
                    </form>
                    <?php if ($h['hasBlock']) : ?>
                        <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.unhtaccess'); ?>" method="post">
                            <button type="submit" class="btn btn-secondary"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_REMOVE'); ?></button>
                            <?php echo HTMLHelper::_('form.token'); ?>
                        </form>
                    <?php endif; ?>
                    <?php if ($h['backup']) : ?><p class="small text-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_HTA_BACKUP'); ?></p><?php endif; ?>
                <?php endif; ?>
            </section>

            <section class="card card-body" aria-labelledby="cps-srv-admin">
                <h2 class="h5" id="cps-srv-admin"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN'); ?></h2>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_TEXT'); ?></p>
                <?php if ($s['adminList']['apache']['count'] === 0) : ?>
                    <div class="alert alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_EMPTY'); ?></div>
                <?php else : ?>
                    <div class="alert alert-warning"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_ADMIN_WARN'); ?></div>
                    <?php foreach (['apache' => 'COM_COLORPACK_SHIELD_SRV_APACHE', 'nginx' => 'COM_COLORPACK_SHIELD_SRV_NGINX'] as $t => $label) : ?>
                        <h3 class="h5"><?php echo Text::_($label); ?></h3>
                        <pre class="cps-log" id="cps-admin-<?php echo $t; ?>" tabindex="0"><?php echo $this->escape($s['adminList'][$t]['text']); ?></pre>
                        <div><button type="button" class="btn btn-secondary" data-cps-copy="cps-admin-<?php echo $t; ?>" data-done="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_SRV_COPIED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_COPY'); ?></button></div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </section>

            <section class="card card-body" aria-labelledby="cps-srv-verify">
                <h2 class="h5" id="cps-srv-verify"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY'); ?></h2>
                <?php if ($s['verify'] === null) : ?>
                    <span class="badge"><?php echo Text::_('COM_COLORPACK_SHIELD_STATUS_UNKNOWN'); ?></span>
                <?php else : $r = $s['verify']['result']; ?>
                    <span class="badge <?php echo ['refused' => 'bg-success', 'open' => 'bg-danger', 'unknown' => ''][$r]; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_VERIFY_V_' . strtoupper($r)); ?></span>
                    <p class="small text-muted"><?php echo Text::sprintf('COM_COLORPACK_SHIELD_NET_PROBE_AGE', (int) $s['verify']['age']); ?></p>
                <?php endif; ?>
                <p><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_TEXT'); ?></p>
                <?php if ($this->canChange) : ?>
                    <form action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=server.verify'); ?>" method="post">
                        <button type="submit" class="btn btn-primary"><?php echo Text::_('COM_COLORPACK_SHIELD_SRV_VERIFY_BTN'); ?></button>
                        <?php echo HTMLHelper::_('form.token'); ?>
                    </form>
                <?php endif; ?>
            </section>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
