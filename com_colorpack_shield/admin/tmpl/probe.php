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

/**
 * The proxy test button and the same test as a command, with this site's own values filled in.
 * Expects $cpsProbeUi (array|null) and $cpsReturn ('network' | 'setup').
 *
 * @var \Joomla\CMS\MVC\View\HtmlView $this
 */
?>
<?php if ($cpsProbeUi !== null) : ?>
    <?php if ($this->canChange) : ?>
        <form id="cps-probe-form" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=network.probe'); ?>" method="post" class="cps-actions" style="position:static;padding:0">
            <input type="hidden" name="report" value="">
            <input type="hidden" name="return" value="<?php echo $this->escape($cpsReturn); ?>">
            <button type="button" class="cps-btn cps-btn-primary" data-cps-probe
                    data-url="<?php echo $this->escape($cpsProbeUi['url']); ?>"
                    data-headers="<?php echo $this->escape(json_encode($cpsProbeUi['headers'])); ?>"
                    data-form="cps-probe-form" data-status="cps-probe-status"
                    data-busy="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PROBE_BUSY')); ?>"
                    data-fail="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_PROBE_FAILED')); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_BTN'); ?></button>
            <span id="cps-probe-status" class="cps-small" role="status"></span>
            <?php echo HTMLHelper::_('form.token'); ?>
        </form>
        <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_BTN_NOTE'); ?></p>
    <?php endif; ?>
    <details>
        <summary class="cps-small"><?php echo Text::_('COM_COLORPACK_SHIELD_PROBE_CMD'); ?></summary>
        <pre class="cps-log" tabindex="0" style="margin-top:8px"><?php echo $this->escape($cpsProbeUi['command']); ?></pre>
    </details>
<?php endif; ?>
