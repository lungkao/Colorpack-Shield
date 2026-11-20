<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Service\Screens;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Joomla\CMS\MVC\View\HtmlView $this */
$cpsTag = \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::tag();
?>
<div class="d-flex flex-wrap align-items-end justify-content-between gap-2 mb-3">
    <nav aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD')); ?>">
        <ul class="nav nav-tabs">
            <?php foreach (Screens::ALL as $cpsView => $cpsKey) : ?>
                <li class="nav-item">
                    <a class="nav-link<?php echo $this->screen === $cpsView ? ' active' : ''; ?>" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=' . $cpsView); ?>"<?php echo $this->screen === $cpsView ? ' aria-current="page"' : ''; ?>><?php echo Text::_($cpsKey); ?></a>
                </li>
            <?php endforeach; ?>
        </ul>
    </nav>
    <form class="btn-group btn-group-sm" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=display.language'); ?>" method="post" role="group" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_LANG')); ?>">
        <input type="hidden" name="return" value="<?php echo $this->escape($this->screen); ?>">
        <button type="submit" name="lang" value="th-TH" lang="th" class="btn btn-outline-secondary<?php echo $cpsTag === 'th-TH' ? ' active' : ''; ?>"<?php echo $cpsTag === 'th-TH' ? ' aria-current="true"' : ''; ?>>ไทย</button>
        <button type="submit" name="lang" value="en-GB" lang="en" class="btn btn-outline-secondary<?php echo $cpsTag === 'en-GB' ? ' active' : ''; ?>"<?php echo $cpsTag === 'en-GB' ? ' aria-current="true"' : ''; ?>>English</button>
        <?php echo HTMLHelper::_('form.token'); ?>
    </form>
</div>
