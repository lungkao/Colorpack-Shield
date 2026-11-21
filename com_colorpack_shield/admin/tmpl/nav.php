<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Service\Screens;
use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/**
 * The page head and the section tabs of every screen (Colorpack Admin UI Standard, section 2): the answer sentence on
 * the left, the language switch on the right, then the underline tabs. The screen sets $cpsLead (a plain sentence,
 * not HTML) before including this file.
 *
 * @var \Joomla\CMS\MVC\View\HtmlView $this
 * @var string                        $cpsLead
 */
$cpsTag  = \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::tag();
$cpsLead = isset($cpsLead) ? (string) $cpsLead : '';
?>
<header class="cp-head">
    <?php if ($cpsLead !== '') : ?><p class="cp-lead"><?php echo Ui::e($cpsLead); ?></p><?php endif; ?>
    <div class="cp-tools">
        <form class="cp-lang" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=display.language'); ?>" method="post" role="group" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_LANG')); ?>">
            <input type="hidden" name="return" value="<?php echo $this->escape($this->screen); ?>">
            <span class="cp-lang__icon" aria-hidden="true"><?php echo Ui::icon('globe'); ?></span>
            <button type="submit" name="lang" value="th-TH" lang="th" class="cp-lang__btn" aria-pressed="<?php echo $cpsTag === 'th-TH' ? 'true' : 'false'; ?>" title="ภาษาไทย">ไทย</button>
            <button type="submit" name="lang" value="en-GB" lang="en" class="cp-lang__btn" aria-pressed="<?php echo $cpsTag === 'en-GB' ? 'true' : 'false'; ?>" title="English">EN</button>
            <?php echo HTMLHelper::_('form.token'); ?>
        </form>
    </div>
</header>

<nav aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD')); ?>">
    <ul class="cp-tabs">
        <?php foreach (Screens::ALL as $cpsView => $cpsKey) : ?>
            <li><a class="cp-tab" href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=' . $cpsView); ?>"<?php echo $this->screen === $cpsView ? ' aria-current="page"' : ''; ?>><?php echo Text::_($cpsKey); ?></a></li>
        <?php endforeach; ?>
    </ul>
</nav>
