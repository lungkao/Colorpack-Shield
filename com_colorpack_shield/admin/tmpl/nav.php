<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\Language\Text;
use Colorpack\Component\ColorpackShield\Administrator\Service\Screens;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;

/** @var \Joomla\CMS\MVC\View\HtmlView $this */
$cpsItems = Screens::ALL;
?>
<div class="cps-head">
    <div class="cps-brand">
        <img class="cps-logo" src="<?php echo $this->escape(Uri::root(true)); ?>/media/com_colorpack_shield/images/logo.png" alt="" width="36" height="36" loading="lazy">
        <h1><?php echo Text::_('COM_COLORPACK_SHIELD'); ?></h1>
    </div>
    <nav class="cps-nav" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD')); ?>">
        <?php foreach ($cpsItems as $cpsView => $cpsKey) : ?>
            <a href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=' . $cpsView); ?>"<?php echo $this->screen === $cpsView ? ' aria-current="page"' : ''; ?>><?php echo Text::_($cpsKey); ?></a>
        <?php endforeach; ?>
    </nav>
    <?php $cpsTag = \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::tag(); ?>
    <form class="cps-lang" action="<?php echo Route::_('index.php?option=com_colorpack_shield&task=display.language'); ?>" method="post" role="group" aria-label="<?php echo $this->escape(Text::_('COM_COLORPACK_SHIELD_LANG')); ?>">
        <input type="hidden" name="return" value="<?php echo $this->escape($this->screen); ?>">
        <button type="submit" name="lang" value="th-TH" lang="th"<?php echo $cpsTag === 'th-TH' ? ' aria-current="true"' : ''; ?>>ไทย</button>
        <button type="submit" name="lang" value="en-GB" lang="en"<?php echo $cpsTag === 'en-GB' ? ' aria-current="true"' : ''; ?>>English</button>
        <?php echo \Joomla\CMS\HTML\HTMLHelper::_('form.token'); ?>
    </form>
</div>
