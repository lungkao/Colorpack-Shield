<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Colorpack\Component\ColorpackShield\Administrator\Service\Ui;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Rules\HtmlView $this */
$r     = $this->rules;
$modes = ['block' => 'bad', 'log' => 'warn', 'off' => ''];
$cpsLead = Text::_($r['installed'] ? 'COM_COLORPACK_SHIELD_RULES_LEAD' : 'COM_COLORPACK_SHIELD_PLUGIN_MISSING');
?>
<div id="cps-app" class="j-main-container cp">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-flow">
        <?php if (!$r['installed']) : ?>
            <?php echo Ui::callout('bad', '', Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING')); ?>
        <?php else : ?>
            <?php echo Ui::callout('info', '', Text::_('COM_COLORPACK_SHIELD_RULES_CAVEAT')); ?>
            <?php foreach (['path' => 'COM_COLORPACK_SHIELD_RULES_PATH', 'header' => 'COM_COLORPACK_SHIELD_RULES_HEADER'] as $group => $title) : ?>
                <section class="cp-card" aria-labelledby="cps-rules-<?php echo $group; ?>">
                    <h2 class="cp-card__title" id="cps-rules-<?php echo $group; ?>"><?php echo Text::_($title); ?></h2>
                    <div class="cp-tablewrap" role="region" tabindex="0" aria-labelledby="cps-rules-<?php echo $group; ?>">
                        <table class="table cp-table">
                            <caption class="visually-hidden"><?php echo Text::_($title); ?></caption>
                            <thead>
                                <tr>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_RULE'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_CLASS'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_DEFAULT'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_NOW'); ?></th>
                                    <th scope="col" class="cp-num"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_HITS7'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($r['rows'] as $row) : if ($row['group'] !== $group) { continue; } ?>
                                    <tr>
                                        <td>
                                            <code><?php echo $this->escape($row['id']); ?></code>
                                            <div class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_RULE_' . strtoupper($row['id'])); ?></div>
                                        </td>
                                        <td><?php echo $this->escape($row['class']); ?></td>
                                        <td><?php echo Ui::badge($modes[$row['default']] ?? '', Text::_('COM_COLORPACK_SHIELD_MODE_' . strtoupper($row['default']))); ?></td>
                                        <td>
                                            <ul class="cp-badges">
                                                <li><?php echo Ui::badge($modes[$row['effective']] ?? '', Text::_('COM_COLORPACK_SHIELD_MODE_' . strtoupper($row['effective']))); ?></li>
                                                <?php if ($row['review']) : ?><li><?php echo Ui::badge('info', Text::_('COM_COLORPACK_SHIELD_REVIEW')); ?></li><?php endif; ?>
                                            </ul>
                                        </td>
                                        <td class="cp-num"><?php echo $r['logReadable'] ? (int) $row['hits'] : '—'; ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </section>
            <?php endforeach; ?>
            <p class="cp-small cp-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_RULES_MODES_NOTE'); ?> <a href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NAV_SETTINGS'); ?></a></p>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
