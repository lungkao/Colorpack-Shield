<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

\defined('_JEXEC') || die;

use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;

/** @var \Colorpack\Component\ColorpackShield\Administrator\View\Rules\HtmlView $this */
$r     = $this->rules;
$modes = ['block' => 'cps-badge-bad', 'log' => 'cps-badge-warn', 'off' => ''];
?>
<div id="cps-app">
    <?php require __DIR__ . '/../nav.php'; ?>

    <div class="cps-stack">
        <?php if (!$r['installed']) : ?>
            <div class="cps-alert cps-alert-bad" role="alert"><?php echo Text::_('COM_COLORPACK_SHIELD_PLUGIN_MISSING'); ?></div>
        <?php else : ?>
            <div class="cps-alert cps-alert-info"><?php echo Text::_('COM_COLORPACK_SHIELD_RULES_CAVEAT'); ?></div>
            <?php foreach (['path' => 'COM_COLORPACK_SHIELD_RULES_PATH', 'header' => 'COM_COLORPACK_SHIELD_RULES_HEADER'] as $group => $title) : ?>
                <section class="cps-card">
                    <h2 class="cps-h3"><?php echo Text::_($title); ?></h2>
                    <div class="cps-scroll">
                        <table class="cps-table">
                            <thead>
                                <tr>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_RULE'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_CLASS'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_DEFAULT'); ?></th>
                                    <th scope="col"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_NOW'); ?></th>
                                    <th scope="col" class="cps-num"><?php echo Text::_('COM_COLORPACK_SHIELD_COL_HITS7'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($r['rows'] as $row) : if ($row['group'] !== $group) { continue; } ?>
                                    <tr>
                                        <td>
                                            <code><?php echo $this->escape($row['id']); ?></code>
                                            <div class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_RULE_' . strtoupper($row['id'])); ?></div>
                                        </td>
                                        <td><?php echo $this->escape($row['class']); ?></td>
                                        <td><span class="cps-badge <?php echo $modes[$row['default']] ?? ''; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_MODE_' . strtoupper($row['default'])); ?></span></td>
                                        <td>
                                            <span class="cps-badge <?php echo $modes[$row['effective']] ?? ''; ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_MODE_' . strtoupper($row['effective'])); ?></span>
                                            <?php if ($row['review']) : ?><span class="cps-badge cps-badge-info"><?php echo Text::_('COM_COLORPACK_SHIELD_REVIEW'); ?></span><?php endif; ?>
                                        </td>
                                        <td class="cps-num"><?php echo $r['logReadable'] ? (int) $row['hits'] : '—'; ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </section>
            <?php endforeach; ?>
            <p class="cps-small cps-muted"><?php echo Text::_('COM_COLORPACK_SHIELD_RULES_MODES_NOTE'); ?> <a href="<?php echo Route::_('index.php?option=com_colorpack_shield&view=settings'); ?>"><?php echo Text::_('COM_COLORPACK_SHIELD_NAV_SETTINGS'); ?></a></p>
        <?php endif; ?>
    </div>

    <?php require __DIR__ . '/../footer.php'; ?>
</div>
