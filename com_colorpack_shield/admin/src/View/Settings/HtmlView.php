<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\View\Settings;

use Colorpack\Component\ColorpackShield\Administrator\View\ScreenTrait;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;

\defined('_JEXEC') || die;

class HtmlView extends BaseHtmlView
{
    use ScreenTrait;

    public ?Form $form = null;

    /** @var array<string,mixed> */
    public array $params = [];

    /** @var array<string,string>  field name => error code, for fields to mark */
    public array $fieldErrors = [];

    public function display($tpl = null): void
    {
        $this->prepare('settings');

        $app          = Factory::getApplication();
        $model        = $this->getModel();
        $this->form   = $model->getForm();
        $this->params = $model->getParams();
        $state        = $app->getUserState('com_colorpack_shield.settings');

        // A refused save comes back with what was typed, so nothing is lost.
        if (\is_array($state)) {
            $this->params = array_merge($this->params, $state['params'] ?? []);

            foreach ($state['errors'] ?? [] as $e) {
                $this->fieldErrors[$e['key']] = $e['code'];
            }

            $app->setUserState('com_colorpack_shield.settings', null);
        }

        $this->form?->bind(['params' => $this->params]);

        parent::display($tpl);
    }
}
