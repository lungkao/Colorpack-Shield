<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\ScoreCalculator;
use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsGuard;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Component\ColorpackShield\Administrator\Service\SiteManagerSync;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * The plugin's own form, shown in the component. The plugin's parameters stay the only store.
 */
class SettingsModel extends BaseDatabaseModel
{
    /** The settings most sites ever touch; everything else is "Advanced". */
    public const BASIC = [
        'cover_site', 'cover_admin', 'cover_api', 'allow_ips', 'alert_email', 'killswitch_token', 'auto_allow_admin',
        'trust_cloudflare', 'header_mode', 'path_mode', 'login_lockout', 'mfa_enforce',
    ];

    public function plugin(): ShieldPlugin
    {
        return new ShieldPlugin($this->getDatabase());
    }

    public function getForm(): ?Form
    {
        $plugin = $this->plugin();

        if (!$plugin->installed()) {
            return null;
        }

        $lang = Factory::getApplication()->getLanguage();
        $lang->load('plg_system_colorpack_shield', JPATH_ADMINISTRATOR);
        $lang->load('plg_system_colorpack_shield', $plugin->pluginDir());

        // The plugin's own language file was just loaded: put the chosen language over it again.
        \Colorpack\Component\ColorpackShield\Administrator\Service\Locale::apply();

        $form = Form::getInstance('com_colorpack_shield.settings', '<form />', ['control' => 'jform']);
        $form->loadFile($plugin->formFile(), false, '//config');

        return $form;
    }

    /**
     * @return array<string,mixed>
     */
    public function getParams(): array
    {
        $p = $this->plugin()->params();

        // The access key, the kill-switch token, and the Gemini API key are for Super Users only; a person who may merely look never receives them.
        if (!Factory::getApplication()->getIdentity()->authorise('core.admin', 'com_colorpack_shield')) {
            $p['gate_key']         = '';
            $p['killswitch_token'] = '';
            $p['gemini_api_key']   = '';
        }

        return $p;
    }

    /**
     * Validate and save submitted settings.
     *
     * @param  array<string,mixed>  $submitted  the "params" array of the posted form
     *
     * @return array{saved:bool,errors:array<int,array{key:string,code:string,detail:string}>,warnings:array<int,array{key:string,code:string,detail:string}>}
     */
    public function saveSettings(array $submitted): array
    {
        $plugin = $this->plugin();
        $form   = $this->getForm();

        if ($form === null) {
            return ['saved' => false, 'errors' => [['key' => '', 'code' => 'plugin_missing', 'detail' => '']], 'warnings' => []];
        }

        $known = [];

        foreach ($form->getFieldset() as $field) {
            $known[$field->fieldname] = true;
        }

        // Only fields the plugin form defines are taken from the request.
        $data = array_intersect_key($submitted, $known);
        $data = $form->filter(['params' => $data])['params'] ?? [];

        // Switching the access key on without one: make a strong one (the person never has to invent it).
        $truthy = static fn (mixed $v): bool => filter_var($v, FILTER_VALIDATE_BOOLEAN) === true;

        if ($truthy($data['gate_enabled'] ?? false)) {
            $key              = trim((string) ($data['gate_key'] ?? $plugin->params()['gate_key'] ?? ''));
            $data['gate_key'] = $key !== '' ? $key : AccessGateConfig::generateKey();
        }

        // A switch posted without its list is judged with the list already stored.
        if ($truthy($data['admin_ip_enforce'] ?? false) && !isset($data['admin_ip_list'])) {
            $data['admin_ip_list'] = (string) ($plugin->params()['admin_ip_list'] ?? '');
        }

        $res  = SettingsGuard::check($data, fn (array $p): bool => $plugin->wouldBlockSelf($p + $plugin->params()), $plugin->visitor($data + $plugin->params()));

        if ($res['errors'] !== []) {
            return ['saved' => false, 'errors' => $res['errors'], 'warnings' => $res['warnings']];
        }

        $saved = $plugin->save($res['params']);

        if ($saved) {
            $plugin->issueGateCookie($res['params'] + $plugin->params());
            SiteManagerSync::refresh($plugin, ScoreCalculator::calculate($plugin->facts($plugin->params())), $plugin->version());
        }

        return ['saved' => $saved, 'errors' => [], 'warnings' => $res['warnings']];
    }
}
