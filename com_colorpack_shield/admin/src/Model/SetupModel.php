<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\SettingsGuard;
use Colorpack\Component\ColorpackShield\Administrator\Core\SetupAdvisor;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\AdminProtect\AccessGateConfig;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

/**
 * Quick setup: proposes a small patch per step; applies one only when asked.
 */
class SetupModel extends BaseDatabaseModel
{
    public const STEPS = [1, 2, 3, 4];

    public function plugin(): ShieldPlugin
    {
        return new ShieldPlugin($this->getDatabase());
    }

    /**
     * @return array{installed:bool,steps:array<int,array{patch:array<string,mixed>,advice:string,current:array<string,mixed>}>,probe:?array{verdict:string,age:int}}
     */
    public function getPlan(): array
    {
        $plugin = $this->plugin();

        if (!$plugin->installed()) {
            return ['installed' => false, 'steps' => [], 'probe' => null];
        }

        $p     = $plugin->params();
        $probe = $plugin->storedProbe();
        $email = (string) (Factory::getApplication()->getIdentity()->email ?? '');
        $raw   = [
            1 => SetupAdvisor::realIp($probe['verdict'] ?? null, $this->behindCloudflare(), $p),
            2 => SetupAdvisor::safety($p, $email),
            3 => SetupAdvisor::logMode($p),
            // The preview shows a placeholder; the real key is made when the step is applied.
            4 => SetupAdvisor::accessKey($p, '(a new key is made)'),
        ];
        $steps = [];

        foreach ($raw as $n => $step) {
            $steps[$n] = $step + ['current' => array_intersect_key($p, $step['patch'])];
        }

        $gate = AccessGateConfig::fromArray($p);

        return [
            'installed' => true,
            'steps'     => $steps,
            'probe'     => $probe,
            'probeUi'   => $plugin->probeUi(),
            // The access link, for Super Users only (it is the key).
            'gateLink'  => $gate->gateActive && Factory::getApplication()->getIdentity()->authorise('core.admin', 'com_colorpack_shield')
                ? rtrim(\Joomla\CMS\Uri\Uri::root(), '/') . '/administrator/?cpskey=' . $gate->key : null,
        ];
    }

    /**
     * @return array{applied:bool,nothing:bool,errors:array<int,array{key:string,code:string,detail:string}>}
     */
    public function apply(int $step): array
    {
        $plan = $this->getPlan();

        if (!$plan['installed'] || !isset($plan['steps'][$step])) {
            return ['applied' => false, 'nothing' => false, 'errors' => [['key' => '', 'code' => 'plugin_missing', 'detail' => '']]];
        }

        $patch = $plan['steps'][$step]['patch'];

        if ($patch === []) {
            return ['applied' => false, 'nothing' => true, 'errors' => []];
        }

        $plugin = $this->plugin();

        if ($step === 4) {
            // The real key: made now, never shown before it is saved.
            $patch = SetupAdvisor::accessKey($plugin->params(), AccessGateConfig::generateKey())['patch'];
        }

        $res    = SettingsGuard::check($patch, fn (array $p): bool => $plugin->wouldBlockSelf($p + $plugin->params()), $plugin->visitor($patch + $plugin->params()));

        if ($res['errors'] !== []) {
            return ['applied' => false, 'nothing' => false, 'errors' => $res['errors']];
        }

        $saved = $plugin->save($patch);

        if ($saved && $step === 4) {
            // So that switching the key on does not shut out the person who did it.
            $plugin->issueGateCookie($patch + $plugin->params());
        }

        return ['applied' => $saved, 'nothing' => false, 'errors' => []];
    }

    /**
     * True when this request came through Cloudflare (its visitor header is present).
     */
    private function behindCloudflare(): bool
    {
        return !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);
    }
}
