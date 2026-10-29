<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Model;

use Colorpack\Component\ColorpackShield\Administrator\Core\LogReader;
use Colorpack\Component\ColorpackShield\Administrator\Core\LogStats;
use Colorpack\Component\ColorpackShield\Administrator\Core\RuleCatalog;
use Colorpack\Component\ColorpackShield\Administrator\Service\ShieldPlugin;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\HeaderRules;
use Colorpack\Plugin\System\ColorpackShield\Waf\Rules\PathRules;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

\defined('_JEXEC') || die;

class RulesModel extends BaseDatabaseModel
{
    /**
     * @return array{installed:bool,rows:array<int,array<string,mixed>>,logReadable:bool}
     */
    public function getRules(): array
    {
        $plugin = new ShieldPlugin($this->getDatabase());

        if (!$plugin->installed()) {
            return ['installed' => false, 'rows' => [], 'logReadable' => false];
        }

        $log  = (new LogReader($plugin->logFile()))->read();
        $hits = LogStats::ruleCounts($log['entries'], time(), 86400 * 7);

        return [
            'installed'   => true,
            'rows'        => RuleCatalog::withHits(RuleCatalog::rows(PathRules::RULES, HeaderRules::RULES, $plugin->params()), $hits),
            'logReadable' => $log['readable'],
        ];
    }
}
