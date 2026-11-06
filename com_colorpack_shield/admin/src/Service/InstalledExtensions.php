<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

use Joomla\Database\DatabaseInterface;

\defined('_JEXEC') || die;

/**
 * The third-party extensions installed on this site (name, element, type, version), read from #__extensions.
 * Joomla's own protected extensions are left out. Read-only; any database problem gives an empty list.
 */
final class InstalledExtensions
{
    /**
     * @return array<int,array{name:string,element:string,type:string,version:string}>
     */
    public static function list(DatabaseInterface $db): array
    {
        try {
            $query = $db->getQuery(true)
                ->select($db->quoteName(['type', 'element', 'name', 'manifest_cache']))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' IN (' . implode(',', array_map([$db, 'quote'], ['component', 'module', 'plugin', 'template', 'package'])) . ')')
                ->where($db->quoteName('protected') . ' = 0');
            $rows = (array) $db->setQuery($query)->loadObjectList();
        } catch (\Throwable) {
            return [];
        }

        $out = [];

        foreach ($rows as $r) {
            $manifest = json_decode((string) $r->manifest_cache, true);
            $manifest = \is_array($manifest) ? $manifest : [];
            $element  = (string) $r->element;

            $out[] = [
                'name'    => (string) ($manifest['name'] ?? $r->name),
                'element' => $element,
                'type'    => (string) $r->type,
                'version' => (string) ($manifest['version'] ?? ''),
            ];
        }

        return $out;
    }
}
