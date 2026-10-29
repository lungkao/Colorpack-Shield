<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Rows for a rule table, built from the plugin's own rule tables so the screen can never
 * disagree with the plugin. The effective mode applies the group setting the same way the
 * plugin does (PathShield::modeFor / HeaderShield).
 */
final class RuleCatalog
{
    /**
     * @param  array<string,array{0:string,1:string}>  $pathRules   PathRules::RULES
     * @param  array<string,string>                    $headerRules HeaderRules::RULES
     * @param  array<string,mixed>                     $params      plugin parameters
     *
     * @return array<int,array{id:string,group:string,class:string,default:string,effective:string}>
     */
    public static function rows(array $pathRules, array $headerRules, array $params): array
    {
        $rows       = [];
        $pathMode   = self::oneOf($params['path_mode'] ?? null, ['recommended', 'log', 'block'], 'recommended');
        $probeMode  = self::oneOf($params['path_probe_mode'] ?? null, ['off', 'log', 'block'], 'log');
        $headerMode = self::oneOf($params['header_mode'] ?? null, ['default', 'log', 'block'], 'default');

        foreach ($pathRules as $id => [$class, $default]) {
            $effective = $default;

            if ($class === 'F') {
                $effective = $probeMode === 'off' ? 'off' : ($probeMode === 'block' ? 'block' : 'log');
            }

            if ($effective !== 'off' && $pathMode !== 'recommended') {
                $effective = $pathMode;
            }

            $rows[] = ['id' => $id, 'group' => 'path', 'class' => $class, 'default' => $default, 'effective' => $effective];
        }

        foreach ($headerRules as $id => $default) {
            $rows[] = [
                'id'        => $id,
                'group'     => 'header',
                'class'     => 'H',
                'default'   => $default,
                'effective' => $headerMode === 'default' ? $default : $headerMode,
            ];
        }

        return $rows;
    }

    /**
     * @param  string[]  $allowed
     */
    private static function oneOf(mixed $value, array $allowed, string $default): string
    {
        return \is_string($value) && \in_array($value, $allowed, true) ? $value : $default;
    }

    /**
     * Adds the 7-day hit count and a "review" flag: a log-only rule that keeps firing is worth a
     * look before promoting it. The flag never changes a mode, and it cannot know whether the
     * hits were real attacks, so it only says "review".
     *
     * @param  array<int,array{id:string,group:string,class:string,default:string,effective:string}>  $rows
     * @param  array<string,int>  $hits
     *
     * @return array<int,array{id:string,group:string,class:string,default:string,effective:string,hits:int,review:bool}>
     */
    public static function withHits(array $rows, array $hits, int $reviewFrom = 20): array
    {
        foreach ($rows as &$row) {
            $row['hits']   = $hits[$row['id']] ?? 0;
            $row['review'] = $row['effective'] === 'log' && $row['hits'] >= $reviewFrom;
        }

        return $rows;
    }
}
