<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Update;

\defined('ABSPATH') || \defined('COLORPACK_SHIELD_WP_TEST') || die;

/**
 * Turns a GitHub "latest release" answer into the update record WordPress understands (what the Plugins screen needs to
 * show "There is a new version"). Pure: no WordPress, no network, so it is unit-testable.
 *
 * Only a stable release whose tag looks like v1.2.3 and that carries the asset colorpack-shield-for-wordpress-1.2.3.zip,
 * served from this project's own releases, is accepted. Anything else is ignored, never trusted.
 */
final class ReleaseFeed
{
    public const REPO = 'lungkao/Colorpack-Shield';

    public const SLUG = 'colorpack-shield';

    /**
     * @param  array<string,mixed>  $release    decoded JSON of GET /repos/{repo}/releases/latest
     * @param  string               $installed  version running on this site
     *
     * @return array{id:string,slug:string,version:string,url:string,package:string,requires_php:string}|null  null when there is nothing newer
     */
    public static function newerThan(array $release, string $installed): ?array
    {
        if (!empty($release['draft']) || !empty($release['prerelease'])) {
            return null;
        }

        $tag = \is_string($release['tag_name'] ?? null) ? $release['tag_name'] : '';

        if (preg_match('/^v?(\d{1,3}\.\d{1,3}\.\d{1,3})$/', $tag, $m) !== 1) {
            return null;
        }

        $version = $m[1];

        if (version_compare($version, $installed, '<=')) {
            return null;
        }

        $name    = 'colorpack-shield-for-wordpress-' . $version . '.zip';
        $prefix  = 'https://github.com/' . self::REPO . '/releases/download/';
        $package = null;

        foreach (\is_array($release['assets'] ?? null) ? $release['assets'] : [] as $asset) {
            $url = \is_array($asset) && \is_string($asset['browser_download_url'] ?? null) ? $asset['browser_download_url'] : '';

            if (\is_array($asset) && ($asset['name'] ?? '') === $name && str_starts_with($url, $prefix) && !str_contains($url, '..')) {
                $package = $url;

                break;
            }
        }

        if ($package === null) {
            return null;
        }

        return [
            'id'           => 'https://github.com/' . self::REPO,
            'slug'         => self::SLUG,
            'version'      => $version,
            'url'          => 'https://github.com/' . self::REPO . '/releases/tag/v' . $version,
            'package'      => $package,
            'requires_php' => '8.1',
        ];
    }
}
