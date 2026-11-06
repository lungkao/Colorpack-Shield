<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Update;

defined('ABSPATH') || die;

/**
 * Lets the WordPress Plugins screen (and WordPress's own updater) offer new versions of this plugin, the way the Joomla
 * edition is updated through its update feed. The plugin header "Update URI: https://github.com/lungkao/Colorpack-Shield"
 * routes the check here, so WordPress.org is never asked about this plugin.
 *
 * What is sent: one anonymous GET to the public GitHub releases API of this project (no site address, no cookies, no
 * credentials), at most twice a day. Turn it off with  add_filter('colorpack_shield_update_check', '__return_false');
 */
final class Updater
{
    private const TRANSIENT = 'colorpack_shield_latest_release';

    public static function boot(): void
    {
        add_filter('update_plugins_github.com', [self::class, 'filter'], 10, 3);
    }

    /**
     * @param  mixed                $update       what an earlier filter returned (false = none)
     * @param  array<string,mixed>  $pluginData   the plugin's header data
     * @param  string               $pluginFile   path relative to the plugins folder
     *
     * @return mixed
     */
    public static function filter($update, array $pluginData, string $pluginFile)
    {
        // The hook is named after the host, so it also runs for other plugins whose Update URI is on github.com.
        if ($pluginFile !== plugin_basename(COLORPACK_SHIELD_WP_FILE) || !apply_filters('colorpack_shield_update_check', true)) {
            return $update;
        }

        $release = self::latestRelease();

        if ($release === null) {
            return $update;
        }

        return ReleaseFeed::newerThan($release, (string) ($pluginData['Version'] ?? COLORPACK_SHIELD_WP_VERSION)) ?? $update;
    }

    /** @return array<string,mixed>|null */
    private static function latestRelease(): ?array
    {
        $cached = get_site_transient(self::TRANSIENT);

        if (\is_array($cached)) {
            return $cached === [] ? null : $cached;
        }

        $res = wp_remote_get('https://api.github.com/repos/' . ReleaseFeed::REPO . '/releases/latest', [
            'timeout'    => 5,
            'user-agent' => 'ColorpackShield/' . COLORPACK_SHIELD_WP_VERSION,
            'headers'    => ['Accept' => 'application/vnd.github+json'],
        ]);

        $data = !is_wp_error($res) && (int) wp_remote_retrieve_response_code($res) === 200 ? json_decode((string) wp_remote_retrieve_body($res), true) : null;

        if (!\is_array($data)) {
            // Nothing usable (no release yet, no network, rate limit): ask again in an hour, not on every page load.
            set_site_transient(self::TRANSIENT, [], HOUR_IN_SECONDS);

            return null;
        }

        // Keep only what the feed needs.
        $keep = [
            'tag_name'   => $data['tag_name'] ?? '',
            'draft'      => $data['draft'] ?? false,
            'prerelease' => $data['prerelease'] ?? false,
            'assets'     => array_map(
                static fn ($a): array => ['name' => \is_array($a) ? ($a['name'] ?? '') : '', 'browser_download_url' => \is_array($a) ? ($a['browser_download_url'] ?? '') : ''],
                \array_slice((array) ($data['assets'] ?? []), 0, 20)
            ),
        ];
        set_site_transient(self::TRANSIENT, $keep, 12 * HOUR_IN_SECONDS);

        return $keep;
    }
}
