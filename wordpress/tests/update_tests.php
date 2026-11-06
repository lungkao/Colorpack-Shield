<?php
/**
 * The release feed behind the "new version available" notice on the WordPress Plugins screen.
 * Included by run.php, shares its ok() helper and $pass/$fail counters.
 *
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

use Colorpack\WP\ColorpackShield\Update\ReleaseFeed;

$base    = 'https://github.com/lungkao/Colorpack-Shield/releases/download/';
$release = static fn (string $tag, array $extra = []): array => $extra + [
    'tag_name' => $tag,
    'draft'    => false,
    'prerelease' => false,
    'assets'   => [
        ['name' => 'colorpack-shield-for-joomla-' . ltrim($tag, 'v') . '.zip', 'browser_download_url' => $base . $tag . '/colorpack-shield-for-joomla-' . ltrim($tag, 'v') . '.zip'],
        ['name' => 'colorpack-shield-for-wordpress-' . ltrim($tag, 'v') . '.zip', 'browser_download_url' => $base . $tag . '/colorpack-shield-for-wordpress-' . ltrim($tag, 'v') . '.zip'],
    ],
];

$u = ReleaseFeed::newerThan($release('v0.14.0'), '0.13.1');
ok('update: a newer stable release is offered', $u !== null && $u['version'] === '0.14.0');
ok('update: with the WordPress zip, not the Joomla one', $u !== null && $u['package'] === $base . 'v0.14.0/colorpack-shield-for-wordpress-0.14.0.zip');
ok('update: WordPress is told which plugin it is', $u !== null && $u['slug'] === 'colorpack-shield' && $u['id'] === 'https://github.com/lungkao/Colorpack-Shield' && $u['requires_php'] === '8.1');
ok('update: the details link is the release page', $u !== null && $u['url'] === 'https://github.com/lungkao/Colorpack-Shield/releases/tag/v0.14.0');
ok('update: same version is not offered', ReleaseFeed::newerThan($release('v0.13.1'), '0.13.1') === null);
ok('update: an older release is not offered', ReleaseFeed::newerThan($release('v0.12.3'), '0.13.1') === null);
ok('update: "0.9" is older than "0.13" (numbers, not text)', ReleaseFeed::newerThan($release('v0.9.0'), '0.13.1') === null);
ok('update: a draft is ignored', ReleaseFeed::newerThan($release('v0.14.0', ['draft' => true]), '0.13.1') === null);
ok('update: a pre-release is ignored', ReleaseFeed::newerThan($release('v0.14.0', ['prerelease' => true]), '0.13.1') === null);
ok('update: a tag that is not a plain version is ignored', ReleaseFeed::newerThan($release('v0.14.0-beta'), '0.13.1') === null && ReleaseFeed::newerThan($release('latest'), '0.13.1') === null);
ok('update: a release without the WordPress zip is ignored', ReleaseFeed::newerThan($release('v0.14.0', ['assets' => [['name' => 'colorpack-shield-for-joomla-0.14.0.zip', 'browser_download_url' => $base . 'v0.14.0/colorpack-shield-for-joomla-0.14.0.zip']]]), '0.13.1') === null);
ok('update: a zip served from somewhere else is ignored', ReleaseFeed::newerThan($release('v0.14.0', ['assets' => [['name' => 'colorpack-shield-for-wordpress-0.14.0.zip', 'browser_download_url' => 'https://evil.example/colorpack-shield-for-wordpress-0.14.0.zip']]]), '0.13.1') === null);
ok('update: a zip from another project of the same host is ignored', ReleaseFeed::newerThan($release('v0.14.0', ['assets' => [['name' => 'colorpack-shield-for-wordpress-0.14.0.zip', 'browser_download_url' => 'https://github.com/someone/else/releases/download/v0.14.0/colorpack-shield-for-wordpress-0.14.0.zip']]]), '0.13.1') === null);
ok('update: an empty or odd answer gives nothing', ReleaseFeed::newerThan([], '0.13.1') === null && ReleaseFeed::newerThan(['tag_name' => ['x'], 'assets' => 'x'], '0.13.1') === null);
