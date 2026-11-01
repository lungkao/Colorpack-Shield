<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Scanner\ScanStore;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield" landing page: the score ring + "what to fix next" list - the
 * WordPress equivalent of the Joomla edition's Dashboard screen, built on the WP-specific
 * `ScoreCalculator` (see its own docblock for why it scores only 4 items, not the Joomla
 * edition's 11) and the ported `DashboardPlanner`.
 */
final class DashboardPage
{
    private const ITEM_LABELS = [
        'protection'  => ['title' => 'Protection is on', 'ok' => 'The web application firewall is on.', 'bad' => 'The web application firewall is off.'],
        'admin_login' => [
            'title' => 'Admin login protection',
            'ok'    => 'Lock-out after failed logins is on, and two-factor authentication is enforced.',
            'warn'  => 'Lock-out after failed logins is on. Recommended: also enforce two-factor authentication in Settings.',
            'bad'   => 'Lock-out after failed logins is off.',
        ],
        'admin_door'  => ['title' => 'Administrator door', 'ok' => 'The admin login is hidden behind an access key or an address list.', 'warn' => 'Recommended: anyone can reach wp-login.php. Turn on the access key in Settings.'],
        'file_scan'   => [
            'title' => 'File scan',
            'ok'      => 'The last scan is recent and found nothing serious.',
            'warn'    => 'The last scan is more than 30 days old. Scan again.',
            'bad'     => 'The last scan found serious things. Open the Files page.',
            'unknown' => 'No scan yet. Run one on the Files page.',
        ],
    ];

    private const BAND_LABELS = [
        'good'  => 'Basic protection is in place',
        'watch' => 'Mostly protected, a few things are worth doing',
        'risk'  => 'Needs your attention now',
        'none'  => 'Not enough information yet',
    ];

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        $score = ScoreCalculator::calculate(self::facts());
        $plan  = DashboardPlanner::plan($score);
        $pct   = (int) ($score['score'] ?? 0);
        $ringClass = ['good' => 'ok', 'watch' => 'warn', 'risk' => 'bad', 'none' => 'none'][$plan['band']];
        $left  = $plan['counts']['warn'] + $plan['counts']['bad'] + $plan['counts']['unknown'];
        $todo  = $plan['todo'];
        $first = $todo[0] ?? null;
        $rest  = \array_slice($todo, 1);
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield'); ?>

                <?php if ($score['score'] !== null) : ?>
                    <section class="cps-card" aria-labelledby="cps-score-h">
                        <div class="cps-hero">
                            <div class="cps-ring cps-ring-<?php echo esc_attr($ringClass); ?>" style="--p:<?php echo (int) $pct; ?>" role="img" aria-label="<?php echo esc_attr($pct . ' / 100'); ?>">
                                <i><b><?php echo (int) $pct; ?></b><span><?php esc_html_e('of 100', 'colorpack-shield'); ?></span></i>
                            </div>
                            <div class="cps-hero-text">
                                <p class="cps-eyebrow">
                                    <?php
                                    esc_html_e('Security score', 'colorpack-shield');
                                    echo ' · ';
                                    printf(
                                        /* translators: 1: tested item count, 2: total item count */
                                        esc_html__('%1$d of %2$d tested', 'colorpack-shield'),
                                        (int) $score['tested'],
                                        (int) $score['total']
                                    );
                                    ?>
                                </p>
                                <h2 id="cps-score-h"><?php echo esc_html(Lang::translate(self::BAND_LABELS[$plan['band']] ?? '')); ?></h2>
                                <?php if ($left > 0) : ?>
                                    <span class="cps-muted">
                                        <?php
                                        printf(
                                            /* translators: %d: number of items left to fix */
                                            esc_html__('%d thing(s) worth doing', 'colorpack-shield'),
                                            $left
                                        );
                                        ?>
                                    </span>
                                <?php endif; ?>
                                <p class="cps-small cps-muted"><?php esc_html_e('Only what this plugin can verify is counted - an untested item is shown grey, never scored as good or bad.', 'colorpack-shield'); ?></p>
                            </div>
                        </div>
                        <?php if ($first !== null) : $labels = self::ITEM_LABELS[$first['id']] ?? ['title' => $first['id']]; ?>
                            <div class="cps-next">
                                <span class="cps-badge cps-badge-warn"><?php esc_html_e('Worth doing next', 'colorpack-shield'); ?></span>
                                <strong><?php echo esc_html(Lang::translate($labels['title'] ?? $first['id'])); ?></strong>
                                <span class="cps-small cps-muted"><?php echo esc_html(Lang::translate($labels[$first['status']] ?? '')); ?></span>
                                <?php if ($first['screen'] !== null) : ?>
                                    <a class="cps-btn cps-btn-primary" href="<?php echo esc_url(self::screenUrl($first['screen'])); ?>"><?php esc_html_e('Fix it', 'colorpack-shield'); ?></a>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    </section>

                    <?php if ($rest !== []) : ?>
                        <section class="cps-card" aria-labelledby="cps-todo-h">
                            <h2 class="cps-h3" id="cps-todo-h"><?php esc_html_e('Worth doing next', 'colorpack-shield'); ?></h2>
                            <div>
                                <?php foreach ($rest as $n => $t) : $labels = self::ITEM_LABELS[$t['id']] ?? ['title' => $t['id']]; ?>
                                    <div class="cps-todo">
                                        <span class="cps-marker <?php echo $t['status'] === 'bad' ? 'cps-marker-red' : ($t['status'] === 'warn' ? 'cps-marker-orange' : ''); ?>" aria-hidden="true"><?php echo (int) $n + 2; ?></span>
                                        <div class="cps-todo-t">
                                            <h3><?php echo esc_html(Lang::translate($labels['title'] ?? $t['id'])); ?></h3>
                                            <span class="cps-small cps-muted"><?php echo esc_html(Lang::translate($labels[$t['status']] ?? '')); ?></span>
                                        </div>
                                        <?php if ($t['screen'] !== null) : ?>
                                            <a class="cps-btn" href="<?php echo esc_url(self::screenUrl($t['screen'])); ?>"><?php esc_html_e('Fix it', 'colorpack-shield'); ?></a>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </section>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    private static function screenUrl(string $screen): string
    {
        return admin_url('admin.php?page=colorpack-shield-' . $screen);
    }

    /** @return array<string,mixed> */
    private static function facts(): array
    {
        $s = Settings::get();

        $storeDir = trailingslashit(wp_upload_dir()['basedir']) . 'colorpack-shield/scan';
        $result   = (new ScanStore($storeDir))->read('result');
        $fileScan = null;

        if (\is_array($result)) {
            $lastfiles = (new ScanStore($storeDir))->read('lastfiles');
            $age       = \is_array($lastfiles) && \is_int($lastfiles['at'] ?? null) ? (int) ((time() - $lastfiles['at']) / 86400) : 0;
            $fileScan  = ['high' => (int) ($result['count']['high'] ?? 0), 'age' => $age];
        }

        return [
            'waf_enabled'   => $s['waf_enabled'],
            'login_lockout' => $s['login_protect_enabled'] && $s['login_lockout'],
            'mfa_enforce'   => $s['mfa_mode'],
            'admin_door'    => $s['gate_enabled'] || $s['admin_ip_enforce'],
            'file_scan'     => $fileScan,
        ];
    }
}
