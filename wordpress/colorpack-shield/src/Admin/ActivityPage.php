<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\Gemini\Client;
use Colorpack\WP\ColorpackShield\Gemini\PromptBuilder;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > Activity" screen: the WAF log, filtered, plus the on-demand
 * "Analyze with AI" button - the WordPress equivalent of the Joomla edition's Activity screen
 * and ActivityModel::analyzeWithAi()/ActivityController::analyze().
 *
 * No analysis history here (unlike the Joomla edition's AnalysisHistory/FileStateStore) - just
 * the single latest result, in `colorpack_shield_ai_latest`. A history list wasn't asked for on
 * this side; add it only if it is.
 */
final class ActivityPage
{
    public const AI_ACTION = 'cps_ai_analyze';

    private const AI_NONCE = 'cps_ai_analyze';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        $criteria = LogFilter::criteria($_GET);
        $log      = (new LogReader(ActivityLog::defaultPath()))->read();
        $rows     = LogFilter::apply($log['entries'], $criteria, time());
        $page     = LogFilter::page($rows, (int) ($_GET['paged'] ?? 1), 50);
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-activity'); ?>

                <?php if (!$log['readable']) : ?>
                    <div class="cps-alert cps-alert-info"><p><?php esc_html_e('No activity has been recorded yet.', 'colorpack-shield'); ?></p></div>
                <?php else : ?>
                    <?php if ($log['truncated']) : ?>
                        <div class="cps-alert cps-alert-info"><p><?php esc_html_e('The log is large; showing only the most recent portion.', 'colorpack-shield'); ?></p></div>
                    <?php endif; ?>

                    <section class="cps-card">
                        <table class="cps-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Time (UTC)', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Type', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('IP address', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Client', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Shield / Rule', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('URI', 'colorpack-shield'); ?></th>
                                    <th><?php esc_html_e('Sample', 'colorpack-shield'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if ($page['rows'] === []) : ?>
                                    <tr><td colspan="7" class="cps-muted"><?php esc_html_e('No matching activity.', 'colorpack-shield'); ?></td></tr>
                                <?php endif; ?>
                                <?php foreach ($page['rows'] as $row) : ?>
                                    <tr>
                                        <td><?php echo esc_html(gmdate('Y-m-d H:i:s', $row['time'])); ?></td>
                                        <td><?php echo esc_html($row['type']); ?></td>
                                        <td><?php echo esc_html($row['ip'] ?? ''); ?><?php
                                            $cc = ($row['ip'] ?? '') !== '' ? \Colorpack\WP\ColorpackShield\Net\IpCountry::lookup($row['ip'], !empty(\Colorpack\WP\ColorpackShield\Admin\Settings::get()['ip_country_lookup'])) : null;
                                            if ($cc !== null) : ?> <span class="cps-muted" title="<?php esc_attr_e('Country', 'colorpack-shield'); ?>"><?php echo esc_html(\Colorpack\WP\ColorpackShield\Net\IpCountry::label($cc)); ?></span><?php endif; ?></td>
                                        <td><?php echo esc_html($row['f']['client'] ?? ''); ?></td>
                                        <td><?php echo esc_html(($row['f']['shield'] ?? '') . ' / ' . ($row['f']['rule'] ?? '')); ?></td>
                                        <td><?php echo esc_html($row['f']['uri'] ?? ''); ?></td>
                                        <td><?php echo esc_html($row['f']['sample'] ?? ''); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        <p class="cps-help">
                            <?php
                            printf(
                                /* translators: 1: current page, 2: total pages, 3: total rows */
                                esc_html__('Page %1$d of %2$d (%3$d total)', 'colorpack-shield'),
                                (int) $page['page'],
                                (int) $page['pages'],
                                (int) $page['total']
                            );
                            ?>
                        </p>
                    </section>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    /**
     * admin-post.php handler for the "Analyze with AI" button. Redirects back to the Activity
     * screen with a plain GET and no leftover POST-only params - the exact shape the Joomla
     * edition's 0.10.1 CSRF-chain bug came from (a redirect target that still carried
     * action/task values, so the browser's next GET re-triggered this same handler without a
     * POST body and without the nonce, logging a bogus "invalid token" message every time).
     */
    public static function handleAnalyze(): void
    {
        check_admin_referer(self::AI_NONCE);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $config = Settings::geminiConfig();

        $target = admin_url('admin.php?page=colorpack-shield-tools') . '#ai';

        if ($config === null) {
            wp_safe_redirect($target);
            exit;
        }

        $criteria = LogFilter::criteria([]);
        $log      = (new LogReader(ActivityLog::defaultPath()))->read();
        $rows     = LogFilter::apply($log['entries'], $criteria, time());

        if ($rows !== []) {
            // The admin's own current interface language (their profile's "Language" setting,
            // the WordPress equivalent of the Joomla edition's language-switcher), not the
            // site's front-end locale - two Thai admins shouldn't get an English reply just
            // because the site itself defaults to English.
            $lang   = substr(get_user_locale(), 0, 2);
            $prompt = (new PromptBuilder())->forWafActivity($rows, $lang);
            $answer = (new Client())->ask($config, $prompt);

            update_option('colorpack_shield_ai_latest', [
                'prompt' => $prompt,
                'answer' => $answer,
                'when'   => time(),
            ]);
            AiStore::history()->record('waf_ondemand', $prompt, $answer, time());
        }

        wp_safe_redirect($target);
        exit;
    }
}
