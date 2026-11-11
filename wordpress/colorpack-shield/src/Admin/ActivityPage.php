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

    public const ALLOW_ACTION = 'cps_allow_field';

    public const WATCH_ACTION = 'cps_watch_field';

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'colorpack-shield'));
        }

        $criteria = LogFilter::criteria($_GET);
        $log      = (new LogReader(ActivityLog::defaultPath()))->read();
        $entries  = $log['entries'];
        $match    = $criteria;

        // An 8-character reference code from a blocked page: show exactly that row, whatever the other filters say.
        if (preg_match('/^[0-9A-Fa-f]{8}$/', (string) $criteria['text']) === 1) {
            $ref     = strtoupper((string) $criteria['text']);
            $entries = array_values(array_filter($entries, static fn (array $e): bool => ($e['f']['ref'] ?? '') === $ref));
            $match   = ['client' => '', 'rule' => '', 'text' => '', 'days' => 90] + $criteria;
        }

        $rows = LogFilter::apply($entries, $match, time());
        $page = LogFilter::page($rows, (int) ($_GET['paged'] ?? 1), 50);
        $note = isset($_GET['cps_allowed']) ? sanitize_text_field(wp_unslash((string) $_GET['cps_allowed'])) : '';
        $watching = isset($_GET['cps_watching']) ? sanitize_text_field(wp_unslash((string) $_GET['cps_watching'])) : '';
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-activity'); ?>

                <?php if ($note === '0') : ?>
                    <div class="cps-alert cps-alert-warn"><p><?php esc_html_e('This block cannot be allowed from here (headers, paths, uploads, bans and rate limits have their own settings), or the reference was not found in the log.', 'colorpack-shield'); ?></p></div>
                <?php elseif ($note !== '') : ?>
                    <div class="cps-alert cps-alert-info"><p><?php echo esc_html(sprintf(__('Allowed: %s. Try the action again.', 'colorpack-shield'), $note)); ?></p></div>
                <?php endif; ?>

                <?php if ($watching === '0') : ?>
                    <div class="cps-alert cps-alert-warn"><p><?php esc_html_e('This block cannot be watched: only low and medium rules can be (real attack patterns cannot), or the reference was not found in the log.', 'colorpack-shield'); ?></p></div>
                <?php elseif ($watching !== '') : ?>
                    <div class="cps-alert cps-alert-info"><p><?php echo esc_html(sprintf(__('Watching %s. Try the action again; what is seen will appear here.', 'colorpack-shield'), $watching)); ?></p></div>
                <?php endif; ?>

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
                                        <td><?php echo esc_html($row['f']['sample'] ?? ''); ?>
                                            <?php if (($row['f']['note'] ?? '') === 'tolerated') : ?>
                                                <div class="cps-muted"><?php esc_html_e('Not blocked: a trusted editor (low or medium rule).', 'colorpack-shield'); ?></div>
                                            <?php endif; ?>
                                            <?php if (($row['type'] === 'BLOCK' || ($row['type'] === 'DETECT' && ($row['f']['note'] ?? '') === 'watch')) && ($row['f']['ref'] ?? '') !== '') : ?>
                                                <?php if (($row['f']['note'] ?? '') === 'watch') : ?><div class="cps-muted"><?php esc_html_e('Seen while watching this field (not blocked). Press Allow this field to make it permanent.', 'colorpack-shield'); ?></div><?php endif; ?>
                                                <div class="cps-muted"><?php esc_html_e('Reference', 'colorpack-shield'); ?> <code><?php echo esc_html($row['f']['ref']); ?></code><?php if (($row['f']['key'] ?? '') !== '') : ?> · <?php esc_html_e('field', 'colorpack-shield'); ?> <code><?php echo esc_html(mb_substr($row['f']['key'], 0, 80)); ?></code><?php endif; ?></div>
                                                <?php if (($row['f']['src'] ?? '') === 'POST' && ExceptionLine::fromRow($row['f']) !== null) : ?>
                                                    <div class="cps-muted" style="margin:6px 0 0"><?php esc_html_e('This field takes text people type or paste. If it came from another website or Facebook, ask the person to paste it as plain text (Ctrl+Shift+V) and save again. If the content is fine and keeps being blocked, press “Allow this field”.', 'colorpack-shield'); ?></div>
                                                <?php endif; ?>
                                                <?php if (ExceptionLine::fromRow($row['f']) !== null) : ?>
                                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin:6px 0 0">
                                                        <input type="hidden" name="action" value="<?php echo esc_attr(self::ALLOW_ACTION); ?>">
                                                        <input type="hidden" name="ref" value="<?php echo esc_attr($row['f']['ref']); ?>">
                                                        <?php wp_nonce_field(self::ALLOW_ACTION); ?>
                                                        <button type="submit" class="cps-btn" title="<?php esc_attr_e('Lets this rule group skip only this field on this page. Every other check still runs. It is not tied to any IP address and can be removed in Settings → Advanced.', 'colorpack-shield'); ?>"><?php esc_html_e('Allow this field', 'colorpack-shield'); ?></button>
                                                    </form>
                                                    <?php if ($row['type'] === 'BLOCK' && ExceptionLine::isWatchable($row['f']['rule'] ?? '')) : ?>
                                                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin:6px 0 0">
                                                            <input type="hidden" name="action" value="<?php echo esc_attr(self::WATCH_ACTION); ?>">
                                                            <input type="hidden" name="ref" value="<?php echo esc_attr($row['f']['ref']); ?>">
                                                            <?php wp_nonce_field(self::WATCH_ACTION); ?>
                                                            <button type="submit" class="cps-btn" title="<?php esc_attr_e('For one week this field is only observed: its low and medium rules are logged here instead of blocking. Real attack patterns still block. Afterwards the watch ends by itself, and you can turn what you saw into an Allow.', 'colorpack-shield'); ?>"><?php esc_html_e('Watch for 7 days', 'colorpack-shield'); ?></button>
                                                        </form>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </td>
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
     * Allow one blocked field. Takes only the reference code and rebuilds the exception from the log row on
     * the server, so nothing typed in the browser can widen it. Not tied to any IP address.
     */
    public static function handleAllow(): void
    {
        check_admin_referer(self::ALLOW_ACTION);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $ref  = strtoupper(trim(sanitize_text_field(wp_unslash((string) ($_POST['ref'] ?? '')))));
        $line = null;

        if (preg_match('/^[0-9A-F]{8}$/', $ref) === 1) {
            foreach ((new LogReader(ActivityLog::defaultPath()))->read()['entries'] as $entry) {
                $watched = $entry['type'] === 'DETECT' && ($entry['f']['note'] ?? '') === 'watch';

                if (($entry['type'] === 'BLOCK' || $watched) && ($entry['f']['ref'] ?? '') === $ref) {
                    $line = ExceptionLine::fromRow($entry['f']);

                    break;
                }
            }
        }

        if ($line !== null) {
            $settings = Settings::get();
            $current  = ExceptionLine::withoutWatch((string) ($settings['waf_exceptions'] ?? ''), $line);

            if (!ExceptionLine::contains($current, $line)) {
                $current = ExceptionLine::append($current, $line);
            }

            $settings['waf_exceptions'] = $current;
            Settings::store($settings);
        }

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-activity&cps_allowed=' . ($line === null ? '0' : rawurlencode($line))));
        exit;
    }

    /**
     * Watch one blocked field for a week instead of allowing it: its low and medium rules are logged but no longer
     * block, real attack patterns still block, and the watch ends by itself. Takes only the reference code.
     */
    public static function handleWatch(): void
    {
        check_admin_referer(self::WATCH_ACTION);

        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'colorpack-shield'));
        }

        $ref  = strtoupper(trim(sanitize_text_field(wp_unslash((string) ($_POST['ref'] ?? '')))));
        $line = null;

        if (preg_match('/^[0-9A-F]{8}$/', $ref) === 1) {
            foreach ((new LogReader(ActivityLog::defaultPath()))->read()['entries'] as $entry) {
                if ($entry['type'] === 'BLOCK' && ($entry['f']['ref'] ?? '') === $ref && ExceptionLine::isWatchable($entry['f']['rule'] ?? '')) {
                    $line = ExceptionLine::fromRow($entry['f']);

                    break;
                }
            }
        }

        $until = 0;

        if ($line !== null) {
            $now      = time();
            $until    = $now + ExceptionLine::WATCH_SECONDS;
            $settings = Settings::get();

            $settings['waf_exceptions'] = ExceptionLine::withWatch((string) ($settings['waf_exceptions'] ?? ''), $line, $until, $now);
            Settings::store($settings);
        }

        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield-activity&cps_watching=' . ($line === null ? '0' : rawurlencode($line . ' | ' . gmdate('Y-m-d H:i', $until) . ' UTC'))));
        exit;
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
