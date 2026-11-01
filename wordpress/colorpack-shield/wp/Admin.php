<?php

namespace Colorpack\Shield\Wp;

defined('ABSPATH') || die;

/** The wp-admin screen: status, settings, file scan, recent log. Administrators only; every write is nonce-checked. */
final class Admin
{
    public static function hooks(): void
    {
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_post_colorpack_shield_save', [self::class, 'save']);
        add_action('admin_post_colorpack_shield_baseline', [self::class, 'baseline']);
        add_action('wp_ajax_colorpack_shield_scan', [self::class, 'ajaxScan']);
        add_filter('plugin_action_links_colorpack-shield/colorpack-shield.php', static fn (array $l): array => array_merge(['<a href="' . esc_url(admin_url('admin.php?page=colorpack-shield')) . '">Settings</a>'], $l));
    }

    public static function menu(): void
    {
        add_menu_page('Colorpack Shield', 'Colorpack Shield', 'manage_options', 'colorpack-shield', [self::class, 'page'], 'dashicons-shield', 81);
    }

    private static function guard(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('Forbidden', '', ['response' => 403]);
        }
    }

    public static function save(): void
    {
        self::guard();
        check_admin_referer('colorpack_shield_save');

        $in = [];

        foreach (Settings::DEFAULTS as $key => $default) {
            if (is_int($default) && in_array($key, self::checkboxes(), true)) {
                $in[$key] = isset($_POST[$key]) ? 1 : 0;
            } elseif (isset($_POST[$key])) {
                $in[$key] = wp_unslash($_POST[$key]);
            }
        }

        Settings::save($in);
        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield&saved=1'));
        exit;
    }

    public static function baseline(): void
    {
        self::guard();
        check_admin_referer('colorpack_shield_baseline');
        Scan::acceptBaseline();
        wp_safe_redirect(admin_url('admin.php?page=colorpack-shield&tab=scan'));
        exit;
    }

    public static function ajaxScan(): void
    {
        self::guard();
        check_ajax_referer('colorpack_shield_scan');

        if (($_POST['phase'] ?? '') === 'start' && !Scan::start()) {
            wp_send_json(['ok' => false]);
        }

        wp_send_json(Scan::step());
    }

    /** @return string[] */
    private static function checkboxes(): array
    {
        return ['waf_enforce', 'cover_site', 'cover_admin', 'cover_api', 'shield_sqli', 'shield_xss', 'shield_lfi', 'shield_rfi', 'header_scan', 'path_scan', 'scan_uploads', 'scan_body', 'trust_cloudflare', 'login_lockout', 'site_manager_enabled'];
    }

    public static function page(): void
    {
        self::guard();
        $tab  = in_array($_GET['tab'] ?? '', ['settings', 'scan', 'log'], true) ? $_GET['tab'] : 'status';
        $base = admin_url('admin.php?page=colorpack-shield');

        echo '<div class="wrap"><h1>Colorpack Shield <small>' . esc_html(COLORPACK_SHIELD_WP_VERSION) . '</small></h1>';

        if (isset($_GET['saved'])) {
            echo '<div class="notice notice-success is-dismissible"><p>Saved.</p></div>';
        }

        echo '<nav class="nav-tab-wrapper">';

        foreach (['status' => 'Status', 'settings' => 'Settings', 'scan' => 'File scan', 'log' => 'Activity'] as $key => $label) {
            printf('<a class="nav-tab%s" href="%s">%s</a>', $tab === $key ? ' nav-tab-active' : '', esc_url($base . '&tab=' . $key), esc_html($label));
        }

        echo '</nav>';

        match ($tab) {
            'settings' => self::settings(),
            'scan'     => self::scan(),
            'log'      => self::log(),
            default    => self::status(),
        };

        echo '</div>';
    }

    private static function status(): void
    {
        $health = Health::build();
        $labels = ['pass' => ['OK', '#1a7f37'], 'should_fix' => ['Should fix', '#9a6700'], 'must_fix' => ['Must fix', '#cf222e']];

        echo '<p>' . (Settings::get('waf_enforce')
            ? '<b style="color:#1a7f37">Firewall is blocking.</b>'
            : '<b style="color:#9a6700">Firewall is in detect-only mode:</b> it records what it would block. Review <a href="' . esc_url(admin_url('admin.php?page=colorpack-shield&tab=log')) . '">Activity</a>, then turn on blocking in Settings.') . '</p>';
        echo '<table class="widefat striped" style="max-width:900px"><tbody>';

        foreach ($health['items'] as $i) {
            [$text, $color] = $labels[$i['status']];
            printf('<tr><td style="width:110px"><b style="color:%s">%s</b></td><td>%s%s</td></tr>', esc_attr($color), esc_html($text), esc_html($i['title']), isset($i['fix']) && $i['status'] !== 'pass' ? '<br><span class="description">' . esc_html($i['fix']) . '</span>' : '');
        }

        echo '</tbody></table>';
        echo '<p class="description">Site Manager reporting: ' . (AgentConfig::load() ? 'connected through the Colorpack Agent.' : 'not connected (install and enable the Colorpack Agent).') . '</p>';
    }

    private static function settings(): void
    {
        $v = Settings::all();
        $cb = static fn (string $k, string $label, string $help = ''): string => sprintf('<tr><th scope="row">%s</th><td><label><input type="checkbox" name="%s" value="1"%s> %s</label></td></tr>', esc_html($label), esc_attr($k), $v[$k] ? ' checked' : '', esc_html($help));
        $sel = static function (string $k, string $label, array $opts, string $help = '') use ($v): string {
            $o = '';

            foreach ($opts as $val => $text) {
                $o .= sprintf('<option value="%s"%s>%s</option>', esc_attr($val), selected($v[$k], $val, false), esc_html($text));
            }

            return sprintf('<tr><th scope="row">%s</th><td><select name="%s">%s</select> <span class="description">%s</span></td></tr>', esc_html($label), esc_attr($k), $o, esc_html($help));
        };
        $num = static fn (string $k, string $label, string $help = ''): string => sprintf('<tr><th scope="row">%s</th><td><input type="number" name="%s" value="%d" class="small-text"> <span class="description">%s</span></td></tr>', esc_html($label), esc_attr($k), (int) $v[$k], esc_html($help));

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="colorpack_shield_save">';
        wp_nonce_field('colorpack_shield_save');
        echo '<h2>Firewall</h2><table class="form-table">';
        echo $cb('waf_enforce', 'Block for real', 'Off = detect and log only. Turn on after checking Activity for false alarms.');
        echo $cb('cover_site', 'Cover the public site') . $cb('cover_admin', 'Cover wp-admin / wp-login') . $cb('cover_api', 'Cover the REST API');
        echo $cb('shield_sqli', 'SQL injection') . $cb('shield_xss', 'Cross-site scripting') . $cb('shield_lfi', 'Local file inclusion') . $cb('shield_rfi', 'Remote file inclusion');
        echo $cb('header_scan', 'Inspect request headers') . $cb('path_scan', 'Inspect the URL path') . $cb('scan_uploads', 'Inspect uploaded files') . $cb('scan_body', 'Inspect JSON / raw request bodies');
        echo $sel('path_probe_mode', 'Scanner probes', ['off' => 'Ignore', 'log' => 'Log only', 'block' => 'Block the request', 'ban' => 'Block and ban the address'], 'Requests for other CMSs\' files, old exploit paths, web-shell names.');
        echo $num('path_probe_ban_hours', 'Ban length (hours)');
        echo '</table><h2>Login protection</h2><table class="form-table">';
        echo $cb('login_lockout', 'Lock out guessed passwords') . $num('login_max_failures', 'Failures before lock') . $num('login_failure_window', 'Counting window (seconds)') . $num('login_lock_minutes', 'First lock (minutes)', 'Doubles with every repeat.') . $num('login_lock_max_hours', 'Longest lock (hours)') . $num('login_rate_per_minute', 'Login attempts per minute', '0 = no limit.');
        echo '</table><h2>Network</h2><table class="form-table">';
        printf('<tr><th scope="row">Trusted addresses</th><td><textarea name="allow_ips" rows="3" cols="40">%s</textarea><p class="description">One IP or range per line. Never inspected or locked out - add your own office address.</p></td></tr>', esc_textarea((string) $v['allow_ips']));
        echo $cb('trust_cloudflare', 'Trust Cloudflare', 'Read the visitor address from Cloudflare when the request really comes from Cloudflare.');
        printf('<tr><th scope="row">Trusted proxies</th><td><textarea name="trusted_proxies" rows="2" cols="40">%s</textarea></td></tr>', esc_textarea((string) $v['trusted_proxies']));
        echo $cb('site_manager_enabled', 'Report to Colorpack Site Manager', 'Health, lock-out events and banned attackers; receives the fleet\'s shared attacker list.');
        echo '</table>';
        submit_button();
        echo '</form>';
    }

    private static function scan(): void
    {
        $st = Scan::status();
        $r  = $st['result'];

        echo '<p>Looks for PHP hidden in uploads, web-shell names, decode-and-run code, odd .htaccess files, and what changed since the last accepted baseline.</p>';
        echo '<p><button class="button button-primary" id="cps-start">Run scan</button> <span id="cps-progress"></span></p>';

        if ($r) {
            printf('<p>Last scan %s: %d files looked at, <b>%d high</b>, %d medium, %d low.</p>', esc_html(wp_date('Y-m-d H:i', (int) $r['finished'])), (int) $r['seen'], (int) $r['count']['high'], (int) $r['count']['medium'], (int) $r['count']['low']);

            if ($r['findings']) {
                echo '<table class="widefat striped"><thead><tr><th>Severity</th><th>File</th><th>Why</th></tr></thead><tbody>';

                foreach (array_slice($r['findings'], 0, 200) as $f) {
                    printf('<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>', esc_html($f['sev']), esc_html($f['path']), esc_html(implode(', ', $f['rules'])));
                }

                echo '</tbody></table>';
            } else {
                echo '<p>Nothing suspicious found.</p>';
            }

            if (is_array($r['changes'] ?? null)) {
                printf('<p>Since baseline: %d new, %d changed, %d removed PHP files.</p>', count($r['changes']['new']), count($r['changes']['changed']), count($r['changes']['removed']));
            }
        }

        if ($st['canAccept']) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="colorpack_shield_baseline">';
            wp_nonce_field('colorpack_shield_baseline');
            submit_button('Accept this scan as my baseline', 'secondary');
            echo '</form>';
        }

        $nonce = wp_create_nonce('colorpack_shield_scan');
        echo '<script>(function(){var b=document.getElementById("cps-start"),p=document.getElementById("cps-progress"),u=' . wp_json_encode(admin_url('admin-ajax.php')) . ',n=' . wp_json_encode($nonce) . ';'
            . 'function go(phase){var f=new FormData();f.append("action","colorpack_shield_scan");f.append("_ajax_nonce",n);f.append("phase",phase);'
            . 'fetch(u,{method:"POST",body:f,credentials:"same-origin"}).then(function(r){return r.json()}).then(function(d){'
            . 'if(!d.ok){p.textContent="Scan failed";b.disabled=false;return}'
            . 'if(d.done){location.reload();return}'
            . 'p.textContent="Looked at "+(d.seen||0)+" files...";setTimeout(function(){go("step")},d.busy?1500:100)}).catch(function(){p.textContent="Scan failed";b.disabled=false})}'
            . 'b.addEventListener("click",function(){b.disabled=true;p.textContent="Starting...";go("start")});})();</script>';
    }

    private static function log(): void
    {
        $lines = Logger::tail(100);

        echo $lines === [] ? '<p>Nothing recorded yet.</p>' : '<pre style="max-width:1100px;overflow:auto;background:#fff;padding:12px;border:1px solid #ccd0d4">' . esc_html(implode("\n", $lines)) . '</pre>';
    }
}
