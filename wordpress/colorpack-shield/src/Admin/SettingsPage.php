<?php
/**
 * @package     Colorpack Shield (WordPress)
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\WP\ColorpackShield\Admin;

use Colorpack\WP\ColorpackShield\AdminProtect\AccessGateConfig;
use Colorpack\WP\ColorpackShield\Net\ClientIpResolver;
use Colorpack\WP\ColorpackShield\Net\CloudflareRanges;
use Colorpack\WP\ColorpackShield\Net\IpAllowList;

\defined('ABSPATH') || die;

/**
 * wp-admin "Colorpack Shield > Settings": the same screen as the Joomla edition's - a Basic/Advanced
 * switch, one tab per group of settings, the private-door link, and a save that first refuses what
 * would lock the saving administrator out. Every field, label and help text comes from
 * {@see SettingsSchema} and the language files, so Thai and English both work.
 */
final class SettingsPage
{
    private const NONCE_ACTION = 'cps_save_settings';

    /** @var array<int,array{key:string,code:string,detail:string}> */
    private static array $errors = [];

    /** @var array<int,array{key:string,code:string,detail:string}> */
    private static array $warnings = [];

    private static bool $saved = false;

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html(Lang::t('WPS_NOT_ADMIN')));
        }

        $posted = null;

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            $posted = self::handleSave();
        }

        $s     = $posted ?? Settings::get();
        $basic = array_flip(SettingsSchema::BASIC);
        $tabs  = [];

        foreach (SettingsSchema::fieldsets() as $name => $set) {
            $anyBasic = false;
            $hasError = false;

            foreach ($set['fields'] as $f) {
                $anyBasic = $anyBasic || isset($basic[$f['name']]);
                $hasError = $hasError || self::errorFor($f['name']) !== null;
            }

            $tabs[$name] = ['set' => $set, 'basic' => $anyBasic, 'error' => $hasError];
        }
        ?>
        <div class="wrap">
            <div id="cps-app">
                <?php Nav::render('colorpack-shield-settings'); ?>

                <?php if (self::$saved) : ?>
                    <div class="cps-alert cps-alert-ok" role="status"><?php echo esc_html(Lang::t('WPS_SAVED')); ?></div>
                <?php endif; ?>
                <?php foreach (self::$errors as $e) : ?>
                    <div class="cps-alert cps-alert-bad" role="alert"><?php echo esc_html(self::message($e)); ?></div>
                <?php endforeach; ?>
                <?php foreach (self::$warnings as $w) : ?>
                    <div class="cps-alert cps-alert-info" role="status"><?php echo esc_html(self::message($w)); ?></div>
                <?php endforeach; ?>

                <form method="post" id="cps-settings-form" class="cps-stack">
                    <?php wp_nonce_field(self::NONCE_ACTION); ?>

                    <button type="button" class="cps-adv-toggle" id="cps-toggle-advanced" aria-pressed="false"
                            data-show="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_SHOW_ADVANCED')); ?>"
                            data-hide="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_HIDE_ADVANCED')); ?>">
                        <span class="cps-adv-toggle-switch" aria-hidden="true"><i></i></span>
                        <span class="cps-adv-toggle-text">
                            <span class="cps-adv-toggle-label"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_SHOW_ADVANCED')); ?></span>
                            <span class="cps-adv-toggle-note"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_SETTINGS_NOTE')); ?></span>
                        </span>
                        <span class="cps-adv-toggle-chev" aria-hidden="true">▾</span>
                    </button>

                    <?php
                    $gate = AccessGateConfig::fromArray(['gate_enabled' => '1', 'gate_key' => (string) $s['gate_key']]);

                    if ($s['gate_enabled'] && $gate->gateActive) : ?>
                        <div class="cps-alert cps-alert-info"><div>
                            <?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_GATE_LINK')); ?>
                            <pre class="cps-log" tabindex="0" style="margin-top:8px"><?php echo esc_html(site_url('wp-login.php') . '?cpskey=' . $s['gate_key']); ?></pre>
                            <span class="cps-small"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_GATE_LINK_NOTE')); ?></span>
                        </div></div>
                    <?php endif; ?>

                    <div class="cps-tablist" role="tablist" aria-label="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_NAV_SETTINGS')); ?>" data-cps-tabs>
                        <?php foreach ($tabs as $name => $t) : ?>
                            <button type="button" role="tab" class="cps-tab<?php echo $t['basic'] ? '' : ' cps-adv'; ?><?php echo $t['error'] ? ' has-error' : ''; ?>" id="cps-tab-<?php echo esc_attr($name); ?>"
                                    aria-controls="cps-panel-<?php echo esc_attr($name); ?>" aria-selected="false" tabindex="-1" data-cps-panel="cps-panel-<?php echo esc_attr($name); ?>"><?php echo esc_html(Lang::t($t['set']['label'])); ?></button>
                        <?php endforeach; ?>
                    </div>

                    <div class="cps-stack">
                        <?php foreach ($tabs as $name => $t) : ?>
                            <section class="cps-card cps-panel<?php echo $t['basic'] ? '' : ' cps-adv'; ?>" role="tabpanel" id="cps-panel-<?php echo esc_attr($name); ?>" aria-labelledby="cps-tab-<?php echo esc_attr($name); ?>">
                                <h2 class="cps-h3"><?php echo esc_html(Lang::t($t['set']['label'])); ?></h2>
                                <?php foreach ($t['set']['fields'] as $f) : ?>
                                    <?php $err = self::errorFor($f['name']); ?>
                                    <div class="cps-field cps-fieldwrap<?php echo isset($basic[$f['name']]) ? '' : ' cps-adv'; ?><?php echo $err !== null ? ' is-error' : ''; ?>" id="cps-f-<?php echo esc_attr($f['name']); ?>"<?php echo isset($f['showon']) ? ' data-cps-showon="' . esc_attr($f['showon']) . '"' : ''; ?>>
                                        <?php self::field($f, $s[$f['name']] ?? $f['default']); ?>
                                        <?php if ($f['name'] === 'gate_key') : ?>
                                            <div id="cps-gate-helper" class="cps-small" role="status" aria-live="polite"
                                                 data-min="<?php echo (int) AccessGateConfig::MIN_KEY; ?>" data-max="<?php echo (int) AccessGateConfig::MAX_KEY; ?>"
                                                 data-alphabet="<?php echo esc_attr(AccessGateConfig::ALPHABET); ?>" data-length="<?php echo (int) AccessGateConfig::GENERATED_LENGTH; ?>"
                                                 data-ok="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_OK')); ?>" data-short="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_SHORT')); ?>"
                                                 data-long="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_LONG')); ?>" data-chars="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_CHARS')); ?>"
                                                 data-empty="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_EMPTY')); ?>" data-button="<?php echo esc_attr(Lang::t('COM_COLORPACK_SHIELD_KEY_GENERATE')); ?>"></div>
                                        <?php endif; ?>
                                        <?php if ($err !== null) : ?>
                                            <p class="cps-error" role="alert"><?php echo esc_html(self::message($err)); ?></p>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </section>
                        <?php endforeach; ?>
                    </div>

                    <div class="cps-actions">
                        <button type="submit" class="cps-btn cps-btn-primary"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_SAVE')); ?></button>
                        <span class="cps-help"><?php echo esc_html(Lang::t('COM_COLORPACK_SHIELD_SAVE_NOTE')); ?></span>
                    </div>
                </form>
            </div>
        </div>
        <?php
    }

    /**
     * One field: label, control and help text.
     *
     * @param  array<string,mixed>  $f
     */
    private static function field(array $f, mixed $value): void
    {
        $name = (string) $f['name'];
        $id   = 'cps-i-' . $name;
        $help = Lang::t((string) $f['desc']);

        if ($f['type'] === 'switch') {
            ?>
            <span class="cps-label" id="<?php echo esc_attr($id); ?>-l"><?php echo esc_html(Lang::t((string) $f['label'])); ?></span>
            <div class="cps-radio" role="radiogroup" aria-labelledby="<?php echo esc_attr($id); ?>-l">
                <label><input type="radio" name="<?php echo esc_attr($name); ?>" value="1" <?php checked((bool) $value); ?>> <?php echo esc_html(Lang::t('JYES')); ?></label>
                <label><input type="radio" name="<?php echo esc_attr($name); ?>" value="0" <?php checked(!$value); ?>> <?php echo esc_html(Lang::t('JNO')); ?></label>
            </div>
            <?php
        } else {
            ?>
            <label for="<?php echo esc_attr($id); ?>"><?php echo esc_html(Lang::t((string) $f['label'])); ?></label>
            <?php
            switch ($f['type']) {
                case 'textarea':
                    ?>
                    <textarea id="<?php echo esc_attr($id); ?>" name="<?php echo esc_attr($name); ?>" rows="<?php echo (int) ($f['rows'] ?? 4); ?>" spellcheck="false"><?php echo esc_textarea((string) $value); ?></textarea>
                    <?php
                    break;

                case 'list':
                    ?>
                    <select id="<?php echo esc_attr($id); ?>" name="<?php echo esc_attr($name); ?>">
                        <?php foreach ($f['options'] as $v => $labelKey) : ?>
                            <option value="<?php echo esc_attr((string) $v); ?>" <?php selected((string) $value, (string) $v); ?>><?php echo esc_html(Lang::t((string) $labelKey)); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?php
                    break;

                case 'number':
                    ?>
                    <input type="number" id="<?php echo esc_attr($id); ?>" name="<?php echo esc_attr($name); ?>" value="<?php echo esc_attr((string) $value); ?>"
                           <?php echo isset($f['min']) ? 'min="' . esc_attr((string) $f['min']) . '"' : ''; ?> <?php echo isset($f['max']) ? 'max="' . esc_attr((string) $f['max']) . '"' : ''; ?> <?php echo isset($f['step']) ? 'step="' . esc_attr((string) $f['step']) . '"' : ''; ?>>
                    <?php
                    break;

                default:
                    $type = \in_array($f['type'], ['password', 'email'], true) ? $f['type'] : 'text';
                    ?>
                    <input type="<?php echo esc_attr($type); ?>" id="<?php echo esc_attr($id); ?>" name="<?php echo esc_attr($name); ?>" value="<?php echo esc_attr((string) $value); ?>" autocomplete="off">
                    <?php
            }
        }
        ?>
        <p class="cps-help"><?php echo esc_html($help); ?></p>
        <?php
    }

    /**
     * @return array<string,mixed>|null  the values to show again (what was posted), or null when nothing was posted
     */
    private static function handleSave(): ?array
    {
        check_admin_referer(self::NONCE_ACTION);

        $params = Settings::clean(wp_unslash($_POST));

        // Switching the access key on without one: make a strong one (nobody has to invent it).
        if ($params['gate_enabled']) {
            $params['gate_key'] = trim((string) $params['gate_key']) !== '' ? trim((string) $params['gate_key']) : AccessGateConfig::generateKey();
        }

        $guard = SettingsGuard::check($params, null, self::visitor($params));

        self::$errors   = $guard['errors'];
        self::$warnings = $guard['warnings'];

        if (self::$errors !== []) {
            return $params;
        }

        Settings::save($guard['params']);
        self::$saved = true;

        return Settings::get();
    }

    /**
     * Who is saving, for the "you would lock yourself out" check.
     *
     * @param  array<string,mixed>  $p
     *
     * @return array{ip:string,enforceable:bool}
     */
    private static function visitor(array $p): array
    {
        $proxies = IpAllowList::fromText((string) $p['trusted_proxies'])->entries();
        $client  = (new ClientIpResolver(CloudflareRanges::bundled(), $proxies, (bool) $p['trust_cloudflare']))->resolve($_SERVER);

        return ['ip' => $client->ip, 'enforceable' => IpAllowList::isSafeToAutoAdd($client, CloudflareRanges::bundled(), $proxies)];
    }

    /**
     * @return array{key:string,code:string,detail:string}|null
     */
    private static function errorFor(string $field): ?array
    {
        foreach (self::$errors as $e) {
            if ($e['key'] === $field) {
                return $e;
            }
        }

        return null;
    }

    /**
     * @param  array{key:string,code:string,detail:string}  $m
     */
    private static function message(array $m): string
    {
        $code = strtoupper($m['code']);

        // A warning's key is WARN_*, an error's is ERR_*; a code can only be one of the two.
        $key = Lang::has('COM_COLORPACK_SHIELD_ERR_' . $code) ? 'COM_COLORPACK_SHIELD_ERR_' . $code : 'COM_COLORPACK_SHIELD_WARN_' . $code;

        return Lang::t($key, $m['key'], $m['detail']);
    }
}
