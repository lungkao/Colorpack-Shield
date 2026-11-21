<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Component\ColorpackShield\Administrator\Service;

\defined('_JEXEC') || die;

/**
 * Small markup helpers for the Colorpack Admin UI Standard (docs/design-system/STANDARD.md): the pieces the
 * screens repeat and that must stay identical everywhere (icon + label badges, callouts, empty states, the score
 * ring and the day-by-day bar chart). Pure string builders; every text is escaped here, so a caller passes
 * plain, already translated text and never HTML (except the $extra / $actions arguments, which are trusted markup).
 */
final class Ui
{
    /** Severity vocabulary of the standard. */
    public const STATES = ['ok', 'warn', 'bad', 'info'];

    public static function e(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** The state a Bootstrap-style class list (the markup this component used before) stood for: '' = neutral. */
    public static function stateOf(string $legacy): string
    {
        return match (true) {
            str_contains($legacy, 'success') => 'ok',
            str_contains($legacy, 'warning') => 'warn',
            str_contains($legacy, 'danger')  => 'bad',
            str_contains($legacy, 'info')    => 'info',
            default                          => '',
        };
    }

    /** A 16 px inline icon (stroke, currentColor, hidden from assistive technology). */
    public static function icon(string $name): string
    {
        $paths = [
            'ok'    => '<circle cx="8" cy="8" r="6.5"/><path d="M5 8.2l2 2 4-4.4"/>',
            'warn'  => '<path d="M8 2l6.5 11.5h-13z"/><path d="M8 6.6v3M8 11.7v.1"/>',
            'bad'   => '<circle cx="8" cy="8" r="6.5"/><path d="M5.7 5.7l4.6 4.6M10.3 5.7l-4.6 4.6"/>',
            'info'  => '<circle cx="8" cy="8" r="6.5"/><path d="M8 7.2v4M8 4.9v.1"/>',
            'globe' => '<circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5c2 2 2.6 4.2 2.6 6.5S10 12.5 8 14.5C6 12.5 5.4 10.3 5.4 8S6 3.5 8 1.5z"/>',
            'inbox' => '<path d="M2 9l1.8-5.2A1 1 0 0 1 4.7 3h6.6a1 1 0 0 1 .9.8L14 9v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/><path d="M2 9h3.4l.8 1.6h3.6l.8-1.6H14"/>',
        ];
        $width = $name === 'globe' || $name === 'inbox' ? '1.4' : '1.6';

        return '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="' . $width . '" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
            . ($paths[$name] ?? $paths['info']) . '</svg>';
    }

    /** Pill with icon and label (a neutral pill, state '', has the label only). Never colour alone. */
    public static function badge(string $state, string $label, string $title = ''): string
    {
        $state = \in_array($state, self::STATES, true) ? $state : '';

        return '<span class="cp-badge"' . ($state !== '' ? ' data-state="' . $state . '"' : '') . ($title !== '' ? ' title="' . self::e($title) . '"' : '') . '>'
            . ($state !== '' ? self::icon($state) : '') . '<span>' . self::e($label) . '</span></span>';
    }

    /**
     * Callout: icon, title (the result), text (what it means and what to do). $extra is markup that goes under the
     * text inside the body (a code box, a list); $actions is markup for the button row.
     */
    public static function callout(string $state, string $title, string $text = '', string $extra = '', string $actions = ''): string
    {
        $state = \in_array($state, self::STATES, true) ? $state : 'info';
        $role  = $state === 'bad' ? 'alert' : 'status';

        return '<div class="cp-callout" data-state="' . $state . '" role="' . $role . '"><span class="cp-callout__icon" aria-hidden="true">' . self::icon($state) . '</span>'
            . '<div class="cp-callout__body">'
            . ($title !== '' ? '<p class="cp-callout__title">' . self::e($title) . '</p>' : '')
            . ($text !== '' ? '<p class="cp-callout__text">' . self::e($text) . '</p>' : '')
            . $extra . '</div>'
            . ($actions !== '' ? '<div class="cp-callout__actions">' . $actions . '</div>' : '')
            . '</div>';
    }

    /** The opening of a callout whose body the template writes itself (use with calloutEnd()). */
    public static function calloutStart(string $state, string $title = ''): string
    {
        $state = \in_array($state, self::STATES, true) ? $state : 'info';

        return '<div class="cp-callout" data-state="' . $state . '" role="' . ($state === 'bad' ? 'alert' : 'status') . '"><span class="cp-callout__icon" aria-hidden="true">' . self::icon($state) . '</span>'
            . '<div class="cp-callout__body">' . ($title !== '' ? '<p class="cp-callout__title">' . self::e($title) . '</p>' : '');
    }

    public static function calloutEnd(): string
    {
        return '</div></div>';
    }

    /** Empty state: what is empty, why, and (optionally) the one action. */
    public static function empty(string $title, string $text = '', string $actions = ''): string
    {
        return '<div class="cp-empty">' . self::icon('inbox') . '<p class="cp-empty__title">' . self::e($title) . '</p>'
            . ($text !== '' ? '<p class="cp-empty__text">' . self::e($text) . '</p>' : '') . $actions . '</div>';
    }

    /**
     * The score ring: an SVG arc with the figure inside. $pct 0..100, $state ok|warn|bad|'' (neutral), $big and
     * $small are the text in the middle, $label the accessible name. $compact makes the small version.
     */
    public static function ring(int $pct, string $state, string $big, string $small, string $label, bool $compact = false): string
    {
        $pct   = max(0, min(100, $pct));
        $state = \in_array($state, self::STATES, true) ? $state : 'none';

        return '<div class="cps-ring cps-ring--' . $state . ($compact ? ' cps-ring--sm' : '') . '" role="img" aria-label="' . self::e($label) . '">'
            . '<svg viewBox="0 0 36 36" aria-hidden="true" focusable="false">'
            . '<circle class="cps-ring__track" cx="18" cy="18" r="15.9155" fill="none" stroke-width="3"/>'
            . ($pct > 0 ? '<circle class="cps-ring__arc" cx="18" cy="18" r="15.9155" fill="none" stroke-width="3" stroke-dasharray="' . $pct . ' 100" transform="rotate(-90 18 18)"/>' : '')
            . '</svg><div class="cps-ring__txt"><b>' . self::e($big) . '</b><span>' . self::e($small) . '</span></div></div>';
    }

    /**
     * A day-by-day bar chart as an SVG (no inline style): one bar per day, optionally a second bar stacked on top.
     *
     * @param list<array{label:string, a:int, b?:int, flag?:bool}> $days  a = the main bar, b = the bar stacked on it
     *                                                                     (drawn in the "logged only" colour), flag = draw a in the "bad" colour
     */
    public static function bars(array $days, string $aria): string
    {
        $n = \count($days);

        if ($n === 0) {
            return '';
        }

        $peak = 1;

        foreach ($days as $d) {
            $peak = max($peak, (int) $d['a'] + (int) ($d['b'] ?? 0));
        }

        $left = 28.0;
        $base = 108.0;
        $high = 92.0;
        $slot = (316.0 - $left) / $n;
        $bw   = min(22.0, $slot * 0.6);
        $h    = static fn (int $v): float => $v > 0 ? max(2.0, round($v / $peak * $high, 1)) : 0.0;
        $f    = static fn (float $x): string => rtrim(rtrim(number_format($x, 1, '.', ''), '0'), '.');

        $out = '<svg class="cp-chart cps-chart" viewBox="0 0 320 132" role="img" aria-label="' . self::e($aria) . '">'
            . '<line class="cp-chart__grid" x1="28" x2="316" y1="16" y2="16"/><line class="cp-chart__grid" x1="28" x2="316" y1="62" y2="62"/>'
            . '<line class="cp-chart__axis" x1="28" x2="316" y1="108" y2="108"/>'
            . '<text class="cp-chart__text" x="2" y="20">' . number_format($peak) . '</text>'
            . '<text class="cp-chart__text" x="2" y="66">' . number_format((int) round($peak / 2)) . '</text><g>';

        foreach ($days as $i => $d) {
            $x  = $left + $i * $slot + ($slot - $bw) / 2;
            $ha = $h((int) $d['a']);
            $hb = $h((int) ($d['b'] ?? 0));

            if ($ha > 0) {
                $out .= '<rect class="cp-chart__bar' . (!empty($d['flag']) ? ' cp-chart__bar--bad' : '') . '" x="' . $f($x) . '" y="' . $f($base - $ha) . '" width="' . $f($bw) . '" height="' . $f($ha) . '" rx="2"/>';
            }

            if ($hb > 0) {
                $out .= '<rect class="cp-chart__bar cps-bar-log" x="' . $f($x) . '" y="' . $f($base - $ha - $hb) . '" width="' . $f($bw) . '" height="' . $f($hb) . '" rx="2"/>';
            }

            $out .= '<text class="cp-chart__text" text-anchor="middle" x="' . $f($left + $i * $slot + $slot / 2) . '" y="125">' . self::e((string) $d['label']) . '</text>';
        }

        return $out . '</g></svg>';
    }
}
