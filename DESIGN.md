---
name: Colorpack Shield
description: Plain-spoken security admin screens for Joomla, on the shared Colorpack Admin UI (Atum host look).
colors:
  action: "#1c539c"
  action-hover: "#15437f"
  on-action: "#ffffff"
  action-tint: "#e9f1fc"
  text: "#212529"
  text-2: "#50565e"
  surface: "#ffffff"
  surface-2: "#f8f9fa"
  line: "#dee2e6"
  line-strong: "#848d9a"
  ok-tint: "#e6f4eb"
  ok-line: "#a1ceb2"
  ok-deep: "#13532b"
  warn-tint: "#fdf1d8"
  warn-line: "#e7bd74"
  warn-deep: "#693507"
  bad-tint: "#fce8e8"
  bad-line: "#e9aaaa"
  bad-deep: "#8c1717"
  info-line: "#aac3e4"
  info-deep: "#133e76"
colors-dark:
  action: "#77abee"
  action-hover: "#99c1f5"
  on-action: "#0a1729"
  action-tint: "#16263b"
  text: "#ffffffd9"
  text-2: "#c1c6cd"
  surface: "#0f151d"
  surface-2: "#2b3035"
  line: "#ffffff1a"
  line-strong: "#6c7889"
  ok-tint: "#1a2e21"
  ok-line: "#3a5f48"
  ok-deep: "#9cdeb4"
  warn-tint: "#362917"
  warn-line: "#6f5734"
  warn-deep: "#f6d08e"
  bad-tint: "#341818"
  bad-line: "#713d3d"
  bad-deep: "#f49f9f"
  info-line: "#375376"
  info-deep: "#a3c7f5"
typography:
  family: "inherit (Atum: Roboto, system-ui; Thai falls back to the system Thai face)"
  title: { size: "24px", weight: 600, lineHeight: "1.3" }
  card-title: { size: "20px", weight: 600, lineHeight: "1.3" }
  lead: { size: "18px", weight: 400, lineHeight: "1.55" }
  body: { size: "16px", weight: 400, lineHeight: "1.55 (1.7 for Thai)" }
  small: { size: "14px", weight: 400, lineHeight: "1.55" }
rounded: { sm: "6px", md: "8px", lg: "12px", pill: "999px" }
spacing: { 1: "4px", 2: "8px", 3: "12px", 4: "16px", 5: "24px", 6: "32px", 7: "48px" }
components:
  control-height: "40px (44px on touch devices)"
  button-primary: { background: "{colors.action}", color: "{colors.on-action}", rounded: "{rounded.md}" }
  card: { background: "{colors.surface}", border: "1px {colors.line}", rounded: "{rounded.lg}", padding: "24px" }
  badge: { rounded: "{rounded.pill}", height: "28px", content: "icon + label" }
  callout: { background: "{colors.*-tint}", border: "1px {colors.*-line}", color: "{colors.*-deep}", rounded: "{rounded.lg}" }
---

# Design System: Colorpack Shield

Colorpack Shield uses the **Colorpack Admin UI Standard 1.0.0** (the rulebook, the shared stylesheet and the specimen live in
the Colorpack SEO repository, `docs/design-system/`). The tokens in the front matter above are the standard's; they are not
redefined here. The stylesheet is copied verbatim to `com_colorpack_shield/media/css/colorpack-admin.css` (never edited
in this repository); `media/css/cps.css` is only the Shield layer on top of it.

## 1. What the screens do

Every screen is one `div.cp` (`#cps-app`, kept because the JavaScript looks for it): a page head with the answer in one
sentence and the language switch (`form.cp-lang`, posting `display.language`), the underline section tabs, then
callouts, cards, tables and forms in a vertical flow. The Dashboard opens with the checklist band ("Basic protection is in
place") and a ranked "Do next" list; the first action is the one filled button.

## 2. Shield additions (prefix `cps-`)

Built only from `--cp-*` tokens and only for things the standard has no component for:

- **Score ring** (`Ui::ring`): an SVG arc with the figure inside; colour is the severity deep tone.
- **Day chart** (`Ui::bars`): the standard's `svg.cp-chart`, with one more series colour for "logged only".
- **Basic / advanced switch** and the **in-page tab strip** of Settings and Tools (`role=tab` buttons, `aria-selected`);
  the standard's `cp-tab` is a link with `aria-current`, so the JavaScript tabs need their own variant.
- **File-scan toolbars** (severity segments, bulk bars) and the **code dialog** (a native `<dialog>` with a line-number
  gutter, painted with the surface tokens so it follows light and dark).
- **Activity rows**: one row per event, the technical part folded behind Details.

Markup that repeats lives in `Service/Ui.php` (badge with icon and label, callout, empty state, ring, bar chart); every text
is escaped there.

## 3. Rules kept from the standard

Colour never carries meaning alone (icon and label travel with it); severity is tint, line and deep text, never a solid fill;
no side stripes, no gradients, no `!important`, no inline style, no hard-coded colour; 40 px controls (44 px on touch);
Thai line height 1.7; works without JavaScript (the scan loop, copy buttons, tabs and confirmations are enhancements).
The Atum font is used as it is: the bundled ColorPack typeface is no longer applied to text.

## 4. Checking a change

`php tests/run.php` includes `tests/ui_tests.php`: the helper output, the stylesheet bans (no `!important`, no raw colours,
no side stripe) and the templates' bans (no inline style, no Bootstrap alert or badge classes, no table-responsive), and
the identical key sets of the two language files.
