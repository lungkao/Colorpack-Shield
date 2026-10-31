---
name: Colorpack Shield
description: Plain-spoken security admin screens for Joomla on shared hosting.
colors:
  ink: "#2d3236"
  gray: "#666666"
  paper: "#ffffff"
  ground: "#f4f6f8"
  line: "#e1e6eb"
  action: "#1f5fa8"
  action-hover: "#174c87"
  blue: "#3b8fe0"
  blue-tint: "#e3effb"
  green: "#6cc04a"
  green-deep: "#2f7a1a"
  green-tint: "#e8f5e1"
  orange: "#f7941c"
  orange-deep: "#9a5300"
  orange-tint: "#fef0dc"
  red: "#ef2b2c"
  red-deep: "#b81b1c"
  red-tint: "#fde8e8"
  terminal: "#1b1f24"
  terminal-text: "#d6dee6"
typography:
  h1:
    fontFamily: "ColorPack, Kanit, Noto Sans Thai, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 400
    lineHeight: "36px"
  h2:
    fontFamily: "ColorPack, Kanit, Noto Sans Thai, system-ui, sans-serif"
    fontSize: "24px"
    fontWeight: 400
    lineHeight: "32px"
  h3:
    fontFamily: "ColorPack, Kanit, Noto Sans Thai, system-ui, sans-serif"
    fontSize: "20px"
    fontWeight: 700
    lineHeight: "28px"
  body:
    fontFamily: "ColorPack, Kanit, Noto Sans Thai, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: "28px"
  small:
    fontFamily: "ColorPack, Kanit, Noto Sans Thai, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: "24px"
  mono:
    fontFamily: "ui-monospace, JetBrains Mono, IBM Plex Mono, Menlo, Consolas, monospace"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: "24px"
rounded:
  sm: "8px"
  md: "10px"
  lg: "12px"
  pill: "999px"
spacing:
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "0 22px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.action-hover}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
  button-secondary:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 22px"
    height: "48px"
  card:
    backgroundColor: "{colors.paper}"
    rounded: "{rounded.lg}"
    padding: "24px"
  badge-ok:
    backgroundColor: "{colors.green-tint}"
    textColor: "{colors.green-deep}"
    rounded: "{rounded.pill}"
  badge-warn:
    backgroundColor: "{colors.orange-tint}"
    textColor: "{colors.orange-deep}"
    rounded: "{rounded.pill}"
  badge-bad:
    backgroundColor: "{colors.red-tint}"
    textColor: "{colors.red-deep}"
    rounded: "{rounded.pill}"
  badge-info:
    backgroundColor: "{colors.blue-tint}"
    textColor: "{colors.action}"
    rounded: "{rounded.pill}"
---

# Design System: Colorpack Shield

## 1. Overview

**Creative North Star: "The Site Inspector's Logbook"**

Colorpack Shield reads like a calm, competent inspector writing up findings in plain language —
not a consumer antivirus app congratulating you with badges and exclamation marks, and not a
dense enterprise SOC console built to impress other security engineers. Every screen answers one
question first ("is this OK, and if not, why") before it offers detail. Severity is carried by
color + icon + label together — never color alone — so a finding reads correctly even in
grayscale or to someone colorblind. The system is plain-spoken on purpose: no jargon where a
sentence would do, no bare score without the sentence that explains it.

It is built to survive shared hosting and a stressed, non-expert reader: no animation for its own
sake, generous touch targets, strong contrast, and layouts that hold up whether the text running
through them is Thai or English.

**Key Characteristics:**
- Calm severity, never theatrical — color-coded, but always paired with a label.
- Plain language first; the raw log/table is there to back it up, not to replace the sentence.
- Dense information (long scan/activity lists) stays scannable through row rhythm, not bigger fonts.
- Flat, confident surfaces — one soft card shadow, no glassmorphism, no gradients-as-decoration.
- Bilingual by construction: no element assumes English's shorter word length.

## 2. Colors

A cool, restrained neutral base (paper/ground/ink/line) carries almost the whole interface; one
brand blue is the only accent, and it is reserved for actions and current state. Red/orange/green
exist solely as a severity vocabulary — always on a tint background with a deep-toned foreground,
never as a loud solid fill across a large area.

### Primary
- **Deep Harbor Blue** (`#1f5fa8` / `action`): the one accent. Primary buttons, active nav/tab
  state, links, focus-adjacent emphasis. Chosen over the lighter brand blue (`#3b8fe0`) because
  white text on the lighter blue only measures 3.4:1 — this is the deep tone specifically because
  it passes contrast, not a stylistic choice.
- **Harbor Blue** (`#3b8fe0` / `blue`): focus rings, input focus borders, radio/checkbox accent —
  the "you're interacting with this" signal, distinct from the "this is the current action" signal
  above.

### Neutral
- **Charcoal Ink** (`#2d3236`): all body text and headings.
- **Slate Gray** (`#666666`): secondary text, field labels, help text, table header labels.
- **Paper White** (`#ffffff`): card and input surfaces.
- **Mist Ground** (`#f4f6f8`): the page background cards sit on; also code-snippet background.
- **Hairline** (`#e1e6eb`): every border, divider, and table rule in the system.

### Severity vocabulary (not a free palette — a fixed meaning)
- **Good / Green** (`#6cc04a` tint `#e8f5e1`, deep `#2f7a1a`): clean, passing, resolved.
- **Warn / Orange** (`#f7941c` tint `#fef0dc`, deep `#9a5300`): needs attention, not urgent.
- **Bad / Red** (`#ef2b2c` tint `#fde8e8`, deep `#b81b1c`): actively wrong, needs action now.
- **Info / Blue tint** (`#e3effb`, text `#1f5fa8`): neutral explanatory callouts.

### Named Rules
**The Tint-and-Deep Rule.** A severity color never appears as a large solid fill. It is always a
soft tint background (`*-tint`) paired with its `*-deep` foreground for text/icons — loud enough
to scan, never alarming enough to feel like a warning dialog.

**The Label-Beside-Color Rule.** Color never carries meaning alone. A badge, dot, or row always
ships with a text label or `title` tooltip next to the color, because color-only severity fails
colorblind readers and fails at a glance under a small badge dot.

## 3. Typography

**Body Font:** ColorPack (bundled, SIL OFL), falling back to Kanit → Noto Sans Thai → system-ui.
**Label/Mono Font:** ui-monospace, falling back to JetBrains Mono / IBM Plex Mono / Menlo / Consolas.

**Character:** One typeface for everything, used at a generous base size (17px body, never
smaller than 15px for anything a user must read) — legibility for a stressed, possibly
non-technical reader outranks typographic variety. Monospace is reserved for things that are
literally code or raw data (file paths, log lines, diffs), which doubles as a visual cue: "this
is evidence, not prose."

### Hierarchy
- **H1** (400, 28px/36px): page title only, one per screen.
- **H2** (400, 24px/32px): major section headers (e.g. a hero's own heading).
- **H3 / `.cps-h3`** (700, 20px/28px): card titles — the only bold heading weight in the system,
  which is what makes a card read as a distinct unit.
- **Body** (400, 17px/28px): default text everywhere; no body text should ever drop below this
  without a specific reason (see Label below).
- **Label / `.cps-small`** (400, 15px/24px): field labels, help text, table headers, badges,
  timestamps — the system's "supporting information" size, used consistently so a reader learns
  "small gray text = context, not content."
- **Mono** (400, 15px/24px): file paths, code, log lines, diffs.

### Named Rules
**The One Bold Weight Rule.** Bold (700) exists in exactly two places: card `h3` titles and
active-state nav/tab/badge labels. Nothing else is ever bold — not even severity text, which gets
its urgency from color + background tint, not weight.

## 4. Elevation

Flat by default, one shadow role used sparingly. The interface does not layer tone-on-tone the
way Material does; depth exists only to mark "this is a distinct clickable surface sitting above
the page," never for atmosphere.

### Shadow Vocabulary
- **Card** (`box-shadow: 0 2px 12px rgba(23,50,77,.10)`): every `.cps-card`/`.cps-tile`. The only
  resting shadow in the system.
- **Focus ring** (`box-shadow: 0 0 0 4px rgba(59,143,224,.28)`): the universal keyboard-focus
  treatment, replacing the browser default outline on every interactive element.
- **Dialog** (`box-shadow: 0 16px 48px rgba(17,17,17,.3)`): reserved for the one true modal (the
  file-scan code viewer/editor), signaling "this has left the page," not reused elsewhere.

### Named Rules
**The Flat-Except-Cards Rule.** Nothing floats except a card and the one modal dialog. Buttons,
badges, tabs, and inputs are all flat with a 2px border; shadow is not how this system marks
"interactive," borders and color are.

## 5. Components

### Buttons
- **Shape:** 10px radius (`--radius-md`), 48px minimum height, 22px horizontal padding.
- **Primary:** Deep Harbor Blue fill (`#1f5fa8`), white text, 700 weight. Hover darkens to
  `#174c87`.
- **Secondary / default:** white fill, 2px hairline border, charcoal text; hover darkens the
  border to ink rather than changing the fill — a quieter hover than primary's fill-darken.
  Danger variant swaps border/text to red-deep, tint fill on hover.
- **Disabled:** 45% opacity, default cursor, no hover change.

### Badges
- **Style:** pill radius, 4px/13px padding, 14px/20px text, 700 weight, a 7px solid dot before
  the label colored `currentColor` with a soft halo ring in the same hue.
- **State:** `ok` / `warn` / `bad` / `info` map directly to the severity vocabulary's tint/deep
  pairs in Section 2 — a badge's color is never chosen independently of that vocabulary.

### Cards
- **Corner Style:** 12px radius (`--radius-lg`).
- **Background:** Paper White on Mist Ground page background — the contrast between the two
  neutrals is what separates "card" from "page," not a border.
- **Shadow Strategy:** the one Card shadow from Section 4; no border.
- **Internal Padding:** 24px, with an internal 12px gap between stacked elements.
- **Title:** the `h3` inside a card is always rendered in Deep Harbor Blue, not charcoal — the one
  place body-adjacent text takes the accent color, functioning as a quiet section label.

### Inputs / Fields
- **Style:** 2px hairline border, 8px radius, 48px minimum height, white background.
- **Focus:** border shifts to Harbor Blue plus the universal focus-ring shadow — never color
  alone, the ring itself is the accessible signal.
- **Error:** border shifts to `#ef2b2c` (red, not red-deep — the louder of the two reds, since an
  inline field error needs to be caught mid-scan of a form).

### Tables (the primary vehicle for Scan/Activity content)
- **Style:** full-width, collapsed borders, 17px/26px text, header row in 15px gray/400-weight
  (deliberately smaller and lighter than body — headers are label-weight, not content-weight, per
  the Label hierarchy rule).
- **Row rhythm:** zebra striping via a faint tint on even rows, plus a hover tint — the two
  together are what makes a wide, many-column row trackable across the eye's horizontal sweep,
  which is this system's single highest-leverage scannability device.
- **Numeric columns:** right-aligned, tabular-nums.

### Navigation / Tabs
- **Style:** pill-shaped buttons/tabs, 2px hairline border, 44px min height; the active state is
  the only place in nav/tabs that uses a solid Deep Harbor Blue fill with white 700-weight text —
  exactly one visually "on" state per nav group, never two.

### Score Ring (signature component)
A 150px conic-gradient ring (`--p` percentage, `--c` severity color) with a white inner disc
showing the number — the dashboard's single highest-density "is my site OK" answer, deliberately
a near-donut-chart rather than a bare number, so a glance at color alone (before reading the
number) already tells most of the story.

## 6. Do's and Don'ts

### Do:
- **Do** pair every severity color with a text label or icon — never ship color as the only
  signal (colorblind readers, grayscale printing, small-badge legibility).
- **Do** keep the card shadow as the only resting shadow in the system; mark new "distinct
  surface" components the same way rather than inventing a second shadow depth.
- **Do** use the 15px/24px "label" size consistently for anything that is context rather than
  content (table headers, help text, timestamps, badges) so readers learn the size-to-role mapping.
- **Do** keep table rows scannable with the zebra + hover tint pattern on any new table or list of
  findings/events — this is the system's answer to "how do I track one row across many columns."
- **Do** write what a finding or log entry *means* in a plain sentence before (or instead of) a
  raw code/score — per PRODUCT.md, the screens are the documentation.

### Don't:
- **Don't** use a severity color as a large solid fill (a red card background, a full-width
  orange banner) — severity colors are tint-plus-deep-text only, per the Tint-and-Deep Rule.
- **Don't** add badges-as-trophies, mascots, confetti, or "you're protected!" triumphalism — the
  explicit consumer-antivirus anti-reference from PRODUCT.md. A clean result is a quiet green
  badge and a plain sentence, not a celebration.
- **Don't** pack the screen with raw metrics, acronyms, or a SOC-console data-wall either — the
  other PRODUCT.md anti-reference. If a number needs a term a site owner wouldn't know, it needs a
  sentence next to it, not a tooltip-only glossary entry.
- **Don't** introduce a second bold-text weight anywhere outside card `h3` titles and the one
  active nav/tab/badge state — bold is reserved, not decorative.
- **Don't** use the lighter Harbor Blue (`#3b8fe0`) as a button fill with white text — it fails
  contrast (3.4:1); only Deep Harbor Blue (`#1f5fa8`) is cleared for that use.
- **Don't** design any layout assuming English word length — Thai labels run longer per character
  and must not clip, wrap badly, or break a pill shape.
