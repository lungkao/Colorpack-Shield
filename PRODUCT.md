# Product

## Register

product

## Users

Joomla site owners and site admins on ordinary shared hosting - often with no server
administrator rights and no shell access. Many are not security experts; they install
Colorpack Shield, then come back to the admin screens periodically (or after a scare) to check
whether the site is still clean, see what the firewall has been blocking, and decide whether a
file the scanner flagged is safe or needs quarantining. The job to be done on these two screens
specifically: scan a File scan results page or an Activity log fast, correctly judge severity at
a glance, and act on a finding (view/edit/delete/quarantine a file, or simply confirm "nothing to
worry about") without reading a manual.

## Product Purpose

A fleet-hardening security package (WAF, admin-login protection, file-integrity scanner) built so
every feature works on constrained shared hosting with no separate manual - the admin screens
themselves are the documentation. Success is a site owner who can tell, in seconds, "is my site
OK right now," and who trusts a flagged item enough to act on it correctly the first time.

## Brand Personality

Plain-spoken, calm, no-nonsense. Explains itself in plain language rather than security jargon
or a raw score; confident without being alarmist. Bilingual Thai/English as equals, not a
translated afterthought.

## Anti-references

Consumer antivirus dashboards that gamify security (badges-as-trophies, mascots, exclamation-mark
urgency, "you're protected!" triumphalism). Also avoid the opposite failure: a dense enterprise
SOC console that reads as impressive but illegible to a non-specialist site owner. Severity must
read as information, not spectacle.

## Design Principles

- Plain language over jargon or a bare score - every finding and every log entry explains itself.
- Severity is legible at a glance (color + icon + label together, never color alone) but never
  theatrical.
- Shared-hosting realism: screens must stay usable and fast on a plain admin page, no heavy
  JS framework, no feature that assumes a cushy VPS.
- Scannability for long lists: a results/activity table is read row by row, often under time
  pressure after a scare - optimize for finding the one row that matters.
- Thai and English are both first-class; no layout choice should privilege one language's text
  length over the other.

## Accessibility & Inclusion

WCAG AA at minimum (already reflected in the existing design system: verified-contrast action
color, visible focus rings, 44px+ touch targets, dark mode via `prefers-color-scheme` and
Joomla's own theme attribute). Preserve all of this in the redesign; do not regress it.
