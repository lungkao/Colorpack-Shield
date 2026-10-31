<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\Gemini;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Turns WAF log entries / file-scan findings into a bounded, redacted prompt for Gemini.
 *
 * This is the safety-critical piece: a visitor's IP address, the request-parameter name/source
 * that carried an attack, and raw file content must never leave the server. Every field not
 * explicitly listed below is dropped before anything is serialized - this is an allowlist, not a
 * blocklist, so a new log field added later cannot silently start leaking.
 */
final class PromptBuilder
{
    /** At most this many distinct (type, shield, rule, client) groups go into one prompt. */
    private const MAX_GROUPS = 40;

    /** At most this many sample payloads/URIs kept per group, so one noisy rule cannot dominate the prompt. */
    private const MAX_SAMPLES_PER_GROUP = 3;

    /**
     * Supported reply languages: ISO 639-1 code => the name Gemini is told to answer in. Anything
     * not in this list falls back to English - see {@see languageName()}.
     */
    private const LANGUAGES = ['th' => 'Thai', 'en' => 'English'];

    private const PREAMBLE_WAF = <<<'TXT'
You are helping a system administrator triage a web application firewall's recent activity.
Below is an aggregated, anonymised summary: counts per rule, plus a few representative matched
payloads and request paths. No visitor identity or request-field names are included - only the
rule that fired and what text it matched.

For each notable group:
1. Explain in plain language what pattern this looks like, and whether it is more likely a real
   attack or a false positive against normal traffic.
2. If it looks like a real, recurring attack pattern that is not already well covered, suggest a
   new detection rule as a PCRE pattern in the same "rule_name => /pattern/" shape already used by
   this project's SignatureRules/LocationRules classes - but only if you are reasonably confident
   it would not also match legitimate traffic.

Write the whole reply in %s only. Keep it concise and skimmable; use Markdown headings, bold, and
lists.

TXT;

    private const PREAMBLE_SCAN = <<<'TXT'
You are helping a system administrator triage a file-integrity scanner's findings on a web
server. Below is metadata only for each flagged file - path, matched signature rule names,
severity, size, and modification time. File CONTENTS were never read or sent.

For each notable finding:
1. Say whether the file path, name, and matched rule combination look like a real backdoor/
   webshell, or more likely a false positive (e.g. a legitimate plugin file that happens to match
   a broad pattern).
2. If several findings share a pattern that suggests a new, more precise signature is needed,
   describe it in plain language (not sent file contents, so an exact regex is not expected here).

Write the whole reply in %s only. Keep it concise and skimmable; use Markdown headings, bold, and
lists.

TXT;

    /**
     * @param  array<int, array{time:int, type:string, f:array<string,string>}>  $logEntries
     * @param  string  $lang  ISO 639-1 code of the admin's current interface language - the
     *                        reply comes back in that one language, not a fixed set. Unsupported
     *                        codes fall back to English (see {@see LANGUAGES}).
     */
    public function forWafActivity(array $logEntries, string $lang = 'en'): string
    {
        $groups = [];

        foreach ($logEntries as $entry) {
            $f      = \is_array($entry['f'] ?? null) ? $entry['f'] : [];
            $type   = (string) ($entry['type'] ?? '-');
            $shield = (string) ($f['shield'] ?? '-');
            $rule   = (string) ($f['rule'] ?? '-');
            $client = (string) ($f['client'] ?? '-');
            $gKey   = $type . '|' . $shield . '|' . $rule . '|' . $client;

            if (!isset($groups[$gKey])) {
                if (\count($groups) >= self::MAX_GROUPS) {
                    continue;
                }

                $groups[$gKey] = ['type' => $type, 'shield' => $shield, 'rule' => $rule, 'client' => $client, 'count' => 0, 'samples' => []];
            }

            $groups[$gKey]['count']++;

            if (\count($groups[$gKey]['samples']) < self::MAX_SAMPLES_PER_GROUP) {
                // Allowlist: only these two fields, never ip/key/src/anything else.
                $sample = self::clean((string) ($f['sample'] ?? ''));
                $uri    = self::clean((string) ($f['uri'] ?? ''));
                $piece  = trim($uri . ($sample !== '' ? ' :: ' . $sample : ''));

                if ($piece !== '') {
                    $groups[$gKey]['samples'][] = $piece;
                }
            }
        }

        $lines = [];

        foreach ($groups as $g) {
            $lines[] = sprintf(
                '- type=%s shield=%s rule=%s client=%s count=%d samples=%s',
                $g['type'],
                $g['shield'],
                $g['rule'],
                $g['client'],
                $g['count'],
                $g['samples'] === [] ? '(none)' : implode(' | ', $g['samples'])
            );
        }

        return sprintf(self::PREAMBLE_WAF, self::languageName($lang)) . ($lines === [] ? '(no activity)' : implode("\n", $lines));
    }

    /**
     * @param  array<int, array{path:string, rules:string[], sev:string, size:int, mtime:int, hash:string}>  $findings
     * @param  string  $lang  see {@see forWafActivity()}
     */
    public function forScanFindings(array $findings, string $lang = 'en'): string
    {
        $lines = [];

        foreach (array_slice($findings, 0, self::MAX_GROUPS) as $finding) {
            // Allowlist: path/rules/sev/size/mtime/hash only - file content is never read here.
            $lines[] = sprintf(
                '- path=%s rules=%s severity=%s size=%d mtime=%s hash=%s',
                self::clean((string) ($finding['path'] ?? '')),
                implode(',', array_map(static fn ($r) => self::clean((string) $r), $finding['rules'] ?? [])),
                self::clean((string) ($finding['sev'] ?? '')),
                (int) ($finding['size'] ?? 0),
                gmdate('Y-m-d', (int) ($finding['mtime'] ?? 0)),
                self::clean((string) ($finding['hash'] ?? ''))
            );
        }

        return sprintf(self::PREAMBLE_SCAN, self::languageName($lang)) . ($lines === [] ? '(no findings)' : implode("\n", $lines));
    }

    private static function languageName(string $lang): string
    {
        return self::LANGUAGES[strtolower(substr($lang, 0, 2))] ?? self::LANGUAGES['en'];
    }

    /**
     * Strip control bytes/newlines and cap length so one field can't forge extra prompt lines.
     *
     * A real attack sample can contain raw bytes that are not valid UTF-8 (url-decoded binary,
     * overlong sequences meant to evade filters); a plain byte-counted substr() can also slice a
     * valid multibyte character in half at the cut point. Either way, the later json_encode()
     * call in Client::ask() fails *silently* (returns false) the moment any invalid UTF-8 reaches
     * it, which Client::ask() can only see as "the call failed" - with no HTTP request ever sent.
     * mb_convert_encoding() substitutes any invalid bytes first, so the string handed back here
     * is always safe to json_encode(), and mb_substr() then caps it by character, not raw byte.
     */
    private static function clean(string $s): string
    {
        $s = preg_replace('/[\x00-\x1f\x7f]+/', ' ', $s) ?? '';
        $s = trim($s);

        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }

        return mb_substr($s, 0, 300, 'UTF-8');
    }
}
