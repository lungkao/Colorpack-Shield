<?php

declare(strict_types=1);

namespace Colorpack\Component\ColorpackShield\Administrator\Core;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * Renders the Gemini advisor's reply as HTML. The reply is free text from an external API, so
 * every byte is HTML-escaped first and only a narrow, fixed allowlist of patterns (headings,
 * bold, inline code, bullet/numbered lists, horizontal rules, blank-line-separated paragraphs) is
 * turned back into markup afterward - never raw HTML from the model, and no PCRE pattern here
 * reads attacker-controlled input (that's `PromptBuilder`'s job, already done before this point).
 */
final class SimpleMarkdown
{
    public static function toHtml(string $markdown): string
    {
        $lines = preg_split('/\r\n|\r|\n/', trim($markdown)) ?: [];
        $html  = '';
        $list  = null; // 'ul' | 'ol' | null - the list currently open

        $closeList = static function () use (&$html, &$list): void {
            if ($list !== null) {
                $html .= '</' . $list . '>';
                $list  = null;
            }
        };

        $paragraph = [];

        $flushParagraph = static function () use (&$html, &$paragraph): void {
            if ($paragraph !== []) {
                $html .= '<p>' . self::inline(implode(' ', $paragraph)) . '</p>';
                $paragraph = [];
            }
        };

        $inFence = false;
        $fence   = [];

        foreach ($lines as $line) {
            // Indentation itself carries no meaning here (the model's nesting is inconsistent
            // and this renderer has no nested-list concept) - trim leading whitespace too, or an
            // indented sub-bullet falls through to the paragraph branch and its leading "*"
            // gets misread as an italic marker instead of a list marker.
            $line = trim($line, " \t");

            if (preg_match('/^```/', $line) === 1) {
                if ($inFence) {
                    $html   .= '<pre><code>' . implode("\n", $fence) . '</code></pre>';
                    $fence   = [];
                    $inFence = false;
                } else {
                    $flushParagraph();
                    $closeList();
                    $inFence = true;
                }

                continue;
            }

            if ($inFence) {
                $fence[] = htmlspecialchars($line, \ENT_QUOTES, 'UTF-8');

                continue;
            }

            if ($line === '') {
                $flushParagraph();
                $closeList();

                continue;
            }

            if (preg_match('/^(#{1,6})\s+(.*)$/', $line, $m) === 1) {
                $flushParagraph();
                $closeList();
                $level = \strlen($m[1]);
                $html .= '<h' . $level . '>' . self::inline($m[2]) . '</h' . $level . '>';

                continue;
            }

            if (preg_match('/^(-{3,}|\*{3,})$/', $line) === 1) {
                $flushParagraph();
                $closeList();
                $html .= '<hr>';

                continue;
            }

            if (preg_match('/^[-*]\s+(.*)$/', $line, $m) === 1) {
                $flushParagraph();

                if ($list !== 'ul') {
                    $closeList();
                    $html .= '<ul>';
                    $list  = 'ul';
                }

                $html .= '<li>' . self::inline($m[1]) . '</li>';

                continue;
            }

            if (preg_match('/^\d+[.)]\s+(.*)$/', $line, $m) === 1) {
                $flushParagraph();

                if ($list !== 'ol') {
                    $closeList();
                    $html .= '<ol>';
                    $list  = 'ol';
                }

                $html .= '<li>' . self::inline($m[1]) . '</li>';

                continue;
            }

            $closeList();
            $paragraph[] = $line;
        }

        $flushParagraph();
        $closeList();

        if ($inFence) {
            $html .= '<pre><code>' . implode("\n", $fence) . '</code></pre>';
        }

        return $html;
    }

    private static function inline(string $text): string
    {
        $escaped = htmlspecialchars($text, \ENT_QUOTES, 'UTF-8');
        $escaped = preg_replace('/`([^`]+)`/', '<code>$1</code>', $escaped) ?? $escaped;
        $escaped = preg_replace('/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $escaped) ?? $escaped;

        return preg_replace('/(?<!\*)\*([^*]+)\*(?!\*)/', '<em>$1</em>', $escaped) ?? $escaped;
    }
}
