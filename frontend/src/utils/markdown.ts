/**
 * Sanitized markdown rendering for LLM output (AI Analyst chat, AI triage
 * verdicts). Links open safely; no raw HTML/scripts survive. The DOMPurify
 * hook is registered once at module scope — extracted from AnalystChat.vue so
 * a second consumer doesn't register a duplicate global hook.
 */
import { marked } from 'marked';
import DOMPurify from 'dompurify';

DOMPurify.addHook('afterSanitizeAttributes', (node: any) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

/**
 * Some models emit an enumerated list as one unbroken line ("1. foo 2. bar
 * 3. baz") instead of real markdown (each item needs its own line to parse as
 * a list) — that renders as a single run-on paragraph. Detect a strictly
 * increasing 1, 2, 3, … sequence of "N. " markers and insert the missing
 * newlines before rendering. Requires 3+ markers in sequence so it can't
 * misfire on an incidental "at 2. " in ordinary prose.
 */
function fixInlineNumberedList(text: string): string {
  const markers = [...text.matchAll(/(?:^|\s)(\d{1,2})\.\s+/g)];
  const nums = markers.map((m) => Number(m[1]));
  const looksLikeList = nums.length >= 3 && nums.every((n, i) => n === i + 1);
  if (!looksLikeList) return text;

  let seen = 0;
  return text.replace(/(^|\s)(\d{1,2})\.\s+/g, (_match, lead, num) => {
    seen++;
    return `${seen === 1 ? lead : '\n'}${num}. `;
  });
}

export function renderMarkdown(text: string): string {
  const html = marked.parse(fixInlineNumberedList(text || ''), { breaks: true, async: false }) as string;
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
