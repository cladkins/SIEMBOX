/**
 * Sanitized markdown rendering for LLM output (AI Analyst chat, AI triage
 * verdicts). Links open safely; no raw HTML/scripts survive. The DOMPurify
 * hook is registered once at module scope — extracted from AnalystChat.vue so
 * a second consumer doesn't register a duplicate global hook.
 */
import { Marked } from 'marked';
import DOMPurify from 'dompurify';
import { alertIdFromHref, alertRefMarkdown } from './alertRef.ts';
import { guideMarkdownHtml } from './guideMarkdown.ts';

// ALR-#### in model output becomes a link to that alert (built from the parsed
// number only; see alertRef.ts).
const marked = new Marked({ extensions: [alertRefMarkdown] });

DOMPurify.addHook('afterSanitizeAttributes', (node: any) => {
  if (node.tagName === 'A') {
    // An in-app alert link opens in place (the chat intercepts the click);
    // every other link opens in a new tab.
    if (alertIdFromHref(node.getAttribute('href')) !== null && node.hasAttribute('data-alert-ref')) return;
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
  // `async: false` makes marked return a string, never a Promise (typed by its
  // overloads, so no cast), and makes it throw rather than go async if an
  // async extension is ever registered globally.
  const html = marked.parse(fixInlineNumberedList(text || ''), { breaks: true, async: false });
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}

/**
 * Content Pack setup guides (catalog content): rendered with raw HTML escaped
 * and unsafe links dropped (guideMarkdown.ts), then sanitized here like LLM
 * output, so a hostile guide renders as inert text.
 */
export function renderGuideMarkdown(text: string): string {
  return DOMPurify.sanitize(guideMarkdownHtml(text), { USE_PROFILES: { html: true } });
}
