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

export function renderMarkdown(text: string): string {
  const html = marked.parse(text || '', { breaks: true, async: false }) as string;
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
