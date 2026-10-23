/**
 * Markdown for Content Pack setup guides (catalog content, shown before an
 * install). Two layers: this renderer never emits markup the guide did not
 * ask for in markdown — raw HTML is escaped to text, images become their alt
 * text, and a link whose target is not http(s), mailto or relative becomes
 * plain text — and the page then passes the result through DOMPurify
 * (utils/markdown.ts renderGuideMarkdown), the same sanitizer as the AI
 * Analyst's output. The catalog's validator (validate-packs) refuses HTML and
 * unsafe links in the first place; this is the defence for content that did
 * not come through it. DOM-free, so it is unit-tested under node.
 */
import { Marked, type Tokens } from 'marked';

const SAFE_HREF = /^(?:https?:\/\/|mailto:|\/(?!\/)|#|\.{1,2}\/)/i;

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export function safeHref(href: string | null | undefined): string | null {
  const h = String(href ?? '').trim();
  // Control characters and whitespace inside a scheme ("java\tscript:") are how filters are dodged.
  // eslint-disable-next-line no-control-regex
  if (!h || /[\u0000-\u001f\u007f]/.test(h)) return null;
  return SAFE_HREF.test(h) ? h : null;
}

const guide = new Marked({
  gfm: true,
  breaks: false,
  renderer: {
    html({ text }: Tokens.HTML | Tokens.Tag) {
      return escapeHtml(text);
    },
    image({ text }: Tokens.Image) {
      return escapeHtml(text);
    },
    link(this: { parser: { parseInline: (t: Tokens.Link['tokens']) => string } }, token: Tokens.Link) {
      const inner = this.parser.parseInline(token.tokens);
      const href = safeHref(token.href);
      if (!href) return inner;
      const title = token.title ? ` title="${escapeHtml(token.title)}"` : '';
      return `<a href="${escapeHtml(href)}"${title} target="_blank" rel="noopener noreferrer">${inner}</a>`;
    },
  },
});

/** Guide markdown -> HTML with no raw markup and only safe links (sanitize it again before v-html). */
export function guideMarkdownHtml(text: string): string {
  return guide.parse(String(text ?? ''), { async: false });
}
