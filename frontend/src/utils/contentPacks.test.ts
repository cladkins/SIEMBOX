import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, guideMarkdownHtml, safeHref } from './guideMarkdown.ts';
import {
  countsLine,
  installLabel,
  sigmaBadge,
  sigmaCompatNote,
  sourceNotice,
  statusLabel,
  whatsNewSummary,
  type PackSigmaItem,
  type PackSource,
} from './contentPacks.ts';

/** Every tag the rendered HTML contains, with its attributes. */
const tags = (html: string) => [...html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*)>/gi)].map((m) => ({ tag: m[1].toLowerCase(), attrs: m[2] }));
const ALLOWED = new Set(['p', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'blockquote', 'br', 'hr', 'del']);

describe('setup guide markdown (hostile guide)', () => {
  const hostile = [
    'Intro <script>alert(document.cookie)</script>',
    '<img src=x onerror="alert(1)">',
    '<iframe src="https://evil.example"></iframe>',
    '<a href="javascript:alert(1)">click</a>',
    '[click](javascript:alert(1))',
    '[click](JAVASCRIPT:alert(1))',
    '[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
    '[x](vbscript:msgbox(1))',
    '[x][ref]\n\n[ref]: javascript:alert(1)',
    '![pixel](https://evil.example/p.png "t")',
    '<div onclick="alert(1)">**bold**</div>',
    '<svg><script>alert(1)</script></svg>',
    '<style>body{display:none}</style>',
    '[x](https://ok.example "a\\" onmouseover=\\"alert(1)")',
  ].join('\n\n');
  const html = guideMarkdownHtml(hostile);

  it('emits only plain markdown tags: no script, iframe, img, svg, style, div', () => {
    for (const t of tags(html)) assert.ok(ALLOWED.has(t.tag), `unexpected <${t.tag}> in ${html}`);
  });

  it('carries no event handlers or script/data links', () => {
    for (const t of tags(html)) {
      // Attribute names only (a quoted value may contain any text, escaped).
      const names = t.attrs.replace(/"[^"]*"/g, '""');
      assert.doesNotMatch(names, /\son\w+\s*=/i, `handler on <${t.tag}${t.attrs}>`);
      assert.doesNotMatch(t.attrs, /(javascript|vbscript|data):/i, `scheme on <${t.tag}${t.attrs}>`);
    }
    assert.doesNotMatch(html, /href="(?!https:\/\/ok\.example)/, 'the only link is the safe one');
  });

  it('shows the raw HTML as text, so the reader sees what the guide tried', () => {
    assert.match(html, /&lt;script&gt;alert\(document\.cookie\)&lt;\/script&gt;/);
    assert.match(html, /&lt;img src=x onerror=/);
  });

  it('keeps ordinary markdown, code and safe links working', () => {
    const ok = guideMarkdownHtml('Use a **File** source for `/var/log/<app>.log`.\n\n```yaml\nvolumes:\n  - /var/log:/var/log:ro\n```\n\nSee [docs](https://example.com/x).');
    assert.match(ok, /<strong>File<\/strong>/);
    assert.match(ok, /<code>\/var\/log\/&lt;app&gt;\.log<\/code>/);
    assert.match(ok, /<pre><code class="language-yaml">volumes:/);
    assert.match(ok, /<a href="https:\/\/example\.com\/x" target="_blank" rel="noopener noreferrer">docs<\/a>/);
  });

  it('safeHref allows http(s), mailto and relative links only', () => {
    for (const h of ['https://a.example', 'http://a', 'mailto:x@y', '/rules', '#top', './x']) assert.equal(safeHref(h), h);
    for (const h of ['javascript:1', ' javascript:1', 'java\tscript:1', 'data:x', '//evil.example', 'file:///etc/passwd', '', null]) {
      assert.equal(safeHref(h as string), null, String(h));
    }
    assert.equal(escapeHtml(`<"'&>`), '&lt;&quot;&#39;&amp;&gt;');
  });
});

describe('content pack labels', () => {
  const sigma = (over: Partial<PackSigmaItem>): PackSigmaItem => ({
    id: 'x', title: 't', installed: false, enabled_parts: 0, state: 'available', reason: null,
    compatible: null, missing_field: null, level: 'high', new: false, ...over,
  });

  it('status, counts and the install button', () => {
    assert.equal(statusLabel('partial'), 'Partially installed');
    assert.equal(countsLine({ parserTotal: 1, detectionTotal: 0, sigmaTotal: 2, catalogUnavailable: false }), '1 parser · 2 Sigma rules');
    assert.equal(countsLine({ parserTotal: 5, detectionTotal: 9, sigmaTotal: 0, catalogUnavailable: false }), '5 parsers · 9 detections');
    assert.equal(installLabel({ status: 'not_installed', install: null }), 'Install');
    assert.equal(installLabel({ status: 'partial', install: null }), 'Install missing');
    assert.equal(installLabel({ status: 'installed', install: null }), 'Reinstall');
  });

  it("what's new summary", () => {
    assert.equal(whatsNewSummary(null), '');
    const w = { from_version: 1, to_version: 2, version_bumped: true, parsers: ['a'], detections: ['b', 'c'], sigma: [{ id: 'x', title: 'X' }], count: 4 };
    assert.equal(whatsNewSummary(w), '1 parser, 2 detections and 1 Sigma rule');
    assert.equal(whatsNewSummary({ ...w, parsers: [], detections: [], count: 1 }), '1 Sigma rule');
  });

  it('Sigma item badges: installed, off, pending with the reason, not compatible', () => {
    assert.equal(sigmaBadge(sigma({ state: 'installed', installed: true, enabled_parts: 1 })).label, 'Installed');
    assert.equal(sigmaBadge(sigma({ state: 'installed', installed: true, enabled_parts: 0 })).label, 'Added (off)');
    const pending = sigmaBadge(sigma({ state: 'pending', reason: 'the SigmaHQ library has not been loaded yet' }));
    assert.deepEqual([pending.label, pending.type, pending.detail], ['Pending', 'warning', 'the SigmaHQ library has not been loaded yet']);
    assert.equal(sigmaBadge(sigma({ state: 'not_convertible' })).type, 'danger');
    assert.equal(sigmaCompatNote(sigma({ compatible: false, missing_field: 'user_agent' })), 'no matching logs yet (no parser emits user_agent)');
    assert.equal(sigmaCompatNote(sigma({ compatible: true })), null);
  });

  it('source notice for bundled, cached and partly invalid catalogs', () => {
    const src: PackSource = { source: 'catalog', repo: 'r', ref: 'main', invalid: [], fetched_at: 'now', error: null };
    assert.equal(sourceNotice(src), null);
    assert.equal(sourceNotice({ ...src, source: 'bundled', error: 'the catalog has no packs/ yet' })!.title, 'Showing the packs built into SIEMBox');
    assert.equal(sourceNotice({ ...src, source: 'cache', error: 'unreachable' })!.type, 'warning');
    assert.equal(sourceNotice({ ...src, invalid: [{ path: 'p', errors: ['e'] }], error: '1 left out' })!.title, 'Some catalog packs were left out');
  });
});
