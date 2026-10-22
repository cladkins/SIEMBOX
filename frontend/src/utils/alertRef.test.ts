import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Marked } from 'marked';
import {
  MAX_ALERT_ID,
  alertIdFromHref,
  alertRefMarkdown,
  alertRefPath,
  alertRefUrl,
  formatAlertRef,
  parseAlertRef,
} from './alertRef.ts';

const md = new Marked({ extensions: [alertRefMarkdown] });
const render = (s: string) => md.parse(s, { async: false });
const link = (id: number) =>
  `<a href="/alerts?alert=ALR-${id}" class="alert-ref-link" data-alert-ref="ALR-${id}">ALR-${id}</a>`;

describe('formatAlertRef / parseAlertRef', () => {
  it('formats and round-trips', () => {
    assert.equal(formatAlertRef(4821), 'ALR-4821');
    assert.equal(parseAlertRef(formatAlertRef(4821)), 4821);
  });

  it('accepts ALR-, lower case, bare and # forms, trimming whitespace', () => {
    for (const s of ['ALR-4821', 'alr-4821', '4821', '#4821', ' ALR-4821 ']) assert.equal(parseAlertRef(s), 4821, s);
    assert.equal(parseAlertRef(12), 12);
    assert.equal(parseAlertRef(`ALR-${MAX_ALERT_ID}`), MAX_ALERT_ID);
  });

  it('rejects zero, junk, inner whitespace and out-of-range ids', () => {
    for (const v of [
      'ALR-0', '0', 'ALR-abc', 'ALR-', 'ALR -1', 'ALR-1 2', 'ALR-012', 'ALR-1.5', '-3', `ALR-${MAX_ALERT_ID + 1}`,
      'ALR-99999999999', 'x'.repeat(100), 0, -1, 2.5, NaN, null, undefined, {},
    ]) {
      assert.equal(parseAlertRef(v), null, String(v));
    }
  });
});

describe('alert links', () => {
  it('builds the deep link from the id', () => {
    assert.equal(alertRefPath(7), '/alerts?alert=ALR-7');
    assert.equal(alertRefUrl(7, 'https://siem.example:8420/'), 'https://siem.example:8420/alerts?alert=ALR-7');
  });

  it('recognises only an exact in-app alert link', () => {
    assert.equal(alertIdFromHref('/alerts?alert=ALR-7'), 7);
    for (const h of [
      'https://evil.example/alerts?alert=ALR-7', '/alerts?alert=ALR-7&x=1', '/alerts?alert=7', 'javascript:alert(1)',
      '/alerts?alert=ALR-0', null, undefined,
    ]) {
      assert.equal(alertIdFromHref(h), null, String(h));
    }
  });
});

describe('alertRefMarkdown', () => {
  it('links a reference in prose', () => {
    assert.equal(render('See ALR-4821 and alr-12.'), `<p>See ${link(4821)} and ${link(12)}.</p>\n`);
    assert.equal(render('ALR-5'), `<p>${link(5)}</p>\n`);
    assert.ok(render('- **ALR-9**: brute force').includes(`<strong>${link(9)}</strong>`));
  });

  it('leaves text that is not a reference alone', () => {
    for (const s of ['XALR-5', 'ALR-0', 'ALR-5x', 'ALR-abc', 'ALR-99999999999', 'ALR-5-6', 'MY_ALR-5']) {
      assert.ok(!render(s).includes('<a '), s);
    }
  });

  it('does not link inside code or an existing link', () => {
    assert.equal(render('`ALR-5`'), '<p><code>ALR-5</code></p>\n');
    assert.ok(!render('```\nALR-5\n```').includes('<a '));
    const linked = render('[ALR-5](https://example.com)');
    assert.equal((linked.match(/<a /g) || []).length, 1);
    assert.ok(linked.includes('href="https://example.com"'));
  });

  it('builds the link from the number only, so model text cannot inject markup', () => {
    const out = render('ALR-7"><img src=x onerror=alert(1)> ALR-8<script>');
    assert.ok(out.includes(link(7)));
    assert.ok(out.includes(link(8)));
    // The link markup never carries anything but the digits.
    for (const m of out.matchAll(/<a [^>]*>/g)) assert.match(m[0], /^<a href="\/alerts\?alert=ALR-\d+" class="alert-ref-link" data-alert-ref="ALR-\d+">$/);
  });
});
