import { test } from 'node:test';
import assert from 'node:assert/strict';
import { documentKind, fetchDocument, htmlToText, parseFeed, urlRejection } from './fetchSource';
import type { HttpGet } from '../exposure/domainMonitor/http';

test('urlRejection allows public https URLs only', () => {
  assert.equal(urlRejection('https://www.bleepingcomputer.com/news/security/x/'), null);
  assert.match(urlRejection('http://example.org/')!, /https/);
  assert.match(urlRejection('https://localhost/')!, /can't be fetched/);
  assert.match(urlRejection('https://10.0.0.1/')!, /IP-address/);
  assert.match(urlRejection('https://nas.lan/')!, /internal-only/);
  assert.match(urlRejection('https://u:p@site.org/')!, /user name/);
  assert.match(urlRejection('https://site.org:8443/')!, /port/);
  assert.match(urlRejection('not a url')!, /valid URL/);
});

test('fetchDocument follows redirects and checks every hop', async () => {
  const calls: string[] = [];
  const get: HttpGet = async (url) => {
    calls.push(url.toString());
    if (url.pathname === '/a') return { status: 301, headers: { location: '/b' }, body: Buffer.alloc(0) };
    if (url.pathname === '/b') return { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }, body: Buffer.from('<p>hi</p>') };
    return { status: 404, headers: {}, body: Buffer.alloc(0) };
  };
  const doc = await fetchDocument('https://news.site.org/a', get);
  assert.equal(doc.url, 'https://news.site.org/b');
  assert.equal(doc.body, '<p>hi</p>');
  assert.deepEqual(calls, ['https://news.site.org/a', 'https://news.site.org/b']);

  const toLan: HttpGet = async () => ({ status: 302, headers: { location: 'https://router.lan/' }, body: Buffer.alloc(0) });
  await assert.rejects(fetchDocument('https://news.site.org/a', toLan), /Redirected/);
  const toHttp: HttpGet = async () => ({ status: 302, headers: { location: 'http://news.site.org/' }, body: Buffer.alloc(0) });
  await assert.rejects(fetchDocument('https://news.site.org/a', toHttp), /https/);
  const loop: HttpGet = async () => ({ status: 302, headers: { location: '/again' }, body: Buffer.alloc(0) });
  await assert.rejects(fetchDocument('https://news.site.org/a', loop), /redirects/);
});

test('htmlToText keeps the article and drops scripts, styles and navigation', () => {
  const body = 'IOC list: 45.142.212[.]100 and evil[.]com. '.repeat(20);
  const html = `<html><head><title>Fallback</title><meta property="og:title" content="Big &amp; Bad Campaign"></head>
    <body><nav><a href="https://navlink.com">Nav</a></nav>
    <article><h1>Title</h1><script>var x = "1.1.1.1";</script><style>.a{}</style><p>${body}</p><pre><code>rundll32.exe x.dll</code></pre></article>
    <footer>footer.com</footer></body></html>`;
  const page = htmlToText(html);
  assert.equal(page.title, 'Big & Bad Campaign');
  assert.ok(page.text.includes('45.142.212[.]100'));
  assert.ok(page.text.includes('rundll32.exe x.dll'));
  assert.ok(!page.text.includes('1.1.1.1'));
  assert.ok(!page.text.includes('navlink.com'));
  assert.ok(!page.text.includes('footer.com'));
});

test('documentKind tells feeds, STIX, HTML and text apart', () => {
  assert.equal(documentKind({ contentType: 'application/rss+xml', body: '<rss></rss>' }), 'feed');
  assert.equal(documentKind({ contentType: 'text/xml', body: '<?xml version="1.0"?><feed xmlns="x"></feed>' }), 'feed');
  assert.equal(documentKind({ contentType: 'application/json', body: '{"type":"bundle","objects":[]}' }), 'stix');
  assert.equal(documentKind({ contentType: 'application/json', body: '{"a":1}' }), 'text');
  assert.equal(documentKind({ contentType: 'text/html', body: '<html></html>' }), 'html');
  assert.equal(documentKind({ contentType: 'text/plain', body: '1.2.3.4' }), 'text');
});

test('parseFeed reads RSS 2.0 and Atom, newest first', async () => {
  const rss = await parseFeed(`<?xml version="1.0"?><rss version="2.0"><channel><title>Blog</title>
    <item><title>Old</title><link>https://b.org/old</link><guid>g1</guid><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
    <item><title>New</title><link>https://b.org/new</link><guid isPermaLink="false">g2</guid><pubDate>Tue, 01 Oct 2024 00:00:00 GMT</pubDate>
      <description>&lt;p&gt;IOC 45.142.212.100&lt;/p&gt;</description></item>
  </channel></rss>`);
  assert.equal(rss.title, 'Blog');
  assert.deepEqual(rss.items.map((i) => i.key), ['g2', 'g1']);
  assert.equal(rss.items[0].url, 'https://b.org/new');
  assert.ok(rss.items[0].content?.includes('45.142.212.100'));

  const atom = await parseFeed(`<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Atom</title>
    <entry><title>E1</title><id>urn:1</id><link rel="alternate" href="https://a.org/1"/><updated>2024-05-01T00:00:00Z</updated></entry>
  </feed>`);
  assert.equal(atom.items[0].key, 'urn:1');
  assert.equal(atom.items[0].url, 'https://a.org/1');
  await assert.rejects(parseFeed('<rss><channel>'), /not valid XML/);
});
