/**
 * Fetch a threat report or a feed for Threat Hunting, and turn it into text.
 *
 * The URL comes from a user, so every request goes through the domain
 * monitor's pinned HTTPS client (exposure/domainMonitor/http.ts) with the
 * public-address check (netSafety.ts): HTTPS only, a hard deadline, a size
 * cap, and a connection only to addresses that are public and globally
 * routable, checked at connect time so DNS rebinding cannot reach the LAN or
 * a cloud metadata service. Redirects are followed by hand (up to
 * MAX_REDIRECTS), each hop checked the same way.
 */
import { parseStringPromise } from 'xml2js';
import { httpsGet, HttpError, type HttpGet } from '../exposure/domainMonitor/http';
import { hostnameRejection, resolvePublicAddresses, UnsafeTargetError } from '../exposure/domainMonitor/netSafety';

export const FETCH_TIMEOUT_MS = 20_000;
export const FETCH_MAX_BYTES = 3 * 1024 * 1024;
export const MAX_REDIRECTS = 5;
export const MAX_URL_LENGTH = 2048;

const USER_AGENT = 'Mozilla/5.0 (compatible; SIEMBox-ThreatHunt/1.0; +https://github.com/cladkins/siembox)';

export class SourceFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SourceFetchError';
  }
}

/** Why a URL can't be hunted from, or null. Checked before anything is stored. */
export function urlRejection(raw: string): string | null {
  if (!raw || raw.length > MAX_URL_LENGTH) return `The URL must be 1 to ${MAX_URL_LENGTH} characters.`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return 'That is not a valid URL.';
  }
  if (u.protocol !== 'https:') return 'Only https:// URLs can be fetched.';
  if (u.username || u.password) return 'URLs with a user name or password are not allowed.';
  if (u.port && u.port !== '443') return 'Only the default HTTPS port (443) is allowed.';
  const why = hostnameRejection(u.hostname);
  return why ? `That host can't be fetched: ${why}.` : null;
}

export interface FetchedDocument {
  /** The URL after redirects. */
  url: string;
  contentType: string;
  body: string;
}

function decode(body: Buffer, contentType: string): string {
  const charset = /charset=["']?([\w-]+)/i.exec(contentType)?.[1]?.toLowerCase() || 'utf-8';
  try {
    return new TextDecoder(charset).decode(body);
  } catch {
    return new TextDecoder('utf-8').decode(body);
  }
}

export async function fetchDocument(rawUrl: string, get: HttpGet = httpsGet): Promise<FetchedDocument> {
  let current = rawUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const why = urlRejection(current);
    if (why) throw new SourceFetchError(hop ? `Redirected to a URL that can't be fetched: ${why}` : why);
    let res;
    try {
      res = await get(new URL(current), {
        timeoutMs: FETCH_TIMEOUT_MS,
        maxBytes: FETCH_MAX_BYTES,
        resolve: (host) => resolvePublicAddresses(host),
        headers: {
          'User-Agent': USER_AGENT,
          Accept:
            'text/html,application/xhtml+xml,application/rss+xml,application/atom+xml,application/xml;q=0.9,' +
            'application/json;q=0.9,text/plain;q=0.8,*/*;q=0.5',
        },
      });
    } catch (err) {
      if (err instanceof HttpError || err instanceof UnsafeTargetError) {
        throw new SourceFetchError(
          err instanceof HttpError && err.kind === 'too_large'
            ? `The page is larger than ${FETCH_MAX_BYTES / (1024 * 1024)} MB.`
            : `Could not fetch ${new URL(current).hostname}: ${err.message}`
        );
      }
      throw err;
    }
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.location;
      if (!location) throw new SourceFetchError(`HTTP ${res.status} without a Location header.`);
      current = new URL(location, current).toString();
      continue;
    }
    if (res.status < 200 || res.status > 299) {
      throw new SourceFetchError(`The server answered HTTP ${res.status}.`);
    }
    const contentType = String(res.headers['content-type'] || '');
    return { url: current, contentType, body: decode(res.body, contentType) };
  }
  throw new SourceFetchError(`More than ${MAX_REDIRECTS} redirects.`);
}

// ---- What kind of document ------------------------------------------------------

export type DocumentKind = 'feed' | 'stix' | 'html' | 'text';

export function documentKind(doc: { contentType: string; body: string }): DocumentKind {
  const ct = doc.contentType.toLowerCase();
  const head = doc.body.slice(0, 2000).trimStart();
  if (/json/.test(ct) || head.startsWith('{') || head.startsWith('[')) {
    try {
      const parsed = JSON.parse(doc.body);
      if (
        (parsed && typeof parsed === 'object' && Array.isArray(parsed.objects)) ||
        (parsed && parsed.type === 'bundle')
      ) {
        return 'stix';
      }
    } catch {
      /* not JSON after all */
    }
    return 'text';
  }
  if (/rss|atom/.test(ct) || /^(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*<(?:rss|feed|rdf:RDF)\b/i.test(head)) {
    return 'feed';
  }
  if (/html/.test(ct) || /<html|<body|<!doctype html/i.test(head)) return 'html';
  if (/xml/.test(ct) && /<(?:rss|feed|rdf:RDF)\b/i.test(head)) return 'feed';
  return 'text';
}

// ---- HTML to text ---------------------------------------------------------------

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'", ndash: '-', mdash: '-',
  hellip: '…', lsquo: "'", rsquo: "'", ldquo: '"', rdquo: '"', lbrack: '[', rbrack: ']', period: '.',
  colon: ':', sol: '/', commat: '@',
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8}|#39);/gi, (all, name: string) => {
    if (name[0] === '#') {
      const code = name[1] === 'x' || name[1] === 'X' ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : all;
    }
    return ENTITIES[name.toLowerCase()] ?? all;
  });
}

function stripTags(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style|noscript|svg|template|iframe)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(?:br|hr)\b[^>]*>/gi, '\n')
      .replace(/<\/(?:p|div|li|tr|td|th|h[1-6]|pre|blockquote|section|article|table|ul|ol|dd|dt)\s*>/gi, '\n')
      .replace(/<[^>]{0,10000}>/g, ' ')
  )
    .replace(/[ \t\f\v\u00a0]+/g, ' ')
    .replace(/\n\s*\n\s*\n+/g, '\n\n')
    .trim();
}

export interface PageText {
  title: string | null;
  text: string;
}

/**
 * The readable text of an HTML page. Navigation, sidebars and footers are
 * dropped (their links are no indicators). When an <article> or <main> holds
 * most of the page's text, only that is kept; a small one (a sidebar some
 * themes wrap in <main>) is ignored.
 */
export function htmlToText(html: string): PageText {
  const ogTitle = /<meta[^>]{1,500}property=["']og:title["'][^>]{0,500}content=["']([^"']{1,500})["']/i.exec(html)?.[1];
  const tagTitle = /<title[^>]*>([\s\S]{1,1000}?)<\/title>/i.exec(html)?.[1];
  const rawTitle = ogTitle || tagTitle;
  const title = rawTitle ? decodeEntities(rawTitle).replace(/\s+/g, ' ').trim() : null;

  const bodyStart = html.search(/<body\b/i);
  const body = (bodyStart >= 0 ? html.slice(bodyStart) : html).replace(
    /<(nav|footer|aside)\b[\s\S]*?<\/\1\s*>/gi,
    ' '
  );
  const bodyText = stripTags(body);
  for (const tag of ['article', 'main']) {
    const start = body.search(new RegExp(`<${tag}\\b`, 'i'));
    const end = body.toLowerCase().lastIndexOf(`</${tag}>`);
    if (start >= 0 && end > start) {
      const text = stripTags(body.slice(start, end));
      if (text.length >= 400 && text.length >= bodyText.length * 0.5) return { title, text };
    }
  }
  return { title, text: bodyText };
}

// ---- Feeds ----------------------------------------------------------------------

export interface FeedItem {
  /** guid / id, else the link: what makes the item new. */
  key: string;
  url: string | null;
  title: string | null;
  published: Date | null;
  /** The item's own content (HTML), used when its link can't be fetched. */
  content: string | null;
}

function textOf(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === 'string') return v.trim() || null;
  if (Array.isArray(v)) return textOf(v[0]);
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if (typeof o._ === 'string') return o._.trim() || null;
  }
  return null;
}

function linkOf(v: unknown): string | null {
  const links = Array.isArray(v) ? v : v == null ? [] : [v];
  // Atom: <link rel="alternate" href="..."/>; RSS: <link>url</link>.
  let fallback: string | null = null;
  for (const l of links) {
    if (typeof l === 'string' && l.trim()) return l.trim();
    if (l && typeof l === 'object') {
      const attrs = (l as any).$ || {};
      if (typeof attrs.href === 'string') {
        if (!attrs.rel || attrs.rel === 'alternate') return attrs.href;
        fallback = fallback || attrs.href;
      }
      const t = textOf(l);
      if (t) return t;
    }
  }
  return fallback;
}

function dateOf(v: unknown): Date | null {
  const s = textOf(v);
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

export const MAX_FEED_ITEMS = 200;

/** The items of an RSS 2.0, RSS 1.0 (RDF) or Atom feed, newest first. */
export async function parseFeed(xml: string): Promise<{ title: string | null; items: FeedItem[] }> {
  let doc: any;
  try {
    doc = await parseStringPromise(xml, { explicitArray: false, trim: true, normalizeTags: true });
  } catch (err) {
    throw new SourceFetchError(`The feed is not valid XML (${(err as Error).message.split('\n')[0]}).`);
  }
  const channel = doc?.rss?.channel ?? doc?.['rdf:rdf']?.channel ?? null;
  const rawItems = doc?.rss?.channel?.item ?? doc?.['rdf:rdf']?.item ?? doc?.feed?.entry ?? [];
  const list: any[] = Array.isArray(rawItems) ? rawItems : [rawItems];
  const title = textOf(channel?.title) ?? textOf(doc?.feed?.title);
  const items: FeedItem[] = [];
  for (const it of list.slice(0, MAX_FEED_ITEMS)) {
    if (!it || typeof it !== 'object') continue;
    const url = linkOf(it.link);
    const key = textOf(it.guid) ?? textOf(it.id) ?? url;
    if (!key) continue;
    items.push({
      key: key.slice(0, 2048),
      url: url ? url.slice(0, 2048) : null,
      title: textOf(it.title)?.slice(0, 500) ?? null,
      published: dateOf(it.pubdate ?? it.published ?? it.updated ?? it['dc:date']),
      content: textOf(it['content:encoded']) ?? textOf(it.content) ?? textOf(it.description) ?? textOf(it.summary),
    });
  }
  items.sort((a, b) => (b.published?.getTime() ?? 0) - (a.published?.getTime() ?? 0));
  return { title, items };
}
