/**
 * Monitored hunt sources: URLs SIEMBox checks on a schedule, creating a hunt
 * whenever they carry something new.
 *
 *   feed  an RSS/Atom feed (a vendor's threat research blog, a news site):
 *         each new item becomes a hunt for the article it links to. The first
 *         check hunts only the newest FIRST_CHECK_ITEMS items, so adding a
 *         feed doesn't start a hunt for its whole archive.
 *   page  a single page (an advisory, an IOC list): a new hunt whenever the
 *         set of indicators on it changes.
 *   misp  a MISP feed (the directory with manifest.json and one <uuid>.json
 *         per event, like CIRCL's OSINT feed): each new event becomes a hunt
 *         that reads the event's attributes (misp.ts). The first check hunts
 *         the newest FIRST_CHECK_ITEMS events and marks the rest seen.
 *   auto  decide from what the URL returns: a manifest.json URL, a MISP
 *         manifest or a directory listing that links to one is a MISP feed;
 *         a STIX bundle counts as a page.
 *
 * Fetching uses fetchSource.ts: public HTTPS hosts only.
 */
import { createHash } from 'crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';
import { getTechnique } from '../attack/attackData';
import { extractIocs, siteDomain } from './iocExtract';
import { documentKind, fetchDocument, htmlToText, LARGE_FETCH_MAX_BYTES, parseFeed, urlRejection } from './fetchSource';
import { isMispManifest, looksLikeMispFeedIndex, mispFeedUrls, parseMispManifest } from './misp';
import { clampLookback, createHunt, HuntError } from './huntService';

export const FIRST_CHECK_ITEMS = 3;
export const MAX_NEW_ITEMS_PER_CHECK = 10;
const MIN_INTERVAL = 30;
const MAX_INTERVAL = 10_080;
const DEFAULT_INTERVAL = 360;

export type SourceKind = 'auto' | 'feed' | 'page' | 'misp';

export interface HuntSource {
  id: number;
  name: string;
  url: string;
  kind: SourceKind;
  enabled: boolean;
  check_interval_minutes: number;
  lookback_days: number;
  alert_on_match: boolean;
  use_ai: boolean;
  last_checked_at: Date | null;
  last_status: string | null;
  last_error: string | null;
  last_content_hash: string | null;
  hunts_created: number;
  created_by: number | null;
  created_at: Date;
  updated_at: Date;
}

const PUBLIC_COLUMNS = `id, name, url, kind, enabled, check_interval_minutes, lookback_days, alert_on_match, use_ai,
  last_checked_at, last_status, last_error, hunts_created, created_by, created_at, updated_at`;

function clampInterval(raw: unknown): number {
  const n = parseInt(String(raw ?? ''), 10);
  if (Number.isNaN(n)) return DEFAULT_INTERVAL;
  return Math.min(Math.max(n, MIN_INTERVAL), MAX_INTERVAL);
}

function cleanKind(raw: unknown): SourceKind {
  if (raw === undefined || raw === null || raw === '') return 'auto';
  if (raw === 'auto' || raw === 'feed' || raw === 'page' || raw === 'misp') return raw;
  throw new HuntError(400, 'kind must be auto, feed, page or misp');
}

export async function listSources(): Promise<HuntSource[]> {
  const r = await query(`SELECT ${PUBLIC_COLUMNS} FROM hunt_sources ORDER BY name, id`);
  return r.rows;
}

export async function getSource(id: number): Promise<HuntSource | null> {
  const r = await query(`SELECT * FROM hunt_sources WHERE id = $1`, [id]);
  return r.rows[0] || null;
}

export interface SourceInput {
  name?: unknown;
  url?: unknown;
  kind?: unknown;
  enabled?: unknown;
  check_interval_minutes?: unknown;
  lookback_days?: unknown;
  alert_on_match?: unknown;
  use_ai?: unknown;
}

export async function createSource(input: SourceInput, createdBy: number | null): Promise<HuntSource> {
  const url = typeof input.url === 'string' ? input.url.trim() : '';
  const why = urlRejection(url);
  if (why) throw new HuntError(400, why);
  let name = typeof input.name === 'string' ? input.name.trim().slice(0, 200) : '';
  if (!name) name = new URL(url).hostname;
  try {
    const r = await query(
      `INSERT INTO hunt_sources (name, url, kind, enabled, check_interval_minutes, lookback_days, alert_on_match, use_ai, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING ${PUBLIC_COLUMNS}`,
      [
        name,
        url,
        cleanKind(input.kind),
        input.enabled !== false,
        clampInterval(input.check_interval_minutes),
        clampLookback(input.lookback_days),
        input.alert_on_match !== false,
        input.use_ai !== false,
        createdBy,
      ]
    );
    return r.rows[0];
  } catch (err) {
    if ((err as { code?: string }).code === '23505') throw new HuntError(409, 'That URL is already a source.');
    throw err;
  }
}

export async function updateSource(id: number, input: SourceInput): Promise<HuntSource | null> {
  const sets: string[] = [];
  const params: unknown[] = [id];
  const set = (col: string, v: unknown) => {
    params.push(v);
    sets.push(`${col} = $${params.length}`);
  };
  if (typeof input.name === 'string' && input.name.trim()) set('name', input.name.trim().slice(0, 200));
  if (typeof input.url === 'string') {
    const url = input.url.trim();
    const why = urlRejection(url);
    if (why) throw new HuntError(400, why);
    set('url', url);
    sets.push('last_content_hash = NULL');
  }
  if (input.kind !== undefined) set('kind', cleanKind(input.kind));
  if (typeof input.enabled === 'boolean') set('enabled', input.enabled);
  if (input.check_interval_minutes !== undefined) set('check_interval_minutes', clampInterval(input.check_interval_minutes));
  if (input.lookback_days !== undefined) set('lookback_days', clampLookback(input.lookback_days));
  if (typeof input.alert_on_match === 'boolean') set('alert_on_match', input.alert_on_match);
  if (typeof input.use_ai === 'boolean') set('use_ai', input.use_ai);
  if (!sets.length) throw new HuntError(400, 'Nothing to change.');
  try {
    const r = await query(
      `UPDATE hunt_sources SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING ${PUBLIC_COLUMNS}`,
      params
    );
    return r.rows[0] || null;
  } catch (err) {
    if ((err as { code?: string }).code === '23505') throw new HuntError(409, 'That URL is already a source.');
    throw err;
  }
}

export async function deleteSource(id: number): Promise<boolean> {
  const r = await query(`DELETE FROM hunt_sources WHERE id = $1`, [id]);
  return (r.rowCount ?? 0) > 0;
}

function textOfHtml(html: string | null): string | null {
  if (!html) return null;
  return htmlToText(`<body>${html}</body>`).text || null;
}

export interface CheckResult {
  ok: boolean;
  kind?: 'feed' | 'page' | 'misp';
  hunts_created: number;
  error?: string;
}

/** Check one source now. Records the outcome on the source; never throws. */
export async function checkSource(id: number): Promise<CheckResult> {
  const source = await getSource(id);
  if (!source) return { ok: false, hunts_created: 0, error: 'Source not found' };
  let created = 0;
  try {
    const huntDefaults = {
      lookbackDays: source.lookback_days,
      alertOnMatch: source.alert_on_match,
      useAi: source.use_ai,
      sourceId: source.id,
      createdBy: source.created_by,
    };
    const counted = { created: 0 };
    const misp = async () => {
      await checkMispFeed(source, huntDefaults, counted);
      created = counted.created;
      await recordCheck(id, 'ok', null, source.last_content_hash, created);
      return { ok: true, kind: 'misp' as const, hunts_created: created };
    };
    if (source.kind === 'misp' || (source.kind === 'auto' && /\/manifest\.json$/i.test(new URL(source.url).pathname))) {
      return await misp();
    }

    const doc = await fetchDocument(source.url);
    const detected = documentKind(doc);
    if (
      source.kind === 'auto' &&
      (detected === 'misp-manifest' || (detected === 'html' && looksLikeMispFeedIndex(doc.body)))
    ) {
      return await misp();
    }
    const kind: 'feed' | 'page' =
      source.kind === 'feed' || (source.kind === 'auto' && detected === 'feed') ? 'feed' : 'page';

    if (kind === 'feed') {
      if (detected !== 'feed') throw new HuntError(422, 'The URL did not return an RSS or Atom feed.');
      const feed = await parseFeed(doc.body);
      const keys = feed.items.map((i) => i.key);
      const seenRows = keys.length
        ? await query(`SELECT item_key FROM hunt_source_items WHERE source_id = $1 AND item_key = ANY($2::text[])`, [
            id,
            keys,
          ])
        : { rows: [] };
      const seen = new Set(seenRows.rows.map((r: { item_key: string }) => r.item_key));
      const fresh = feed.items.filter((i) => !seen.has(i.key));
      const firstCheck = !source.last_checked_at;
      const toHunt = fresh.slice(0, firstCheck ? FIRST_CHECK_ITEMS : MAX_NEW_ITEMS_PER_CHECK);
      // On the first check, the older items are recorded as seen without a hunt.
      const skipped = firstCheck ? fresh.slice(FIRST_CHECK_ITEMS) : [];
      for (const item of toHunt) {
        const itemUrl = item.url ? new URL(item.url, doc.url).toString() : null;
        const content = textOfHtml(item.content);
        let huntId: number | null = null;
        if ((itemUrl && !urlRejection(itemUrl)) || (content && content.length >= 20)) {
          const hunt = await createHunt({
            origin: 'source',
            url: itemUrl,
            text: content,
            title: item.title,
            ...huntDefaults,
          });
          huntId = hunt.id;
          created++;
        }
        await query(
          `INSERT INTO hunt_source_items (source_id, item_key, item_url, title, published_at, hunt_id)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (source_id, item_key) DO NOTHING`,
          [id, item.key, itemUrl, item.title, item.published, huntId]
        );
      }
      await markSeen(
        id,
        skipped.map((i) => ({ key: i.key, url: i.url, title: i.title, published: i.published }))
      );
    } else {
      // A page: a new hunt when its indicators change.
      let fingerprint: string;
      let text: string | null = null;
      let title: string | null = null;
      if (detected === 'stix') {
        fingerprint = createHash('sha256').update(doc.body).digest('hex');
      } else {
        const page = detected === 'html' ? htmlToText(doc.body) : { title: null, text: doc.body };
        text = page.text;
        title = page.title;
        const found = extractIocs(page.text, {
          referenceDomains: [siteDomain(new URL(doc.url).hostname)],
          isTechnique: (t) => !!getTechnique(t),
        });
        if (!found.indicators.length) {
          await recordCheck(id, 'ok', null, source.last_content_hash, 0);
          return { ok: true, kind, hunts_created: 0 };
        }
        fingerprint = createHash('sha256')
          .update(found.indicators.map((i) => `${i.type}:${i.value}`).sort().join('\n'))
          .digest('hex');
      }
      if (fingerprint !== source.last_content_hash) {
        await createHunt({ origin: 'source', url: source.url, text, title, ...huntDefaults });
        created++;
      }
      await recordCheck(id, 'ok', null, fingerprint, created);
      return { ok: true, kind, hunts_created: created };
    }

    await recordCheck(id, 'ok', null, source.last_content_hash, created);
    return { ok: true, kind, hunts_created: created };
  } catch (err) {
    const message = ((err as Error)?.message || 'Check failed').slice(0, 500);
    await recordCheck(id, 'error', message, source.last_content_hash, created).catch(() => undefined);
    ErrorLogService.logBackgroundError('hunt-source', `${source.name}: ${message}`, { dedupeKey: `hunt-source-${id}` });
    logger.warn(`[HuntSources] ${source.name} check failed: ${message}`);
    return { ok: false, hunts_created: created, error: message };
  }
}

/** Record items as seen without a hunt, in bulk (a MISP feed's first check can skip thousands). */
async function markSeen(
  sourceId: number,
  items: Array<{ key: string; url: string | null; title: string | null; published: Date | null }>
): Promise<void> {
  for (let i = 0; i < items.length; i += 1000) {
    const chunk = items.slice(i, i + 1000);
    await query(
      `INSERT INTO hunt_source_items (source_id, item_key, item_url, title, published_at)
       SELECT $1, k, u, t, p FROM unnest($2::text[], $3::text[], $4::text[], $5::timestamptz[]) AS x(k, u, t, p)
       ON CONFLICT (source_id, item_key) DO NOTHING`,
      [
        sourceId,
        chunk.map((c) => c.key),
        chunk.map((c) => c.url),
        chunk.map((c) => c.title),
        chunk.map((c) => c.published),
      ]
    );
  }
}

/**
 * A MISP feed: read its manifest.json and start a hunt for each event not seen
 * before (the newest FIRST_CHECK_ITEMS on the first check, which marks the
 * rest seen; then up to MAX_NEW_ITEMS_PER_CHECK a check, newest first). Each
 * hunt reads the event file <uuid>.json (misp.ts parseMispEvent).
 */
async function checkMispFeed(
  source: HuntSource,
  huntDefaults: { lookbackDays: number; alertOnMatch: boolean; useAi: boolean; sourceId: number; createdBy: number | null },
  counted: { created: number }
): Promise<void> {
  const { base, manifest } = mispFeedUrls(source.url);
  const doc = await fetchDocument(manifest, undefined, { maxBytes: LARGE_FETCH_MAX_BYTES });
  let json: unknown;
  try {
    json = JSON.parse(doc.body);
  } catch {
    throw new HuntError(422, `${manifest} is not JSON, so this is not a MISP feed.`);
  }
  if (!isMispManifest(json)) throw new HuntError(422, `${manifest} is not a MISP feed manifest.`);
  const entries = parseMispManifest(json);
  const keys = entries.map((e) => e.uuid);
  const seenRows = keys.length
    ? await query(`SELECT item_key FROM hunt_source_items WHERE source_id = $1 AND item_key = ANY($2::text[])`, [
        source.id,
        keys,
      ])
    : { rows: [] };
  const seen = new Set(seenRows.rows.map((r: { item_key: string }) => r.item_key));
  const fresh = entries.filter((e) => !seen.has(e.uuid));
  const firstCheck = !source.last_checked_at;
  const toHunt = fresh.slice(0, firstCheck ? FIRST_CHECK_ITEMS : MAX_NEW_ITEMS_PER_CHECK);
  const published = (e: (typeof entries)[number]) =>
    e.timestamp > 0 ? new Date(e.timestamp * 1000) : e.date ? new Date(e.date) : null;

  for (const e of toHunt) {
    const eventUrl = `${base}${e.uuid}.json`;
    const hunt = await createHunt({
      origin: 'source',
      url: eventUrl,
      title: e.info || `MISP event ${e.uuid}`,
      ...huntDefaults,
    });
    counted.created++;
    await query(
      `INSERT INTO hunt_source_items (source_id, item_key, item_url, title, published_at, hunt_id)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (source_id, item_key) DO NOTHING`,
      [source.id, e.uuid, eventUrl, e.info, published(e), hunt.id]
    );
  }
  if (firstCheck) {
    await markSeen(
      source.id,
      fresh.slice(FIRST_CHECK_ITEMS).map((e) => ({ key: e.uuid, url: `${base}${e.uuid}.json`, title: e.info, published: published(e) }))
    );
  }
}

async function recordCheck(id: number, status: string, error: string | null, hash: string | null, created: number) {
  await query(
    `UPDATE hunt_sources
        SET last_checked_at = NOW(), last_status = $2, last_error = $3, last_content_hash = $4,
            hunts_created = hunts_created + $5, updated_at = NOW()
      WHERE id = $1`,
    [id, status, error, hash, created]
  );
}

/** Check every enabled source that is due. */
export async function checkDueSources(): Promise<{ checked: number; hunts_created: number }> {
  const due = await query(
    `SELECT id FROM hunt_sources
      WHERE enabled = true
        AND (last_checked_at IS NULL
             OR last_checked_at < NOW() - make_interval(mins => check_interval_minutes))
      ORDER BY last_checked_at NULLS FIRST, id`
  );
  let created = 0;
  for (const row of due.rows) created += (await checkSource(row.id)).hunts_created;
  return { checked: due.rows.length, hunts_created: created };
}
