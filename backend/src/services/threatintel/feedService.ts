/**
 * External threat-feed service (Phase 4).
 *
 * Fetches free, no-auth IP blocklists, stores their indicators, and answers
 * "which feeds flag this IP?". Everything is best-effort: a feed that can't be
 * reached (blocked egress, 5xx, timeout) is recorded with last_status='error'
 * and last_error, and never throws out of the refresh loop.
 */

import { isIP } from 'net';
import pool, { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';

const FETCH_TIMEOUT_MS = 30_000;
const INSERT_BATCH = 1000;

export interface ThreatFeed {
  id: number;
  slug: string;
  name: string;
  description: string | null;
  category: string;
  url: string;
  format: string;
  enabled: boolean;
  refresh_interval_minutes: number;
  last_fetched_at: string | null;
  last_status: string | null;
  last_error: string | null;
  indicator_count: number;
}

export interface FeedMatch {
  slug: string;
  name: string;
  category: string;
}

async function fetchText(url: string): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'SIEMBox-ThreatFeeds/1.0' },
      redirect: 'follow',
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Parse a plain blocklist: one IP per line, '#'/';' comment lines ignored. Only
 * bare IPv4/IPv6 addresses are kept — CIDR ranges are skipped so lookups stay a
 * simple exact-match index probe (range matching would need a different model).
 */
export function parsePlainList(text: string): string[] {
  const out = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    // Some lists append columns (e.g. "1.2.3.4 # comment" or CSV); take col 1.
    const token = line.split(/[\s,]/)[0].trim();
    if (token && !token.includes('/') && isIP(token)) out.add(token);
  }
  return [...out];
}

export class FeedService {
  static async getFeeds(): Promise<ThreatFeed[]> {
    const r = await query(
      `SELECT id, slug, name, description, category, url, format, enabled,
              refresh_interval_minutes, last_fetched_at, last_status, last_error, indicator_count
         FROM threat_feeds ORDER BY category, name`
    );
    return r.rows;
  }

  static async getFeed(id: number): Promise<ThreatFeed | null> {
    const r = await query(`SELECT * FROM threat_feeds WHERE id = $1`, [id]);
    return r.rows[0] || null;
  }

  static async setFeedEnabled(id: number, enabled: boolean): Promise<ThreatFeed | null> {
    const r = await query(
      `UPDATE threat_feeds SET enabled = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id, enabled]
    );
    return r.rows[0] || null;
  }

  static async setRefreshInterval(id: number, minutes: number): Promise<ThreatFeed | null> {
    const clamped = Math.min(Math.max(Math.round(minutes), 15), 10080); // 15m .. 7d
    const r = await query(
      `UPDATE threat_feeds SET refresh_interval_minutes = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id, clamped]
    );
    return r.rows[0] || null;
  }

  /** Fetch + store one feed's indicators. Records status; never throws. */
  static async refreshFeed(id: number): Promise<{ ok: boolean; count: number; error?: string }> {
    const feed = await this.getFeed(id);
    if (!feed) return { ok: false, count: 0, error: 'Feed not found' };

    try {
      const text = await fetchText(feed.url);
      // Every seeded feed is a plain newline-delimited IP list today; parsePlainList
      // also tolerates the "IP <whitespace/comma> ..." shapes some lists use.
      const indicators = parsePlainList(text);

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM threat_indicators WHERE feed_id = $1', [id]);
        for (let i = 0; i < indicators.length; i += INSERT_BATCH) {
          const slice = indicators.slice(i, i + INSERT_BATCH);
          // $1 is feed_id (reused across every row tuple); $2.. are the indicators.
          const sql =
            `INSERT INTO threat_indicators (feed_id, indicator) VALUES ` +
            slice.map((_, j) => `($1, $${j + 2})`).join(', ') +
            ` ON CONFLICT (feed_id, indicator) DO NOTHING`;
          await client.query(sql, [id, ...slice]);
        }
        await client.query(
          `UPDATE threat_feeds
              SET last_fetched_at = NOW(), last_status = 'ok', last_error = NULL,
                  indicator_count = $2, updated_at = NOW()
            WHERE id = $1`,
          [id, indicators.length]
        );
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }

      logger.info(`[ThreatFeeds] ${feed.slug}: stored ${indicators.length} indicators`);
      return { ok: true, count: indicators.length };
    } catch (err: any) {
      const msg = (err?.name === 'AbortError' ? 'Fetch timed out' : err?.message || 'Refresh failed').slice(0, 500);
      await query(
        `UPDATE threat_feeds SET last_fetched_at = NOW(), last_status = 'error', last_error = $2, updated_at = NOW() WHERE id = $1`,
        [id, msg]
      );
      ErrorLogService.logBackgroundError('threat-feed', `${feed.slug}: ${msg}`, { dedupeKey: feed.slug });
      logger.warn(`[ThreatFeeds] ${feed.slug} refresh failed: ${msg}`);
      return { ok: false, count: 0, error: msg };
    }
  }

  /**
   * Refresh every enabled feed that is due (never fetched, or older than its
   * interval). With force=true, refresh all enabled feeds regardless of age.
   */
  static async refreshAllEnabled(force = false): Promise<{ refreshed: number }> {
    const due = await query(
      `SELECT id FROM threat_feeds
        WHERE enabled = true
          AND ($1 = true
               OR last_fetched_at IS NULL
               OR last_fetched_at < NOW() - (refresh_interval_minutes || ' minutes')::interval)
        ORDER BY id`,
      [force]
    );
    let refreshed = 0;
    for (const row of due.rows) {
      const r = await this.refreshFeed(row.id);
      if (r.ok) refreshed++;
    }
    return { refreshed };
  }

  /** Which enabled feeds currently flag this IP. */
  static async lookupIp(ip: string): Promise<FeedMatch[]> {
    if (!isIP(ip)) return [];
    const r = await query(
      `SELECT DISTINCT f.slug, f.name, f.category
         FROM threat_indicators ti
         JOIN threat_feeds f ON f.id = ti.feed_id
        WHERE ti.indicator = $1 AND f.enabled = true
        ORDER BY f.category`,
      [ip]
    );
    return r.rows;
  }
}
