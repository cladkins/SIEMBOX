// Pi-hole adapter — pulls /admin/api.php?getAllQueries. Auth is a QUERY PARAM
// (?auth=<token>), not a header, per Pi-hole's classic API — unlike every
// other adapter here. Maps rows to catalog/parsers/pihole-query.parser.json's
// expected "query[TYPE] domain from client" text format.
import crypto from 'crypto';
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch } from '../httpFetch';

const FIRST_POLL_LOOKBACK_SECONDS = 60 * 60; // 1h — bounds the very first pull

function buildBaseUrl(target: PollTarget): string {
  return `http://${target.ip}`;
}

function synthesizeEventId(row: unknown[]): string {
  // Classic Pi-hole API has no native per-query id; a hash of the row is a
  // stable-enough dedup key for overlapping poll windows.
  return crypto.createHash('sha256').update(row.join('|')).digest('hex').slice(0, 16);
}

/** Maps one getAllQueries row to catalog/parsers/pihole-query.parser.json's expected text format. Null for a row with no numeric timestamp. */
export function mapRow(row: unknown[]): PolledEvent | null {
  const tsRaw = Number(row[0]);
  if (!Number.isFinite(tsRaw)) return null;
  return {
    message: `query[${row[1]}] ${row[2]} from ${row[3]}`,
    timestamp: new Date(tsRaw * 1000),
    eventId: synthesizeEventId(row),
  };
}

async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
  const endpoint = target.logAccess.endpoint || '/admin/api.php';
  const sinceUnix = cursor ? Math.floor(new Date(cursor).getTime() / 1000) : Math.floor(Date.now() / 1000) - FIRST_POLL_LOOKBACK_SECONDS;
  const url = `${buildBaseUrl(target)}${endpoint}?getAllQueries&from=${sinceUnix}&auth=${encodeURIComponent(credential.secret)}`;

  const res = await httpFetch(url);
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from Pi-hole API`);

  let parsed: any;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    throw new Error('Pi-hole API returned non-JSON body');
  }
  // Wrong/missing auth on a privileged classic-API call doesn't 401 -- it
  // silently returns {} with no "data" key, so that's treated as the error case.
  if (!Array.isArray(parsed?.data)) {
    throw new Error('Pi-hole API returned no data — check the API token');
  }

  const events: PolledEvent[] = [];
  let newestUnix = sinceUnix;
  for (const row of parsed.data as unknown[][]) {
    const tsRaw = Number(row[0]);
    if (!Number.isFinite(tsRaw)) continue;
    if (cursor && tsRaw <= sinceUnix) continue; // backstop against imprecise/absent server-side from= filtering
    if (tsRaw > newestUnix) newestUnix = tsRaw;

    const mapped = mapRow(row);
    if (mapped) events.push(mapped);
  }

  return { events, nextCursor: new Date(newestUnix * 1000).toISOString() };
}

export const piholeAdapter: ApiPollAdapter = {
  fingerprintId: 'pihole',
  fetchEvents,
};
