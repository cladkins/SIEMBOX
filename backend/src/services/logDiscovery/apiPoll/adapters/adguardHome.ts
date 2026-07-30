// AdGuard Home adapter — pulls /control/querylog (newest-first), HTTP Basic
// auth. No catalog parser exists for adguard-home yet (catalog content is
// authored separately per CLAUDE.md), so rows land unparsed-but-stored in the
// meantime; the message format below is deliberately modeled on
// pihole-query.parser.json's so an adguard-home parser can reuse the same
// pattern when one is authored.
import crypto from 'crypto';
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch, basicAuthHeader } from '../httpFetch';

const PAGE_LIMIT = 500;

function buildBaseUrl(target: PollTarget): string {
  return `http://${target.ip}:3000`;
}

function synthesizeEventId(entry: any): string {
  return crypto
    .createHash('sha256')
    .update(`${entry.time}|${entry.client}|${entry.question?.name}|${entry.question?.type}`)
    .digest('hex')
    .slice(0, 16);
}

/** Maps one querylog entry to a pihole-query-style text format. Null for an entry with no usable `time`. */
export function mapEntry(e: any): PolledEvent | null {
  const time = typeof e?.time === 'string' ? e.time : null;
  if (!time) return null;
  return {
    message: `query[${e.question?.type ?? '?'}] ${e.question?.name ?? '?'} from ${e.client ?? '?'} reason=${e.reason ?? '?'}`,
    timestamp: new Date(time),
    eventId: synthesizeEventId(e),
  };
}

async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
  if (!credential.username) {
    throw new Error('AdGuard Home requires a username in addition to the password/token');
  }
  const endpoint = target.logAccess.endpoint || '/control/querylog';
  const url = `${buildBaseUrl(target)}${endpoint}?limit=${PAGE_LIMIT}`;

  const res = await httpFetch(url, { headers: { Authorization: basicAuthHeader(credential.username, credential.secret) } });
  if (res.status === 401) throw new Error('AdGuard Home rejected the credentials (HTTP 401)');
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from AdGuard Home querylog API`);

  let parsed: any;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    throw new Error('AdGuard Home querylog API returned non-JSON body');
  }
  const entries: any[] = Array.isArray(parsed?.data) ? parsed.data : [];

  const events: PolledEvent[] = [];
  let newestTime = cursor;
  for (const e of entries) {
    const time = typeof e.time === 'string' ? e.time : null;
    if (!time) continue;
    if (cursor && new Date(time) <= new Date(cursor)) continue; // querylog is newest-first; stop-worthy rows are simply skipped, not break'd, since order isn't guaranteed across every AdGuard version
    if (!newestTime || new Date(time) > new Date(newestTime)) newestTime = time;

    const mapped = mapEntry(e);
    if (mapped) events.push(mapped);
  }

  return { events, nextCursor: newestTime };
}

export const adguardHomeAdapter: ApiPollAdapter = {
  fingerprintId: 'adguard-home',
  fetchEvents,
};
