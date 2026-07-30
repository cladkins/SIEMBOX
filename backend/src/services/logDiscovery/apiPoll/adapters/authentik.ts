// Authentik adapter — pulls /api/v3/events/events/ (Authentik's own audit-log
// API), maps each event into the JSON shape catalog/parsers/authentik-audit.parser.json
// expects (timestamp/event/user/ip/success/app), and emits it as raw_message.
//
// Assumption flagged for a future maintainer: pagination shape (`pagination.next`
// as a truthy "more pages" signal, `created__gte` as the incremental-fetch
// filter) is inferred from Authentik's documented API conventions, not verified
// against a live instance from this dev environment. The client-side
// `created > cursor` filter below is a deliberate backstop in case the
// server-side filter doesn't behave exactly as expected on some version — worth
// confirming against a real instance during the manual E2E pass.
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch } from '../httpFetch';

const MAX_PAGES_PER_TICK = 5;
const PAGE_SIZE = 100;
const FIRST_POLL_LOOKBACK_MS = 60 * 60 * 1000; // 1h — bounds the very first pull instead of fetching all history

function buildBaseUrl(target: PollTarget): string {
  // authentik.yaml signals 9443 (HTTPS, primary) and 9000 (HTTP, secondary).
  return target.openPorts.includes(9443) || !target.openPorts.includes(9000)
    ? `https://${target.ip}:9443`
    : `http://${target.ip}:9000`;
}

export function isFailure(action: string | undefined | null): boolean {
  return /fail|denied|invalid/i.test(action || '');
}

/**
 * Maps one Authentik event object to the JSON shape
 * catalog/parsers/authentik-audit.parser.json expects. Returns null for an
 * event with no usable `created` timestamp (shouldn't happen against a real
 * instance, but defensive against a malformed/partial API response).
 */
export function mapEvent(e: any): PolledEvent | null {
  const created = typeof e?.created === 'string' ? e.created : null;
  if (!created) return null;
  return {
    message: JSON.stringify({
      timestamp: created,
      event: e.action ?? 'unknown',
      user: e.user?.username ?? null,
      ip: e.client_ip ?? null,
      success: !isFailure(e.action),
      app: e.app ?? null,
    }),
    timestamp: new Date(created),
    eventId: typeof e.pk === 'string' ? e.pk : null,
  };
}

async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
  const baseUrl = buildBaseUrl(target);
  const since = cursor ? new Date(cursor) : new Date(Date.now() - FIRST_POLL_LOOKBACK_MS);
  const events: PolledEvent[] = [];
  let newestCreated = cursor;
  let page = 1;

  for (; page <= MAX_PAGES_PER_TICK; page++) {
    const url = `${baseUrl}${target.logAccess.endpoint || '/api/v3/events/events/'}?ordering=created&created__gte=${encodeURIComponent(
      since.toISOString()
    )}&page_size=${PAGE_SIZE}&page=${page}`;
    const res = await httpFetch(url, {
      headers: { Authorization: `Bearer ${credential.secret}`, Accept: 'application/json' },
      rejectUnauthorized: false,
    });
    if (res.status === 401 || res.status === 403) {
      throw new Error(`Authentik rejected the token (HTTP ${res.status})`);
    }
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`HTTP ${res.status} from Authentik events API`);
    }

    let parsed: any;
    try {
      parsed = JSON.parse(res.body);
    } catch {
      throw new Error('Authentik events API returned non-JSON body');
    }
    const results: any[] = Array.isArray(parsed?.results) ? parsed.results : [];

    for (const e of results) {
      // Backstop against imprecise/absent server-side created__gte filtering.
      if (cursor && typeof e.created === 'string' && new Date(e.created) <= new Date(cursor)) continue;
      const mapped = mapEvent(e);
      if (!mapped) continue;
      if (!newestCreated || (mapped.timestamp && mapped.timestamp > new Date(newestCreated))) {
        newestCreated = e.created;
      }
      events.push(mapped);
    }

    if (!parsed?.pagination?.next || results.length === 0) break;
  }

  return { events, nextCursor: newestCreated };
}

export const authentikAdapter: ApiPollAdapter = {
  fingerprintId: 'authentik',
  fetchEvents,
};
