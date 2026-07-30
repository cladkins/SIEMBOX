// Home Assistant adapter — pulls /api/error_log, which unlike Authentik's API
// has no time filter or pagination: it returns HA's entire current in-memory
// log buffer on every call. Lines are passed through verbatim to match
// catalog/parsers/home-assistant.parser.json's regex, which expects HA's
// native line format unmodified.
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch } from '../httpFetch';

const TAIL_WINDOW_LINES = 3;
const FIRST_POLL_FALLBACK_LINES = 200;
const LINE_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/;

export function parseLineTimestamp(line: string): Date | null {
  const m = LINE_TIMESTAMP_RE.exec(line);
  if (!m) return null;
  const d = new Date(m[1].replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? null : d;
}

function tailWindow(lines: string[]): string | null {
  if (lines.length === 0) return null;
  return lines.slice(-TAIL_WINDOW_LINES).join('\n');
}

/**
 * The cursor is the literal text of the last few lines already seen (not a
 * hash — a plain substring search is simpler to reason about and to inspect
 * in the DB while debugging, and does the same job). Finding that window in
 * the new response tells us where to resume. If it's not found (HA restarted
 * and truncated/rotated the buffer) or this is the first poll, fall back to a
 * bounded tail so one poll never floods the pipeline with the whole buffer.
 * A small duplicate/gap window across an HA restart is an accepted platform
 * limitation of this best-effort approach, not a bug to chase further —
 * /api/error_log gives us nothing more precise to key off.
 */
export function selectNewLines(fullText: string, cursor: string | null): { newLines: string[]; nextCursor: string | null } {
  const lines = fullText.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return { newLines: [], nextCursor: cursor };

  if (cursor) {
    const idx = fullText.indexOf(cursor);
    if (idx !== -1) {
      const afterText = fullText.slice(idx + cursor.length);
      const newLines = afterText.split(/\r?\n/).filter((l) => l.length > 0);
      return { newLines, nextCursor: tailWindow(lines) };
    }
  }

  const bounded = lines.slice(-FIRST_POLL_FALLBACK_LINES);
  return { newLines: bounded, nextCursor: tailWindow(lines) };
}

function buildBaseUrl(target: PollTarget): string {
  return `http://${target.ip}:8123`;
}

async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
  const url = `${buildBaseUrl(target)}${target.logAccess.endpoint || '/api/error_log'}`;
  const res = await httpFetch(url, { headers: { Authorization: `Bearer ${credential.secret}` } });
  if (res.status === 401) throw new Error('Home Assistant rejected the token (HTTP 401)');
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from Home Assistant error_log`);

  const { newLines, nextCursor } = selectNewLines(res.body, cursor);
  const events: PolledEvent[] = newLines.map((line) => ({
    message: line,
    timestamp: parseLineTimestamp(line),
    eventId: null, // cursor is the sole dedup mechanism -- see selectNewLines' doc comment
  }));

  return { events, nextCursor };
}

export const homeAssistantAdapter: ApiPollAdapter = {
  fingerprintId: 'home-assistant',
  fetchEvents,
};
