// Home Assistant adapter. Home Assistant serves its log at one of two places,
// depending on how it is installed:
//
// - GET /api/error_log returns the log FILE. Home Assistant registers the route
//   only while it writes one (homeassistant/components/api/__init__.py,
//   APIErrorLog, behind DATA_LOGGING). Container and Core installs do by default,
//   unless HA_DISABLE_LOG_FILE=true. Home Assistant OS and Supervised installs
//   log to the systemd journal instead and skip the file unless
//   HA_DUPLICATE_LOG_FILE is set (homeassistant/bootstrap.py). Without a file the
//   route doesn't exist and aiohttp answers 404.
// - GET /api/hassio/core/logs is Home Assistant's proxy to the Supervisor's
//   journal of the Core container, so it exists only under the Supervisor
//   (homeassistant/components/hassio/http.py). It forwards the query string and
//   the Range header (entries=cursor[[:num_skip]:num_entries]; the default is the
//   last 100 entries); ?no_colors strips the ANSI colours of the console log. The
//   answer is plain text, one record per line, in the same format as the file.
//
// Both are admin-only (require_admin / PATHS_ADMIN): a non-admin token gets 401.
//
// So /api/error_log is the first choice, and a 404 falls back to the Supervisor
// endpoint. Which one works is remembered per source, in the cursor, so a
// Supervisor install doesn't send a doomed request every poll; /api/error_log is
// re-probed every ERROR_LOG_REPROBE_MS and whenever the remembered endpoint
// fails. An endpoint the admin set in the source's settings is used alone.
//
// Neither endpoint filters by time, so new lines are found with a tail-window
// text cursor (selectNewLines). Lines reach the pipeline in Home Assistant's
// native format, which catalog/parsers/home-assistant.parser.json expects:
// /api/error_log verbatim, the Supervisor's lines without colour codes or a
// journal prefix (normalizeSupervisorLine).
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch, HttpFetchOptions, HttpFetchResult } from '../httpFetch';
import { urlHost } from '../urls';
import { PollError } from '../pollError';
import { stripAnsi } from '../../../syslog/syslogParser';

export const ERROR_LOG_ENDPOINT = '/api/error_log';
export const SUPERVISOR_LOG_ENDPOINT = '/api/hassio/core/logs';
/** Journal entries asked of the Supervisor per poll. More new lines than this between two polls leaves a gap. */
export const SUPERVISOR_LOG_ENTRIES = 500;
/** While on the Supervisor fallback, try /api/error_log again this often. */
export const ERROR_LOG_REPROBE_MS = 6 * 60 * 60 * 1000;

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
 * The tail window is the literal text of the last few lines already seen (not a
 * hash — a plain substring search is simpler to reason about and to inspect
 * in the DB while debugging, and does the same job). Finding that window in
 * the new response tells us where to resume. If it's not found (HA restarted
 * and truncated/rotated the buffer, or more lines arrived than the Supervisor
 * endpoint returns) or this is the first poll, fall back to a bounded tail so
 * one poll never floods the pipeline with the whole buffer. A small
 * duplicate/gap window across an HA restart is an accepted platform limitation
 * of this best-effort approach, not a bug to chase further — neither endpoint
 * gives us anything more precise to key off. Both endpoints carry the same
 * lines, so a window found on one is found on the other after a switch.
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

export function buildBaseUrl(target: PollTarget): string {
  // Default (scan-discovered source): HA's standard http://ip:8123. A manual
  // source, or an admin override, may change the port and/or switch to https;
  // absent both, this is byte-for-byte the previous http://ip:8123.
  const https = target.tls != null ? target.tls : false;
  const port = target.port ?? 8123;
  return `${https ? 'https' : 'http'}://${urlHost(target.ip)}:${port}`;
}

/**
 * True for a path served by the Supervisor proxy (…/api/hassio/…), which takes
 * ?no_colors and a Range header. Also true behind a reverse-proxy prefix
 * (/ha/api/hassio/core/logs).
 */
export function isSupervisorLogPath(path: string): boolean {
  return path.includes('/api/hassio/');
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/**
 * The poll cursor, stored as text in discovery_source_pollers.poll_cursor in
 * one of two formats:
 * - plain text: the tail window alone. Every cursor written before the
 *   Supervisor fallback existed has this form, and it is still what's written
 *   while /api/error_log (or an endpoint the admin set) works, so those
 *   sources keep exactly the cursor they had.
 * - JSON {"ha_log_endpoint":"supervisor","error_log_checked_at":<ISO>,"tail":…}:
 *   written only while the automatic fallback is in use.
 */
export interface HaCursor {
  /** The tail window: the last few lines already seen (see selectNewLines). */
  tail: string | null;
  /** Set while the automatic Supervisor fallback is in use: when /api/error_log last answered 404 (epoch ms). */
  errorLogCheckedAt: number | null;
}

const FALLBACK_MARKER = 'supervisor';

export function parseCursor(raw: string | null): HaCursor {
  if (!raw) return { tail: null, errorLogCheckedAt: null };
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      if (obj && typeof obj === 'object' && obj.ha_log_endpoint === FALLBACK_MARKER) {
        const checked = Date.parse(String(obj.error_log_checked_at));
        return {
          tail: typeof obj.tail === 'string' && obj.tail.length > 0 ? obj.tail : null,
          // Unreadable time: 0, so /api/error_log is re-probed on the next poll.
          errorLogCheckedAt: Number.isFinite(checked) ? checked : 0,
        };
      }
    } catch {
      // A plain-text tail window that happens to start with "{".
    }
  }
  return { tail: raw, errorLogCheckedAt: null };
}

export function serializeCursor(cursor: HaCursor): string | null {
  if (cursor.errorLogCheckedAt === null) return cursor.tail;
  return JSON.stringify({
    ha_log_endpoint: FALLBACK_MARKER,
    error_log_checked_at: new Date(cursor.errorLogCheckedAt).toISOString(),
    tail: cursor.tail,
  });
}

// ---------------------------------------------------------------------------
// Line format
// ---------------------------------------------------------------------------

// The Supervisor's verbose journal format (like `journalctl -o short`) puts
// "<time> <host> <identifier>[<pid>]: " in front of each record. It is never
// asked for here, but a record that arrives that way still reaches the parser
// as Home Assistant's own line.
const JOURNAL_PREFIX_RE = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})? \S+ [^\s:[\]]+(?:\[\d+\])?: /;

/**
 * One Supervisor log record as Home Assistant's native line: ANSI colour codes
 * removed (in case ?no_colors isn't honoured) and a verbose journal prefix
 * dropped when what follows it is a native line.
 */
export function normalizeSupervisorLine(line: string): string {
  const plain = stripAnsi(line);
  const prefix = JOURNAL_PREFIX_RE.exec(plain);
  if (prefix) {
    const rest = plain.slice(prefix[0].length);
    if (LINE_TIMESTAMP_RE.test(rest)) return rest;
  }
  return plain;
}

export function normalizeSupervisorLog(body: string): string {
  return body.split(/\r?\n/).map(normalizeSupervisorLine).join('\n');
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

interface LogResponse {
  /** The path requested, without the query string. */
  path: string;
  supervisor: boolean;
  res: HttpFetchResult;
}

function isOk(r: LogResponse): boolean {
  return r.res.status >= 200 && r.res.status < 300;
}

const FIX_IN_SETTINGS = "this source's settings (Log Discovery, Edit)";

function responseError(r: LogResponse, base: string, ctx: { configured?: boolean; fileMissingAt?: string } = {}): PollError {
  const status = r.res.status;
  const where = `HTTP ${status} from ${r.path}`;
  if (status === 401) {
    return new PollError(
      `Home Assistant rejected the token (${where}): it is invalid or revoked, or it belongs to a user who is not an administrator. Both log endpoints (${ERROR_LOG_ENDPOINT} and ${SUPERVISOR_LOG_ENDPOINT}) are admin-only. Create a long-lived access token while signed in as an administrator (Profile, Security tab) and replace the token in ${FIX_IN_SETTINGS}.`,
      {
        human: 'Home Assistant rejected the poll token',
        resolution: 'Replace the token with a long-lived access token created by a Home Assistant administrator',
        category: 'authentication',
      }
    );
  }
  if (status === 403) {
    return new PollError(
      `Home Assistant refused the request (${where}). It answers 403 to an address it has banned after failed logins (ip_bans.yaml in its config folder), and a reverse proxy may refuse it too. Remove SIEMBox's address from ip_bans.yaml, restart Home Assistant, then check the token.`,
      {
        human: "Home Assistant refused SIEMBox's poll",
        resolution: "Remove SIEMBox's address from Home Assistant's ip_bans.yaml and check the token",
        category: 'authentication',
      }
    );
  }
  if (status === 404 && ctx.fileMissingAt) {
    return new PollError(
      `Home Assistant at ${base} answered 404 for both log endpoints. ${ctx.fileMissingAt} exists only while Home Assistant writes a log file (not with HA_DISABLE_LOG_FILE=true, nor on Home Assistant OS/Supervised without HA_DUPLICATE_LOG_FILE); ${r.path} only on Home Assistant OS/Supervised. Check the port and any reverse-proxy path, then set the endpoint or address in ${FIX_IN_SETTINGS}.`,
      {
        human: 'Home Assistant has no log endpoint at the polled address',
        resolution: "Set the log endpoint or address in the source's settings (Log Discovery, Edit)",
        category: 'configuration',
      }
    );
  }
  if (status === 404 && ctx.configured) {
    return new PollError(
      `Home Assistant answered 404 for the configured endpoint ${r.path}. Use ${ERROR_LOG_ENDPOINT} on Container/Core installs or ${SUPERVISOR_LOG_ENDPOINT} on Home Assistant OS/Supervised (behind a reverse proxy, include its path prefix), or clear the endpoint in ${FIX_IN_SETTINGS} so SIEMBox finds it.`,
      {
        human: 'Home Assistant has no log at the configured endpoint',
        resolution: "Correct or clear the endpoint in the source's settings (Log Discovery, Edit)",
        category: 'configuration',
      }
    );
  }
  if (r.supervisor && (status === 502 || status === 503 || status === 504)) {
    return new PollError(
      `Home Assistant could not get its log from the Supervisor (${where}): the Supervisor or its journal service isn't answering. Check Settings, System, Repairs and the Supervisor log on the Home Assistant host; polling retries on the next cycle.`,
      {
        human: "Home Assistant's Supervisor did not return the log",
        resolution: "Check the Supervisor's health on the Home Assistant host",
        category: 'network',
      }
    );
  }
  return new PollError(`HTTP ${status} from Home Assistant ${r.path}`, {
    human: `Home Assistant answered HTTP ${status}`,
    resolution: 'Check that the address, port and endpoint point at Home Assistant',
    category: 'network',
  });
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export interface HomeAssistantAdapterDeps {
  /** Defaults to the real httpFetch; tests pass a fake. */
  fetch?: (url: string, opts?: HttpFetchOptions) => Promise<HttpFetchResult>;
  /** Defaults to Date.now; tests pass a fixed clock. */
  now?: () => number;
}

export function makeHomeAssistantAdapter(deps: HomeAssistantAdapterDeps = {}): ApiPollAdapter {
  const fetch = deps.fetch ?? httpFetch;
  const now = deps.now ?? Date.now;

  async function get(base: string, path: string, secret: string): Promise<LogResponse> {
    const supervisor = isSupervisorLogPath(path);
    const headers: Record<string, string> = { Authorization: `Bearer ${secret}` };
    let url = `${base}${path}`;
    if (supervisor) {
      // entries=cursor[[:num_skip]:num_entries]: from the end of the journal (no
      // cursor), back N-1 entries, N entries: the latest N, in the same form the
      // Supervisor uses for its own default. .../logs/latest ignores Range and
      // takes ?lines instead.
      headers.Range = `entries=:-${SUPERVISOR_LOG_ENTRIES - 1}:${SUPERVISOR_LOG_ENTRIES}`;
      url += path.endsWith('/latest') ? `?no_colors&lines=${SUPERVISOR_LOG_ENTRIES}` : '?no_colors';
    }
    return { path, supervisor, res: await fetch(url, { headers }) };
  }

  function toResult(r: LogResponse, base: string, prevTail: string | null, errorLogCheckedAt: number | null): PollFetchResult {
    // A web page instead of a log means the port or path reaches something else
    // (a reverse proxy's or another app's UI); its lines must not be ingested.
    if (/^\s*text\/html/i.test(String(r.res.headers['content-type'] || ''))) {
      throw new PollError(
        `${base}${r.path} returned a web page, not Home Assistant's log: the port or endpoint points at something else (another app or a reverse proxy page). Check them in ${FIX_IN_SETTINGS}.`,
        {
          human: 'The polled address returned a web page instead of a log',
          resolution: "Check the port and endpoint in the source's settings (Log Discovery, Edit)",
          category: 'configuration',
        }
      );
    }
    const text = r.supervisor ? normalizeSupervisorLog(r.res.body) : r.res.body;
    const { newLines, nextCursor: tail } = selectNewLines(text, prevTail);
    const events: PolledEvent[] = newLines.map((line) => ({
      message: line,
      timestamp: parseLineTimestamp(line),
      eventId: null, // the cursor is the sole dedup mechanism -- see selectNewLines' doc comment
    }));
    return { events, nextCursor: serializeCursor({ tail, errorLogCheckedAt }) };
  }

  async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
    const base = buildBaseUrl(target);
    const state = parseCursor(cursor);
    const secret = credential.secret;

    // An endpoint the admin set is used alone, never second-guessed.
    if (target.endpoint) {
      const r = await get(base, target.endpoint, secret);
      if (!isOk(r)) throw responseError(r, base, { configured: true });
      return toResult(r, base, state.tail, null);
    }

    const primary = target.logAccess.endpoint || ERROR_LOG_ENDPOINT;
    if (isSupervisorLogPath(primary)) {
      const r = await get(base, primary, secret);
      if (!isOk(r)) throw responseError(r, base);
      return toResult(r, base, state.tail, null);
    }

    // On the remembered fallback and /api/error_log isn't due a re-probe: go
    // straight to the Supervisor endpoint. If that fails, re-probe the file
    // endpoint before reporting it (Home Assistant may have moved to an install
    // that writes a log file).
    let rememberedFailure: LogResponse | null = null;
    if (state.errorLogCheckedAt !== null) {
      const age = now() - state.errorLogCheckedAt;
      if (age >= 0 && age < ERROR_LOG_REPROBE_MS) {
        const r = await get(base, SUPERVISOR_LOG_ENDPOINT, secret);
        if (isOk(r)) return toResult(r, base, state.tail, state.errorLogCheckedAt);
        rememberedFailure = r;
      }
    }

    const file = await get(base, primary, secret);
    if (isOk(file)) return toResult(file, base, state.tail, null); // (back) on the log file
    if (file.res.status !== 404) throw responseError(file, base);

    const supervisor = rememberedFailure ?? (await get(base, SUPERVISOR_LOG_ENDPOINT, secret));
    if (isOk(supervisor)) return toResult(supervisor, base, state.tail, now());
    throw responseError(supervisor, base, { fileMissingAt: primary });
  }

  function describeUrl(target: PollTarget, cursor: string | null): string {
    const base = buildBaseUrl(target);
    if (target.endpoint) return `${base}${target.endpoint}`;
    const primary = target.logAccess.endpoint || ERROR_LOG_ENDPOINT;
    if (isSupervisorLogPath(primary)) return `${base}${primary}`;
    // The endpoint in use: the Supervisor's while the fallback is remembered
    // (also between a due re-probe and the poll that does it).
    return `${base}${parseCursor(cursor).errorLogCheckedAt !== null ? SUPERVISOR_LOG_ENDPOINT : primary}`;
  }

  return { fingerprintId: 'home-assistant', fetchEvents, describeUrl };
}

export const homeAssistantAdapter: ApiPollAdapter = makeHomeAssistantAdapter();
