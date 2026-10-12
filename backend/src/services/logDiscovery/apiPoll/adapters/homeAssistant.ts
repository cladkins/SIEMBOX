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
// text cursor (selectNewLines). Only the end of a log is read: the last
// LOG_MAX_BYTES of the file (a byte Range request) and the Supervisor's latest
// journal entries. Lines reach the pipeline in Home Assistant's native format,
// which catalog/parsers/home-assistant.parser.json expects: /api/error_log
// verbatim, the Supervisor's lines without colour codes or a journal prefix
// (normalizeSupervisorLine).
import { ApiPollAdapter, PollCredential, PollFetchResult, PollTarget, PolledEvent } from '../types';
import { httpFetch, HttpFetchOptions, HttpFetchResult } from '../httpFetch';
import { urlHost } from '../urls';
import { PollError } from '../pollError';
import { stripAnsi } from '../../../syslog/syslogParser';

export const ERROR_LOG_ENDPOINT = '/api/error_log';
export const SUPERVISOR_LOG_ENDPOINT = '/api/hassio/core/logs';
/**
 * New journal entries asked of the Supervisor per poll. The request is for this
 * many plus windowReach() more (the previous poll's tail window), so the window
 * is in the answer whenever no more than this many lines arrived since.
 */
export const SUPERVISOR_LOG_ENTRIES = 500;
/**
 * Asked for instead (plus windowReach() more) when the window is not in that
 * answer (more new lines than SUPERVISOR_LOG_ENTRIES since; a login brute force
 * can do it): about 1 MB. More new lines than this between two polls leaves a
 * gap: the latest this many are collected and the poll reports a warning.
 */
export const SUPERVISOR_LOG_ENTRIES_WIDE = 5000;
/**
 * At most this much of a log is read per request: the END of the log file
 * (Range: bytes=-LOG_MAX_BYTES), and the newest part of any longer answer.
 * home-assistant.log only rotates when Home Assistant starts, so it can grow far
 * past this between restarts, and its newest lines are the ones wanted.
 */
export const LOG_MAX_BYTES = 5 * 1024 * 1024;
/** While on the Supervisor fallback, try /api/error_log again this often. */
export const ERROR_LOG_REPROBE_MS = 6 * 60 * 60 * 1000;

const TAIL_WINDOW_LINES = 3;
/**
 * How far back tailWindow looks for the last record's timestamped header line:
 * a last record up to this many lines (and MAX_RECORD_CHARS) is resumed after
 * exactly, however often it repeats.
 */
export const MAX_RECORD_LINES = 2000;
/** About 256 KB: the most text the tail window (stored as the cursor) holds for one record. */
export const MAX_RECORD_CHARS = 256 * 1024;
/** The window when no header is within that reach (a log not in Home Assistant's format, or a longer record): its last lines alone. */
export const MAX_TAIL_WINDOW_LINES = 100;
const FIRST_POLL_FALLBACK_LINES = 200;
const LINE_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/;

export function parseLineTimestamp(line: string): Date | null {
  const m = LINE_TIMESTAMP_RE.exec(line);
  if (!m) return null;
  const d = new Date(m[1].replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? null : d;
}

/** A log's lines, without empty ones. */
function splitLines(text: string): string[] {
  return text.split(/\r?\n/).filter((l) => l.length > 0);
}

/**
 * The tail window: the last lines already seen, from the start of the last
 * record (its timestamped header line) to the end, however long the record is
 * (up to MAX_RECORD_LINES and MAX_RECORD_CHARS); at least TAIL_WINDOW_LINES
 * lines. The header's millisecond timestamp is what makes the window unique. A
 * traceback that an integration logs again and again repeats its lines in every
 * copy, so a window of bare traceback lines would match the OLDEST copy in the
 * next answer, and everything after it would be taken as new on every poll.
 * Only when no header is within reach is the window the last
 * MAX_TAIL_WINDOW_LINES lines.
 */
function tailWindow(lines: string[]): string[] {
  const floor = Math.max(0, lines.length - MAX_RECORD_LINES);
  let chars = 0; // of the record's lines after its header
  for (let i = lines.length - 1; i >= floor; i--) {
    if (LINE_TIMESTAMP_RE.test(lines[i])) return lines.slice(Math.min(i, Math.max(0, lines.length - TAIL_WINDOW_LINES)));
    chars += lines[i].length + 1;
    if (chars > MAX_RECORD_CHARS) break;
  }
  return lines.slice(-MAX_TAIL_WINDOW_LINES);
}

/**
 * How many journal entries a Supervisor request needs beyond the new ones it
 * asks for, so that its answer holds the previous poll's tail window and the
 * next window can again start at its record's header: the window's own lines
 * when it holds a record's header; otherwise (no window yet, or one of bare
 * lines because its record began before the answer it came from, or is longer
 * than a window holds) as many as a record can have, MAX_RECORD_LINES.
 */
export function windowReach(prevTail: string | null): number {
  const window = prevTail ? splitLines(prevTail) : [];
  return window.some((line) => LINE_TIMESTAMP_RE.test(line)) ? window.length : MAX_RECORD_LINES;
}

/** The index just after the first place `window` appears in `lines` as consecutive whole lines, or -1. */
function indexAfterWindow(lines: string[], window: string[]): number {
  if (window.length === 0) return -1;
  for (let i = 0; i + window.length <= lines.length; i++) {
    let j = 0;
    while (j < window.length && lines[i + j] === window[j]) j++;
    if (j === window.length) return i + window.length;
  }
  return -1;
}

export interface NewLines {
  newLines: string[];
  nextCursor: string | null;
  /** True when a previous tail window was given but is not in this text: lines in between may be missing. */
  gap: boolean;
}

/**
 * The tail window is the literal text of the last lines already seen (not a
 * hash -- a plain comparison is simpler to reason about and to inspect in the
 * DB while debugging, and does the same job), matched as whole lines. Finding
 * it in the new response tells us where to resume. If it's not found (HA
 * restarted and started a new log file, or more lines arrived than one answer
 * holds) or this is the first poll, fall back to a bounded tail so one poll
 * never floods the pipeline with the whole buffer: the last `missLimit` lines
 * of an answer the window is not in (200 by default). For the Supervisor's
 * journal, which survives restarts, the caller passes the number of new lines
 * the answer was asked for beyond the window: a window that is missing from it
 * means more than that many arrived, so its latest that many are all new. A
 * small duplicate/gap window across an HA restart is an accepted platform
 * limitation of this best-effort approach, not a bug to chase further --
 * neither endpoint gives us anything more precise to key off. Both endpoints
 * carry the same lines, so a window found on one is found on the other after a
 * switch.
 */
export function selectNewLines(fullText: string, cursor: string | null, missLimit = FIRST_POLL_FALLBACK_LINES): NewLines {
  const lines = splitLines(fullText);
  if (lines.length === 0) return { newLines: [], nextCursor: cursor, gap: false };
  const nextCursor = tailWindow(lines).join('\n');

  if (cursor) {
    const after = indexAfterWindow(lines, splitLines(cursor));
    if (after !== -1) return { newLines: lines.slice(after), nextCursor, gap: false };
    return { newLines: lines.slice(-missLimit), nextCursor, gap: true };
  }
  return { newLines: lines.slice(-FIRST_POLL_FALLBACK_LINES), nextCursor, gap: false };
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
  /** For a Supervisor answer: the new entries it was asked for beyond the previous poll's tail window. */
  newEntries: number;
}

function isOk(r: LogResponse): boolean {
  return r.res.status >= 200 && r.res.status < 300;
}

/** A web page instead of a log: the port or path reaches something else (see toResult). */
function isWebPage(r: LogResponse): boolean {
  return /^\s*text\/html/i.test(String(r.res.headers['content-type'] || ''));
}

/**
 * True when the answer starts part-way through a line: the server sent a byte
 * range from past the start of the file (206, Content-Range "bytes N-.../..."
 * with N > 0), or a longer answer was cut to its last LOG_MAX_BYTES.
 */
function startsMidLine(r: LogResponse): boolean {
  if (r.res.truncated) return true;
  if (r.supervisor || r.res.status !== 206) return false;
  const range = /^bytes\s+(\d+)-/i.exec(String(r.res.headers['content-range'] || '').trim());
  return !range || Number(range[1]) > 0;
}

/**
 * An answer's log text: whole lines only, and a Supervisor answer as Home
 * Assistant's native lines. Home Assistant ends every record with a newline
 * (so does the Supervisor, every journal line), so a last line without one is
 * still being written: aiohttp sends the file up to its size when the request
 * came, which can fall in the middle of a record. That line is left for the
 * next poll, which reads it whole; taken now, it would be stored cut in two and
 * its completed form would not match the tail window.
 */
function logText(r: LogResponse): string {
  let body = r.res.body;
  if (startsMidLine(r)) {
    const newline = body.indexOf('\n');
    body = newline === -1 ? '' : body.slice(newline + 1);
  }
  body = body.slice(0, body.lastIndexOf('\n') + 1);
  return r.supervisor ? normalizeSupervisorLog(body) : body;
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

  /**
   * One request for the log at `path`. From the Supervisor: `newEntries` plus
   * `reach` entries (see windowReach), so the previous poll's tail window is in
   * the answer whenever no more than newEntries lines arrived since.
   */
  async function get(base: string, path: string, secret: string, newEntries: number, reach: number): Promise<LogResponse> {
    const supervisor = isSupervisorLogPath(path);
    const headers: Record<string, string> = { Authorization: `Bearer ${secret}` };
    let url = `${base}${path}`;
    if (supervisor) {
      // entries=cursor[[:num_skip]:num_entries]: from the end of the journal (no
      // cursor), back N-1 entries, N entries: the latest N, in the same form the
      // Supervisor uses for its own default. .../logs/latest ignores Range and
      // takes ?lines instead.
      const entries = newEntries + reach;
      headers.Range = `entries=:-${entries - 1}:${entries}`;
      url += path.endsWith('/latest') ? `?no_colors&lines=${entries}` : '?no_colors';
    } else {
      // The end of the log file. /api/error_log is aiohttp's FileResponse, which
      // answers 206 with just the last LOG_MAX_BYTES (no compression without an
      // Accept-Encoding). A server that ignores Range sends the whole file, and
      // httpFetch then keeps its end (keep: 'tail').
      headers.Range = `bytes=-${LOG_MAX_BYTES}`;
    }
    const opts: HttpFetchOptions = { headers, maxBytes: LOG_MAX_BYTES, keep: 'tail' };
    let res = await fetch(url, opts);
    if (!supervisor && res.status === 416) {
      // An empty file has no last bytes to send (aiohttp answers 416): ask for all of it.
      res = await fetch(url, { ...opts, headers: { Authorization: headers.Authorization } });
    }
    return { path, supervisor, res, newEntries };
  }

  /**
   * get(), and for the Supervisor's journal: when the previous poll's tail
   * window is not in the answer (more than SUPERVISOR_LOG_ENTRIES new lines
   * since), ask again for SUPERVISOR_LOG_ENTRIES_WIDE new ones before the lines
   * in between are given up. If that wider request fails, the first answer is used.
   */
  async function read(base: string, path: string, secret: string, prevTail: string | null): Promise<LogResponse> {
    const reach = windowReach(prevTail);
    const r = await get(base, path, secret, SUPERVISOR_LOG_ENTRIES, reach);
    if (!r.supervisor || !prevTail || !isOk(r) || isWebPage(r)) return r;
    if (!selectNewLines(logText(r), prevTail).gap) return r;
    try {
      const wide = await get(base, path, secret, SUPERVISOR_LOG_ENTRIES_WIDE, reach);
      if (isOk(wide) && !isWebPage(wide)) return wide;
    } catch {
      // Keep the first answer; its gap is reported by toResult.
    }
    return r;
  }

  function toResult(r: LogResponse, base: string, prevTail: string | null, errorLogCheckedAt: number | null): PollFetchResult {
    // A web page instead of a log means the port or path reaches something else
    // (a reverse proxy's or another app's UI); its lines must not be ingested.
    if (isWebPage(r)) {
      throw new PollError(
        `${base}${r.path} returned a web page, not Home Assistant's log: the port or endpoint points at something else (another app or a reverse proxy page). Check them in ${FIX_IN_SETTINGS}.`,
        {
          human: 'The polled address returned a web page instead of a log',
          resolution: "Check the port and endpoint in the source's settings (Log Discovery, Edit)",
          category: 'configuration',
        }
      );
    }
    // In the Supervisor's journal, which survives restarts, a previous tail that
    // is missing from an answer asked for it plus newEntries more means more
    // lines than that arrived: the latest newEntries are all new, and the lines
    // before them were not collected. In the log file it means a restart started
    // a new file: the bounded tail of selectNewLines.
    const { newLines, nextCursor: tail, gap } = selectNewLines(logText(r), prevTail, r.supervisor ? r.newEntries : undefined);
    const events: PolledEvent[] = newLines.map((line) => ({
      message: line,
      timestamp: parseLineTimestamp(line),
      eventId: null, // the cursor is the sole dedup mechanism -- see selectNewLines' doc comment
    }));
    const result: PollFetchResult = { events, nextCursor: serializeCursor({ tail, errorLogCheckedAt }) };
    if (gap && r.supervisor) {
      result.warning = `Home Assistant logged more lines since the last poll than its Supervisor returns at once (the ${events.length} collected now are the latest): the lines before them were not collected.`;
    }
    return result;
  }

  async function fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult> {
    const base = buildBaseUrl(target);
    const state = parseCursor(cursor);
    const secret = credential.secret;
    const readLog = (path: string) => read(base, path, secret, state.tail);

    // An endpoint the admin set is used alone, never second-guessed.
    if (target.endpoint) {
      const r = await readLog(target.endpoint);
      if (!isOk(r)) throw responseError(r, base, { configured: true });
      return toResult(r, base, state.tail, null);
    }

    const primary = target.logAccess.endpoint || ERROR_LOG_ENDPOINT;
    if (isSupervisorLogPath(primary)) {
      const r = await readLog(primary);
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
        const r = await readLog(SUPERVISOR_LOG_ENDPOINT);
        if (isOk(r)) return toResult(r, base, state.tail, state.errorLogCheckedAt);
        rememberedFailure = r;
      }
    }

    const file = await readLog(primary);
    if (isOk(file)) return toResult(file, base, state.tail, null); // (back) on the log file
    if (file.res.status !== 404) throw responseError(file, base);

    const supervisor = rememberedFailure ?? (await readLog(SUPERVISOR_LOG_ENDPOINT));
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
