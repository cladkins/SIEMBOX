/**
 * Home Assistant adapter: the tail-window cursor, and fetching from either of
 * Home Assistant's log endpoints — /api/error_log (log file; Container/Core) or
 * the Supervisor's /api/hassio/core/logs (Home Assistant OS/Supervised) — with
 * the automatic fallback, the remembered endpoint, its re-probe, admin-set
 * endpoints, cursor backward compatibility, the error messages, and the lines
 * reaching the real catalog parser unmodified. HTTP is a fake recording every
 * request; nothing here touches the network. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import {
  selectNewLines,
  parseLineTimestamp,
  makeHomeAssistantAdapter,
  normalizeSupervisorLine,
  parseCursor,
  serializeCursor,
  ERROR_LOG_REPROBE_MS,
  MAX_TAIL_WINDOW_LINES,
  MAX_RECORD_LINES,
  MAX_RECORD_CHARS,
  SUPERVISOR_LOG_ENTRIES_WIDE,
  LEGACY_CUT_CHARS,
  LOG_MAX_BYTES,
  windowReach,
  windowReadBytes,
} from './homeAssistant';
import { HttpFetchOptions, HttpFetchResult } from '../httpFetch';
import { PollTarget } from '../types';
import { PollError } from '../pollError';
import { runParser, ParserDef } from '../../../parser/runParser';

const LINE1 = '2024-01-15 12:00:00.001 INFO (MainThread) [homeassistant.core] Starting Home Assistant';
const LINE2 = '2024-01-15 12:00:01.002 WARNING (MainThread) [homeassistant.components.http.ban] Banned IP 203.0.113.5';
const LINE3 = '2024-01-15 12:00:02.003 INFO (MainThread) [homeassistant.core] Home Assistant initialized';
const LINE4 = '2024-01-15 12:00:03.004 INFO (MainThread) [homeassistant.core] Some later event';

test('selectNewLines with no cursor (first poll) returns a bounded tail, not the whole buffer', () => {
  const manyLines = Array.from({ length: 300 }, (_, i) => `2024-01-15 12:00:00.${i} INFO (MainThread) [x] line ${i}`);
  const { newLines, nextCursor } = selectNewLines(manyLines.join('\n'), null);
  assert.equal(newLines.length, 200);
  assert.equal(newLines[newLines.length - 1], manyLines[manyLines.length - 1]);
  assert.equal(nextCursor, manyLines.slice(-3).join('\n'));
});

test('selectNewLines finds the cursor window and returns only lines after it', () => {
  const cursor = [LINE1, LINE2, LINE3].join('\n'); // a prior poll's tail-of-3
  const fullText = [LINE1, LINE2, LINE3, LINE4].join('\n');
  const { newLines, nextCursor } = selectNewLines(fullText, cursor);
  assert.deepEqual(newLines, [LINE4]);
  assert.equal(nextCursor, [LINE2, LINE3, LINE4].join('\n'));
});

test('selectNewLines falls back to a bounded tail when the cursor window is not found (buffer reset)', () => {
  const staleCursor = 'some line that no longer exists\nanother stale line\nand a third';
  const fullText = [LINE1, LINE2, LINE3, LINE4].join('\n');
  const { newLines } = selectNewLines(fullText, staleCursor);
  assert.deepEqual(newLines, [LINE1, LINE2, LINE3, LINE4]); // fewer than 200 lines total, so the whole (small) buffer
});

test('selectNewLines returns nothing new when the cursor is the whole buffer (no new lines yet)', () => {
  const fullText = [LINE1, LINE2, LINE3].join('\n');
  const cursor = [LINE1, LINE2, LINE3].join('\n');
  const { newLines } = selectNewLines(fullText, cursor);
  assert.deepEqual(newLines, []);
});

test('parseLineTimestamp extracts HA\'s native leading timestamp', () => {
  const ts = parseLineTimestamp(LINE2);
  assert.ok(ts);
  assert.equal(ts!.toISOString(), '2024-01-15T12:00:01.002Z');
});

test('parseLineTimestamp returns null for a line with no leading timestamp', () => {
  assert.equal(parseLineTimestamp('not a log line'), null);
});

// ---------------------------------------------------------------------------
// Fetching: fallback, remembered endpoint, re-probe, admin-set endpoints
// ---------------------------------------------------------------------------

// Real Home Assistant core log lines (the format of home-assistant.log and of
// the Supervisor's core journal), including a traceback and an s6 line, which
// carry no leading timestamp.
const HA_LINES = [
  '2026-10-12 14:02:57.913 INFO (MainThread) [homeassistant.bootstrap] Home Assistant initialized in 12.31s',
  '2026-10-12 14:02:58.120 INFO (MainThread) [homeassistant.setup] Setting up http',
  "2026-10-12 14:03:10.004 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from 192.168.1.77 (192.168.1.77). Requested URL: '/auth/login_flow/2f1c'. (Mozilla/5.0 (X11; Linux x86_64))",
  '2026-10-12 14:03:11.482 WARNING (MainThread) [homeassistant.components.http.ban] Banned IP 192.168.1.77 for too many login attempts',
  '2026-10-12 14:03:12.001 ERROR (MainThread) [homeassistant.components.mqtt.client] Failed to connect to MQTT server due to exception: [Errno 111] Connection refused',
  'Traceback (most recent call last):',
  '  File "/usr/src/homeassistant/homeassistant/components/mqtt/client.py", line 712, in _async_connect',
  's6-rc: info: service legacy-services successfully started',
];
const LATER_LINES = [
  '2026-10-12 14:05:00.250 INFO (MainThread) [homeassistant.components.automation.porch] Porch light: Running automation actions',
  "2026-10-12 14:05:02.700 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from 203.0.113.9 (203.0.113.9). Requested URL: '/api/states'. (curl/8.5.0)",
];

const ESC = '\u001b';
/** How the Supervisor journal carries a line when ?no_colors is not honoured: colorlog's ANSI colours. */
function colored(line: string): string {
  const color = line.includes(' ERROR ') ? '31' : line.includes(' WARNING ') ? '33' : '32';
  return /^\d{4}-/.test(line) ? `${ESC}[${color}m${line}${ESC}[0m` : line;
}

const T0 = Date.parse('2026-10-12T14:10:00Z');
const FILE = '/api/error_log';
const SUPERVISOR = '/api/hassio/core/logs';
/** The byte Range a first poll (no tail window yet) asks of the log file: its last 5 MB. */
const FILE_RANGE = 'bytes=-5242880';
/**
 * The byte Range a poll that resumes after HA_TAIL asks for: the last 5 MB plus
 * the window (357 bytes as stored, 3 per line for its 4 lines, and 2).
 */
const FILE_RANGE_AFTER_HA_TAIL = 'bytes=-5243251';
/**
 * A first poll of the Supervisor's journal (no tail window yet): 500 new
 * entries plus MAX_RECORD_LINES (2000), so the window can start at the last
 * record's header however long the record is.
 */
const FIRST_RANGE = 'entries=:-2499:2500';
/** The cursor after HA_LINES: its last record, from that record's header line (the MQTT ERROR) to the end. */
const HA_TAIL = HA_LINES.slice(-4).join('\n');

interface Call {
  url: string;
  headers: Record<string, string>;
}
type Reply = {
  status: number;
  body?: string;
  contentType?: string;
  headers?: Record<string, string>;
  truncated?: boolean;
  /** Send the body exactly as given, even without a final newline (a record caught while it is being written). */
  unterminated?: boolean;
};
/** A fixed reply, or one worked out from the request's headers. */
type Route = Reply | ((headers: Record<string, string>) => Reply);

/**
 * A fake Home Assistant: answers per path (404 for anything unlisted) and
 * records every request. Like Home Assistant's log file and the Supervisor's
 * journal lines, a body ends with a newline (one is added where a test's text
 * has none), unless the reply is `unterminated`.
 */
function fakeHomeAssistant(routes: Record<string, Route>) {
  const calls: Call[] = [];
  const fetch = async (url: string, opts: HttpFetchOptions = {}): Promise<HttpFetchResult> => {
    const headers = { ...(opts.headers || {}) };
    calls.push({ url, headers });
    const route = routes[new URL(url).pathname];
    const reply = (typeof route === 'function' ? route(headers) : route) ?? { status: 404, body: '404: Not Found' };
    const body = reply.body ?? '';
    return {
      status: reply.status,
      body: reply.unterminated || body === '' || body.endsWith('\n') ? body : `${body}\n`,
      headers: { 'content-type': reply.contentType ?? 'text/plain; charset=utf-8', ...(reply.headers || {}) },
      truncated: reply.truncated,
    };
  };
  return { fetch, calls, paths: () => calls.map((c) => new URL(c.url).pathname) };
}

/** A scan-discovered Home Assistant source: no overrides, the fingerprint's api_pull entry. */
function target(over: Partial<PollTarget> = {}): PollTarget {
  return {
    sourceId: 94,
    ip: '192.168.1.50',
    openPorts: [8123],
    evidence: {},
    logAccess: { method: 'api_pull', endpoint: FILE, auth: 'bearer_token', target_port: 8123 },
    ...over,
  };
}

const CRED = { username: null, secret: 'llat-token' };

function adapterAt(now: number, fake: ReturnType<typeof fakeHomeAssistant>) {
  return makeHomeAssistantAdapter({ fetch: fake.fetch, now: () => now });
}

function messages(result: { events: Array<{ message: string }> }): string[] {
  return result.events.map((e) => e.message);
}

test('auto: /api/error_log answers -> one request, the exact URL as before, a byte Range for the end of the file, lines verbatim, plain-text cursor', async () => {
  const ha = fakeHomeAssistant({ [FILE]: { status: 200, body: HA_LINES.join('\n') + '\n' } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, null);

  assert.equal(ha.calls.length, 1);
  assert.equal(ha.calls[0].url, 'http://192.168.1.50:8123/api/error_log');
  assert.deepEqual(ha.calls[0].headers, { Authorization: 'Bearer llat-token', Range: FILE_RANGE });
  assert.deepEqual(messages(result), HA_LINES);
  assert.equal(result.nextCursor, HA_TAIL, 'the cursor keeps its plain-text tail-window form');
});

test('auto: a 404 from /api/error_log falls back to the Supervisor endpoint (no_colors; a first poll asks for 500 entries plus the longest record)', async () => {
  const ha = fakeHomeAssistant({
    [FILE]: { status: 404, body: '404: Not Found' },
    [SUPERVISOR]: { status: 200, body: HA_LINES.map(colored).join('\n') },
  });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, null);

  assert.deepEqual(ha.paths(), [FILE, SUPERVISOR]);
  assert.equal(ha.calls[1].url, 'http://192.168.1.50:8123/api/hassio/core/logs?no_colors');
  assert.deepEqual(ha.calls[1].headers, { Authorization: 'Bearer llat-token', Range: FIRST_RANGE });
  assert.deepEqual(messages(result), HA_LINES, 'native lines: colour codes removed, nothing else changed');
  assert.ok(result.events.every((e) => !e.message.includes(ESC)));

  const cursor = JSON.parse(result.nextCursor!);
  assert.deepEqual(cursor, {
    ha_log_endpoint: 'supervisor',
    error_log_checked_at: new Date(T0).toISOString(),
    tail: HA_TAIL,
  });
});

test('remembered fallback: the next poll asks only the Supervisor endpoint and returns only the new lines', async () => {
  const first = fakeHomeAssistant({ [SUPERVISOR]: { status: 200, body: HA_LINES.map(colored).join('\n') } });
  const { nextCursor } = await adapterAt(T0, first).fetchEvents(target(), CRED, null);

  const ha = fakeHomeAssistant({
    [FILE]: { status: 404 },
    [SUPERVISOR]: { status: 200, body: [...HA_LINES, ...LATER_LINES].map(colored).join('\n') },
  });
  const result = await adapterAt(T0 + 60 * 60 * 1000, ha).fetchEvents(target(), CRED, nextCursor);

  assert.deepEqual(ha.paths(), [SUPERVISOR], 'no doomed /api/error_log request');
  assert.equal(ha.calls[0].headers.Range, 'entries=:-503:504', '500 new entries plus the 4 lines of the tail window');
  assert.deepEqual(messages(result), LATER_LINES);
  const cursor = parseCursor(result.nextCursor);
  assert.equal(cursor.errorLogCheckedAt, T0, 'the re-probe clock is not reset by a normal poll');
  assert.equal(cursor.tail, [...HA_LINES, ...LATER_LINES].slice(-3).join('\n'));
});

test('re-probe: once ERROR_LOG_REPROBE_MS has passed /api/error_log is tried first; a 404 keeps the fallback and restarts the clock', async () => {
  const cursor = serializeCursor({ tail: HA_LINES.slice(-3).join('\n'), errorLogCheckedAt: T0 });
  const later = T0 + ERROR_LOG_REPROBE_MS + 1;
  const ha = fakeHomeAssistant({
    [FILE]: { status: 404 },
    [SUPERVISOR]: { status: 200, body: [...HA_LINES, ...LATER_LINES].join('\n') },
  });
  const result = await adapterAt(later, ha).fetchEvents(target(), CRED, cursor);

  assert.deepEqual(ha.paths(), [FILE, SUPERVISOR]);
  assert.deepEqual(messages(result), LATER_LINES);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, later);
});

test('re-probe: /api/error_log answers again -> back on the file endpoint, plain cursor, no duplicates', async () => {
  const cursor = serializeCursor({ tail: HA_LINES.slice(-3).join('\n'), errorLogCheckedAt: T0 });
  const ha = fakeHomeAssistant({
    [FILE]: { status: 200, body: [...HA_LINES, ...LATER_LINES].join('\n') + '\n' },
    [SUPERVISOR]: { status: 200, body: '' },
  });
  const result = await adapterAt(T0 + ERROR_LOG_REPROBE_MS, ha).fetchEvents(target(), CRED, cursor);

  assert.deepEqual(ha.paths(), [FILE]);
  assert.deepEqual(messages(result), LATER_LINES, 'the tail window from the journal is found in the file');
  assert.equal(result.nextCursor, [...HA_LINES, ...LATER_LINES].slice(-3).join('\n'));
});

test('a fallback time in the future (clock change) does not postpone the re-probe', async () => {
  const cursor = serializeCursor({ tail: null, errorLogCheckedAt: T0 + 24 * 60 * 60 * 1000 });
  const ha = fakeHomeAssistant({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 200, body: HA_LINES[0] } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, cursor);
  assert.deepEqual(ha.paths(), [FILE, SUPERVISOR]);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, T0);
});

test('remembered endpoint fails: /api/error_log is re-probed at once, and its 404 reports the Supervisor failure (no second Supervisor request)', async () => {
  const cursor = serializeCursor({ tail: 'x', errorLogCheckedAt: T0 });
  const ha = fakeHomeAssistant({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 502, body: '502: Bad Gateway' } });

  await assert.rejects(adapterAt(T0 + 1000, ha).fetchEvents(target(), CRED, cursor), (err: unknown) => {
    assert.ok(err instanceof PollError);
    assert.match(err.message, /could not get its log from the Supervisor \(HTTP 502 from \/api\/hassio\/core\/logs\)/);
    return true;
  });
  assert.deepEqual(ha.paths(), [SUPERVISOR, FILE]);
});

test('remembered endpoint fails but /api/error_log now works (HA moved to a Container install) -> switches back', async () => {
  const cursor = serializeCursor({ tail: HA_LINES.slice(-3).join('\n'), errorLogCheckedAt: T0 });
  const ha = fakeHomeAssistant({
    [FILE]: { status: 200, body: [...HA_LINES, ...LATER_LINES].join('\n') },
    [SUPERVISOR]: { status: 404 },
  });
  const result = await adapterAt(T0 + 1000, ha).fetchEvents(target(), CRED, cursor);

  assert.deepEqual(ha.paths(), [SUPERVISOR, FILE]);
  assert.deepEqual(messages(result), LATER_LINES);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, null, 'the fallback is forgotten');
});

test('an admin-set /api/error_log is used alone: its 404 is reported without trying the Supervisor endpoint', async () => {
  const ha = fakeHomeAssistant({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 200, body: HA_LINES.join('\n') } });
  await assert.rejects(adapterAt(T0, ha).fetchEvents(target({ endpoint: FILE }), CRED, null), (err: unknown) => {
    assert.ok(err instanceof PollError);
    assert.match(err.message, /404 for the configured endpoint \/api\/error_log/);
    assert.match(err.message, /clear the endpoint/);
    return true;
  });
  assert.deepEqual(ha.paths(), [FILE]);
});

test('an admin-set Supervisor endpoint is requested directly (no_colors + Range), never /api/error_log, and keeps a plain cursor', async () => {
  const ha = fakeHomeAssistant({ [SUPERVISOR]: { status: 200, body: HA_LINES.map(colored).join('\n') } });
  const result = await adapterAt(T0, ha).fetchEvents(target({ endpoint: SUPERVISOR, port: 443, tls: true }), CRED, null);

  assert.deepEqual(ha.paths(), [SUPERVISOR]);
  assert.equal(ha.calls[0].url, 'https://192.168.1.50:443/api/hassio/core/logs?no_colors');
  assert.equal(ha.calls[0].headers.Range, FIRST_RANGE);
  assert.deepEqual(messages(result), HA_LINES);
  assert.equal(result.nextCursor, HA_TAIL);
});

test('an admin-set path behind a reverse proxy keeps its prefix; .../logs/latest gets ?lines (it ignores Range)', async () => {
  const proxied = fakeHomeAssistant({ '/ha/api/hassio/core/logs': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, proxied).fetchEvents(target({ endpoint: '/ha/api/hassio/core/logs' }), CRED, null);
  assert.equal(proxied.calls[0].url, 'http://192.168.1.50:8123/ha/api/hassio/core/logs?no_colors');
  assert.equal(proxied.calls[0].headers.Range, FIRST_RANGE);

  const latest = fakeHomeAssistant({ '/api/hassio/core/logs/latest': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, latest).fetchEvents(target({ endpoint: '/api/hassio/core/logs/latest' }), CRED, null);
  assert.equal(latest.calls[0].url, 'http://192.168.1.50:8123/api/hassio/core/logs/latest?no_colors&lines=2500');

  const file = fakeHomeAssistant({ '/homeassistant/api/error_log': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, file).fetchEvents(target({ endpoint: '/homeassistant/api/error_log' }), CRED, null);
  assert.deepEqual(
    file.calls[0].headers,
    { Authorization: 'Bearer llat-token', Range: FILE_RANGE },
    'a file path gets a byte Range for the end of the file, not journal entries'
  );
});

// ---------------------------------------------------------------------------
// Cursor backward compatibility
// ---------------------------------------------------------------------------

test('a plain-text cursor written before the fallback existed keeps working on /api/error_log', async () => {
  const legacy = HA_LINES.slice(-3).join('\n');
  const ha = fakeHomeAssistant({ [FILE]: { status: 200, body: [...HA_LINES, ...LATER_LINES].join('\n') } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, legacy);
  assert.deepEqual(messages(result), LATER_LINES);
  assert.equal(result.nextCursor, [...HA_LINES, ...LATER_LINES].slice(-3).join('\n'));
});

test('a plain-text cursor carries over to the Supervisor fallback without duplicates', async () => {
  const legacy = HA_LINES.slice(-3).join('\n');
  const ha = fakeHomeAssistant({
    [FILE]: { status: 404 },
    [SUPERVISOR]: { status: 200, body: [...HA_LINES, ...LATER_LINES].map(colored).join('\n') },
  });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, legacy);
  assert.deepEqual(messages(result), LATER_LINES);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, T0);
});

test('parseCursor: a plain tail that starts with "{" stays a tail; a fallback cursor with an unreadable time is due a re-probe', () => {
  assert.deepEqual(parseCursor('{"not":"ours"}\nline 2\nline 3'), { tail: '{"not":"ours"}\nline 2\nline 3', errorLogCheckedAt: null });
  assert.deepEqual(parseCursor('{broken json'), { tail: '{broken json', errorLogCheckedAt: null });
  assert.deepEqual(parseCursor(null), { tail: null, errorLogCheckedAt: null });
  assert.deepEqual(parseCursor('{"ha_log_endpoint":"supervisor","error_log_checked_at":"garbage","tail":"t"}'), {
    tail: 't',
    errorLogCheckedAt: 0,
  });
  // Round trip; and without the fallback the cursor is just the tail (null stays null).
  const c = { tail: 'a\nb\nc', errorLogCheckedAt: T0 };
  assert.deepEqual(parseCursor(serializeCursor(c)), c);
  assert.equal(serializeCursor({ tail: 'a\nb\nc', errorLogCheckedAt: null }), 'a\nb\nc');
  assert.equal(serializeCursor({ tail: null, errorLogCheckedAt: null }), null);
});

test('the fallback is remembered even when the journal is empty, so the next poll still skips /api/error_log', async () => {
  const ha = fakeHomeAssistant({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 200, body: '' } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, null);
  assert.deepEqual(result.events, []);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, T0);
});

// ---------------------------------------------------------------------------
// The tail window: repeated tracebacks, whole lines, long records
// ---------------------------------------------------------------------------

/** One copy of an error an integration logs every minute: its header line, then the same traceback each time. */
function repeatedError(minute: number): string[] {
  return [
    `2026-10-12 13:${String(minute).padStart(2, '0')}:00.123 ERROR (MainThread) [homeassistant.components.foo] Error doing job: Task exception was never retrieved`,
    'Traceback (most recent call last):',
    '  File "/usr/src/homeassistant/homeassistant/components/foo/__init__.py", line 100, in async_update',
    '    await self._fetch()',
    '  File "/usr/src/homeassistant/homeassistant/components/foo/api.py", line 50, in _fetch',
    '    raise FooError("boom")',
    'foo.FooError: boom',
  ];
}

/** `minutes` copies of repeatedError: a log that ends with the traceback, whose last lines are in every copy. */
function repeatingLog(minutes: number): string[] {
  return Array.from({ length: minutes }, (_, m) => repeatedError(m)).flat();
}

const LATER_INFO = '2026-10-12 14:00:30.500 INFO (MainThread) [homeassistant.components.automation.porch] Porch light: Running automation actions';

test('a traceback logged again and again: the next poll of the log file returns only the new lines, not every copy since the first', async () => {
  const log = repeatingLog(50); // 350 lines
  const first = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: log.join('\n') } })).fetchEvents(target(), CRED, null);
  assert.equal(first.events.length, 200, 'the first poll is bounded');
  assert.equal(first.nextCursor, repeatedError(49).join('\n'), 'the window is the last record, from its timestamped header');

  const unchanged = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: log.join('\n') } })).fetchEvents(
    target(),
    CRED,
    first.nextCursor
  );
  assert.deepEqual(messages(unchanged), [], 'nothing new: nothing returned');

  const grown = [...log, LATER_INFO, ...repeatedError(51)];
  const next = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: grown.join('\n') } })).fetchEvents(
    target(),
    CRED,
    unchanged.nextCursor
  );
  assert.deepEqual(messages(next), [LATER_INFO, ...repeatedError(51)]);
});

test('a traceback logged again and again: the same on the Supervisor journal', async () => {
  const journal = repeatingLog(60); // 420 lines, under the 500 entries asked for
  const answer = () => ({ status: 200, body: journal.map(colored).join('\n') });
  const first = await adapterAt(T0, fakeHomeAssistant({ [SUPERVISOR]: answer })).fetchEvents(target(), CRED, null);
  assert.equal(parseCursor(first.nextCursor).tail, repeatedError(59).join('\n'));

  const unchanged = await adapterAt(T0 + 60_000, fakeHomeAssistant({ [SUPERVISOR]: answer })).fetchEvents(target(), CRED, first.nextCursor);
  assert.deepEqual(messages(unchanged), []);

  journal.push(LATER_INFO, ...repeatedError(61));
  const ha = fakeHomeAssistant({ [SUPERVISOR]: answer });
  const next = await adapterAt(T0 + 120_000, ha).fetchEvents(target(), CRED, unchanged.nextCursor);
  assert.deepEqual(messages(next), [LATER_INFO, ...repeatedError(61)]);
  assert.deepEqual(ha.paths(), [SUPERVISOR], 'found in the first answer: no wider request');
  assert.equal(next.warning, undefined);
});

test('selectNewLines matches the window as whole lines: blank lines and CRLF line endings do not hide it', () => {
  const cursor = [LINE1, LINE2, LINE3].join('\n'); // the previous poll's window, as stored
  const { newLines, gap } = selectNewLines([LINE1, '', LINE2, LINE3, LINE4].join('\r\n'), cursor);
  assert.deepEqual(newLines, [LINE4]);
  assert.equal(gap, false);
  // Not a line of its own: a window that only matches part of a line is not found.
  assert.equal(selectNewLines(`x${LINE1}\n${LINE2}\n${LINE3}\n${LINE4}`, cursor).gap, true);
});

/**
 * One copy of a long error (`lines` lines: its header, then the same traceback
 * lines in every copy), like a chained exception with deep stacks.
 */
function longError(copy: number, lines: number): string[] {
  const time = new Date(Date.UTC(2026, 9, 12, 13) + copy * 60_000 + 123).toISOString().replace('T', ' ').slice(0, 23);
  const frames = Array.from({ length: lines - 1 }, (_, i) =>
    i % 2 === 0
      ? `  File "/usr/src/homeassistant/homeassistant/components/foo/coordinator.py", line ${100 + i}, in _async_refresh`
      : `    data = await self._async_update_data()  # frame ${i}`
  );
  return [`${time} ERROR (MainThread) [homeassistant.components.foo] Error fetching foo data: Cannot connect`, ...frames];
}

test('the tail window is the whole last record however long (up to MAX_RECORD_LINES); past that, or past MAX_RECORD_CHARS, its last MAX_TAIL_WINDOW_LINES lines', () => {
  const record = longError(0, 150);
  assert.deepEqual(selectNewLines([LINE1, ...record].join('\n'), null).nextCursor!.split('\n'), record, 'a 150-line record: all of it, from its header');

  const huge = longError(0, MAX_RECORD_LINES + 50);
  assert.deepEqual(
    selectNewLines([LINE1, ...huge].join('\n'), null).nextCursor!.split('\n'),
    huge.slice(-MAX_TAIL_WINDOW_LINES),
    'a header further back than MAX_RECORD_LINES: the last lines alone'
  );

  const wide = [huge[0], ...Array.from({ length: 300 }, (_, i) => `  data = ${String(i).padStart(4, '0')}${'x'.repeat(1020)}`)];
  assert.ok(wide.join('\n').length > MAX_RECORD_CHARS);
  assert.deepEqual(
    selectNewLines([LINE1, ...wide].join('\n'), null).nextCursor!.split('\n'),
    wide.slice(-MAX_TAIL_WINDOW_LINES),
    'a record longer than MAX_RECORD_CHARS: the last lines alone'
  );
});

test('a traceback of more than 100 lines logged again and again: both endpoints resume after the last copy, not the first', async () => {
  const copies = (from: number, n: number) => Array.from({ length: n }, (_, c) => longError(from + c, 150)).flat();

  // The log file: 40 copies (6000 lines), then one more, with an INFO line between.
  const log = copies(0, 40);
  const file = () => ({ status: 200, body: log.join('\n') });
  const first = await adapterAt(T0, fakeHomeAssistant({ [FILE]: file })).fetchEvents(target(), CRED, null);
  assert.equal(first.nextCursor, longError(39, 150).join('\n'), 'the window is the whole last copy, from its header');
  const unchanged = await adapterAt(T0, fakeHomeAssistant({ [FILE]: file })).fetchEvents(target(), CRED, first.nextCursor);
  assert.deepEqual(messages(unchanged), [], 'nothing new: nothing returned (not every copy since the first)');
  log.push(LATER_INFO, ...longError(40, 150));
  const grown = await adapterAt(T0, fakeHomeAssistant({ [FILE]: file })).fetchEvents(target(), CRED, unchanged.nextCursor);
  assert.deepEqual(messages(grown), [LATER_INFO, ...longError(40, 150)]);

  // The Supervisor journal: the same, with each request reaching back over the window.
  const journal = copies(0, 30);
  const first2 = await adapterAt(T0, fakeJournal(journal)).fetchEvents(target(), CRED, null);
  const ha = fakeJournal(journal);
  const unchanged2 = await adapterAt(T0 + 60_000, ha).fetchEvents(target(), CRED, first2.nextCursor);
  assert.deepEqual(messages(unchanged2), []);
  assert.deepEqual(
    ha.calls.map((c) => c.headers.Range),
    ['entries=:-649:650'],
    '500 new entries plus the 150-line window'
  );
  journal.push(LATER_INFO, ...longError(30, 150));
  const grown2 = await adapterAt(T0 + 120_000, fakeJournal(journal)).fetchEvents(target(), CRED, unchanged2.nextCursor);
  assert.deepEqual(messages(grown2), [LATER_INFO, ...longError(30, 150)]);
  assert.equal(grown2.warning, undefined);
});

test('a record longer than one Supervisor answer (700 lines) that repeats between other lines: every poll returns exactly the new lines', async () => {
  // A login warning, then the long error; three more of each between polls.
  let n = 0;
  const round = () => [bruteForceLine(n++), ...longError(n, 700)];
  const journal = round();
  let cursor = (await adapterAt(T0, fakeJournal(journal)).fetchEvents(target(), CRED, null)).nextCursor;
  assert.equal(parseCursor(cursor).tail, journal.slice(1).join('\n'), "the first poll reaches back to the last record's header");
  for (let poll = 1; poll <= 3; poll++) {
    const added = [...round(), ...round(), ...round()];
    journal.push(...added);
    const result = await adapterAt(T0 + poll * 60_000, fakeJournal(journal)).fetchEvents(target(), CRED, cursor);
    assert.deepEqual(messages(result), added, `poll ${poll}: the ${added.length} new lines, the login warnings included`);
    assert.equal(result.warning, undefined);
    cursor = result.nextCursor;
  }
});

test('windowReach: a window that starts at a header asks for its own lines; none, or one of bare lines, for MAX_RECORD_LINES', () => {
  assert.equal(windowReach([LINE1, LINE2, LINE3].join('\n')), 3);
  assert.equal(windowReach(longError(0, 150).join('\n')), 150);
  assert.equal(windowReach(null), MAX_RECORD_LINES);
  assert.equal(windowReach('  File "/usr/src/x.py", line 1, in f\n    raise FooError("boom")'), MAX_RECORD_LINES);
});

// ---------------------------------------------------------------------------
// Only the end of the log: byte ranges, and lines that scrolled out
// ---------------------------------------------------------------------------

test('a 206 from past the start of the file: its first line, cut in two, is dropped; a 206 from byte 0 keeps it', async () => {
  const cut = 'ice 77 state from the polling loop'; // the end of a line that started before the range
  const partial = await adapterAt(
    T0,
    fakeHomeAssistant({
      [FILE]: { status: 206, body: [cut, ...HA_LINES].join('\n'), headers: { 'content-range': 'bytes 1048576-1049999/1050000' } },
    })
  ).fetchEvents(target(), CRED, null);
  assert.deepEqual(messages(partial), HA_LINES);

  const whole = await adapterAt(
    T0,
    fakeHomeAssistant({ [FILE]: { status: 206, body: HA_LINES.join('\n'), headers: { 'content-range': 'bytes 0-999/1000' } } })
  ).fetchEvents(target(), CRED, null);
  assert.deepEqual(messages(whole), HA_LINES);

  // A longer answer whose end httpFetch kept (a server that ignores Range) starts mid-line too.
  const kept = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: [cut, ...HA_LINES].join('\n'), truncated: true } })).fetchEvents(
    target(),
    CRED,
    null
  );
  assert.deepEqual(messages(kept), HA_LINES);
});

test('a last record caught while Home Assistant writes it (no final newline) is left for the next poll, which reads it whole', async () => {
  const lines = Array.from({ length: 300 }, (_, i) => bruteForceLine(i));
  const record = bruteForceLine(300);
  const later = Array.from({ length: 23 }, (_, i) => bruteForceLine(301 + i));
  const cursor = lines.slice(-3).join('\n');

  // The file ends 40 characters into the record: nothing of it is taken, the cursor stays before it.
  const midWrite = await adapterAt(
    T0,
    fakeHomeAssistant({ [FILE]: { status: 200, body: `${lines.join('\n')}\n${record.slice(0, 40)}`, unterminated: true } })
  ).fetchEvents(target(), CRED, cursor);
  assert.deepEqual(messages(midWrite), []);
  assert.equal(midWrite.nextCursor, cursor);

  // The next poll gets the record whole, then the lines after it, and nothing already stored.
  const next = await adapterAt(
    T0,
    fakeHomeAssistant({ [FILE]: { status: 200, body: [...lines, record, ...later].join('\n') } })
  ).fetchEvents(target(), CRED, midWrite.nextCursor);
  assert.deepEqual(messages(next), [record, ...later]);

  // The same for a Supervisor answer cut short.
  const journal = fakeHomeAssistant({
    [SUPERVISOR]: { status: 200, body: `${lines.join('\n')}\n${record.slice(0, 40)}`, unterminated: true },
  });
  const cut = await adapterAt(T0, journal).fetchEvents(target({ endpoint: SUPERVISOR }), CRED, cursor);
  assert.deepEqual(messages(cut), []);
  assert.equal(cut.nextCursor, cursor);
});

test('an empty log file (416 to the byte Range) is asked for again without Range', async () => {
  const ha = fakeHomeAssistant({ [FILE]: (headers) => (headers.Range ? { status: 416, body: '' } : { status: 200, body: '' }) });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, 'previous tail');
  assert.deepEqual(result.events, []);
  assert.equal(result.nextCursor, 'previous tail', 'the cursor is kept');
  assert.deepEqual(
    ha.calls.map((c) => c.headers.Range ?? null),
    // The last 5 MB plus the window: its 13 bytes, 3 for its one line, and 2.
    ['bytes=-5242898', null]
  );
});

/** A log line of a login brute force, 50 ms after the previous one: each one distinct. */
function bruteForceLine(i: number): string {
  const time = new Date(Date.UTC(2026, 9, 12, 14, 20) + i * 50).toISOString().replace('T', ' ').slice(0, 23);
  const ip = `203.0.113.${i % 250}`;
  return `${time} WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from ${ip} (${ip}). Requested URL: '/auth/login_flow/${i}'. (curl/8.5.0)`;
}

/** A fake Home Assistant OS whose Supervisor answers the latest N journal entries asked for in Range (entries=:-(N-1):N). */
function fakeJournal(journal: string[], opts: { wideFails?: boolean } = {}) {
  return fakeHomeAssistant({
    [SUPERVISOR]: (headers) => {
      const n = Number(/^entries=:-\d+:(\d+)$/.exec(headers.Range ?? '')?.[1] ?? 100);
      if (opts.wideFails && n > SUPERVISOR_LOG_ENTRIES_WIDE) return { status: 502, body: '502: Bad Gateway' };
      return { status: 200, body: journal.slice(-n).join('\n') };
    },
  });
}

test('more new lines than the 500 journal entries asked for: the Supervisor is asked for 5000, and every new line is collected', async () => {
  const journal = HA_LINES.slice(0, 5);
  const first = await adapterAt(T0, fakeJournal(journal)).fetchEvents(target(), CRED, null);

  const burst = Array.from({ length: 797 }, (_, i) => bruteForceLine(i));
  journal.push(...burst);
  const ha = fakeJournal(journal);
  const result = await adapterAt(T0 + 60_000, ha).fetchEvents(target(), CRED, first.nextCursor);

  assert.deepEqual(
    ha.calls.map((c) => c.headers.Range),
    ['entries=:-502:503', 'entries=:-5002:5003'],
    'each request: the new entries plus the 3 lines of the tail window'
  );
  assert.deepEqual(messages(result), burst, 'all 797 new lines, nothing older');
  assert.equal(result.warning, undefined);
});

test('up to 5000 new lines, however the tail window falls in the wider answer: exactly the new lines and no warning', async () => {
  for (const [lastRecord, burst] of [
    [1, 4998],
    [1, 5000],
    [61, 4950], // a 61-line traceback last: its window reaches 61 entries back
    [61, 5000],
  ]) {
    const journal = [...HA_LINES.slice(0, 4), ...(lastRecord === 1 ? [HA_LINES[4]] : longError(0, lastRecord))];
    const first = await adapterAt(T0, fakeJournal(journal)).fetchEvents(target(), CRED, null);
    const added = Array.from({ length: burst }, (_, i) => bruteForceLine(i));
    journal.push(...added);
    const result = await adapterAt(T0 + 60_000, fakeJournal(journal)).fetchEvents(target(), CRED, first.nextCursor);
    const label = `${burst} new lines after a ${lastRecord}-line record`;
    assert.equal(result.events.length, burst, label);
    assert.deepEqual(messages(result), added, label);
    assert.equal(result.warning, undefined, `${label}: every new line was collected, so no warning`);
  }
});

test('more new lines than 5000: the latest 5000 are collected and the gap is reported as a warning', async () => {
  const journal = HA_LINES.slice(0, 5);
  const first = await adapterAt(T0, fakeJournal(journal)).fetchEvents(target(), CRED, null);
  journal.push(...Array.from({ length: 5001 }, (_, i) => bruteForceLine(i)));

  const result = await adapterAt(T0 + 60_000, fakeJournal(journal)).fetchEvents(target(), CRED, first.nextCursor);
  assert.deepEqual(messages(result), journal.slice(-5000), 'only lines that are certainly new: none of the 3-line window');
  assert.match(result.warning ?? '', /more lines since the last poll than its Supervisor returns at once .*not collected/);

  // The wider request fails: the latest 500 of the first answer, which are certainly new, are kept.
  const failing = fakeJournal(journal, { wideFails: true });
  const narrow = await adapterAt(T0 + 60_000, failing).fetchEvents(target(), CRED, first.nextCursor);
  assert.equal(failing.calls.length, 2);
  assert.deepEqual(messages(narrow), journal.slice(-500));
  assert.match(narrow.warning ?? '', /not collected/);
});

test('the log file: a window that is gone (Home Assistant restarted, a new file) still gets the 200-line bound and no warning', async () => {
  const restarted = Array.from({ length: 300 }, (_, i) => bruteForceLine(i));
  const ha = fakeHomeAssistant({ [FILE]: { status: 200, body: restarted.join('\n') } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, HA_TAIL);
  assert.deepEqual(messages(result), restarted.slice(-200));
  assert.equal(result.warning, undefined);
  assert.deepEqual(ha.paths(), [FILE], 'no second request for the file');
});

/**
 * /api/error_log as Home Assistant serves it (aiohttp's FileResponse): the
 * byte Range asked for, as a 206 with its Content-Range (the whole file when it
 * is shorter). The log is ASCII, so characters are bytes.
 */
function fakeLogFile(log: { text: string }) {
  return fakeHomeAssistant({
    [FILE]: (headers) => {
      const size = log.text.length;
      const suffix = /^bytes=-(\d+)$/.exec(headers.Range ?? '');
      if (!suffix) return { status: 200, body: log.text };
      const start = Math.max(0, size - Number(suffix[1]));
      return { status: 206, body: log.text.slice(start), headers: { 'content-range': `bytes ${start}-${size - 1}/${size}` } };
    },
  });
}

/** `bytes` worth of brute-force lines, numbered from `from`. */
function bruteForceBurst(from: number, bytes: number): string[] {
  const lines: string[] = [];
  for (let size = 0; size < bytes; size += lines[lines.length - 1].length + 1) lines.push(bruteForceLine(from + lines.length));
  return lines;
}

test('more than 5 MB logged between two polls of the log file: every line of the last 5 MB is collected, and the gap is reported as a warning', async () => {
  const log = { text: HA_LINES.join('\n') + '\n' };
  const first = await adapterAt(T0, fakeLogFile(log)).fetchEvents(target(), CRED, null);

  // Up to 5 MB since the last poll: the window is in the answer, every new line, no warning.
  const fits = bruteForceBurst(0, 4.9 * 1024 * 1024);
  log.text += fits.join('\n') + '\n';
  const ha = fakeLogFile(log);
  const before = await adapterAt(T0 + 60_000, ha).fetchEvents(target(), CRED, first.nextCursor);
  assert.equal(ha.calls[0].headers.Range, FILE_RANGE_AFTER_HA_TAIL);
  assert.equal(before.events.length, fits.length);
  assert.deepEqual(messages(before), fits);
  assert.equal(before.warning, undefined);

  // 5.5 MB since: the answer (the last 5 MB and the window's bytes) starts after the window. All of it is new.
  const burst = bruteForceBurst(fits.length, 5.5 * 1024 * 1024);
  log.text += burst.join('\n') + '\n';
  const overflow = fakeLogFile(log);
  const result = await adapterAt(T0 + 120_000, overflow).fetchEvents(target(), CRED, before.nextCursor);
  const asked = Number(/^bytes=-(\d+)$/.exec(overflow.calls[0].headers.Range)![1]);
  assert.equal(asked, 5 * 1024 * 1024 + windowReadBytes(before.nextCursor));
  const answer = log.text.slice(log.text.length - asked);
  const whole = answer.slice(answer.indexOf('\n') + 1).split('\n').filter(Boolean); // its first line is cut
  assert.ok(whole.length > 20_000, `${whole.length} lines in the answer`);
  assert.deepEqual(messages(result), whole, 'every whole line of the answer, not the last 200');
  assert.deepEqual(messages(result), burst.slice(-whole.length), 'all of them new');
  // (Whether it says lines were or may not have been collected depends on where the answer cut a
  // line, see the next tests: these lines all end alike, so the cut part can also end the window.)
  assert.match(
    result.warning ?? '',
    new RegExp(
      `^Home Assistant logged more than 5 MB since the last poll, more of its log file than one poll reads \\(the ${whole.length} lines collected now are the latest\\): .*not .*collected\\.$`
    )
  );

  // The next poll resumes after them as usual.
  const later = bruteForceBurst(fits.length + burst.length, 2000);
  log.text += later.join('\n') + '\n';
  const next = await adapterAt(T0 + 180_000, fakeLogFile(log)).fetchEvents(target(), CRED, result.nextCursor);
  assert.deepEqual(messages(next), later);
  assert.equal(next.warning, undefined);
});

/** Brute-force lines of exactly `bytes` bytes, newlines included (the last line padded to fit). */
function exactBurst(bytes: number): string[] {
  const lines = bruteForceBurst(0, bytes - 600);
  const used = lines.reduce((n, line) => n + line.length + 1, 0);
  const last = bruteForceLine(lines.length);
  lines.push(`${last} ${'.'.repeat(bytes - used - last.length - 2)}`);
  assert.equal(lines.join('\n').length + 1, bytes);
  return lines;
}

const FIVE_MB = 5 * 1024 * 1024;

/** A record's bytes in the log file: its lines and their newlines. */
function fileBytes(record: string[]): number {
  return record.join('\n').length + 1;
}

/**
 * A poll of a log file that ends on `lastRecord` (so it is the tail window),
 * then the next poll after exactly `bytes` more were logged.
 */
async function pollAcross(lastRecord: string[], bytes: number) {
  const log = { text: [...HA_LINES.slice(0, 4), ...lastRecord].join('\n') + '\n' };
  const first = await adapterAt(T0, fakeLogFile(log)).fetchEvents(target(), CRED, null);
  assert.equal(first.nextCursor, lastRecord.join('\n'), 'the window is the last record');
  const added = exactBurst(bytes);
  log.text += added.join('\n') + '\n';
  const ha = fakeLogFile(log);
  const result = await adapterAt(T0 + 60_000, ha).fetchEvents(target(), CRED, first.nextCursor);
  return { added, result, range: ha.calls[0].headers.Range, window: first.nextCursor! };
}

test('up to 5 MB logged after a long record, so that the last 5 MB start inside it: exactly the new lines and no warning', async () => {
  for (const [label, lastRecord] of [
    ['a 1003-line traceback', longError(0, 1003)],
    ['a 60-line traceback', longError(0, 60)],
    ['three one-line records', [LINE1, LINE2, LINE3]],
  ] as const) {
    // The file's last 5 MB start half-way through the record.
    const { added, result, range, window } = await pollAcross([...lastRecord], FIVE_MB - Math.floor(fileBytes([...lastRecord]) / 2));
    assert.equal(range, `bytes=-${FIVE_MB + windowReadBytes(window)}`, `${label}: the last 5 MB and the window are asked for`);
    assert.equal(result.events.length, added.length, label);
    assert.deepEqual(messages(result), added, `${label}: none of the window again`);
    assert.equal(result.warning, undefined, `${label}: nothing was missed`);
  }
  // Exactly 5 MB.
  const { added, result } = await pollAcross(longError(0, 60), FIVE_MB);
  assert.deepEqual(messages(result), added);
  assert.equal(result.warning, undefined);
});

test('more than 5 MB logged, the read beginning inside the last record collected: its lines are not collected again', async () => {
  // The answer is the file's last FIVE_MB + windowReadBytes bytes, which is `slack` more than the
  // window's own bytes; so FIVE_MB + slack + d new bytes start it d bytes into the window.
  const slack = (record: string[]) => windowReadBytes(record.join('\n')) - fileBytes(record);
  const oneLine = [LINE1, LINE2, LINE3];
  const traceback = longError(0, 60);
  assert.deepEqual([slack(oneLine), slack(traceback)], [10, 181]);

  // One-line records: it starts half-way through the first, so the other two (timestamped) place it.
  const placed = await pollAcross(oneLine, FIVE_MB + slack(oneLine) + Math.floor(LINE1.length / 2));
  assert.deepEqual(messages(placed.result), placed.added, 'exactly the new lines');
  assert.equal(placed.result.warning, undefined, 'nothing was missed');

  // A traceback: it starts half-way through, with bare lines of the window. They are left out, but
  // they could also be another copy of the same traceback logged later, so a gap stays possible.
  const bare = await pollAcross(traceback, FIVE_MB + slack(traceback) + Math.floor(fileBytes(traceback) / 2));
  assert.deepEqual(messages(bare.result), bare.added, 'none of the traceback again');
  assert.equal(
    bare.result.warning,
    `Home Assistant logged more than 5 MB since the last poll, more of its log file than one poll reads (the ${bare.added.length} lines collected now are the latest): lines logged before them may not have been collected.`
  );

  // It starts in the window's last line: no line of the window is left, and nothing was missed either.
  const lastLine = await pollAcross(traceback, FIVE_MB + slack(traceback) + fileBytes(traceback) - 5);
  assert.deepEqual(messages(lastLine.result), lastLine.added);
  assert.match(lastLine.result.warning ?? '', /: lines logged before them may not have been collected\.$/);

  // It starts in the first new line: that line is cut, so a line was missed for certain.
  const past = await pollAcross(traceback, FIVE_MB + slack(traceback) + fileBytes(traceback) + 20);
  assert.deepEqual(messages(past.result), past.added.slice(1));
  assert.match(past.result.warning ?? '', /: the lines before them were not collected\.$/);
});

test('selectNewLines with onMiss "all": a text that starts inside the window skips that part; only a timestamped line in it rules out a gap', () => {
  const window = [LINE2, LINE3, ...repeatedError(5)];
  const cursor = window.join('\n');
  const after = [LATER_INFO, LINE4];

  const anchored = selectNewLines([...window.slice(1), ...after].join('\n'), cursor, 'all');
  assert.deepEqual(anchored.newLines, after);
  assert.equal(anchored.gap, false);
  assert.equal(anchored.overlap, window.length - 1);

  const bareTail = selectNewLines([...window.slice(-2), ...after].join('\n'), cursor, 'all');
  assert.deepEqual(bareTail.newLines, after);
  assert.equal(bareTail.gap, true, 'bare traceback lines could be another copy');
  assert.equal(bareTail.overlap, 2);

  const none = selectNewLines(after.join('\n'), cursor, 'all');
  assert.deepEqual(none.newLines, after);
  assert.equal(none.gap, true);
  assert.equal(none.overlap, 0);

  // A bounded onMiss is unchanged: the latest lines, no overlap search.
  assert.deepEqual(selectNewLines([...window.slice(1), ...after].join('\n'), cursor, 1).newLines, [LINE4]);
});

/**
 * The cursor the reader before this version stored for a log longer than 5 MB: it kept the first
 * 5,242,880 characters of the file and stored their last three lines, the last one cut at that
 * point unless it fell at a line's end, as the cursor (it then found nothing new every poll).
 * Also the index, among the file's lines, of the first line it did not store whole: the one it
 * cut (it stored only the start of it), or the one after the cursor.
 */
function legacyCursor(text: string): { cursor: string; resumeAt: number; atLineEnd: boolean } {
  const head = text.slice(0, LEGACY_CUT_CHARS).split('\n').filter(Boolean);
  const atLineEnd = text[LEGACY_CUT_CHARS] === '\n' || text[LEGACY_CUT_CHARS - 1] === '\n';
  return { cursor: head.slice(-3).join('\n'), resumeAt: atLineEnd ? head.length : head.length - 1, atLineEnd };
}

/**
 * The same, read as that reader read the file: it decoded each piece the socket gave it
 * (`chunkBytes` each here) on its own, so a character outside ASCII split between two pieces became
 * two or three U+FFFD (`replaced` counts them) and its 5,242,880 characters ended earlier in the file.
 */
function legacyCursorRead(text: string, chunkBytes: number): { cursor: string; resumeAt: number; replaced: number } {
  const buf = Buffer.from(text, 'utf8');
  let read = '';
  for (let at = 0; at < buf.length && read.length < LEGACY_CUT_CHARS; at += chunkBytes) read += buf.subarray(at, at + chunkBytes).toString('utf8');
  read = read.slice(0, LEGACY_CUT_CHARS);
  const head = read.split('\n').filter(Boolean);
  const last = head.length - 1;
  return {
    cursor: head.slice(-3).join('\n'),
    resumeAt: head[last] === text.split('\n').filter(Boolean)[last] ? head.length : last,
    replaced: (read.match(/\uFFFD/g) ?? []).length,
  };
}

/** /api/error_log for a log with characters outside ASCII: the Range counts its bytes, not its characters. */
function fakeLogBytes(log: string, ignoresRange = false) {
  const buf = Buffer.from(log, 'utf8');
  return fakeHomeAssistant({
    [FILE]: (headers) => {
      const n = Number(/^bytes=-(\d+)$/.exec(headers.Range ?? '')![1]);
      const start = Math.max(0, buf.length - n);
      const body = buf.subarray(start).toString('utf8');
      // A server that ignores the Range: the whole file, which httpFetch cuts to its end.
      if (ignoresRange) return { status: 200, body, truncated: true };
      return { status: 206, body, headers: { 'content-range': `bytes ${start}-${buf.length - 1}/${buf.length}` } };
    },
  });
}

/** Where a fakeLogBytes answer started in the file: its first byte. */
function answerStart(ha: ReturnType<typeof fakeHomeAssistant>, log: string): number {
  return Math.max(0, Buffer.byteLength(log, 'utf8') - Number(/^bytes=-(\d+)$/.exec(ha.calls[0].headers.Range)![1]));
}

/** True for a cursor of bare traceback lines only (no timestamped header): found in every copy of the traceback. */
function bare(cursor: string): boolean {
  return cursor.split('\n').every((line) => parseLineTimestamp(line) === null);
}

/** deepEqual for tens of thousands of lines, failing with their counts and first difference instead of a diff of them all. */
function assertLines(actual: string[], expected: string[], message: string) {
  const at = actual.findIndex((line, i) => line !== expected[i]);
  if (at === -1 && actual.length === expected.length) return;
  const i = at === -1 ? Math.min(actual.length, expected.length) : at;
  assert.fail(`${message}: ${actual.length} lines, expected ${expected.length}; line ${i} is ${JSON.stringify(actual[i])}, expected ${JSON.stringify(expected[i])}`);
}

test('a cursor whose last line is cut (stored before this version: the first 5 MB of a longer log, or a line still being written): the poll resumes at that line, collecting it whole', async () => {
  const lines = bruteForceBurst(0, 5.3 * 1024 * 1024);
  const log = { text: lines.join('\n') + '\n' };
  const { cursor: oldCursor, resumeAt: cutAt, atLineEnd } = legacyCursor(log.text);
  assert.ok(!atLineEnd && lines[cutAt] !== oldCursor.split('\n')[2], 'the cursor ends in a cut line');
  assert.ok(lines[cutAt].startsWith(oldCursor.split('\n')[2]));

  const result = await adapterAt(T0, fakeLogFile(log)).fetchEvents(target(), CRED, oldCursor);
  assertLines(messages(result), lines.slice(cutAt), 'the cut line whole, then the lines after it: none of the 5 MB already stored');
  assert.equal(result.warning, undefined);

  // A last line caught while it was written, in a whole file.
  const whole = lines.slice(0, 400);
  const partial = [whole[297], whole[298], whole[299].slice(0, 40)].join('\n');
  const resumed = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: whole.join('\n') } })).fetchEvents(target(), CRED, partial);
  assert.deepEqual(messages(resumed), whole.slice(299), 'from the line it caught part of, not the 200-line bound');

  // Only the last line may be cut: the lines before it must match whole.
  assert.equal(selectNewLines(whole.join('\n'), [whole[297].slice(0, 40), whole[298], whole[299]].join('\n')).gap, true);
});

/** A log of `bytes` or more: a first line, then copies of a 26-line traceback, each with its own header line. */
function repeatingTracebackLog(firstLine: string, bytes: number): string[] {
  const lines = [firstLine];
  for (let copy = 0, size = Buffer.byteLength(firstLine) + 1; size < bytes; copy++) {
    for (const line of longError(copy, 26)) {
      lines.push(line);
      size += Buffer.byteLength(line) + 1;
    }
  }
  return lines;
}

test('a cursor stored at 5 MB inside a traceback logged again and again: the poll resumes where the old reader stopped, not at the first copy read', async () => {
  // Each first line moves the 5 MB mark to another line of the traceback, or another place in one;
  // with 3 and 4 it falls at a line's end (before and after its newline), so no line is cut.
  for (const pad of [0, 37, 211, 977, 1234, 2048, 3, 4]) {
    const lines = repeatingTracebackLog(`2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] ${'x'.repeat(pad)}`, 5.3 * 1024 * 1024);
    const log = { text: lines.join('\n') + '\n' };
    const { cursor, resumeAt, atLineEnd } = legacyCursor(log.text);
    assert.ok(bare(cursor), `pad ${pad}: the cursor is bare traceback lines, found in every copy`);
    assert.equal(atLineEnd, pad === 3 || pad === 4, `pad ${pad}: where the mark falls`);
    assert.equal(cursor.split('\n')[2] === lines[resumeAt - 1], atLineEnd, `pad ${pad}: its last line is cut unless the mark is at a line's end`);

    const result = await adapterAt(T0, fakeLogFile(log)).fetchEvents(target(), CRED, cursor);
    assertLines(messages(result), lines.slice(resumeAt), `pad ${pad}: any cut line whole and the lines after it, none collected already`);
    assert.equal(result.warning, undefined, `pad ${pad}`);
  }
});

test('a cursor cut at 5 MB in a log since grown more than one read past it: all of the answer is new and the gap is reported', async () => {
  // The old reader never read past the 5 MB mark; the last 5 MB of an 11 MB log start well after
  // it, so a copy of the traceback found in them is a later one: none of the answer was collected.
  for (const pad of [0, 3]) {
    const lines = repeatingTracebackLog(`2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] ${'x'.repeat(pad)}`, 11 * 1024 * 1024);
    const log = { text: lines.join('\n') + '\n' };
    const { cursor, atLineEnd } = legacyCursor(log.text);
    assert.ok(bare(cursor), `pad ${pad}: bare traceback lines, found in every copy`);
    assert.equal(atLineEnd, pad === 3, `pad ${pad}: a cut line, or whole lines`);

    const ha = fakeLogFile(log);
    const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, cursor);
    const asked = Number(/^bytes=-(\d+)$/.exec(ha.calls[0].headers.Range)![1]);
    const answer = log.text.slice(log.text.length - asked);
    const whole = answer.slice(answer.indexOf('\n') + 1).split('\n').filter(Boolean);
    assertLines(messages(result), whole, `pad ${pad}: every whole line of the answer`);
    assert.match(result.warning ?? '', /^Home Assistant logged more than 5 MB since the last poll.*: the lines before them were not collected\.$/, `pad ${pad}`);
  }
});

test('a cursor cut at 5 MB where the mark cannot be placed exactly: the first copy read, so that no line is skipped', async () => {
  const infoLine = (name: string) => `2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] Turned on ${name}`;

  // A character outside ASCII in the part read before the mark: had the old reader's pieces split it,
  // its mark would be up to one character earlier (its UTF-8 byte beyond it), and only the copy at
  // the mark is that close: exact. (fakeLogBytes and legacyCursor decode the log whole.)
  const inRead = repeatingTracebackLog(infoLine('the porch light'), 5.3 * 1024 * 1024);
  inRead.splice(inRead.length - 30_000, 0, infoLine('the Küche light'));
  const inReadLog = inRead.join('\n') + '\n';
  const placed = legacyCursor(inReadLog);
  assert.ok(bare(placed.cursor), 'bare traceback lines, found in every copy');
  assert.ok(inRead.indexOf(infoLine('the Küche light')) < placed.resumeAt, 'before the cut');
  const exact = await adapterAt(T0, fakeLogBytes(inReadLog)).fetchEvents(target(), CRED, placed.cursor);
  assertLines(messages(exact), inRead.slice(placed.resumeAt), 'the cut line whole and the lines after it');

  // One before the part read puts the old reader's mark later than placed (its bytes count as
  // characters), and a server that ignores the Range gives no position at all. The poll then resumes
  // at the first copy of the cursor's bare lines in the answer: lines collected already are collected
  // again, once, but none is skipped.
  const before = repeatingTracebackLog(infoLine('the Küche light'), 5.3 * 1024 * 1024);
  const beforeLog = before.join('\n') + '\n';
  const unplaced = legacyCursor(beforeLog);
  assert.ok(bare(unplaced.cursor), 'bare traceback lines, found in every copy');
  const due = before.slice(unplaced.resumeAt);
  for (const ignoresRange of [false, true]) {
    const result = await adapterAt(T0, fakeLogBytes(beforeLog, ignoresRange)).fetchEvents(target(), CRED, unplaced.cursor);
    const events = messages(result);
    assert.ok(events.length > due.length, `ignoresRange ${ignoresRange}: some lines again`);
    assertLines(events.slice(-due.length), due, `ignoresRange ${ignoresRange}: every line from the cut one on`);
    assert.equal(result.warning, undefined);
  }
});

test('a cursor cut at 5 MB after characters outside ASCII that the old reader decoded split: the copy it stopped at or the one before, never the first one read, nor a later one', async () => {
  // ASCII for 2.5 MB, then copies of a traceback whose last line has three °: the bytes before the
  // answer are ASCII, the part read before the mark is not. Where the old reader's pieces split a °,
  // its count ran ahead and its mark fell earlier in the file than placed; the copy is looked for
  // back from the mark by the UTF-8 bytes beyond the characters of the answer up to it (`reach`).
  const climateError = (copy: number) => [...longError(copy, 25), 'ValueError: setpoint 21.5°C is out of range 5.0°C-30.0°C'];
  let split = 0;
  for (const [chunkBytes, pad] of [[65_536, 1166], [65_536, 1431], [16_384, 371], [16_384, 583], [65_536, 211]]) {
    const lines = [`2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] ${'x'.repeat(pad)}`];
    for (let copy = 0, size = Buffer.byteLength(lines[0]) + 1; size < 5.4 * 1024 * 1024; copy++) {
      for (const line of size < 2.5 * 1024 * 1024 ? longError(copy, 26) : climateError(copy)) {
        lines.push(line);
        size += Buffer.byteLength(line) + 1;
      }
    }
    const log = lines.join('\n') + '\n';
    const { cursor, resumeAt, replaced } = legacyCursorRead(log, chunkBytes);
    const label = `${chunkBytes}-byte pieces, pad ${pad}`;
    assert.ok(bare(cursor) && !cursor.includes('\uFFFD'), `${label}: bare traceback lines, found in every copy`);
    if (replaced > 0) split++;

    const ha = fakeLogBytes(log);
    const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, cursor);
    const events = messages(result);
    const due = lines.slice(resumeAt);
    assertLines(events.slice(-due.length), due, `${label}: every line from the one the old reader cut on: none skipped`);
    const start = answerStart(ha, log);
    const reach = Buffer.byteLength(log.slice(start, LEGACY_CUT_CHARS), 'utf8') - (LEGACY_CUT_CHARS - start);
    const again = lines.slice(lines.length - events.length, resumeAt);
    const longest = Math.max(...lines.slice(-30).map((line) => line.length));
    assert.ok(again.join('\n').length <= reach + longest, `${label}: collected again only within reach of the mark (${again.length} lines)`);
    assert.ok(again.length <= 26, `${label}: one copy at most here (${again.length} lines), not every copy since the first one read`);
    assert.equal(result.warning, undefined, label);
  }
  assert.equal(split, 4, 'the old reader split a character in four of the five');

  // A cursor of whole lines is placed by the mark alone: the old reader also stored one at the end of
  // a log it read all of, under 5 MB then, and a copy within reach back from the mark is a later one.
  const lines = ['2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] Started'];
  let copies = 0;
  const grow = (bytes: number) => {
    for (let size = Buffer.byteLength(lines.join('\n')) + 1; size < bytes; ) {
      for (const line of climateError(copies++)) {
        lines.push(line);
        size += Buffer.byteLength(line) + 1;
      }
    }
  };
  grow(4.9 * 1024 * 1024);
  const readThen = lines.length;
  const thenCursor = lines.slice(-3).join('\n');
  assert.ok(bare(thenCursor), 'the end of a traceback, found in every copy');
  grow(5.3 * 1024 * 1024);
  const result = await adapterAt(T0, fakeLogBytes(lines.join('\n') + '\n')).fetchEvents(target(), CRED, thenCursor);
  const due = lines.slice(readThen);
  assertLines(messages(result).slice(-due.length), due, 'every line logged after that read: none skipped');
});

test('a cursor of timestamped lines cut at 5 MB, with characters outside ASCII before the answer: resumed where it is, and the gap reported only when lines were missed', async () => {
  // The first line's 20,000 degree signs take 20,000 bytes beyond their characters, which count as
  // characters before the answer: the mark is placed that much earlier than the old reader's. In a
  // log a little over 10 MB it is placed before the answer while it is in it; a window with a
  // timestamped line is unique, so the poll resumes at it all the same.
  const all = [`2026-10-12 12:59:59.999 INFO (MainThread) [homeassistant.core] ${'°'.repeat(20_000)}`, ...bruteForceBurst(0, 10.2 * 1024 * 1024)];
  const { cursor, resumeAt } = legacyCursor(all.join('\n') + '\n');
  assert.ok(!bare(cursor), 'timestamped lines');
  const read = LOG_MAX_BYTES + windowReadBytes(cursor);
  // The old reader's mark (character 5,242,880) is at byte 5,262,880: the answer starts 10,000 bytes
  // before it, or 20,000 after it (so the lines in between were not collected).
  for (const [beyond, missed] of [[10_000, false], [40_000, true]] as const) {
    const lines: string[] = [];
    for (let i = 0, size = 0; size < LEGACY_CUT_CHARS + read + beyond; i++) {
      lines.push(all[i]);
      size += Buffer.byteLength(all[i]) + 1;
    }
    const log = lines.join('\n') + '\n';
    const ha = fakeLogBytes(log);
    const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, cursor);
    if (!missed) {
      assertLines(messages(result), lines.slice(resumeAt), 'the cut line whole, then the lines after it');
      assert.equal(result.warning, undefined, 'nothing was missed');
    } else {
      const answer = Buffer.from(log, 'utf8').subarray(answerStart(ha, log)).toString('utf8');
      assertLines(messages(result), answer.slice(answer.indexOf('\n') + 1).split('\n').filter(Boolean), 'every whole line of the answer');
      assert.match(result.warning ?? '', /: the lines before them were not collected\.$/);
    }
  }
});

test('a new file after a restart: read whole, the 200-line bound and no warning; read past its start (over 5 MB), all of the answer and the warning', async () => {
  const restarted = { text: bruteForceBurst(0, 300_000).join('\n') + '\n' };
  const small = await adapterAt(T0, fakeLogFile(restarted)).fetchEvents(target(), CRED, HA_TAIL);
  assert.equal(small.events.length, 200, 'a 206 from byte 0 is the whole file: the bounded tail');
  assert.equal(small.warning, undefined);

  // A restart and over 5 MB logged since the last poll: everything in the new file is new.
  const big = { text: bruteForceBurst(0, 6 * 1024 * 1024).join('\n') + '\n' };
  const overflow = await adapterAt(T0, fakeLogFile(big)).fetchEvents(target(), CRED, HA_TAIL);
  assert.ok(overflow.events.length > 20_000);
  assert.match(overflow.warning ?? '', /more than 5 MB since the last poll/);
});

test('back on the log file after the Supervisor fallback: a journal tail that is not in the end of a long file keeps the 200-line bound', async () => {
  // The file may hold lines the journal already gave, so its lines are not all taken as new.
  const log = { text: bruteForceBurst(0, 6 * 1024 * 1024).join('\n') + '\n' };
  const cursor = serializeCursor({ tail: HA_TAIL, errorLogCheckedAt: T0 });
  const ha = fakeLogFile(log);
  const result = await adapterAt(T0 + ERROR_LOG_REPROBE_MS, ha).fetchEvents(target(), CRED, cursor);
  assert.deepEqual(ha.paths(), [FILE]);
  assert.equal(result.events.length, 200);
  assert.equal(result.warning, undefined);
  assert.equal(parseCursor(result.nextCursor).errorLogCheckedAt, null, 'back on the file endpoint');

  // A first poll of a file over 5 MB is the 200-line bound too.
  const firstPoll = await adapterAt(T0, fakeLogFile(log)).fetchEvents(target(), CRED, null);
  assert.equal(firstPoll.events.length, 200);
  assert.equal(firstPoll.warning, undefined);
});

// ---------------------------------------------------------------------------
// Line format
// ---------------------------------------------------------------------------

test('normalizeSupervisorLine: colours and a verbose journal prefix are removed; native and other lines are untouched', () => {
  for (const line of HA_LINES) {
    assert.equal(normalizeSupervisorLine(line), line, 'a native line is unchanged');
    assert.equal(normalizeSupervisorLine(colored(line)), line, 'colours are removed');
  }
  assert.equal(
    normalizeSupervisorLine(`2026-10-12 14:03:11.482 homeassistant homeassistant[118]: ${HA_LINES[3]}`),
    HA_LINES[3],
    'journal prefix (journalctl -o short style) dropped'
  );
  assert.equal(normalizeSupervisorLine(`2026-10-12 14:03:11.482 ha-host homeassistant: ${colored(HA_LINES[3])}`), HA_LINES[3]);
  // A prefix is only dropped in front of a native line; other records keep it rather than lose information.
  const s6 = '2026-10-12 14:02:50.000 ha-host homeassistant[118]: s6-rc: info: service legacy-services successfully started';
  assert.equal(normalizeSupervisorLine(s6), s6);
});

test('lines from both endpoints reach the catalog parser in native form and parse', async () => {
  const parser = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../../../../../../catalog/parsers/home-assistant.parser.json'), 'utf8')
  ) as ParserDef;

  const fromFile = await adapterAt(T0, fakeHomeAssistant({ [FILE]: { status: 200, body: HA_LINES.join('\n') } })).fetchEvents(
    target(),
    CRED,
    null
  );
  const fromSupervisor = await adapterAt(
    T0,
    fakeHomeAssistant({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 200, body: HA_LINES.map(colored).join('\n') } })
  ).fetchEvents(target(), CRED, null);

  for (const result of [fromFile, fromSupervisor]) {
    const ban = runParser(parser, result.events[3].message);
    assert.ok(ban, 'the ban line parses');
    assert.equal(ban!.fields.source_ip, '192.168.1.77');
    assert.equal(ban!.fields.event, 'ip_banned');
    const login = runParser(parser, result.events[2].message);
    assert.ok(login, 'the invalid-authentication line parses');
    assert.equal(login!.fields.source_ip, '192.168.1.77');
    assert.equal(login!.fields.event, 'login_failure');
    assert.ok(runParser(parser, result.events[0].message), 'an INFO line parses');
    assert.equal(result.events[3].timestamp?.getTime(), parseLineTimestamp(HA_LINES[3])?.getTime());
  }
});

// ---------------------------------------------------------------------------
// Errors that say what to do
// ---------------------------------------------------------------------------

async function pollError(routes: Record<string, Reply>, over: Partial<PollTarget> = {}) {
  const ha = fakeHomeAssistant(routes);
  try {
    await adapterAt(T0, ha).fetchEvents(target(over), CRED, null);
  } catch (err) {
    assert.ok(err instanceof PollError, `expected a PollError, got ${String(err)}`);
    // The poller stores at most 500 characters; nothing that matters may be cut off.
    assert.ok(err.message.length <= 500, `message is ${err.message.length} characters`);
    return { err, paths: ha.paths() };
  }
  throw new Error('expected the poll to fail');
}

test('401 from /api/error_log: rejected or non-admin token, both endpoints admin-only; no fallback request', async () => {
  const { err, paths } = await pollError({ [FILE]: { status: 401, body: '401: Unauthorized' } });
  assert.deepEqual(paths, [FILE], 'a 401 means the file endpoint exists; the Supervisor endpoint would refuse the token too');
  assert.match(err.message, /rejected the token \(HTTP 401 from \/api\/error_log\)/);
  assert.match(err.message, /not an administrator/);
  assert.match(err.message, /\/api\/error_log and \/api\/hassio\/core\/logs\) are admin-only/);
  assert.match(err.message, /long-lived access token/);
  assert.equal(err.category, 'authentication');
});

test('401 from the Supervisor endpoint after a 404 gets the same token message', async () => {
  const { err, paths } = await pollError({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 401 } });
  assert.deepEqual(paths, [FILE, SUPERVISOR]);
  assert.match(err.message, /HTTP 401 from \/api\/hassio\/core\/logs/);
  assert.match(err.message, /not an administrator/);
});

test('404 from both endpoints: names both, the likely causes and the fix', async () => {
  const { err } = await pollError({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 404 } }, { port: 8124 });
  assert.match(err.message, /^Home Assistant at http:\/\/192\.168\.1\.50:8124 answered 404 for both log endpoints\./);
  assert.match(err.message, /\/api\/error_log exists only while Home Assistant writes a log file/);
  assert.match(err.message, /\/api\/hassio\/core\/logs only on Home Assistant OS\/Supervised/);
  assert.match(err.message, /HA_DISABLE_LOG_FILE/);
  assert.match(err.message, /HA_DUPLICATE_LOG_FILE/);
  assert.match(err.message, /Check the port and any reverse-proxy path/);
  assert.match(err.message, /set the endpoint or address in this source's settings/);
  assert.equal(err.category, 'configuration');
  assert.doesNotMatch(err.message, /llat-token/);

  // Still whole (pollError checks <= 500 characters) with the longest possible address and port.
  const long = await pollError(
    { [FILE]: { status: 404 }, [SUPERVISOR]: { status: 404 } },
    { ip: 'fd00:1234:5678:9abc:def0:1234:5678:9abc', port: 65535, tls: true }
  );
  assert.match(long.err.message, /\(Log Discovery, Edit\)\.$/);
});

test('502 from the Supervisor endpoint is reported as a Supervisor problem', async () => {
  const { err } = await pollError({ [FILE]: { status: 404 }, [SUPERVISOR]: { status: 502, body: '502: Bad Gateway' } });
  assert.match(err.message, /could not get its log from the Supervisor \(HTTP 502 from \/api\/hassio\/core\/logs\)/);
  assert.match(err.message, /retries on the next cycle/);
});

test('403 points at an IP ban; another status names the endpoint; a web page is refused instead of ingested', async () => {
  const banned = await pollError({ [FILE]: { status: 403, body: '403: Forbidden' } });
  assert.match(banned.err.message, /ip_bans\.yaml/);
  assert.deepEqual(banned.paths, [FILE]);

  const other = await pollError({ [FILE]: { status: 500 } });
  assert.equal(other.err.message, 'HTTP 500 from Home Assistant /api/error_log');

  const html = await pollError({ [FILE]: { status: 200, body: '<!DOCTYPE html><html>login</html>', contentType: 'text/html; charset=utf-8' } });
  assert.match(html.err.message, /returned a web page, not Home Assistant's log/);
});

// ---------------------------------------------------------------------------
// The URL shown for a source
// ---------------------------------------------------------------------------

test('describeUrl: the endpoint in use (file, remembered fallback, admin-set), never a token or query string', () => {
  const adapter = makeHomeAssistantAdapter({ fetch: async () => ({ status: 200, body: '', headers: {} }) });
  assert.equal(adapter.describeUrl(target(), null), 'http://192.168.1.50:8123/api/error_log');
  assert.equal(adapter.describeUrl(target(), 'plain tail'), 'http://192.168.1.50:8123/api/error_log');
  const fallback = serializeCursor({ tail: null, errorLogCheckedAt: T0 });
  assert.equal(adapter.describeUrl(target(), fallback), 'http://192.168.1.50:8123/api/hassio/core/logs');
  assert.equal(
    adapter.describeUrl(target({ endpoint: '/ha/api/error_log', tls: true, port: 443 }), fallback),
    'https://192.168.1.50:443/ha/api/error_log'
  );
  assert.equal(adapter.describeUrl(target({ ip: 'fd00::50' }), null), 'http://[fd00::50]:8123/api/error_log');
});
