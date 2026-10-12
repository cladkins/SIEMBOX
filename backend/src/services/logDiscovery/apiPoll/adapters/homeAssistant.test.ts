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

interface Call {
  url: string;
  headers: Record<string, string>;
}
type Reply = { status: number; body?: string; contentType?: string };

/** A fake Home Assistant: answers per path (404 for anything unlisted) and records every request. */
function fakeHomeAssistant(routes: Record<string, Reply>) {
  const calls: Call[] = [];
  const fetch = async (url: string, opts: HttpFetchOptions = {}): Promise<HttpFetchResult> => {
    calls.push({ url, headers: { ...(opts.headers || {}) } });
    const reply = routes[new URL(url).pathname] ?? { status: 404, body: '404: Not Found' };
    return {
      status: reply.status,
      body: reply.body ?? '',
      headers: { 'content-type': reply.contentType ?? 'text/plain; charset=utf-8' },
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

test('auto: /api/error_log answers -> one request, the exact URL and headers as before, lines verbatim, plain-text cursor', async () => {
  const ha = fakeHomeAssistant({ [FILE]: { status: 200, body: HA_LINES.join('\n') + '\n' } });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, null);

  assert.equal(ha.calls.length, 1);
  assert.equal(ha.calls[0].url, 'http://192.168.1.50:8123/api/error_log');
  assert.deepEqual(ha.calls[0].headers, { Authorization: 'Bearer llat-token' });
  assert.deepEqual(messages(result), HA_LINES);
  assert.equal(result.nextCursor, HA_LINES.slice(-3).join('\n'), 'the cursor keeps its plain-text tail-window form');
});

test('auto: a 404 from /api/error_log falls back to the Supervisor endpoint (no_colors, Range for the latest 500)', async () => {
  const ha = fakeHomeAssistant({
    [FILE]: { status: 404, body: '404: Not Found' },
    [SUPERVISOR]: { status: 200, body: HA_LINES.map(colored).join('\n') },
  });
  const result = await adapterAt(T0, ha).fetchEvents(target(), CRED, null);

  assert.deepEqual(ha.paths(), [FILE, SUPERVISOR]);
  assert.equal(ha.calls[1].url, 'http://192.168.1.50:8123/api/hassio/core/logs?no_colors');
  assert.deepEqual(ha.calls[1].headers, { Authorization: 'Bearer llat-token', Range: 'entries=:-499:500' });
  assert.deepEqual(messages(result), HA_LINES, 'native lines: colour codes removed, nothing else changed');
  assert.ok(result.events.every((e) => !e.message.includes(ESC)));

  const cursor = JSON.parse(result.nextCursor!);
  assert.deepEqual(cursor, {
    ha_log_endpoint: 'supervisor',
    error_log_checked_at: new Date(T0).toISOString(),
    tail: HA_LINES.slice(-3).join('\n'),
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
  assert.equal(ha.calls[0].headers.Range, 'entries=:-499:500');
  assert.deepEqual(messages(result), HA_LINES);
  assert.equal(result.nextCursor, HA_LINES.slice(-3).join('\n'));
});

test('an admin-set path behind a reverse proxy keeps its prefix; .../logs/latest gets ?lines (it ignores Range)', async () => {
  const proxied = fakeHomeAssistant({ '/ha/api/hassio/core/logs': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, proxied).fetchEvents(target({ endpoint: '/ha/api/hassio/core/logs' }), CRED, null);
  assert.equal(proxied.calls[0].url, 'http://192.168.1.50:8123/ha/api/hassio/core/logs?no_colors');
  assert.equal(proxied.calls[0].headers.Range, 'entries=:-499:500');

  const latest = fakeHomeAssistant({ '/api/hassio/core/logs/latest': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, latest).fetchEvents(target({ endpoint: '/api/hassio/core/logs/latest' }), CRED, null);
  assert.equal(latest.calls[0].url, 'http://192.168.1.50:8123/api/hassio/core/logs/latest?no_colors&lines=500');

  const file = fakeHomeAssistant({ '/homeassistant/api/error_log': { status: 200, body: HA_LINES[0] } });
  await adapterAt(T0, file).fetchEvents(target({ endpoint: '/homeassistant/api/error_log' }), CRED, null);
  assert.deepEqual(file.calls[0].headers, { Authorization: 'Bearer llat-token' }, 'a file path gets no Range header');
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
