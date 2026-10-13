/**
 * httpFetch over real HTTP on 127.0.0.1: which end of a long body is kept
 * (keep: 'head' for JSON APIs, 'tail' for logs), multi-byte characters split
 * across chunks, and the Home Assistant adapter reading the END of a log file
 * larger than its 5 MB cap -- from a server that honours the byte Range (206,
 * like Home Assistant's aiohttp FileResponse), one that ignores it (200, the
 * whole file), and an empty file (416). Only local servers this file starts.
 * Run with `npm test` (tsx --test).
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { httpFetch } from './httpFetch';
import { makeHomeAssistantAdapter, LOG_MAX_BYTES, windowReadBytes } from './adapters/homeAssistant';
import { PollTarget } from './types';

const servers: http.Server[] = [];
after(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
});

async function serve(handler: http.RequestListener): Promise<number> {
  const server = http.createServer(handler);
  servers.push(server);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return (server.address() as AddressInfo).port;
}

/** Writes `parts` one by one, a few ms apart, so they reach the client as separate chunks. */
function slowly(parts: Buffer[]): http.RequestListener {
  return async (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    for (const part of parts) {
      res.write(part);
      await new Promise((resolve) => setTimeout(resolve, 15));
    }
    res.end();
  };
}

test("keep: 'tail' keeps the last maxBytes of a longer body and says it was cut; the default keeps the first", async () => {
  const body = Buffer.from(Array.from({ length: 50 }, (_, i) => `line ${String(i).padStart(2, '0')}`).join('\n'));
  const port = await serve(slowly([body.subarray(0, 200), body.subarray(200, 300), body.subarray(300)]));
  const url = `http://127.0.0.1:${port}/`;

  const tail = await httpFetch(url, { maxBytes: 64, keep: 'tail' });
  assert.equal(tail.body, body.subarray(body.length - 64).toString());
  assert.equal(tail.truncated, true);

  const head = await httpFetch(url, { maxBytes: 64 });
  assert.equal(head.body, body.subarray(0, 64).toString());
  assert.equal(head.truncated, true);

  const whole = await httpFetch(url, { maxBytes: 4096, keep: 'tail' });
  assert.equal(whole.body, body.toString());
  assert.equal(whole.truncated, false);
});

test('a multi-byte character split across two chunks is decoded whole', async () => {
  const text = 'Küche: Bewegungsmelder ausgelöst';
  const bytes = Buffer.from(text);
  const split = bytes.indexOf(Buffer.from('ü')) + 1; // between the two bytes of "ü"
  const port = await serve(slowly([bytes.subarray(0, split), bytes.subarray(split)]));
  assert.equal((await httpFetch(`http://127.0.0.1:${port}/`)).body, text);
});

// ---------------------------------------------------------------------------
// Home Assistant: a log file larger than LOG_MAX_BYTES
// ---------------------------------------------------------------------------

function infoLine(i: number): string {
  const time = new Date(Date.UTC(2026, 9, 12, 8) + i * 10).toISOString().replace('T', ' ').slice(0, 23);
  return `${time} INFO (MainThread) [homeassistant.components.sensor] Updating sensor.power_${i} from the integration's polling loop`;
}

const BAN_LINE =
  "2026-10-12 23:59:59.999 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from 198.51.100.7 (198.51.100.7). Requested URL: '/auth/login_flow'. (curl/8.5.0)";

/** A fake Home Assistant serving `lines` as home-assistant.log at /api/error_log, like aiohttp's FileResponse when honourRange. */
async function fakeLogFile(lines: string[], honourRange: boolean) {
  const ranges: string[] = [];
  const port = await serve((req, res) => {
    ranges.push(String(req.headers.range ?? '-'));
    const file = Buffer.from(lines.length ? lines.join('\n') + '\n' : '');
    const suffix = /^bytes=-(\d+)$/.exec(String(req.headers.range ?? ''));
    if (honourRange && suffix) {
      if (file.length === 0) return void res.writeHead(416, { 'Content-Range': 'bytes */0' }).end();
      const start = Math.max(0, file.length - Number(suffix[1]));
      res.writeHead(206, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Range': `bytes ${start}-${file.length - 1}/${file.length}` });
      return void res.end(file.subarray(start));
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(file);
  });
  return { port, ranges };
}

function haTarget(port: number): PollTarget {
  return {
    sourceId: 1,
    ip: '127.0.0.1',
    port,
    openPorts: [port],
    evidence: {},
    logAccess: { method: 'api_pull', endpoint: '/api/error_log', auth: 'bearer_token', target_port: 8123 },
  };
}

const CRED = { username: null, secret: 'llat-token' };

for (const honourRange of [true, false]) {
  test(`a log file over ${LOG_MAX_BYTES / 1024 / 1024} MB keeps being read at its end (${honourRange ? '206 to the byte Range' : 'the server ignores Range: 200 with the whole file'})`, async () => {
    const lines: string[] = [];
    while (lines.length * 110 < LOG_MAX_BYTES * 1.2) lines.push(infoLine(lines.length));
    const ha = await fakeLogFile(lines, honourRange);
    const adapter = makeHomeAssistantAdapter();

    const first = await adapter.fetchEvents(haTarget(ha.port), CRED, null);
    assert.deepEqual(
      first.events.map((e) => e.message),
      lines.slice(-200),
      'the first poll: the last 200 lines of the file, not of its first 5 MB'
    );

    lines.push(BAN_LINE);
    const next = await adapter.fetchEvents(haTarget(ha.port), CRED, first.nextCursor);
    assert.deepEqual(
      next.events.map((e) => e.message),
      [BAN_LINE],
      'the line written after the 5 MB mark is collected'
    );
    assert.deepEqual(ha.ranges, [`bytes=-${LOG_MAX_BYTES}`, `bytes=-${LOG_MAX_BYTES + windowReadBytes(first.nextCursor)}`], "then the window's bytes too");
  });
}

test('an empty log file: the 416 to the byte Range is followed by a plain request, and the poll is ok with no lines', async () => {
  const ha = await fakeLogFile([], true);
  const result = await makeHomeAssistantAdapter().fetchEvents(haTarget(ha.port), CRED, null);
  assert.deepEqual(result.events, []);
  assert.deepEqual(ha.ranges, [`bytes=-${LOG_MAX_BYTES}`, '-']);
});
