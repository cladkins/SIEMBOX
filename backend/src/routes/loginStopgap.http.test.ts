/**
 * The interim sign-in limit on POST /api/auth/login (routes/auth.ts):
 *
 * - 10 failed attempts per account per 15 minutes from one client address (an
 *   IPv6 client's /64), then a JSON 429 for that account only, so someone who
 *   shares your address can't lock every user out with a burst of bad
 *   sign-ins;
 * - 100 failed attempts per address across all accounts, after which an
 *   account that already failed from that address is refused, while accounts
 *   that haven't can still sign in;
 * - a 5xx is not a failed sign-in (no password was checked), so a database
 *   outage doesn't use the budget up.
 *
 * A body without a password fails validation (400), which counts as a failure
 * and needs no database; with the database unreachable, a full body gets a
 * 500. Successful sign-ins are checked against Postgres in
 * loginStopgap.db.test.ts.
 *
 * Hermetic like routeAuth.http.test.ts: the database points at a closed port.
 * In a file of its own because the limiter's counters live in the process.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

let tcp: http.Server | undefined;
let socketServer: http.Server | null = null;
let port = 0;
let socketPath = '';
let dir = '';
let closePools: (() => Promise<void>) | undefined;

before(async () => {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const dbPort = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(dbPort);
  const db = await import('../config/database');
  closePools = db.closePools;
  const app = (await import('../app')).default;
  const { createApiServer, listenProxySocket } = await import('../net/apiListeners');
  tcp = createApiServer(app);
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  port = (tcp.address() as AddressInfo).port;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-stopgap-'));
  socketPath = path.join(dir, 'api.sock');
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;
  socketServer = (await listenProxySocket(app, socketPath, quiet)).server;
  assert.ok(socketServer);
});

after(async () => {
  for (const server of [tcp, socketServer]) {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  await closePools?.();
});

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  json: Record<string, unknown>;
}

/** POST /api/auth/login with `body`, straight over TCP or through the proxy socket as `forwardedFor`. */
function login(via: 'tcp' | 'socket', forwardedFor?: string, body: Record<string, unknown> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        method: 'POST',
        path: '/api/auth/login',
        agent: false,
        headers: { 'Content-Type': 'application/json', ...(forwardedFor ? { 'X-Forwarded-For': forwardedFor } : {}) },
        ...(via === 'tcp' ? { host: '127.0.0.1', port } : { socketPath }),
      },
      (res) => {
        let text = '';
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, json: JSON.parse(text) }));
      }
    );
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

function assertRefused(reply: Reply, message: RegExp) {
  assert.equal(reply.status, 429);
  assert.equal(reply.json.code, 'RATE_LIMITED');
  assert.equal(reply.json.statusCode, 429);
  assert.match(String(reply.json.message), message);
  const retryAfter = Number(reply.headers['retry-after']);
  assert.ok(retryAfter > 0 && retryAfter <= 900, `Retry-After ${reply.headers['retry-after']}`);
  assert.equal(reply.json.retryAfter, retryAfter);
}

const ACCOUNT_REFUSED = /^Too many failed sign-in attempts for this account from your address\. Try again in \d+ minutes?\.$/;
const ADDRESS_REFUSED = /^Too many failed sign-in attempts from your address\. Try again in \d+ minutes?\.$/;

test('ten failed sign-ins for one account from one address, then 429 with Retry-After', async () => {
  const statuses: number[] = [];
  let last: Reply | undefined;
  for (let i = 0; i < 11; i++) {
    // Rotating X-Forwarded-For on a direct call changes nothing.
    last = await login('tcp', `198.51.100.${i + 1}`, { username: 'alice' });
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 429]);
  assertRefused(last!, ACCOUNT_REFUSED);
  // The username as typed, trimmed and in any case, is the same account.
  assertRefused(await login('tcp', undefined, { username: ' ALICE ' }), ACCOUNT_REFUSED);
});

test('other accounts from that address are not locked out', async () => {
  assert.equal((await login('tcp', undefined, { username: 'bob' })).status, 400);
  assert.equal((await login('tcp', undefined, {})).status, 400);
});

test('the limit is per client address: other clients behind nginx are unaffected', async () => {
  assert.equal((await login('socket', '203.0.113.70', { username: 'alice' })).status, 400);
});

test('an IPv6 client is limited per /64, whichever addresses it picks inside it', async () => {
  const statuses: number[] = [];
  for (let i = 1; i <= 11; i++) {
    statuses.push((await login('socket', `2001:db8:1:2::${i.toString(16)}`, { username: 'alice' })).status);
  }
  assert.deepEqual(statuses.slice(0, 10), new Array(10).fill(400));
  assert.equal(statuses[10], 429);
  assert.equal((await login('socket', '2001:db8:1:3::1', { username: 'alice' })).status, 400, 'the next /64 is another client');
});

test('after 100 failures from one address, only accounts that already failed there are refused', async () => {
  const client = '203.0.113.80';
  for (let i = 0; i < 100; i++) {
    const reply = await login('socket', client, { username: `spray-${i}` });
    assert.equal(reply.status, 400, `failure ${i + 1}`);
  }
  assertRefused(await login('socket', client, { username: 'spray-0' }), ADDRESS_REFUSED);
  // An account without a failure from this address still gets its attempt...
  assert.equal((await login('socket', client, { username: 'carol' })).status, 400);
  // ...and once that one has failed, it is refused too.
  assertRefused(await login('socket', client, { username: 'carol' }), ADDRESS_REFUSED);
  // Other addresses are not affected.
  assert.equal((await login('socket', '203.0.113.81', { username: 'spray-0' })).status, 400);
});

test('a 5xx is not a failed sign-in: an unreachable database does not use up the budget', async () => {
  const statuses: number[] = [];
  for (let i = 0; i < 11; i++) {
    statuses.push((await login('socket', '203.0.113.90', { username: 'dave', password: 'secret' })).status);
  }
  assert.deepEqual(statuses, new Array(11).fill(500), 'the eleventh is answered, not refused');
});
