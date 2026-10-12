/**
 * The interim sign-in limit on POST /api/auth/login: 10 failed attempts per
 * 15 minutes per client address (an IPv6 client's /64), then a JSON 429.
 * A body without credentials fails validation (400), which counts as a
 * failure and needs no database. That successful sign-ins are not counted is
 * checked against Postgres in loginStopgap.db.test.ts.
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

function login(via: 'tcp' | 'socket', forwardedFor?: string) {
  const body = '{}';
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; json: Record<string, unknown> }>(
    (resolve, reject) => {
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
      req.end(body);
    }
  );
}

test('ten failed sign-ins from one address, then 429 with Retry-After', async () => {
  const statuses: number[] = [];
  let last;
  for (let i = 0; i < 11; i++) {
    // Rotating X-Forwarded-For on a direct call changes nothing.
    last = await login('tcp', `198.51.100.${i + 1}`);
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [400, 400, 400, 400, 400, 400, 400, 400, 400, 400, 429]);
  assert.equal(last!.json.code, 'RATE_LIMITED');
  assert.equal(last!.json.statusCode, 429);
  assert.match(String(last!.json.message), /^Too many failed sign-in attempts from your address\. Try again in \d+ minutes?\.$/);
  const retryAfter = Number(last!.headers['retry-after']);
  assert.ok(retryAfter > 0 && retryAfter <= 900);
  assert.equal(last!.json.retryAfter, retryAfter);
});

test('the limit is per client address: other clients behind nginx are unaffected', async () => {
  assert.equal((await login('socket', '203.0.113.70')).status, 400);
});

test('an IPv6 client is limited per /64, whichever addresses it picks inside it', async () => {
  const statuses: number[] = [];
  for (let i = 1; i <= 11; i++) statuses.push((await login('socket', `2001:db8:1:2::${i.toString(16)}`)).status);
  assert.deepEqual(statuses.slice(0, 10), new Array(10).fill(400));
  assert.equal(statuses[10], 429);
  assert.equal((await login('socket', '2001:db8:1:3::1')).status, 400, 'the next /64 is another client');
});
