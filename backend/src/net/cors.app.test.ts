/**
 * The real app (app.ts) with CORS_ORIGIN unset: same-origin only. A page on
 * another origin gets no CORS headers, and its preflight before a JSON sign-in
 * gets no allow answer, so the browser never sends the sign-in.
 *
 * Hermetic: before app.ts (and so config/database.ts) is loaded, DB_HOST and
 * DB_PORT point at a local port nothing listens on; nothing here reaches SQL
 * (preflights are answered before any route, /health reads no table). Run with
 * `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';

let server: http.Server | undefined;
let port = 0;
let closePools: (() => Promise<void>) | undefined;
let mode: string | undefined;

before(async () => {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const closedPort = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(closedPort);
  delete process.env.CORS_ORIGIN;

  closePools = (await import('../config/database')).closePools;
  const appModule = await import('../app');
  mode = appModule.corsPolicy.mode;
  server = appModule.default.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await closePools?.();
});

/** Sent with node:http, which passes the Origin header through as given. */
function call(method: string, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

function acHeaders(res: { headers: http.IncomingHttpHeaders }): string[] {
  return Object.keys(res.headers).filter((name) => name.startsWith('access-control-'));
}

test('app.ts: CORS_ORIGIN unset is same-origin only', async () => {
  assert.equal(mode, 'same-origin');

  const pre = await call('OPTIONS', '/api/auth/login', {
    Origin: 'http://evil.example',
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'content-type',
  });
  assert.equal(pre.status, 204);
  assert.deepEqual(acHeaders(pre), [], 'no allow answer to a preflight from another origin');

  const health = await call('GET', '/health', { Origin: 'http://evil.example' });
  assert.equal(health.status, 200);
  assert.deepEqual(acHeaders(health), []);
  assert.equal(health.headers.vary, undefined);
});
