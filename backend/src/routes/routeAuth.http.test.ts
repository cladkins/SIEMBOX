/**
 * HTTP-level check against the real Express app (app.ts with every router and
 * middleware) on an ephemeral port. Without a login, shipper management, asset,
 * vulnerability, settings and scan routes answer 401, and the shipper agent's
 * key-authenticated endpoints still do not ask for one. Also checks how the app
 * reads bodies (size limits, undecodable compressed bodies) and query strings.
 *
 * Hermetic: before app.ts (and so config/database.ts) is loaded, DB_HOST and
 * DB_PORT are pointed at a local port nothing listens on, and before() checks
 * that the pool really uses it. `authenticate` rejects a request that has no
 * Bearer token before any query, and the shipper-facing probes fail validation
 * first; if a gate ever regresses, the request cannot reach Postgres, so the test
 * fails instead of writing to the developer's database.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import net from 'node:net';
import zlib from 'node:zlib';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Application } from 'express';

// Anything that loads config/database.ts is imported in before(), once the
// environment points at the closed port: a static import here would build the
// pool from the real settings first.
let app: Application;
let authenticateName = '';
let closePools: (() => Promise<void>) | undefined;
let server: Server | undefined;
let base = '';

/** A local TCP port that nothing listens on (bound, then released). */
async function closedPort(): Promise<number> {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

before(async () => {
  const port = await closedPort();
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(port);
  const db = await import('../config/database');
  closePools = db.closePools;
  const { host, port: poolPort } = (db.default as unknown as { options: { host?: string; port?: number } }).options;
  assert.deepEqual({ host, port: poolPort }, { host: '127.0.0.1', port }, 'the pool must point at the closed port');
  authenticateName = (await import('../middleware/auth')).authenticate.name;
  app = (await import('../app')).default;
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await closePools?.();
});

async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  // API errors are { status: 'error', statusCode, message } (middleware/errorHandler.ts).
  const json = (await res.json().catch(() => null)) as { message?: string } | null;
  return { status: res.status, message: json?.message };
}

const LOGIN_REQUIRED: Array<[string, string, unknown?]> = [
  // Shipper management (every route)
  ['GET', '/api/shippers'],
  ['GET', '/api/shippers/unknown-sources'],
  ['GET', '/api/shippers/direct-syslog-sources'],
  ['GET', '/api/shippers/1'],
  ['POST', '/api/shippers', { name: 'x' }],
  ['PUT', '/api/shippers/1', { name: 'x' }],
  ['DELETE', '/api/shippers/1'],
  ['GET', '/api/shippers/1/sources'],
  ['POST', '/api/shippers/1/sources', { source_type: 'file', tag: 't' }],
  ['PUT', '/api/shippers/sources/1', { enabled: false }],
  ['DELETE', '/api/shippers/sources/1'],
  ['GET', '/api/shippers/1/volumes'],
  ['POST', '/api/shippers/1/volumes', { host_path: '/a', container_path: '/b' }],
  ['DELETE', '/api/shippers/volumes/1'],
  ['GET', '/api/shippers/1/activity'],
  ['POST', '/api/shippers/1/regenerate-key'],
  ['POST', '/api/shippers/1/http-push-key'],
  ['DELETE', '/api/shippers/1/http-push-key'],
  // Assets (every route; writes also check the role)
  ['GET', '/api/assets'],
  ['GET', '/api/assets/statistics'],
  ['GET', '/api/assets/scans/active'],
  ['GET', '/api/assets/scans/statistics'],
  ['GET', '/api/assets/scans'],
  ['GET', '/api/assets/scans/1'],
  ['GET', '/api/assets/1'],
  ['GET', '/api/assets/1/related'],
  ['GET', '/api/assets/1/services'],
  ['POST', '/api/assets/scan', { targets: ['192.0.2.1'] }],
  ['POST', '/api/assets', { ip_address: '192.0.2.1' }],
  ['PUT', '/api/assets/1', { hostname: 'x' }],
  ['DELETE', '/api/assets/1'],
  ['POST', '/api/assets/discover'],
  // Vulnerabilities (every route; writes also check the role)
  ['GET', '/api/vulnerabilities/summary'],
  ['GET', '/api/vulnerabilities/templates'],
  ['GET', '/api/vulnerabilities/templates/categories'],
  ['GET', '/api/vulnerabilities/templates/tags'],
  ['GET', '/api/vulnerabilities/templates/search?q=ssh'],
  ['GET', '/api/vulnerabilities/templates/category/cves'],
  ['GET', '/api/vulnerabilities/templates/tag/cve'],
  ['GET', '/api/vulnerabilities/templates/severity/high'],
  ['GET', '/api/vulnerabilities/scans/active'],
  ['GET', '/api/vulnerabilities/scans'],
  ['GET', '/api/vulnerabilities/scans/1'],
  ['GET', '/api/vulnerabilities/scans/1/status'],
  ['GET', '/api/vulnerabilities'],
  ['GET', '/api/vulnerabilities/1'],
  ['GET', '/api/vulnerabilities/asset/1'],
  ['PATCH', '/api/vulnerabilities/1/1', { status: 'resolved' }],
  ['POST', '/api/vulnerabilities/templates/refresh'],
  ['POST', '/api/vulnerabilities/templates/download'],
  ['POST', '/api/vulnerabilities/scans', { target: '192.0.2.1' }],
  ['POST', '/api/vulnerabilities/scans/1/cancel'],
  // Settings reads (every route; all but /syslog also need admin, see settingsRouteGates.test.ts)
  ['GET', '/api/settings'],
  ['GET', '/api/settings/syslog'],
  // Scan routers mounted behind authenticate (writes also check the role)
  ['GET', '/api/scheduled-scans'],
  ['POST', '/api/scheduled-scans', { name: 'x', scan_type: 'asset', scan_options: { targets: ['192.0.2.1'] }, interval_minutes: 60 }],
  ['PUT', '/api/scheduled-scans/1', { enabled: false }],
  ['DELETE', '/api/scheduled-scans/1'],
  ['POST', '/api/scheduled-scans/1/run'],
  ['POST', '/api/log-discovery/scans', { mode: 'passive' }],
  ['POST', '/api/log-discovery/scans/1/cancel'],
  ['POST', '/api/log-discovery/sources/1/confirm'],
  ['POST', '/api/log-discovery/sources/1/ignore'],
  ['POST', '/api/log-discovery/sources/1/onboard/confirm', { confirm: true }],
  ['PATCH', '/api/log-discovery/sources/1', { port: 8123 }],
  ['POST', '/api/containers/scan', { image_ref: 'nginx:latest' }],
  // Getting Started completion (any role reads it; admins change it)
  ['GET', '/api/settings/onboarding'],
  ['PUT', '/api/settings/onboarding', { completed: true }],
  // The HIBP key's verified domains (admin-only account data)
  ['GET', '/api/exposure/providers/hibp/verified-domains'],
  ['POST', '/api/exposure/providers/hibp/verified-domains/refresh'],
];

for (const [method, path, body] of LOGIN_REQUIRED) {
  test(`${method} ${path} without a login is 401`, async () => {
    const r = await call(method, path, body);
    assert.equal(r.status, 401);
    assert.equal(r.message, 'Authentication required');
  });
}

// Shipper-facing endpoints: an empty body fails key validation (400) before any
// lookup. The point is that no login is demanded first.
for (const path of ['/api/shippers/register', '/api/shippers/containers', '/api/shippers/scan-results', '/api/shippers/discovery-results']) {
  test(`POST ${path} does not require a login (key-authenticated)`, async () => {
    const r = await call('POST', path, {});
    assert.equal(r.status, 400);
    assert.equal(r.message, 'API key is required');
  });
}

test('POST /api/shippers/logs asks for the HTTP push key, not a login', async () => {
  const r = await call('POST', '/api/shippers/logs', { message: 'x' });
  assert.equal(r.status, 401);
  assert.match(r.message ?? '', /X-Shipper-ID \+ Bearer key/);
});

test('login and the health check stay reachable without a login', async () => {
  assert.equal((await call('GET', '/health')).status, 200);
  const login = await call('POST', '/api/auth/login', {});
  assert.equal(login.status, 400, 'missing credentials is a validation error, not an auth wall');
  assert.equal(login.message, 'Username and password are required');
});

test('sign-in fields that are not what the SPA sends are a 400 before any database access, never a 500', async () => {
  // A non-string password used to reach bcrypt, which threw: a 500 and an
  // application_errors row per request.
  for (const body of [
    { username: 'admin', password: 123 },
    { username: 'admin', password: true },
    { username: ['admin'], password: 'x' },
    { username: 'admin', password: { $gt: '' } },
    { username: 'admin', password: 'x', code: true },
    { username: 'admin', password: 'x'.repeat(1025) },
    { username: 'a'.repeat(256), password: 'x' },
  ]) {
    const r = await call('POST', '/api/auth/login', body);
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 80));
    assert.equal(r.message, 'Username and password are required');
  }
});

test('/api/auth answers are never cached', async () => {
  for (const [method, path, body] of [
    ['POST', '/api/auth/login', {}],
    ['GET', '/api/auth/me', undefined],
  ] as const) {
    const res = await fetch(base + path, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.equal(res.headers.get('cache-control'), 'no-store', path);
  }
});

test('a /api/auth body over 16 kB is refused with 413, JSON or form-encoded', async () => {
  const password = 'x'.repeat(20 * 1024);
  for (const [type, body] of [
    ['application/json', JSON.stringify({ username: 'a', password })],
    ['application/x-www-form-urlencoded', new URLSearchParams({ username: 'a', password }).toString()],
  ]) {
    const res = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': type }, body });
    assert.equal(res.status, 413, type);
    assert.equal(((await res.json()) as { message?: string }).message, 'Request body is too large');
  }
});

test('the 16 kB cap is only for /api/auth: other routes keep the general limit', async () => {
  // Fails key validation (400) after parsing, rather than 413 before it.
  const r = await call('POST', '/api/shippers/register', { padding: 'x'.repeat(20 * 1024) });
  assert.equal(r.status, 400);
  assert.equal(r.message, 'API key is required');
});

test('a compressed body that does not decompress is a 400 (Brotli: 415 unread), not a 500 written to application_errors', async () => {
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  const logError = mock.method(ErrorLogService, 'logError', async () => undefined);
  try {
    const body = JSON.stringify({ username: 'admin', password: 'x' });
    // /api/auth reads bodies with its own 16 kB parsers; /api/rules with the
    // general ones, which run before authenticate.
    for (const path of ['/api/auth/login', '/api/rules']) {
      for (const [encoding, data] of [
        ['br', Buffer.from('not brotli at all')],
        ['br', zlib.brotliCompressSync(body).subarray(0, 5)],
        ['gzip', Buffer.from('not gzip at all')],
        ['gzip', zlib.gzipSync(body).subarray(0, 12)],
        ['deflate', Buffer.from('not deflate at all')],
      ] as const) {
        const res = await fetch(base + path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Encoding': encoding },
          body: data,
        });
        const message = ((await res.json()) as { message?: string }).message;
        if (encoding === 'br') {
          // Refused before any parser reads it (CVE-2026-111497, middleware/rejectBrotliBodies).
          assert.equal(res.status, 415, `${path} ${encoding}`);
          assert.match(String(message), /Brotli-encoded request bodies are not accepted/);
        } else {
          assert.equal(res.status, 400, `${path} ${encoding}`);
          assert.equal(message, 'Invalid request body');
        }
      }
    }
    assert.equal(logError.mock.callCount(), 0, 'no application_errors row');
  } finally {
    logError.mock.restore();
  }
});

test('query strings parse with qs as under Express 4, arrays of more than 20 entries included', () => {
  const parse = app.get('query parser fn') as (str: string) => Record<string, unknown>;
  const values = Array.from({ length: 25 }, (_, i) => String(i));
  assert.deepEqual(parse(values.map((v) => `limit=${v}`).join('&')).limit, values);
  assert.deepEqual(parse(values.map((v) => `search[]=${v}`).join('&')).search, values);
  assert.deepEqual(parse('a[21]=x').a, ['x']);
  assert.deepEqual(parse('filter[severity]=high&filter[status]=open').filter, { severity: 'high', status: 'open' });
  assert.equal(parse('q=a%20b').q, 'a b');
});

/**
 * Names of the middleware app.ts mounts for `path` (path-less global middleware
 * excluded).
 */
function mountNames(path: string): string[] {
  return (app as any).router.stack
    .filter((l: any) => !l.slash && l.match(path))
    .map((l: any) => l.name);
}

// The per-route role gates in these routers rely on the mount-level authenticate
// having set req.user.
for (const mount of ['/api/assets', '/api/vulnerabilities', '/api/scheduled-scans', '/api/log-discovery', '/api/containers', '/api/settings']) {
  test(`app.ts mounts ${mount} behind authenticate`, () => {
    assert.ok(mountNames(mount).includes(authenticateName));
  });
}

test('app.ts does not mount /api/shippers behind authenticate (shippers use their key)', () => {
  assert.ok(!mountNames('/api/shippers').includes(authenticateName));
});
