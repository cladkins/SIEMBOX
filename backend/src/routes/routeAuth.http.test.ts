/**
 * HTTP-level check against the real Express app (app.ts with every router and
 * middleware) on an ephemeral port. Without a login, shipper management, asset
 * and vulnerability routes answer 401, and the shipper agent's key-authenticated
 * endpoints still do not ask for one. No database needed: `authenticate` rejects
 * a request that has no Bearer token before any query, and the shipper-facing
 * probes below fail validation before they reach the database.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import { authenticate } from '../middleware/auth';
import { closePools } from '../config/database';

let server: Server;
let base = '';

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await closePools();
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
  // Assets (every read; writes were already gated)
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
  // Vulnerabilities (every read; writes were already gated)
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

/**
 * Names of the middleware app.ts mounts for `path` (path-less global middleware
 * excluded). Compared by name because express-async-errors, which app.ts loads,
 * wraps every layer's handle, so the function objects differ.
 */
function mountNames(path: string): string[] {
  return (app as any)._router.stack
    .filter((l: any) => !l.regexp.fast_slash && l.regexp.test(path))
    .map((l: any) => l.name);
}

test('app.ts mounts /api/assets and /api/vulnerabilities behind authenticate', () => {
  assert.ok(mountNames('/api/assets').includes(authenticate.name));
  assert.ok(mountNames('/api/vulnerabilities').includes(authenticate.name));
});

test('app.ts does not mount /api/shippers behind authenticate (shippers use their key)', () => {
  assert.ok(!mountNames('/api/shippers').includes(authenticate.name));
});
