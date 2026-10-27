/**
 * Role gates on /api/settings. app.ts mounts the router behind `authenticate`;
 * each route then picks its roles. GET / (every system_settings row) used to
 * have no role gate, so a viewer could read the stored API keys' encrypted
 * envelopes: it is admin-only now, like the other settings reads. GET /syslog
 * stays open to every role: it returns only the syslog host and port.
 *
 * Every gate in front of each route's handler runs as every role against the
 * real route stack. Hermetic: the database pool is mocked to throw, so nothing
 * here can reach Postgres. A route added to routes/settings.ts fails the
 * "every route is classified" test until it gets a line in ROUTES with the
 * roles it should allow, so a new read can't come in ungated the way GET / did.
 * Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import type { Router } from 'express';
import pool from '../config/database';
import { ApiError } from '../middleware/errorHandler';
import settingsRouter from './settings';

const SQL_MUST_NOT_RUN = 'SQL must not run in settingsRouteGates.test.ts';
const poolQuery = mock.method(pool, 'query', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});
const poolConnect = mock.method(pool, 'connect', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});

type Role = 'admin' | 'operator' | 'analyst' | 'viewer';
const ROLES: Role[] = ['admin', 'operator', 'analyst', 'viewer'];
const ANY_ROLE: Role[] = ROLES;
const ADMIN_ONLY: Role[] = ['admin'];

/** [method, path, roles allowed] */
const ROUTES: Array<[method: string, path: string, allowed: Role[]]> = [
  // Every system_settings row (stored credentials redacted even for admins).
  ['get', '/', ADMIN_ONLY],
  // AI builder, AI Analyst and AI Triage: provider, model, and whether a key is set.
  ['get', '/ai', ADMIN_ONLY],
  ['put', '/ai', ADMIN_ONLY],
  ['get', '/ai-chat', ADMIN_ONLY],
  ['put', '/ai-chat', ADMIN_ONLY],
  ['get', '/ai-triage', ADMIN_ONLY],
  ['put', '/ai-triage', ADMIN_ONLY],
  // AI budgets: output-token caps, lookups and time budgets.
  ['get', '/ai-budgets', ADMIN_ONLY],
  ['put', '/ai-budgets', ADMIN_ONLY],
  // Data retention
  ['get', '/retention', ADMIN_ONLY],
  ['put', '/retention', ADMIN_ONLY],
  ['get', '/context-graph', ADMIN_ONLY],
  ['put', '/context-graph', ADMIN_ONLY],
  ['get', '/applications', ADMIN_ONLY],
  ['put', '/applications', ADMIN_ONLY],
  ['post', '/retention/cleanup', ADMIN_ONLY],
  ['get', '/retention/cleanup/status', ADMIN_ONLY],
  ['get', '/retention/stats', ADMIN_ONLY],
  // Syslog receiver: host and port only, no secret.
  ['get', '/syslog', ANY_ROLE],
  ['put', '/syslog', ADMIN_ONLY],
  ['get', '/syslog/status', ADMIN_ONLY],
  // Trusted IPs (detection whitelist)
  ['get', '/ip-whitelist', ADMIN_ONLY],
  ['post', '/ip-whitelist', ADMIN_ONLY],
  ['put', '/ip-whitelist/:id', ADMIN_ONLY],
  ['delete', '/ip-whitelist/:id', ADMIN_ONLY],
  ['post', '/ip-whitelist/check', ADMIN_ONLY],
  // Asset auto-discovery
  ['get', '/auto-discovery', ADMIN_ONLY],
  ['put', '/auto-discovery', ADMIN_ONLY],
  // Shipper scan-job expiry
  ['get', '/shipper-jobs', ADMIN_ONLY],
  ['put', '/shipper-jobs', ADMIN_ONLY],
  ['get', '/auto-discovery/stats', ADMIN_ONLY],
  // Getting Started completion: every role reads it (admins also see who); admins change it.
  ['get', '/onboarding', ANY_ROLE],
  ['put', '/onboarding', ADMIN_ONLY],
  // Public URL for links in notifications: admins read and change it.
  ['get', '/public-url', ADMIN_ONLY],
  ['put', '/public-url', ADMIN_ONLY],
];

type Handler = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
interface StackLayer {
  name: string;
  handle: Handler;
  route?: { path: string; methods: Record<string, boolean>; stack: StackLayer[] };
}

function stackOf(router: Router): StackLayer[] {
  return (router as unknown as { stack: StackLayer[] }).stack;
}

/** The middleware in front of a route's handler: its role gates. */
function gatesOf(method: string, path: string): Handler[] {
  const layer = stackOf(settingsRouter).find((l) => l.route && l.route.path === path && l.route.methods[method]);
  assert.ok(layer?.route, `route ${method.toUpperCase()} ${path} exists`);
  return layer.route.stack.slice(0, -1).map((l) => l.handle);
}

/** Run one gate for a logged-in `role`: resolves with what it passed to next(). */
function runGate(gate: Handler, role: Role, method: string, path: string): Promise<unknown> {
  const req = {
    user: { id: 1, username: `gate-${role}`, email: `gate-${role}@siembox.invalid`, role },
    method: method.toUpperCase(),
    path,
    headers: {},
    params: {},
    query: {},
    body: {},
  };
  return new Promise((resolve, reject) => {
    let called = false;
    const next = (err?: unknown) => {
      called = true;
      resolve(err);
    };
    Promise.resolve(gate(req, {}, next)).then(() => {
      if (!called) reject(new Error('the gate returned without calling next()'));
    }, reject);
  });
}

/** 'pass' if every gate lets `role` through, else the status of the first rejection. */
async function outcomeFor(method: string, path: string, role: Role): Promise<'pass' | number> {
  for (const gate of gatesOf(method, path)) {
    const err = await runGate(gate, role, method, path);
    if (err === undefined) continue;
    assert.ok(err instanceof ApiError, `the gate rejects with an ApiError, not ${String(err)}`);
    return err.statusCode;
  }
  return 'pass';
}

test('/api/settings: no router-level middleware (each route gates itself)', () => {
  assert.deepEqual(
    stackOf(settingsRouter).filter((l) => !l.route).map((l) => l.name),
    [],
    'a router.use() here would apply to every route'
  );
});

test('/api/settings: every route is classified, so a new route cannot slip in ungated', () => {
  const known = new Set(ROUTES.map(([method, path]) => `${method} ${path}`));
  for (const layer of stackOf(settingsRouter)) {
    for (const method of Object.keys(layer.route?.methods ?? {})) {
      assert.ok(
        known.has(`${method} ${layer.route!.path}`),
        `unclassified route ${method.toUpperCase()} /api/settings${layer.route!.path}: add it to ROUTES with the roles it should allow`
      );
    }
  }
});

for (const [method, path, allowed] of ROUTES) {
  const who = allowed === ANY_ROLE ? 'any role' : allowed.join(', ');
  test(`${method.toUpperCase()} /api/settings${path === '/' ? '' : path}: ${who}`, async () => {
    for (const role of ROLES) {
      const outcome = await outcomeFor(method, path, role);
      if (allowed.includes(role)) assert.equal(outcome, 'pass', `${role} is let through`);
      else assert.equal(outcome, 403, `${role} is refused with 403`);
    }
  });
}

// Keep last: proves the file stayed hermetic.
test('nothing in this file reached the database', () => {
  assert.equal(poolQuery.mock.callCount(), 0, 'no query may run');
  assert.equal(poolConnect.mock.callCount(), 0, 'no connection may be opened');
});
