/**
 * Role gates on the scan and asset routers: /api/assets, /api/vulnerabilities,
 * /api/scheduled-scans, /api/log-discovery and /api/containers. app.ts mounts
 * each behind `authenticate`, so reads are open to any logged-in role. Each
 * write requires the roles of the UI page(s) that make that call (allowedRoles
 * in frontend/src/router/index.ts), so a viewer can no longer start, cancel or
 * schedule scans, change vulnerability status or edit the asset inventory
 * through the API. Admin-only log-discovery routes stay admin-only.
 *
 * Every gate in front of each route's handler runs as every role against the
 * real route stack; the scanPermissions gates must also write the denial to the
 * audit log. Hermetic: the database pool and AuditService.log are mocked, so
 * nothing here can reach Postgres. Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import type { Router } from 'express';
import pool from '../config/database';
import { AuditService } from '../services/audit/auditService';
import { ApiError } from '../middleware/errorHandler';
import assetsRouter from './assets';
import vulnerabilitiesRouter from './vulnerabilities';
import scheduledScansRouter from './scheduledScans';
import logDiscoveryRouter from './logDiscovery';
import containersRouter from './containers';

const SQL_MUST_NOT_RUN = 'SQL must not run in scanRouteGates.test.ts';
const poolQuery = mock.method(pool, 'query', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});
const poolConnect = mock.method(pool, 'connect', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});
const auditLog = mock.method(AuditService, 'log', async () => undefined);

type Role = 'admin' | 'operator' | 'analyst' | 'viewer';
const ROLES: Role[] = ['admin', 'operator', 'analyst', 'viewer'];

// Who may make a call: the roles of the UI page(s) that make it.
const ANY_ROLE: Role[] = ROLES;
/** Asset Inventory and Templates pages (admin, analyst, operator). */
const INVENTORY: Role[] = ['admin', 'analyst', 'operator'];
/** Log Discovery, Vulnerability Scanning and Management, Container Scanning, Scheduled Scans. */
const SCANNING: Role[] = ['admin', 'operator'];
const ADMIN_ONLY: Role[] = ['admin'];

/** [method, path, roles allowed, denial written to audit_logs] */
type Gate = [method: string, path: string, allowed: Role[], audited?: boolean];

const ROUTERS: Array<{ mount: string; router: Router; routes: Gate[] }> = [
  {
    mount: '/api/assets',
    router: assetsRouter,
    routes: [
      ['get', '/', ANY_ROLE],
      ['get', '/statistics', ANY_ROLE],
      ['get', '/scans/active', ANY_ROLE],
      ['get', '/scans/statistics', ANY_ROLE],
      ['get', '/scans', ANY_ROLE],
      ['get', '/scans/:scanId', ANY_ROLE],
      ['get', '/:id', ANY_ROLE],
      ['get', '/:id/related', ANY_ROLE],
      ['get', '/:id/services', ANY_ROLE],
      ['post', '/', INVENTORY, true],
      ['put', '/:id', INVENTORY, true],
      ['delete', '/:id', INVENTORY, true],
      ['post', '/scan', INVENTORY, true],
      ['post', '/discover', INVENTORY, true],
    ],
  },
  {
    mount: '/api/vulnerabilities',
    router: vulnerabilitiesRouter,
    routes: [
      ['get', '/summary', ANY_ROLE],
      ['get', '/templates', ANY_ROLE],
      ['get', '/templates/categories', ANY_ROLE],
      ['get', '/templates/tags', ANY_ROLE],
      ['get', '/templates/search', ANY_ROLE],
      ['get', '/templates/category/:categoryId', ANY_ROLE],
      ['get', '/templates/tag/:tag', ANY_ROLE],
      ['get', '/templates/severity/:severity', ANY_ROLE],
      ['get', '/scans/active', ANY_ROLE],
      ['get', '/scans', ANY_ROLE],
      ['get', '/scans/:scanId', ANY_ROLE],
      ['get', '/scans/:scanId/status', ANY_ROLE],
      ['get', '/', ANY_ROLE],
      ['get', '/:id', ANY_ROLE],
      ['get', '/asset/:assetId', ANY_ROLE],
      // Templates page (admin, analyst, operator) and Vulnerability Scanning (admin, operator).
      ['post', '/templates/refresh', INVENTORY, true],
      ['post', '/templates/download', SCANNING, true],
      ['post', '/scans', SCANNING, true],
      ['post', '/scans/:scanId/cancel', SCANNING, true],
      ['patch', '/:assetId/:vulnId', SCANNING, true],
    ],
  },
  {
    mount: '/api/scheduled-scans',
    router: scheduledScansRouter,
    routes: [
      ['get', '/', ANY_ROLE],
      ['post', '/', SCANNING, true],
      ['put', '/:id', SCANNING, true],
      ['delete', '/:id', SCANNING, true],
      ['post', '/:id/run', SCANNING, true],
    ],
  },
  {
    mount: '/api/log-discovery',
    router: logDiscoveryRouter,
    routes: [
      ['get', '/scope', ANY_ROLE],
      ['get', '/scope/cidrs', ANY_ROLE],
      ['get', '/fingerprints', ANY_ROLE],
      ['get', '/scans', ANY_ROLE],
      ['get', '/scans/:id', ANY_ROLE],
      ['get', '/sources', ANY_ROLE],
      ['get', '/poller/supported-fingerprints', ANY_ROLE],
      ['get', '/sources/:id/poller', ANY_ROLE],
      // Read-only: renders the onboarding instructions (POST only for its body).
      ['post', '/sources/:id/onboard/preview', ANY_ROLE],
      ['post', '/scans', SCANNING, true],
      ['post', '/scans/:id/cancel', SCANNING, true],
      ['post', '/sources/:id/confirm', SCANNING],
      ['post', '/sources/:id/ignore', SCANNING],
      ['post', '/sources/:id/onboard/confirm', SCANNING],
      // Deliberately admin-only before this change; must not be loosened.
      ['put', '/scope/cidrs', ADMIN_ONLY],
      ['post', '/sources/manual', ADMIN_ONLY],
      ['delete', '/sources/:id', ADMIN_ONLY],
      ['post', '/sources/:id/poller/credential', ADMIN_ONLY],
      ['delete', '/sources/:id/poller/credential', ADMIN_ONLY],
      ['patch', '/sources/:id/poller', ADMIN_ONLY],
      ['post', '/sources/:id/poller/run-now', ADMIN_ONLY],
    ],
  },
  {
    mount: '/api/containers',
    router: containersRouter,
    routes: [
      ['get', '/discovered', ANY_ROLE],
      ['get', '/inventory', ANY_ROLE],
      ['get', '/scans', ANY_ROLE],
      ['get', '/scans/:id', ANY_ROLE],
      ['post', '/scan', SCANNING, true],
    ],
  },
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

/**
 * The middleware in front of a route's handler, minus `authenticate` (app.ts
 * runs it at the mount; some routes repeat it). These are the role gates.
 */
function gatesOf(router: Router, method: string, path: string): Handler[] {
  const layer = stackOf(router).find((l) => l.route && l.route.path === path && l.route.methods[method]);
  assert.ok(layer?.route, `route ${method.toUpperCase()} ${path} exists`);
  return layer.route.stack
    .slice(0, -1)
    .filter((l) => l.name !== 'authenticate')
    .map((l) => l.handle);
}

/** Run one gate for a logged-in `role`: resolves with what it passed to next(). */
function runGate(gate: Handler, role: Role, method: string, path: string): Promise<unknown> {
  const req = {
    user: { id: 1, username: `gate-${role}`, email: `gate-${role}@siembox.invalid`, role },
    method: method.toUpperCase(),
    path,
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
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
async function outcomeFor(router: Router, method: string, path: string, role: Role): Promise<'pass' | number> {
  for (const gate of gatesOf(router, method, path)) {
    const err = await runGate(gate, role, method, path);
    if (err === undefined) continue;
    assert.ok(err instanceof ApiError, `the gate rejects with an ApiError, not ${String(err)}`);
    return err.statusCode;
  }
  return 'pass';
}

for (const { mount, router } of ROUTERS) {
  test(`${mount}: no router-level middleware (each route gates itself)`, () => {
    assert.deepEqual(
      stackOf(router).filter((l) => !l.route).map((l) => l.name),
      [],
      'a router.use() here would apply to every route, reads included'
    );
  });
}

for (const { mount, router, routes } of ROUTERS) {
  test(`${mount}: every route is classified, so a new write cannot slip in ungated`, () => {
    const known = new Set(routes.map(([method, path]) => `${method} ${path}`));
    for (const layer of stackOf(router)) {
      for (const method of Object.keys(layer.route?.methods ?? {})) {
        assert.ok(known.has(`${method} ${layer.route!.path}`), `unclassified route ${method.toUpperCase()} ${mount}${layer.route!.path}`);
      }
    }
  });
}

for (const { mount, router, routes } of ROUTERS) {
  for (const [method, path, allowed, audited = false] of routes) {
    const who = allowed === ANY_ROLE ? 'any role' : allowed.join(', ');
    test(`${method.toUpperCase()} ${mount}${path === '/' ? '' : path}: ${who}`, async () => {
      for (const role of ROLES) {
        auditLog.mock.resetCalls();
        const outcome = await outcomeFor(router, method, path, role);
        if (allowed.includes(role)) {
          assert.equal(outcome, 'pass', `${role} is let through`);
          assert.equal(auditLog.mock.callCount(), 0, `${role}: nothing is audited when the gate passes`);
          continue;
        }
        assert.equal(outcome, 403, `${role} is refused with 403`);
        if (audited) {
          assert.equal(auditLog.mock.callCount(), 1, `${role}: the denial is written to the audit log`);
          const [entry] = auditLog.mock.calls[0].arguments as unknown as [
            { action: string; responseStatus: number; details: { userRole: string; method: string } },
          ];
          assert.equal(entry.action, 'access.denied');
          assert.equal(entry.responseStatus, 403);
          assert.equal(entry.details.userRole, role);
          assert.equal(entry.details.method, method.toUpperCase());
        }
      }
    });
  }
}

// Keep last: proves the file stayed hermetic.
test('nothing in this file reached the database', () => {
  assert.equal(poolQuery.mock.callCount(), 0, 'no query may run');
  assert.equal(poolConnect.mock.callCount(), 0, 'no connection may be opened');
});
