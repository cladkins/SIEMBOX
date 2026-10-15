/**
 * Access control for /api/shippers. app.ts mounts this router without
 * `authenticate`, because the shipper agent's own endpoints authenticate with
 * the shipper's key. The management routes used to have no auth at all, and
 * GET / and GET /:id returned every shipper's syslog api_key. These tests lock
 * in the fix:
 * - every management route requires a login; writes require admin or operator,
 *   and rotating the syslog key requires admin;
 * - the shipper-facing routes carry no JWT middleware (shippers, including
 *   "ghost" shippers with a revoked key, must keep working; see CLAUDE.md);
 * - api_key is returned only to admin and operator, the push-key hash never;
 * - PUT bodies are cut down to editable fields before they can reach SQL.
 * Hermetic: the database pool is mocked to fail, so if a gate or the column
 * allow-list ever regresses, the query fails here instead of writing (with the
 * real-looking ids below) to whatever database the environment points at.
 * Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../config/database';
import router, {
  canManageShippers,
  pickFields,
  shipperForRole,
  SHIPPER_EDITABLE_FIELDS,
  SOURCE_EDITABLE_FIELDS,
} from './shippers';
import { authenticate, authenticateAllowingPasswordChange, requireAdmin, requireOperator } from '../middleware/auth';
import { LogShipperModel, ShipperSourceModel, type LogShipper, type ShipperSource } from '../models/LogShipper';
import { ApiError } from '../middleware/errorHandler';

const SQL_MUST_NOT_RUN = 'SQL must not run in shippers.test.ts';
const poolQuery = mock.method(pool, 'query', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});
const poolConnect = mock.method(pool, 'connect', async () => {
  throw new Error(SQL_MUST_NOT_RUN);
});

type Route = [method: string, path: string];

const READS: Route[] = [
  ['get', '/'],
  ['get', '/unknown-sources'],
  ['get', '/direct-syslog-sources'],
  ['get', '/:id'],
  ['get', '/:id/sources'],
  ['get', '/:id/volumes'],
  ['get', '/:id/activity'],
];

const OPERATOR_WRITES: Route[] = [
  ['post', '/'],
  ['put', '/:id'],
  ['delete', '/:id'],
  ['post', '/:id/sources'],
  ['put', '/sources/:sourceId'],
  ['delete', '/sources/:sourceId'],
  ['post', '/:id/volumes'],
  ['delete', '/volumes/:volumeId'],
];

const ADMIN_WRITES: Route[] = [
  ['post', '/:id/regenerate-key'],
  ['post', '/:id/http-push-key'],
  ['delete', '/:id/http-push-key'],
];

// Authenticated by the shipper's key (or the HTTP push key), never a login.
const SHIPPER_FACING: Route[] = [
  ['post', '/register'],
  ['post', '/containers'],
  ['get', '/config/:api_key'],
  ['get', '/scan-jobs/:api_key'],
  ['post', '/scan-results'],
  ['post', '/discovery-results'],
  ['post', '/logs'],
];

function routeHandlers(method: string, path: string): unknown[] {
  const layer = (router as any).stack.find(
    (l: any) => l.route && l.route.path === path && l.route.methods[method]
  );
  assert.ok(layer, `route ${method.toUpperCase()} ${path} exists`);
  return layer.route.stack.map((l: any) => l.handle);
}

/** Run a route's role gate (the middleware right after authenticate) as `role`; returns the error status, or 0 if it let the request through. */
function gateStatus(method: string, path: string, role: string): number {
  const handlers = routeHandlers(method, path) as Array<(req: any, res: any, next: (err?: unknown) => void) => void>;
  assert.equal(handlers[0], authenticate, 'authenticate runs first');
  const outcome: { called: boolean; err?: unknown } = { called: false };
  handlers[1]({ user: { id: 1, username: 'u', email: 'u@x', role } }, {}, (err?: unknown) => {
    outcome.called = true;
    outcome.err = err;
  });
  assert.ok(outcome.called, 'the role gate answers synchronously');
  if (outcome.err === undefined) return 0;
  const err = outcome.err;
  assert.ok(err instanceof ApiError, 'the role gate rejects with an ApiError');
  return err.statusCode;
}

test('the router has no router-level middleware: each route gates itself', () => {
  const unrouted = (router as any).stack.filter((l: any) => !l.route);
  assert.equal(unrouted.length, 0, 'a router.use() here would also hit the shipper-facing routes');
});

test('every route is classified, so a new route cannot slip in ungated unnoticed', () => {
  const known = new Set([...READS, ...OPERATOR_WRITES, ...ADMIN_WRITES, ...SHIPPER_FACING].map(([m, p]) => `${m} ${p}`));
  for (const layer of (router as any).stack) {
    for (const method of Object.keys(layer.route.methods)) {
      assert.ok(known.has(`${method} ${layer.route.path}`), `unclassified route ${method.toUpperCase()} ${layer.route.path}`);
    }
  }
});

for (const [method, path] of READS) {
  test(`${method.toUpperCase()} ${path} requires a login and no particular role`, () => {
    const handlers = routeHandlers(method, path);
    assert.equal(handlers[0], authenticate);
    assert.ok(!handlers.includes(requireOperator) && !handlers.includes(requireAdmin));
  });
}

for (const [method, path] of OPERATOR_WRITES) {
  test(`${method.toUpperCase()} ${path} requires admin or operator`, () => {
    assert.ok(routeHandlers(method, path).includes(requireOperator));
    assert.equal(gateStatus(method, path, 'admin'), 0);
    assert.equal(gateStatus(method, path, 'operator'), 0);
    assert.equal(gateStatus(method, path, 'analyst'), 403);
    assert.equal(gateStatus(method, path, 'viewer'), 403);
  });
}

for (const [method, path] of ADMIN_WRITES) {
  test(`${method.toUpperCase()} ${path} requires admin`, () => {
    assert.equal(gateStatus(method, path, 'admin'), 0);
    for (const role of ['operator', 'analyst', 'viewer']) {
      assert.equal(gateStatus(method, path, role), 403, `${role} is refused`);
    }
  });
}

for (const [method, path] of SHIPPER_FACING) {
  test(`${method.toUpperCase()} ${path} (shipper-facing) carries no JWT middleware`, () => {
    const handlers = routeHandlers(method, path);
    assert.ok(!handlers.includes(authenticate) && !handlers.includes(authenticateAllowingPasswordChange));
    assert.ok(!handlers.includes(requireOperator) && !handlers.includes(requireAdmin));
  });
}

test('only admin and operator can manage shippers', () => {
  assert.equal(canManageShippers('admin'), true);
  assert.equal(canManageShippers('operator'), true);
  for (const role of ['analyst', 'viewer', 'Admin', '', undefined]) {
    assert.equal(canManageShippers(role), false, `role ${String(role)}`);
  }
});

const row = {
  id: 7,
  name: 'web-01',
  status: 'online',
  api_key: 'a'.repeat(64),
  http_push_key_hash: 'b'.repeat(64),
  sources: [],
};

for (const role of ['admin', 'operator']) {
  test(`${role} gets the syslog api_key, never the push-key hash`, () => {
    const out = shipperForRole(row, role);
    assert.equal(out.api_key, row.api_key);
    assert.ok(!('http_push_key_hash' in out));
    assert.equal(out.http_push_enabled, true);
    assert.equal(out.name, row.name);
  });
}

for (const role of ['analyst', 'viewer', undefined]) {
  test(`role ${String(role)} gets the shipper row without its api_key`, () => {
    const out = shipperForRole(row, role);
    assert.ok(!('api_key' in out));
    assert.ok(!('http_push_key_hash' in out));
    assert.equal(out.http_push_enabled, true);
    assert.equal(out.id, row.id, 'the rest of the row survives (scan pickers, Onboarding count)');
    assert.equal(out.name, row.name);
    assert.ok(!JSON.stringify(out).includes(row.api_key), 'serialized response carries no key');
  });
}

test('redaction does not mutate the input row', () => {
  shipperForRole(row, 'viewer');
  assert.equal(row.api_key, 'a'.repeat(64));
  assert.equal(row.http_push_key_hash, 'b'.repeat(64));
});

test('PUT /:id keeps only editable shipper fields', () => {
  const body = {
    name: 'renamed',
    description: 'd',
    api_key: 'attacker-chosen',
    http_push_key_hash: 'attacker-chosen',
    status: 'online',
    config: { siem_host: 'attacker.example' },
    id: 99,
    'name = name, api_key': 'x',
  };
  assert.deepEqual(pickFields<LogShipper>(body, SHIPPER_EDITABLE_FIELDS), { name: 'renamed', description: 'd' });
  for (const forbidden of ['api_key', 'http_push_key_hash', 'status', 'config', 'id', 'last_seen']) {
    assert.ok(!(SHIPPER_EDITABLE_FIELDS as readonly string[]).includes(forbidden), forbidden);
  }
});

test('PUT /:id cannot set config, which the shipper applies on register (log destination and sources)', async () => {
  const redirect = { config: { siem_host: 'attacker.example', siem_port: 514, sources: [{ source_type: 'file', file_path: '/etc/shadow' }] } };
  assert.deepEqual(pickFields<LogShipper>({ name: 'n', ...redirect }, SHIPPER_EDITABLE_FIELDS), { name: 'n' });
  await assert.rejects(LogShipperModel.update(1, redirect as Partial<LogShipper>), /"config" is not an updatable column/);
});

test('PUT /sources/:sourceId keeps only editable source fields (the UI also sends id)', () => {
  const body = { id: 3, shipper_id: 9, tag: 't', enabled: false, file_path: '/logs/a.log', 'tag = tag, shipper_id': 1 };
  assert.deepEqual(pickFields<ShipperSource>(body, SOURCE_EDITABLE_FIELDS), {
    tag: 't',
    enabled: false,
    file_path: '/logs/a.log',
  });
});

test('pickFields ignores bodies that are not plain objects', () => {
  for (const body of [null, undefined, 'name', 42, ['name']]) {
    assert.deepEqual(pickFields<LogShipper>(body, SHIPPER_EDITABLE_FIELDS), {});
  }
});

test('the update models refuse unknown column names before any SQL runs', async () => {
  await assert.rejects(
    LogShipperModel.update(1, { 'name = name, api_key': 'x' } as unknown as Partial<LogShipper>),
    /not an updatable column/
  );
  await assert.rejects(
    LogShipperModel.update(1, { http_push_key_hash: 'x' } as Partial<LogShipper>),
    /not an updatable column/
  );
  await assert.rejects(
    ShipperSourceModel.update(1, { shipper_id: 2 } as Partial<ShipperSource>),
    /not an updatable column/
  );
});

// Keep last: proves the file stayed hermetic.
test('nothing in this file reached the database', () => {
  assert.equal(poolQuery.mock.callCount(), 0, 'no query may run');
  assert.equal(poolConnect.mock.callCount(), 0, 'no connection may be opened');
});
