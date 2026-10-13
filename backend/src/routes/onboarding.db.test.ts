/**
 * GET/PUT /api/settings/onboarding end to end: the real app on an ephemeral
 * port, a real Postgres, one user (and session) per role.
 *
 * Every role can read the state (the Dashboard and the checklist do), only an
 * admin sees who completed it, and only an admin can change it. Completion is
 * atomic and keeps the first completion; a reopen sticks even against a
 * browser's legacy flag, which applies only on an install that never recorded
 * anything.
 *
 * This is the only test file that touches the `onboarding_completed` row
 * (files run in parallel): before() saves and removes it, after() puts it back
 * exactly. Skips itself when Postgres isn't reachable. Every user, session and
 * error-log row created here is removed again. Run with `npm test`.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const KEY = 'onboarding_completed';
const SKIP = 'Postgres with the system_settings table is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `onbtest-${tag}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
let saved: { value: string; created_at: Date; updated_at: Date } | null = null;
/** 403 responses so far; each one is logged to application_errors (see after()). */
let denials = 0;

before(async () => {
  try {
    for (const table of ['sessions', 'system_settings', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  const row = await pool.query('SELECT value, created_at, updated_at FROM system_settings WHERE key = $1', [KEY]);
  saved = row.rows[0] ?? null;
  await pool.query('DELETE FROM system_settings WHERE key = $1', [KEY]);
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `${name}-${role}`,
      email: `${name}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query('DELETE FROM system_settings WHERE key = $1', [KEY]);
    if (saved) {
      await pool.query(
        'INSERT INTO system_settings (key, value, created_at, updated_at) VALUES ($1, $2, $3, $4)',
        [KEY, saved.value, saved.created_at, saved.updated_at]
      );
    }
    // Each 403 is logged to application_errors fire-and-forget: wait for the
    // rows, then delete them before the users (ON DELETE SET NULL would orphan them).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query(
        'SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)',
        [userIds]
      );
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]).catch(() => undefined);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]); // sessions cascade
  }
  await closePools();
});

async function call(role: Role, method: string, body?: unknown, rawBody?: string) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined || rawBody !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${base}/api/settings/onboarding`, {
    method,
    headers,
    body: rawBody ?? (body === undefined ? undefined : JSON.stringify(body)),
  });
  if (res.status === 403) denials++;
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

async function storedValue(): Promise<string | undefined> {
  const r = await pool.query('SELECT value FROM system_settings WHERE key = $1', [KEY]);
  return r.rows[0]?.value;
}

test('every role can read the state; nothing recorded reads as not completed', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    const r = await call(role, 'GET');
    assert.equal(r.status, 200, role);
    assert.deepEqual(Object.keys(r.json).sort(), ['completed', 'completed_at', 'completed_by']);
    assert.deepEqual(r.json, { completed: false, completed_at: null, completed_by: null });
  }
});

test('only an admin can change it; a refused PUT changes nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    for (const body of [{ completed: true }, { completed: false }, { completed: true, legacy: true }]) {
      assert.equal((await call(role, 'PUT', body)).status, 403, `${role} ${JSON.stringify(body)}`);
    }
  }
  assert.equal(await storedValue(), undefined, 'the row was never written');
});

test('validation: 400 for anything but {completed: boolean, legacy?: boolean}', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const cases: Array<[unknown, string | undefined, RegExp]> = [
    [{}, undefined, /completed must be true or false/],
    [{ completed: 'yes' }, undefined, /completed must be true or false/],
    [{ completed: false, legacy: true }, undefined, /legacy applies only/],
    [{ completed: true, legacy: 'x' }, undefined, /legacy must be true or false/],
    [undefined, '[true]', /Expected a JSON object/],
  ];
  for (const [body, raw, message] of cases) {
    const r = await call('admin', 'PUT', body, raw);
    assert.equal(r.status, 400, JSON.stringify(body ?? raw));
    assert.match(r.json?.message ?? '', message);
  }
  assert.equal(await storedValue(), undefined);
});

test('legacy dismissal on an install that never recorded anything completes it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await pool.query('DELETE FROM system_settings WHERE key = $1', [KEY]);
  const r = await call('admin', 'PUT', { completed: true, legacy: true });
  assert.equal(r.status, 200);
  assert.equal(r.json.completed, true);
  assert.equal(r.json.completed_by, `${name}-admin`);
  await pool.query('DELETE FROM system_settings WHERE key = $1', [KEY]);
});

test('completion is atomic and keeps the first time; reopen sticks against a legacy flag', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await pool.query('DELETE FROM system_settings WHERE key = $1', [KEY]);

  const done = await call('admin', 'PUT', { completed: true });
  assert.equal(done.status, 200);
  assert.equal(done.json.completed, true);
  assert.equal(done.json.completed_by, `${name}-admin`);
  assert.match(done.json.completed_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);

  const viewer = await call('viewer', 'GET');
  assert.deepEqual(viewer.json, { completed: true, completed_at: done.json.completed_at, completed_by: null });
  const operator = await call('operator', 'GET');
  assert.equal(operator.json.completed_by, null, 'the admin username is for admins only');
  assert.equal((await call('admin', 'GET')).json.completed_by, `${name}-admin`);

  await new Promise((resolve) => setTimeout(resolve, 10));
  const again = await call('admin', 'PUT', { completed: true });
  assert.equal(again.json.completed_at, done.json.completed_at, 'idempotent: the first completion is kept');

  // Reopen: recorded as '' and not completed...
  const reopened = await call('admin', 'PUT', { completed: false });
  assert.deepEqual(reopened.json, { completed: false, completed_at: null, completed_by: null });
  assert.equal(await storedValue(), '');
  // ...and a stale browser's legacy flag can't undo it.
  const legacy = await call('admin', 'PUT', { completed: true, legacy: true });
  assert.equal(legacy.status, 200);
  assert.equal(legacy.json.completed, false);
  assert.equal(await storedValue(), '');

  // Two completions at once: one write wins, and both report it.
  const [a, b] = await Promise.all([
    call('admin', 'PUT', { completed: true }),
    call('admin', 'PUT', { completed: true }),
  ]);
  assert.equal(a.json.completed_at, b.json.completed_at);
  const stored = JSON.parse((await storedValue()) ?? '{}');
  assert.equal(stored.at, a.json.completed_at);
  assert.equal(stored.by, `${name}-admin`);
});
