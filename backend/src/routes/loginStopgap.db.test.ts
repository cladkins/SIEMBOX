/**
 * The interim sign-in limit against a real Postgres: successful sign-ins, and
 * the "MFA code required" step that only follows a correct password, are not
 * counted; wrong passwords are, and the eleventh attempt is refused even with
 * the right password. The limit itself (and its JSON 429) is covered
 * hermetically in loginStopgap.http.test.ts.
 *
 * Skips itself when Postgres isn't reachable. The two users it creates
 * (stopgap-<tag>, stopgap-<tag>-mfa) and their sessions are removed again,
 * along with what an interrupted earlier run left behind.
 * Run with `npm test` (tsx --test).
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
import { createApiServer } from '../net/apiListeners';

const SKIP = 'Postgres with the users table is not reachable';
const TEST_USER_NAME = '^stopgap-[0-9a-f]{12}(-mfa)?$';
const tag = crypto.randomBytes(6).toString('hex');
const username = `stopgap-${tag}`;
const password = crypto.randomBytes(12).toString('hex');
const userIds: number[] = [];
let dbReady = false;
let server: Server | undefined;
let base = '';

before(async () => {
  try {
    await pool.query('SELECT 1 FROM users LIMIT 1');
    await pool.query('SELECT 1 FROM sessions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const name of [username, `${username}-mfa`]) {
    const user = await UserModel.create({ username: name, email: `${name}@siembox.invalid`, password, role: 'viewer' });
    userIds.push(user.id);
  }
  // Only the flag matters here: without a code, login stops at "MFA code required".
  await pool.query('UPDATE users SET mfa_enabled = true WHERE id = $1', [userIds[1]]);
  server = createApiServer(app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
  }
  if (dbReady) {
    await pool.query(
      `DELETE FROM users
        WHERE id = ANY($1)
           OR (username ~ $2 AND email LIKE '%@siembox.invalid' AND created_at < NOW() - INTERVAL '10 minutes')`,
      [userIds, TEST_USER_NAME]
    ); // sessions cascade
  }
  await closePools();
});

async function login(name: string, secret: string) {
  const res = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: name, password: secret }),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

test('successful sign-ins and "MFA code required" are not counted; wrong passwords are', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (let i = 0; i < 12; i++) {
    assert.equal((await login(username, password)).status, 200, `successful sign-in ${i + 1}`);
  }
  for (let i = 0; i < 12; i++) {
    const step = await login(`${username}-mfa`, password);
    assert.equal(step.status, 401);
    assert.equal(step.json.mfaRequired, true);
  }
  for (let i = 0; i < 10; i++) {
    assert.equal((await login(username, 'wrong password')).status, 401, `failure ${i + 1}`);
  }
  const refused = await login(username, password);
  assert.equal(refused.status, 429, 'the eleventh attempt is refused, even with the right password');
  assert.equal(refused.json.code, 'RATE_LIMITED');
});
