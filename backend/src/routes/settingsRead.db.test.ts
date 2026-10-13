/**
 * GET /api/settings end to end: the real app on an ephemeral port, a real
 * Postgres, and one user per role holding a session token (as login would
 * issue). The route lists system_settings, where the AI, reputation and Have I
 * Been Pwned API keys are stored as encrypted envelopes. It used to return every
 * row to any signed-in role, a viewer included. Now viewers, analysts and
 * operators get 403, and an admin gets the rows with every stored credential
 * withheld (services/settings/settingsRedaction.ts).
 *
 * The secrets probed here are this test's own rows (settingsread_<tag>_*), so it
 * never reads, writes or depends on a real key. Skips itself when Postgres isn't
 * reachable. Every row created here (settings, users, sessions, and the
 * application_errors rows the 403s produce) is removed again, along with what an
 * interrupted earlier run left behind. Run with `npm test` (tsx --test).
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
import { CredentialEncryption } from '../services/credentials/credentialEncryption';
import { READABLE_SETTING_KEYS, REDACTED_VALUE, type SettingRow } from '../services/settings/settingsRedaction';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the settings schema is not reachable';
/** Usernames this test gives its users (settingsread-<tag>-<role>), any tag. */
const TEST_USER_NAME = '^settingsread-[0-9a-f]{12}-(admin|operator|analyst|viewer)$';
/** Setting keys this test writes (settingsread_<tag>_<name>), any tag. */
const TEST_SETTING_KEY = '^settingsread_[0-9a-f]{12}_[a-z_]+$';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
/** 403 responses so far; each one is logged to application_errors (see after()). */
let denials = 0;

/** This test's own rows: an encrypted key as the services store one, a cleared token, a plain value. */
const KEYS = {
  apiKey: `settingsread_${tag}_api_key`,
  token: `settingsread_${tag}_token`,
  note: `settingsread_${tag}_note`,
};
let envelope = { encrypted: '', iv: '', authTag: '' };

before(async () => {
  try {
    for (const table of ['system_settings', 'sessions', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  // A throwaway key for this test process: the envelope only has to look real.
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  envelope = CredentialEncryption.encrypt(`sk-settingsread-${tag}`);
  const rows: Array<[string, string]> = [
    [KEYS.apiKey, JSON.stringify(envelope)],
    [KEYS.token, ''],
    [KEYS.note, 'plain value nobody has reviewed'],
  ];
  for (const [key, value] of rows) {
    await pool.query('INSERT INTO system_settings (key, value) VALUES ($1, $2)', [key, value]);
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `settingsread-${tag}-${role}`,
      email: `settingsread-${tag}-${role}@siembox.invalid`,
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
    // Leftovers of an interrupted earlier run go too, but only once they are
    // older than 10 minutes: a run going on in parallel keeps its own.
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    await pool.query(`DELETE FROM system_settings WHERE key LIKE $1 OR (key ~ $2 AND ${stale})`, [
      `settingsread_${tag}_%`,
      TEST_SETTING_KEY,
    ]);
    // Every 403 is logged to application_errors, fire-and-forget: wait until
    // those rows have landed, then delete them before the users (deleting a
    // user only nulls user_id, which would leave orphan rows).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_USER_NAME]
    );
    const doomed = [...userIds, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]); // sessions cascade
  }
  await closePools();
});

/** GET /api/settings as `role` (null: no login). API errors are { status, statusCode, message }. */
async function getSettings(role: Role | null): Promise<{ status: number; text: string; json: unknown }> {
  const res = await fetch(`${base}/api/settings`, {
    headers: role ? { Authorization: `Bearer ${tokens[role]}` } : {},
  });
  if (res.status === 403) denials++;
  const text = await res.text();
  return { status: res.status, text, json: JSON.parse(text) };
}

function messageOf(json: unknown): unknown {
  return (json as { message?: unknown } | null)?.message;
}

/** No part of this test's stored key, nor any envelope field, appears in `text`. */
function assertNoEnvelope(text: string, who: string) {
  for (const part of [envelope.encrypted, envelope.iv, envelope.authTag, '"encrypted"', 'authTag']) {
    assert.ok(!text.includes(part), `${who}: the response carries no part of a stored key (${part})`);
  }
}

test('viewers, analysts and operators get 403 and no setting at all', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ['viewer', 'analyst', 'operator'] as const) {
    const r = await getSettings(role);
    assert.equal(r.status, 403, `${role} is refused`);
    assert.equal(messageOf(r.json), 'Access denied. Required role: admin');
    assert.ok(!r.text.includes('setting_key'), `${role} gets no rows`);
    assertNoEnvelope(r.text, role);
  }
});

test('an admin gets every row, with stored credentials withheld', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await getSettings('admin');
  assert.equal(r.status, 200);
  assertNoEnvelope(r.text, 'admin');
  const rows = r.json as SettingRow[];
  assert.ok(Array.isArray(rows));
  const byKey = new Map(rows.map((row) => [row.setting_key, row]));

  // The [{ setting_key, setting_value }] shape stays; credentials are reported, not returned.
  assert.deepEqual(byKey.get(KEYS.apiKey), { setting_key: KEYS.apiKey, setting_value: REDACTED_VALUE, redacted: true, configured: true });
  assert.deepEqual(byKey.get(KEYS.token), { setting_key: KEYS.token, setting_value: '', redacted: true, configured: false });
  // A key nobody has classified yet is withheld too (fails closed).
  assert.deepEqual(byKey.get(KEYS.note), { setting_key: KEYS.note, setting_value: REDACTED_VALUE, redacted: true, configured: true });

  // A plain setting a migration seeds comes back as stored.
  const seeded = await pool.query(`SELECT value FROM system_settings WHERE key = 'retention_alerts_days'`);
  if (seeded.rowCount) {
    assert.deepEqual(byKey.get('retention_alerts_days'), {
      setting_key: 'retention_alerts_days',
      setting_value: seeded.rows[0].value,
      redacted: false,
    });
  }

  // Whatever else this database holds: only reviewed keys come back in clear,
  // never with an envelope, and a withheld row only says whether it is set.
  for (const row of rows) {
    if (row.redacted) {
      assert.ok([REDACTED_VALUE, ''].includes(row.setting_value), row.setting_key);
      assert.equal(row.configured, row.setting_value === REDACTED_VALUE, row.setting_key);
    } else {
      assert.ok(READABLE_SETTING_KEYS.has(row.setting_key), `${row.setting_key} is on the readable list`);
      assert.doesNotMatch(row.setting_value, /"(encrypted|iv|authTag)"\s*:/, row.setting_key);
      assert.equal(row.configured, undefined, row.setting_key);
    }
  }
});

test('without a login GET /api/settings is 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await getSettings(null);
  assert.equal(r.status, 401);
  assert.equal(messageOf(r.json), 'Authentication required');
});
