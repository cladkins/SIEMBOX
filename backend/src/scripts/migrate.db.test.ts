/**
 * The migrate runner's admin seed, default-password scan and banner
 * (scripts/migrate.ts, services/auth/defaultCredentials.ts), each case on a
 * throwaway database of its own, with migrate run as a child process exactly
 * as the image runs it (config/database.ts reads DB_NAME at import):
 *
 * 1. a fresh install creates `admin`, flagged 'initial', with "changeme" when
 *    DEFAULT_ADMIN_PASSWORD is unset, audited once, with the banner;
 * 2. migrating again changes nothing (same hash, flag and date; no new row);
 * 3. once the admin changed its password, migrate never flags or overwrites it,
 *    and the banner is gone;
 * 4. a strong DEFAULT_ADMIN_PASSWORD is flagged 'initial' too;
 * 5. an upgraded admin still on "changeme" is flagged 'default' at the first
 *    start, once (audited, with the WARN);
 * 6. an upgraded admin on another password is left alone; another admin-role
 *    account on "changeme" is flagged; a viewer on it is not (sign-in catches it);
 *    a disabled admin on it is flagged, with a WARN of its own and no banner
 *    until it is enabled again;
 * 7. a deleted or renamed `admin` is not re-created (and a rename that kept
 *    the email no longer stops the start);
 * 8. an empty users table gets `admin` again;
 * and a DEFAULT_ADMIN_PASSWORD longer than sign-in accepts fails the migrate.
 *
 * Skips itself when Postgres isn't reachable or CREATE DATABASE isn't allowed.
 * Its databases (siembox_migrate_<tag>_<n>) are dropped again.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import bcrypt from 'bcrypt';
import { Client, type ClientConfig } from 'pg';

const tag = crypto.randomBytes(4).toString('hex');
const BACKEND = path.resolve(__dirname, '../..');
const connection: ClientConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  user: process.env.DB_USER || 'siembox',
  password: process.env.DB_PASSWORD || 'changeme',
};
let skip: string | null = null;
let admin: Client | null = null;
const created: string[] = [];
let counter = 0;

before(async () => {
  try {
    admin = new Client({ ...connection, database: process.env.DB_NAME || 'siembox', connectionTimeoutMillis: 3000 });
    await admin.connect();
    const probe = `siembox_migrate_${tag}_probe`;
    await admin.query(`CREATE DATABASE ${probe}`);
    await admin.query(`DROP DATABASE ${probe}`);
  } catch (error) {
    skip = `Postgres with CREATE DATABASE is not reachable (${error instanceof Error ? error.message : String(error)})`;
    await admin?.end().catch(() => undefined);
    admin = null;
  }
});

after(async () => {
  if (!admin) return;
  for (const name of created) await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`).catch(() => undefined);
  await admin.end();
});

/** A new, empty database for one case. */
async function freshDatabase(): Promise<string> {
  const name = `siembox_migrate_${tag}_${++counter}`;
  await admin!.query(`CREATE DATABASE ${name}`);
  created.push(name);
  return name;
}

/** Run migrate against `database`, as `node dist/scripts/migrate.js` would, from the TypeScript source. */
function migrate(database: string, env: Record<string, string> = {}): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--import', 'tsx', 'src/scripts/migrate.ts'],
      {
        cwd: BACKEND,
        env: { ...process.env, DB_NAME: database, DEFAULT_ADMIN_PASSWORD: '', NODE_ENV: 'test', ...env },
        timeout: 120_000,
        maxBuffer: 16 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        const code = error ? (typeof error.code === 'number' ? error.code : 1) : 0;
        resolve({ code, output: stdout + stderr });
      }
    );
  });
}

/** Run SQL against `database` with a short-lived connection. */
async function sql<T = Record<string, unknown>>(database: string, text: string, params: unknown[] = []): Promise<T[]> {
  const client = new Client({ ...connection, database });
  await client.connect();
  try {
    return (await client.query(text, params)).rows as T[];
  } finally {
    await client.end();
  }
}

interface UserRow {
  id: number;
  username: string;
  email: string;
  role: string;
  password_hash: string;
  must_change_password: boolean;
  must_change_password_reason: string | null;
  must_change_password_since: Date | null;
  password_changed_at: Date | null;
}

const users = (db: string) => sql<UserRow>(db, 'SELECT * FROM users ORDER BY id');
const auditActions = (db: string) =>
  sql<{ action: string; resource_id: number | null; details: Record<string, unknown> }>(
    db,
    'SELECT action, resource_id, details FROM audit_logs ORDER BY id'
  );

const BANNER = 'ADMIN SIGN-IN: username "admin"';
const WARN = 'still uses the default password "changeme"';

/** An old row, as an install before migration 039 left it: what 039 adds is all FALSE/NULL. */
async function asBeforeTheUpgrade(db: string, where = 'TRUE'): Promise<void> {
  await sql(
    db,
    `UPDATE users SET must_change_password = FALSE, must_change_password_reason = NULL, must_change_password_since = NULL WHERE ${where}`
  );
}

async function addUser(db: string, username: string, role: string, password: string): Promise<void> {
  await sql(db, `INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)`, [
    username,
    `${username}@siembox.invalid`,
    await bcrypt.hash(password, 4),
    role,
  ]);
}

test('fresh install: admin is created flagged initial, once; migrating again changes nothing; a changed password stays', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  const first = await migrate(db);
  assert.equal(first.code, 0, first.output);
  const [row, ...others] = await users(db);
  assert.deepEqual(others, []);
  assert.equal(row.username, 'admin');
  assert.equal(row.email, 'admin@siembox.local');
  assert.equal(row.role, 'admin');
  assert.equal(row.must_change_password, true);
  assert.equal(row.must_change_password_reason, 'initial');
  assert.ok(row.must_change_password_since);
  assert.equal(await bcrypt.compare('changeme', row.password_hash), true, 'DEFAULT_ADMIN_PASSWORD unset: "changeme"');
  assert.ok(first.output.includes(BANNER), first.output);
  assert.ok(!first.output.includes(WARN), 'the initial account is not a "found on the default" case');
  const audit = await auditActions(db);
  assert.deepEqual(audit.map((a) => a.action), ['user.created']);
  assert.deepEqual(audit[0].details, { by: 'seed', username: 'admin', role: 'admin', passwordChangeRequired: 'initial' });
  assert.equal(audit[0].resource_id, row.id);

  // 2. Again: identical.
  const second = await migrate(db);
  assert.equal(second.code, 0, second.output);
  const [again] = await users(db);
  assert.deepEqual(again, row);
  assert.equal((await auditActions(db)).length, 1, 'no new audit row');
  assert.ok(second.output.includes(BANNER), 'still waiting for the change');

  // 3. The admin changes the password (as PUT /api/auth/me/password does).
  const hash = await bcrypt.hash('a password only I know', 4);
  await sql(
    db,
    `UPDATE users SET password_hash = $1, password_changed_at = NOW(), must_change_password = FALSE,
            must_change_password_reason = NULL, must_change_password_since = NULL WHERE id = $2`,
    [hash, row.id]
  );
  const third = await migrate(db);
  assert.equal(third.code, 0, third.output);
  const [changed] = await users(db);
  assert.equal(changed.password_hash, hash, 'never overwritten');
  assert.equal(changed.must_change_password, false, 'never flagged again');
  assert.ok(!third.output.includes('ADMIN SIGN-IN'), 'no banner once the password was changed');
});

test('fresh install with a strong DEFAULT_ADMIN_PASSWORD: flagged initial too', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  const strong = `Strong-${crypto.randomBytes(12).toString('hex')}`;
  const run = await migrate(db, { DEFAULT_ADMIN_PASSWORD: strong });
  assert.equal(run.code, 0, run.output);
  const [row] = await users(db);
  assert.equal(row.must_change_password_reason, 'initial');
  assert.equal(await bcrypt.compare(strong, row.password_hash), true);
  assert.ok(!run.output.includes(strong), 'the configured password is never printed');
});

test('upgrade: an admin still on "changeme" is flagged default at the first start, once', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  assert.equal((await migrate(db)).code, 0);
  await asBeforeTheUpgrade(db);
  await sql(db, 'DELETE FROM audit_logs');

  const upgrade = await migrate(db);
  assert.equal(upgrade.code, 0, upgrade.output);
  const [row] = await users(db);
  assert.equal(row.must_change_password, true);
  assert.equal(row.must_change_password_reason, 'default');
  assert.ok(upgrade.output.includes(`Account "admin" ${WARN}`), upgrade.output);
  assert.ok(upgrade.output.includes(BANNER));
  const audit = await auditActions(db);
  assert.deepEqual(audit.map((a) => a.action), ['auth.password.change_required']);
  assert.deepEqual(audit[0].details, { by: 'startup', reason: 'default' });

  const again = await migrate(db);
  assert.equal(again.code, 0);
  assert.equal((await auditActions(db)).length, 1, 'no second row');
  assert.ok(!again.output.includes(WARN), 'the WARN is once per flag');
  const [same] = await users(db);
  assert.deepEqual(same.must_change_password_since, row.must_change_password_since, 'not re-dated');
});

test('upgrade: only admin-role accounts on "changeme" are flagged; another password is left alone', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  assert.equal((await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' })).code, 0);
  await addUser(db, 'ops', 'admin', 'changeme');
  await addUser(db, 'watcher', 'viewer', 'changeme');
  await asBeforeTheUpgrade(db);

  const upgrade = await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' });
  assert.equal(upgrade.code, 0, upgrade.output);
  const byName = Object.fromEntries((await users(db)).map((u) => [u.username, u]));
  assert.equal(byName.admin.must_change_password, false, 'a non-default DEFAULT_ADMIN_PASSWORD is not forced on upgrade');
  assert.equal(byName.ops.must_change_password_reason, 'default');
  assert.equal(byName.watcher.must_change_password, false, 'other roles are caught at sign-in');
  assert.ok(upgrade.output.includes(`Account "ops" ${WARN}`));
  assert.ok(upgrade.output.includes('ADMIN SIGN-IN: username "ops"'));
  assert.ok(!upgrade.output.includes(BANNER), 'no banner for the admin that changed nothing it needs to');
});

test('upgrade: a disabled admin on "changeme" is flagged, without a "sign in now" WARN or banner until it is enabled', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  assert.equal((await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' })).code, 0);
  await addUser(db, 'dormant', 'admin', 'changeme');
  await sql(db, `UPDATE users SET enabled = FALSE WHERE username = 'dormant'`);
  await asBeforeTheUpgrade(db);

  const upgrade = await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' });
  assert.equal(upgrade.code, 0, upgrade.output);
  const dormant = (await users(db)).find((u) => u.username === 'dormant')!;
  assert.equal(dormant.must_change_password_reason, 'default', 'flagged: right if it is ever enabled again');
  assert.ok(
    upgrade.output.includes('Disabled account "dormant" uses the default password "changeme"; it must choose a new one if it is ever enabled.'),
    upgrade.output
  );
  assert.ok(!upgrade.output.includes(`Account "dormant" ${WARN}`), 'no "sign in now": it cannot');
  assert.ok(!upgrade.output.includes('ADMIN SIGN-IN'), 'no banner for an account that cannot sign in');
  const again = await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' });
  assert.ok(!again.output.includes('ADMIN SIGN-IN'), 'nor on the next start');

  await sql(db, `UPDATE users SET enabled = TRUE WHERE username = 'dormant'`);
  const enabled = await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'scripted-install-password' });
  assert.ok(enabled.output.includes('ADMIN SIGN-IN: username "dormant". Password: "changeme"'), enabled.output);
});

test('a deleted or renamed admin is not re-created; an empty users table gets it again', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  assert.equal((await migrate(db)).code, 0);
  await addUser(db, 'other-admin', 'admin', 'another password 1');

  // Renamed, keeping its email: the old seed's INSERT hit users_email_key and stopped every start.
  await sql(db, `UPDATE users SET username = 'bob' WHERE username = 'admin'`);
  const renamed = await migrate(db);
  assert.equal(renamed.code, 0, renamed.output);
  assert.deepEqual((await users(db)).map((u) => u.username).sort(), ['bob', 'other-admin']);

  await sql(db, `DELETE FROM users WHERE username = 'bob'`);
  const deleted = await migrate(db);
  assert.equal(deleted.code, 0, deleted.output);
  assert.deepEqual((await users(db)).map((u) => u.username), ['other-admin'], 'not brought back with the bootstrap password');

  await sql(db, 'DELETE FROM users');
  const empty = await migrate(db);
  assert.equal(empty.code, 0, empty.output);
  const [row] = await users(db);
  assert.equal(row.username, 'admin');
  assert.equal(row.must_change_password_reason, 'initial');
});

test('a DEFAULT_ADMIN_PASSWORD longer than sign-in accepts fails the migrate, naming the variable', async (t) => {
  if (skip) return t.skip(skip);
  const db = await freshDatabase();
  const run = await migrate(db, { DEFAULT_ADMIN_PASSWORD: 'x'.repeat(1025) });
  assert.equal(run.code, 1);
  assert.ok(run.output.includes('DEFAULT_ADMIN_PASSWORD is 1025 characters long'), run.output);
  assert.deepEqual(await users(db), []);
});
