/**
 * Verified HIBP domains end to end: the real app on an ephemeral port, a real
 * Postgres, one user (and session) per role, and HIBP replaced by mocks on
 * HibpClient.prototype — nothing leaves the machine. The breach searches throw
 * if called: none of these routes may search.
 *
 * Covers the admin-only account view and re-check (role gates, no-key, the
 * one-minute cooldown, 404 and 429 answers, a key change), `hibp_domain` on
 * GET /api/exposure/identities for every role (never a call to HIBP), the
 * re-queue of a domain that turned verified, and the two model methods.
 *
 * Owns the exposure_hibp_key / exposure_hibp_enabled / exposure_hibp_domains
 * rows while it runs: their raw values are saved first and restored after. If
 * an operator's HIBP key is already stored, the key-dependent cases skip so it
 * is never clobbered. Every identity, user, session and error-log row created
 * here is removed again. Skips itself without Postgres. Run with `npm test`.
 */
import { test, before, after, mock, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { MonitoredIdentityModel } from '../models/Exposure';
import { HibpClient, HibpError, type HibpSubscribedDomainList } from '../services/exposure/hibpClient';
import { resetLeakedCredentialPause } from '../services/exposure/leakedCredentialService';
import { HIBP_DOMAINS_DASHBOARD_URL } from '../services/exposure/hibpDomains';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the exposure schema is not reachable';
const OWNED = ['exposure_hibp_key', 'exposure_hibp_enabled', 'exposure_hibp_domains'];
const API_KEY = crypto.randomBytes(16).toString('hex'); // never sent anywhere: HIBP is mocked
const OTHER_KEY = crypto.randomBytes(16).toString('hex');

if (!process.env.CREDENTIAL_ENCRYPTION_KEY) {
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

const tag = crypto.randomBytes(5).toString('hex');
const name = `hibpdom-${tag}`;
const VERIFIED = `verified-${tag}.siembox-test.invalid`;
const UNVERIFIED = `unverified-${tag}.siembox-test.invalid`;
const FLIPPED = `flipped-${tag}.siembox-test.invalid`;
const EMAIL = `alice@mail-${tag}.siembox-test.invalid`;

// ---- HIBP, mocked -------------------------------------------------------------------

const hibp = {
  /** What subscribeddomains lists, as HIBP spells it. */
  domains: [] as string[],
  /** Thrown by subscribeddomains instead of answering. */
  fail: null as Error | null,
  listCalls: 0,
  statusCalls: 0,
  searchCalls: 0,
};
mock.method(HibpClient.prototype, 'subscribedDomains', async (): Promise<HibpSubscribedDomainList> => {
  hibp.listCalls++;
  if (hibp.fail) throw hibp.fail;
  return {
    domains: hibp.domains.map((DomainName) => ({
      DomainName,
      PwnCount: 12,
      PwnCountExcludingSpamLists: 10,
      PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 9,
      NextSubscriptionRenewal: '2027-01-01T00:00:00',
    })),
    unreadable: 0,
    overLimit: 0,
  };
});
mock.method(HibpClient.prototype, 'subscriptionStatus', async () => {
  hibp.statusCalls++;
  // 600 RPM: the pacer spaces calls ~200 ms apart.
  return {
    SubscriptionName: 'Core 2',
    Rpm: 600,
    DomainSearchMaxBreachedAccounts: 100,
    MaxBreachedDomains: 3,
    SubscribedUntil: '2027-01-01T00:00:00',
  };
});
for (const method of ['breachedDomain', 'breachedAccount', 'allBreaches'] as const) {
  mock.method(HibpClient.prototype, method, async () => {
    hibp.searchCalls++;
    throw new Error(`${method} must not be called by these routes`);
  });
}
const hibpCalls = () => hibp.listCalls + hibp.statusCalls + hibp.searchCalls;

// ---- fixtures ---------------------------------------------------------------------

let dbReady = false;
let operatorKeyPresent = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const saved = new Map<string, { value: string; created_at: Date; updated_at: Date } | null>();
const ids = {} as Record<'verified' | 'unverified' | 'flipped' | 'email', number>;
let denials = 0;

before(async () => {
  try {
    for (const table of ['sessions', 'system_settings', 'monitored_identities', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const key of OWNED) {
    const r = await pool.query('SELECT value, created_at, updated_at FROM system_settings WHERE key = $1', [key]);
    saved.set(key, r.rows[0] ?? null);
  }
  operatorKeyPresent = !!saved.get('exposure_hibp_key')?.value;
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

  for (const [slot, kind, value] of [
    ['verified', 'email_domain', VERIFIED],
    ['unverified', 'email_domain', UNVERIFIED],
    ['flipped', 'email_domain', FLIPPED],
    ['email', 'email', EMAIL],
  ] as const) {
    const created = await call('admin', 'POST', '/api/exposure/identities', { kind, value });
    assert.equal(created.status, 201, `create ${value}`);
    ids[slot] = created.json.id;
  }
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query('DELETE FROM monitored_identities WHERE value LIKE $1', [`%${tag}.siembox-test.invalid`]);
    for (const key of OWNED) {
      const row = saved.get(key);
      await pool.query('DELETE FROM system_settings WHERE key = $1', [key]);
      if (row) {
        await pool.query(
          'INSERT INTO system_settings (key, value, created_at, updated_at) VALUES ($1, $2, $3, $4)',
          [key, row.value, row.created_at, row.updated_at]
        );
      }
    }
    resetLeakedCredentialPause();
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]); // sessions cascade
  }
  await closePools();
});

beforeEach(() => {
  resetLeakedCredentialPause();
  hibp.fail = null;
});

async function call(role: Role, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 403) denials++;
  const text = await res.text();
  // Whatever the route and outcome, the API key never comes back.
  assert.ok(!text.includes(API_KEY) && !text.includes(OTHER_KEY), `${method} ${path} must not echo the key`);
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, headers: res.headers };
}

const VIEW = '/api/exposure/providers/hibp/verified-domains';
const REFRESH = `${VIEW}/refresh`;
const VIEW_KEYS = [
  'attribution',
  'checked_at',
  'domains',
  'error',
  'listed_at',
  'next_refresh_allowed_at',
  'plan',
  'skipped_entries',
  'stale',
  'state',
  'truncated',
];

async function setSetting(key: string, value: string) {
  await pool.query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [key, value]
  );
}

async function snapshotRaw(): Promise<string> {
  const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'exposure_hibp_domains'`);
  return r.rows[0]?.value ?? '';
}

/** Move the snapshot's last attempt back, past the one-minute cooldown. */
async function endCooldown() {
  const raw = await snapshotRaw();
  if (!raw) return;
  const snapshot = JSON.parse(raw);
  snapshot.checked_at = new Date(Date.now() - 5 * 60_000).toISOString();
  await setSetting('exposure_hibp_domains', JSON.stringify(snapshot));
}

async function identityRows(role: Role) {
  const r = await call(role, 'GET', '/api/exposure/identities');
  assert.equal(r.status, 200, `${role} GET /identities`);
  const mine = (r.json as any[]).filter((row) => String(row.value).includes(tag));
  return new Map(mine.map((row) => [row.value, row]));
}

async function saveKey(apiKey: string) {
  const r = await call('admin', 'PUT', '/api/exposure/providers/hibp', { api_key: apiKey, enabled: false });
  assert.equal(r.status, 200);
}

// ---- tests ---------------------------------------------------------------------------

test('role gates: the account view and the re-check are admin-only; identities are open to all', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = hibpCalls();
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    assert.equal((await call(role, 'GET', VIEW)).status, 403, `${role} GET`);
    assert.equal((await call(role, 'POST', REFRESH)).status, 403, `${role} POST`);
  }
  assert.equal(hibpCalls(), before, 'a refused request never reaches HIBP');

  for (const role of ROLES) {
    const rows = await identityRows(role);
    assert.equal(rows.size, 4);
    assert.equal(rows.get(EMAIL).hibp_domain, null, 'an email address has no domain status');
    assert.deepEqual(Object.keys(rows.get(VERIFIED).hibp_domain).sort(), [
      'listed_at',
      'message',
      'reason',
      'state',
      'verified_parent',
    ]);
  }
});

test('without a key: no_key, and the re-check is refused with 400', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await setSetting('exposure_hibp_key', '');
  const view = await call('admin', 'GET', VIEW);
  assert.equal(view.status, 200);
  assert.equal(view.json.state, 'no_key');
  assert.deepEqual(Object.keys(view.json).sort(), VIEW_KEYS);
  const refresh = await call('admin', 'POST', REFRESH);
  assert.equal(refresh.status, 400);
  assert.equal(refresh.json.message, 'No usable HIBP API key is saved; save one first');
  const rows = await identityRows('viewer');
  assert.deepEqual([rows.get(VERIFIED).hibp_domain.state, rows.get(VERIFIED).hibp_domain.reason], ['unknown', 'no_key']);
});

test('a saved key: not checked, then a re-check lists, links and normalizes; a second within a minute is cached', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await saveKey(API_KEY);
  hibp.domains = [VERIFIED.replace('verified', 'Verified') + '.', `other-${tag}.siembox-test.invalid`];

  const fresh = await call('admin', 'GET', VIEW);
  assert.deepEqual([fresh.json.state, fresh.json.domains], ['not_checked', null]);

  const before = { list: hibp.listCalls, status: hibp.statusCalls };
  const r = await call('admin', 'POST', REFRESH);
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json).sort(), [...VIEW_KEYS, 'became_due', 'refreshed'].sort());
  assert.equal(r.json.refreshed, true);
  assert.equal(r.json.state, 'listed');
  assert.deepEqual(r.json.became_due, []);
  assert.equal(r.json.attribution, 'https://haveibeenpwned.com');
  assert.deepEqual(r.json.plan, {
    name: 'Core 2',
    domain_search_max_breached_accounts: 100,
    max_breached_domains: 3,
    subscribed_until: '2027-01-01T00:00:00',
  });
  const listed = new Map((r.json.domains as any[]).map((d) => [d.domain, d]));
  assert.ok(listed.has(VERIFIED), 'lowercase, no trailing dot');
  assert.equal(listed.get(VERIFIED).identity_id, ids.verified);
  assert.equal(listed.get(VERIFIED).within_plan, true);
  assert.equal(listed.get(`other-${tag}.siembox-test.invalid`).identity_id, null);
  assert.deepEqual([hibp.listCalls - before.list, hibp.statusCalls - before.status], [1, 1], 'the plan is re-read');
  assert.ok(r.json.next_refresh_allowed_at, 'the cooldown is reported');
  assert.equal(hibp.searchCalls, 0);

  // Nothing secret in the stored row: a hash of the encrypted envelope, not of the key.
  const raw = await snapshotRaw();
  assert.ok(!raw.includes(API_KEY));
  const stored = JSON.parse(raw);
  assert.match(stored.key_ref, /^[0-9a-f]{16}$/);
  assert.notEqual(stored.key_ref, crypto.createHash('sha256').update(API_KEY).digest('hex').slice(0, 16));

  const calls = hibpCalls();
  const again = await call('admin', 'POST', REFRESH);
  assert.equal(again.status, 200);
  assert.equal(again.json.refreshed, false);
  assert.equal(hibpCalls(), calls, 'inside the cooldown nothing is sent');
});

test('identities carry hibp_domain for every role, and no GET calls HIBP', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  const calls = hibpCalls();
  for (const role of ROLES) {
    const rows = await identityRows(role);
    assert.equal(rows.get(VERIFIED).hibp_domain.state, 'verified');
    const missing = rows.get(UNVERIFIED).hibp_domain;
    assert.equal(missing.state, 'not_verified');
    assert.ok(missing.message.includes(HIBP_DOMAINS_DASHBOARD_URL));
    assert.equal(rows.get(EMAIL).hibp_domain, null);
  }
  assert.equal((await call('admin', 'GET', VIEW)).status, 200);
  assert.equal((await call('viewer', 'GET', '/api/exposure/status')).status, 200);
  assert.equal(hibpCalls(), calls, 'reads never reach HIBP');
});

test('a 404 from the list is an unknown answer, never "not verified"', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await setSetting('exposure_hibp_domains', ''); // no earlier list to fall back on
  hibp.fail = new HibpError('transient', 'HIBP answered HTTP 404 for the verified-domain list', { status: 404 });
  const r = await call('admin', 'POST', REFRESH);
  assert.equal(r.status, 200);
  assert.equal(r.json.refreshed, true);
  assert.equal(r.json.state, 'error');
  assert.deepEqual([r.json.error.kind, r.json.error.status], ['bad_response', 404]);
  const rows = await identityRows('analyst');
  const s = rows.get(UNVERIFIED).hibp_domain;
  assert.deepEqual([s.state, s.reason], ['unknown', 'bad_response']);
});

test('a domain that turns verified is re-queued: due again, status cleared', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await MonitoredIdentityModel.markUnverified(ids.flipped, 'Skipped: not verified');
  await endCooldown();
  hibp.domains = [VERIFIED, FLIPPED];
  const r = await call('admin', 'POST', REFRESH);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.became_due, [ids.flipped]);
  const row = (
    await pool.query('SELECT last_checked_at, last_status, last_error FROM monitored_identities WHERE id = $1', [ids.flipped])
  ).rows[0];
  assert.deepEqual(row, { last_checked_at: null, last_status: null, last_error: null });
  assert.equal((await identityRows('viewer')).get(FLIPPED).hibp_domain.state, 'verified');
});

test('a 429 is recorded and pauses; the next re-check is refused with Retry-After and sends nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await endCooldown();
  hibp.fail = new HibpError('rate_limited', 'HIBP rate limit exceeded; retry after 30s', {
    status: 429,
    retryAfterSeconds: 30,
  });
  const r = await call('admin', 'POST', REFRESH);
  assert.equal(r.status, 200);
  assert.equal(r.json.error.kind, 'rate_limited');
  assert.ok(Date.parse(r.json.error.retry_after) > Date.now() + 25_000);
  assert.equal(r.json.state, 'listed', 'the last good list is kept');

  const status = await call('viewer', 'GET', '/api/exposure/status');
  assert.ok(status.json.leaked_creds.paused_until, 'breach checks are paused too');

  const calls = hibpCalls();
  const refused = await call('admin', 'POST', REFRESH);
  assert.equal(refused.status, 429);
  assert.match(refused.json.message, /^HIBP rate limit reached; try again after \d{4}-/);
  const retryAfter = Number(refused.headers.get('retry-after'));
  assert.ok(retryAfter > 0 && retryAfter <= 32, `Retry-After ${retryAfter}`);
  assert.equal(hibpCalls(), calls);

  // Even after a restart (no in-process pause) the recorded retry time holds.
  resetLeakedCredentialPause();
  assert.equal((await call('admin', 'POST', REFRESH)).status, 429);
  assert.equal(hibpCalls(), calls);
});

test('re-saving the same key during a 429 keeps the wait; only a different key starts afresh', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await saveKey(API_KEY);
  await setSetting('exposure_hibp_domains', ''); // no earlier wait recorded
  hibp.fail = new HibpError('rate_limited', 'HIBP rate limit exceeded; retry after 3600s', {
    status: 429,
    retryAfterSeconds: 3600,
  });
  assert.equal((await call('admin', 'POST', REFRESH)).json.error.kind, 'rate_limited');
  const recorded = await snapshotRaw();
  const envelope = (await pool.query(`SELECT value FROM system_settings WHERE key = 'exposure_hibp_key'`)).rows[0].value;
  hibp.fail = null;

  // The admin re-enters the same key (and toggles the provider) hoping to clear the banner.
  const calls = hibpCalls();
  assert.equal((await call('admin', 'PUT', '/api/exposure/providers/hibp', { api_key: API_KEY })).status, 200);
  assert.equal((await call('admin', 'PUT', '/api/exposure/providers/hibp', { enabled: true })).status, 200);
  assert.equal(await snapshotRaw(), recorded, 'the recorded retry-after is kept');
  assert.equal(
    (await pool.query(`SELECT value FROM system_settings WHERE key = 'exposure_hibp_key'`)).rows[0].value,
    envelope,
    'the same key is not re-encrypted, so the snapshot stays bound to it'
  );
  const status = await call('viewer', 'GET', '/api/exposure/status');
  assert.ok(status.json.leaked_creds.paused_until, 'breach checks stay paused');
  const refused = await call('admin', 'POST', REFRESH);
  assert.equal(refused.status, 429);
  assert.ok(Number(refused.headers.get('retry-after')) > 3500);
  assert.equal(hibpCalls(), calls, 'nothing is sent to HIBP inside its retry-after');

  // A different key has its own limit: a fresh start.
  await saveKey(OTHER_KEY);
  assert.equal(await snapshotRaw(), '');
  assert.equal((await call('viewer', 'GET', '/api/exposure/status')).json.leaked_creds.paused_until, null);
  hibp.domains = [VERIFIED];
  const fresh = await call('admin', 'POST', REFRESH);
  assert.equal(fresh.status, 200);
  assert.equal(fresh.json.state, 'listed');
  await saveKey(API_KEY);
  await setSetting('exposure_hibp_enabled', 'false');
});

test('a new key resets the list; a list written for the old key reads as not checked', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  if (operatorKeyPresent) return t.skip('an HIBP key is already stored here; not touching it');
  await setSetting('exposure_hibp_domains', '');
  await endCooldown();
  hibp.domains = [VERIFIED];
  assert.equal((await call('admin', 'POST', REFRESH)).json.state, 'listed');
  const oldSnapshot = await snapshotRaw();

  await saveKey(OTHER_KEY);
  assert.equal(await snapshotRaw(), '', 'saving a key clears the list');
  assert.equal((await call('admin', 'GET', VIEW)).json.state, 'not_checked');

  await setSetting('exposure_hibp_domains', oldSnapshot); // e.g. restored by hand
  assert.equal((await call('admin', 'GET', VIEW)).json.state, 'not_checked', 'bound to the old key');
  const rows = await identityRows('viewer');
  assert.equal(rows.get(VERIFIED).hibp_domain.reason, 'not_checked');

  const removed = await call('admin', 'PUT', '/api/exposure/providers/hibp', { api_key: null });
  assert.equal(removed.status, 200);
  assert.equal((await call('admin', 'GET', VIEW)).json.state, 'no_key');
});

test('model: markUnverified records the skip; requeueVerified touches only unverified email domains', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await MonitoredIdentityModel.markUnverified(ids.unverified, 'x'.repeat(600));
  const row = (
    await pool.query('SELECT last_status, last_error, last_checked_at FROM monitored_identities WHERE id = $1', [ids.unverified])
  ).rows[0];
  assert.equal(row.last_status, 'unverified');
  assert.equal(row.last_error.length, 500, 'capped');
  assert.ok(Date.now() - new Date(row.last_checked_at).getTime() < 60_000);

  // An email row with the same status, and a domain that's verified: untouched.
  await MonitoredIdentityModel.markUnverified(ids.email, 'n/a');
  await MonitoredIdentityModel.markChecked(ids.verified);
  await pool.query('UPDATE monitored_identities SET enabled = false WHERE id = $1', [ids.unverified]);
  const requeued = await MonitoredIdentityModel.requeueVerified([UNVERIFIED, VERIFIED, EMAIL, 'nothing.example']);
  assert.deepEqual(requeued, [{ id: ids.unverified, enabled: false }]);
  const statuses = await pool.query(
    'SELECT id, last_status FROM monitored_identities WHERE id = ANY($1) ORDER BY id',
    [[ids.unverified, ids.email, ids.verified]]
  );
  const byId = new Map(statuses.rows.map((r) => [r.id, r.last_status]));
  assert.equal(byId.get(ids.unverified), null);
  assert.equal(byId.get(ids.email), 'unverified');
  assert.equal(byId.get(ids.verified), 'ok');
  assert.deepEqual(await MonitoredIdentityModel.requeueVerified([]), []);
});
