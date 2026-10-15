/**
 * GET /api/exposure/summary and the newer GET /api/exposure/findings filters,
 * against a real Postgres.
 *
 * Exact numbers: on a dedicated connection, inside one transaction, temp
 * tables shadow exposure_findings, monitored_identities, watched_domains and
 * domain_baselines (pg_temp is searched first), so the summary sees only the
 * fixtures below whatever the other DB tests write meanwhile, and everything
 * is rolled back. The fixtures sit at fixed offsets from the transaction's
 * NOW(), the same NOW() the summary reads.
 *
 * HTTP: the real app on an ephemeral port with one user and session per role.
 * The /findings cases use rows tagged with a random id in the real tables,
 * deleted again in `after`. Skips itself without Postgres. Run with `npm test`.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { PoolClient } from 'pg';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { getExposureSummary } from '../models/Exposure';
import { SECRET_KEY_PATTERN } from '../services/exposure/findingWriter';
import type { ExposureSummary, SummaryDays } from '../services/exposure/summary';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the exposure schema is not reachable';
const DAY = 86_400;

const tag = crypto.randomBytes(5).toString('hex');
const name = `drsummary-${tag}`;

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];

// ---- Fixtures for the exact-number cases (temp tables) --------------------------------

interface FindingFixture {
  id: number;
  source: 'leaked-creds' | 'domain-monitor';
  event_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Seconds before NOW(). */
  first: number;
  /** Seconds before NOW() it was resolved; undefined: open. */
  resolved?: number;
  identity_id?: number;
  domain_id?: number;
  detail: Record<string, unknown>;
  category: 'credentials' | 'impersonation' | 'domain_changes';
}

const breach = (account: string, title: string | null, date: string | null, extra: Record<string, unknown> = {}) => ({
  account,
  ...(title ? { breach_title: title } : {}),
  breach_name: (title ?? 'oldlist').replace(/\s/g, ''),
  breach_date: date,
  data_classes: ['Email addresses'],
  is_stealer_log: false,
  ...extra,
});

const FIXTURES: FindingFixture[] = [
  { id: 1, source: 'leaked-creds', event_type: 'breach', severity: 'high', first: 10 * DAY, identity_id: 1, category: 'credentials', detail: breach('Alice@acme.test', 'MegaCorp', '2023-05-01', { data_classes: ['Passwords ', 'Email addresses'] }) },
  { id: 2, source: 'leaked-creds', event_type: 'breach', severity: 'medium', first: 80 * DAY, identity_id: 1, category: 'credentials', detail: breach('alice@acme.test', null, null) },
  { id: 3, source: 'leaked-creds', event_type: 'breach', severity: 'high', first: 1 * DAY, identity_id: 1, category: 'credentials', detail: breach('bob@acme.test', 'StealerX', '2024-02-02', { is_stealer_log: true }) },
  { id: 4, source: 'leaked-creds', event_type: 'breach', severity: 'low', first: 120 * DAY, resolved: 40 * DAY, identity_id: 1, category: 'credentials', detail: breach('carol@acme.test', 'Spam', '2020-01-01', { data_classes: ['Passwords'] }) },
  { id: 5, source: 'domain-monitor', event_type: 'lookalike_registered', severity: 'high', first: 40 * DAY, domain_id: 1, category: 'impersonation', detail: { lookalike: 'acme.co' } },
  { id: 6, source: 'domain-monitor', event_type: 'new_cert', severity: 'medium', first: 10 * DAY, domain_id: 1, category: 'impersonation', detail: { lookalike: 'acme.co' } },
  { id: 7, source: 'domain-monitor', event_type: 'new_cert', severity: 'medium', first: 120 * DAY, resolved: 10 * DAY, domain_id: 1, category: 'domain_changes', detail: { names: ['www.acme.com'] } },
  { id: 8, source: 'domain-monitor', event_type: 'dns_drift', severity: 'critical', first: 400 * DAY, domain_id: 1, category: 'domain_changes', detail: { record_type: 'MX' } },
  { id: 9, source: 'domain-monitor', event_type: 'rdap_change', severity: 'low', first: 400 * DAY, resolved: 300 * DAY, domain_id: 1, category: 'domain_changes', detail: {} },
  { id: 10, source: 'domain-monitor', event_type: 'expiry_warning', severity: 'medium', first: 1 * DAY, resolved: DAY / 2, domain_id: 1, category: 'domain_changes', detail: {} },
  { id: 11, source: 'domain-monitor', event_type: 'unexpected_ca', severity: 'high', first: 150 * DAY, domain_id: 1, category: 'domain_changes', detail: {} },
  { id: 12, source: 'leaked-creds', event_type: 'breach', severity: 'critical', first: 5 * DAY, identity_id: 2, category: 'credentials', detail: breach('alice@acme.test', 'Zeta', '2024-12-01', { data_classes: ['Auth tokens'] }) },
  { id: 13, source: 'domain-monitor', event_type: 'lookalike_registered', severity: 'medium', first: 20 * DAY, domain_id: 2, category: 'impersonation', detail: { lookalike: 'acme.org.co' } },
  { id: 14, source: 'leaked-creds', event_type: 'breach', severity: 'medium', first: 30 * DAY, identity_id: 2, category: 'credentials', detail: breach('dave@acme.test', 'Forum', '2022-03-03') },
  // An account in the same breach twice (through two identities): one title shown.
  { id: 15, source: 'leaked-creds', event_type: 'breach', severity: 'high', first: 3 * DAY, identity_id: 2, category: 'credentials', detail: breach('bob@acme.test', 'StealerX', '2024-02-02', { is_stealer_log: true }) },
];

async function seedTempTables(db: PoolClient) {
  for (const t of ['exposure_findings', 'monitored_identities', 'watched_domains', 'domain_baselines']) {
    await db.query(`CREATE TEMP TABLE ${t} (LIKE public.${t} INCLUDING DEFAULTS) ON COMMIT DROP`);
  }
  await db.query(
    `INSERT INTO monitored_identities (id, kind, value, created_at, updated_at) VALUES
       (1, 'email', 'alice@acme.test', NOW() - INTERVAL '200 days', NOW()),
       (2, 'email_domain', 'acme.test', NOW() - INTERVAL '5 days', NOW())`
  );
  await db.query(
    `INSERT INTO watched_domains (id, domain, scope, enabled, last_summary, created_at, updated_at) VALUES
       (1, 'acme.com', 'own', true, $1, NOW() - INTERVAL '300 days', NOW()),
       (2, 'acme.org', 'brand', false, $1, NOW() - INTERVAL '20 days', NOW())`,
    [JSON.stringify({ collectors: { lookalike: { status: 'ok', details: { candidates: 150 } } } })]
  );
  const nowSeconds = Number((await db.query(`SELECT floor(extract(epoch FROM NOW()))::bigint AS s`)).rows[0].s);
  const info = (p: Record<string, unknown>) => ({ mx: false, addr: false, fuzzer: 'omission', since: null, seen_at: nowSeconds, prior_drop: null, ...p });
  const lookalike = (registered: Record<string, unknown>) => JSON.stringify({ v: 1, registered, unregistered: {}, dropped: {} });
  const ct = (lookalikes: Record<string, Record<string, number>>) =>
    JSON.stringify({
      v: 1,
      lookalikes: Object.fromEntries(Object.entries(lookalikes).map(([n, certs]) => [n, { certs, names: [n], issuers: [], checked_at: nowSeconds }])),
    });
  await db.query(
    `INSERT INTO domain_baselines (domain_id, collector, snapshot) VALUES
       (1, 'lookalike', $1), (1, 'ct', $2), (1, 'dns', '{"v":1}'), (2, 'lookalike', $3)`,
    [
      lookalike({
        'acme.co': info({ mx: true, addr: true, fuzzer: 'tld-swap', since: nowSeconds - 40 * DAY }),
        'acrne.com': info({ addr: true, fuzzer: 'homoglyph' }),
        'acm.com': info({ mx: null, fuzzer: 'unknown' }),
      }),
      ct({ 'acme.co': { k1: nowSeconds + 30 * DAY }, 'acrne.com': { k2: nowSeconds - DAY } }),
      lookalike({ 'acme.org.co': info({ mx: true }) }),
    ]
  );
  for (const f of FIXTURES) {
    await db.query(
      `INSERT INTO exposure_findings
         (id, source, identity_id, domain_id, event_type, fingerprint, title, severity, detail, first_seen, last_seen, resolved_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
               NOW() - make_interval(secs => $10), NOW(),
               CASE WHEN $11::float8 IS NULL THEN NULL ELSE NOW() - make_interval(secs => $11::float8) END)`,
      [f.id, f.source, f.identity_id ?? null, f.domain_id ?? null, f.event_type, `fp-${f.id}`, `fixture ${f.id}`, f.severity, JSON.stringify(f.detail), f.first, f.resolved ?? null]
    );
  }
}

/** What the summary must say, computed from the fixtures and the window it reports. */
function expectedCounts(s: ExposureSummary) {
  const now = Date.parse(s.generated_at);
  const since = Date.parse(s.window.since);
  const at = (ago: number) => now - ago * 1000;
  const inWindow = (ago: number | undefined) => ago !== undefined && at(ago) >= since;
  const open = FIXTURES.filter((f) => f.resolved === undefined);
  return {
    open: open.length,
    new: FIXTURES.filter((f) => inWindow(f.first)).length,
    resolved: FIXTURES.filter((f) => inWindow(f.resolved)).length,
    prev_new: FIXTURES.filter((f) => at(f.first) < since && at(f.first) >= since - (now - since)).length,
  };
}

async function withFixtures<T>(fn: (db: PoolClient) => Promise<T>): Promise<T> {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    await seedTempTables(db);
    return await fn(db);
  } finally {
    await db.query('ROLLBACK').catch(() => undefined);
    db.release();
  }
}

function assertInvariants(s: ExposureSummary, label: string) {
  const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
  assert.equal(sum(Object.values(s.open.by_severity)), s.open.total, `${label}: severities sum to the open total`);
  assert.equal(
    sum(s.trend.map((b) => b.new.credentials + b.new.impersonation + b.new.domain_changes)),
    s.in_window.new,
    `${label}: the trend sums to the window's new findings`
  );
  assert.equal(sum(s.trend.map((b) => b.resolved)), s.in_window.resolved, `${label}: and to its resolved ones`);
  assert.equal(s.trend.at(-1)?.open_at_end, s.open.total, `${label}: the backlog ends at the open total`);
  assert.equal(s.trend[0]?.start, s.window.since, `${label}: the first bucket starts the window`);
}

// ---- Setup ------------------------------------------------------------------------------

const ids = { identity: 0, domain: 0, alert: 0, findings: {} as Record<string, number> };

before(async () => {
  try {
    for (const table of ['sessions', 'exposure_findings', 'domain_baselines', 'alerts']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
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

  // Tagged rows in the real tables for the /findings cases.
  ids.identity = (
    await pool.query(`INSERT INTO monitored_identities (kind, value) VALUES ('email_domain', $1) RETURNING id`, [
      `mail-${tag}.siembox-test.invalid`,
    ])
  ).rows[0].id;
  ids.domain = (
    await pool.query(`INSERT INTO watched_domains (domain, scope) VALUES ($1, 'own') RETURNING id`, [
      `watch-${tag}.siembox-test.invalid`,
    ])
  ).rows[0].id;
  ids.alert = (
    await pool.query(
      `INSERT INTO alerts (severity, title, matched_data, status, source, event_id)
       VALUES ('high', $1, '{}', 'closed', 'domain-monitor', $2) RETURNING id`,
      [`alert ${tag}`, `drsummary-${tag}`]
    )
  ).rows[0].id;
  const insert = async (
    key: string,
    f: { source: string; event_type: string; severity: string; days: number; title: string; detail: Record<string, unknown>; identity?: boolean; alert?: boolean }
  ) => {
    const r = await pool.query(
      `INSERT INTO exposure_findings (source, identity_id, domain_id, event_type, fingerprint, title, severity, detail, alert_id, first_seen)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() - make_interval(days => $10))
       RETURNING id`,
      [
        f.source,
        f.identity ? ids.identity : null,
        f.identity ? null : ids.domain,
        f.event_type,
        `${tag}-${key}`,
        `${tag} ${f.title}`,
        f.severity,
        JSON.stringify(f.detail),
        f.alert ? ids.alert : null,
        f.days,
      ]
    );
    ids.findings[key] = Number(r.rows[0].id);
  };
  await insert('lookalike', { source: 'domain-monitor', event_type: 'lookalike_registered', severity: 'high', days: 30, title: 'Lookalike registered', detail: { lookalike: `look-${tag}.example` }, alert: true });
  await insert('lookalikeCert', { source: 'domain-monitor', event_type: 'new_cert', severity: 'medium', days: 20, title: 'Certificate for a lookalike', detail: { lookalike: `look-${tag}.example` } });
  await insert('ownCert', { source: 'domain-monitor', event_type: 'new_cert', severity: 'medium', days: 2, title: 'New certificate', detail: { names: ['www'] } });
  await insert('critical', { source: 'domain-monitor', event_type: 'dns_drift', severity: 'critical', days: 60, title: 'MX changed', detail: {} });
  await insert('literal', { source: 'domain-monitor', event_type: 'rdap_change', severity: 'low', days: 3, title: 'promo 50%_off .*( here', detail: {} });
  await insert('lookalikeOfLiteral', { source: 'domain-monitor', event_type: 'rdap_change', severity: 'low', days: 4, title: 'promo 50xyoff here', detail: {} });
  await insert('breach', { source: 'leaked-creds', event_type: 'breach', severity: 'high', days: 1, title: 'found in a breach', identity: true, detail: { account: `Alice-${tag}@Example.test`, breach_title: `Mega${tag}Corp` } });
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    // Findings go with their identity and domain (ON DELETE CASCADE).
    await pool.query('DELETE FROM monitored_identities WHERE id = $1', [ids.identity]);
    await pool.query('DELETE FROM watched_domains WHERE id = $1', [ids.domain]);
    await pool.query('DELETE FROM alerts WHERE id = $1', [ids.alert]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]); // sessions cascade
  }
  await closePools();
});

async function call(role: Role | null, path: string) {
  const headers: Record<string, string> = role ? { Authorization: `Bearer ${tokens[role]}` } : {};
  const res = await fetch(base + path, { headers });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

// ---- Exact numbers ----------------------------------------------------------------------

test('summary, 90 days: exact counts from the fixtures, in one snapshot', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await withFixtures(async (db) => {
    const s = await getExposureSummary(90, db);
    const expected = expectedCounts(s);
    assert.deepEqual([s.window.days, s.window.bucket], [90, 'week']);

    assert.equal(s.open.total, 11);
    assert.equal(s.open.total, expected.open);
    assert.deepEqual(s.open.by_severity, { critical: 2, high: 5, medium: 4, low: 0 });
    assert.deepEqual(s.open.by_source, { 'leaked-creds': 6, 'domain-monitor': 5 });
    const f8 = Date.parse(s.generated_at) - 400 * DAY * 1000;
    assert.equal(Date.parse(s.open.oldest_critical_high_first_seen!), f8, 'the 400-day-old critical DNS change');

    assert.equal(s.in_window.new, 10);
    assert.equal(s.in_window.new, expected.new);
    assert.deepEqual(s.in_window.new_by_severity, { critical: 1, high: 4, medium: 5, low: 0 });
    assert.equal(s.in_window.resolved, 3);
    assert.equal(s.in_window.resolved, expected.resolved);
    assert.equal(s.in_window.prev_new, 3, 'carol, the own certificate and the unexpected CA');
    assert.equal(s.in_window.prev_new, expected.prev_new);

    const type = (e: string, c: string) => s.by_type.find((r) => r.event_type === e && r.category === c)!;
    assert.deepEqual([type('breach', 'credentials').open, type('breach', 'credentials').new], [6, 6]);
    assert.deepEqual(type('breach', 'credentials').open_by_severity, { critical: 1, high: 3, medium: 2, low: 0 });
    assert.deepEqual([type('lookalike_registered', 'impersonation').open, type('new_cert', 'impersonation').open], [2, 1]);
    assert.deepEqual(
      [type('new_cert', 'domain_changes').open, type('new_cert', 'domain_changes').resolved],
      [0, 1],
      'a certificate for the own domain is not counted as a lookalike'
    );
    assert.deepEqual([type('expiry_warning', 'domain_changes').new, type('expiry_warning', 'domain_changes').resolved], [1, 1]);
    assert.equal(type('rdap_change', 'domain_changes').open, 0, 'zero-filled');

    // Accounts: alice (passwords, auth tokens), bob (stealer log) and dave (neither).
    assert.deepEqual([s.accounts.total, s.accounts.to_reset], [3, 2]);
    assert.deepEqual(
      s.accounts.top.map((a) => [a.account, a.open, a.credential_exposures, a.stealer_log, a.worst_severity]),
      [
        ['bob@acme.test', 2, 2, true, 'high'],
        ['alice@acme.test', 3, 2, false, 'critical'],
        ['dave@acme.test', 1, 0, false, 'medium'],
      ],
      'credentials first, then stealer logs, then the worst severity'
    );
    const alice = s.accounts.top[1];
    assert.equal(alice.identity_id, 1);
    assert.deepEqual(alice.breaches, [
      { title: 'Zeta', date: '2024-12-01' },
      { title: 'MegaCorp', date: '2023-05-01' },
      { title: 'oldlist', date: null },
    ]);
    assert.deepEqual(s.accounts.top[0].breaches, [{ title: 'StealerX', date: '2024-02-02' }], 'one breach seen twice');

    // Lookalikes: the enabled domain's baseline only (acme.org is disabled).
    const l = s.lookalikes;
    assert.equal(l.state, 'checked');
    assert.deepEqual([l.candidates_checked, l.registered, l.with_mx, l.with_address, l.with_current_cert], [150, 3, 1, 2, 1]);
    assert.deepEqual(
      l.top.map((r) => [r.lookalike, r.certs, r.technique]),
      [
        ['acme.co', 'current', 'tld-swap'],
        ['acrne.com', 'none', 'homoglyph'],
        ['acm.com', 'not_checked', null],
      ]
    );
    assert.deepEqual(l.top[0].open_findings, { count: 2, worst_severity: 'high' });
    assert.equal(l.top[1].reported_at, null, 'recorded silently on the first run');
    assert.ok(l.top.every((r) => r.watched_domain === 'acme.com'));

    assert.equal(s.trend.reduce((n, b) => n + b.monitoring_added.identities, 0), 1);
    assert.equal(s.trend.reduce((n, b) => n + b.monitoring_added.domains, 0), 1);
    assertInvariants(s, '90');
  });
});

test('summary: each window has whole UTC buckets of its unit, and the same invariants', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await withFixtures(async (db) => {
    const units: Record<SummaryDays, ['day' | 'week' | 'month', number[]]> = {
      30: ['day', [31]],
      90: ['week', [13, 14]],
      180: ['week', [26, 27]],
      365: ['month', [13]],
    };
    for (const days of [30, 90, 180, 365] as const) {
      const s = await getExposureSummary(days, db);
      const [unit, lengths] = units[days];
      assert.equal(s.window.bucket, unit);
      assert.ok(lengths.includes(s.trend.length), `${days}: ${s.trend.length} buckets`);
      const starts = s.trend.map((b) => new Date(b.start));
      for (const [i, d] of starts.entries()) {
        assert.equal(d.getUTCHours() + d.getUTCMinutes() + d.getUTCSeconds() + d.getUTCMilliseconds(), 0, `${days}: UTC midnight`);
        if (unit === 'week') assert.equal(d.getUTCDay(), 1, `${days}: weeks start on Monday`);
        if (unit === 'month') assert.equal(d.getUTCDate(), 1, `${days}: months start on the 1st`);
        if (i === 0) continue;
        const prev = starts[i - 1];
        if (unit === 'month') {
          assert.equal((d.getUTCFullYear() - prev.getUTCFullYear()) * 12 + d.getUTCMonth() - prev.getUTCMonth(), 1, 'contiguous months');
        } else {
          assert.equal(d.getTime() - prev.getTime(), (unit === 'day' ? 1 : 7) * DAY * 1000, `${days}: contiguous`);
        }
      }
      const now = Date.parse(s.generated_at);
      assert.ok(starts.at(-1)!.getTime() <= now, 'the last bucket holds now');
      const expected = expectedCounts(s);
      assert.deepEqual(
        [s.open.total, s.in_window.new, s.in_window.resolved, s.in_window.prev_new],
        [expected.open, expected.new, expected.resolved, expected.prev_new],
        `${days}: counts`
      );
      assertInvariants(s, String(days));
    }
  });
});

test('summary: nothing configured is an empty, consistent answer', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    for (const tbl of ['exposure_findings', 'monitored_identities', 'watched_domains', 'domain_baselines']) {
      await db.query(`CREATE TEMP TABLE ${tbl} (LIKE public.${tbl} INCLUDING DEFAULTS) ON COMMIT DROP`);
    }
    const s = await getExposureSummary(30, db);
    assert.equal(s.open.total, 0);
    assert.equal(s.trend.length, 31);
    assert.ok(s.trend.every((b) => b.open_at_end === 0 && b.resolved === 0));
    assert.deepEqual([s.accounts.total, s.accounts.top], [0, []]);
    assert.equal(s.lookalikes.state, 'not_watched');
    assertInvariants(s, 'empty');
  } finally {
    await db.query('ROLLBACK').catch(() => undefined);
    db.release();
  }
});

// ---- HTTP ---------------------------------------------------------------------------------

function keysOf(value: unknown, out = new Set<string>()): Set<string> {
  if (Array.isArray(value)) value.forEach((v) => keysOf(v, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.add(k);
      keysOf(v, out);
    }
  }
  return out;
}

test('GET /summary: every role gets the same answer; no session is refused; bad windows are 400', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  assert.equal((await call(null, '/api/exposure/summary')).status, 401);

  // Other DB tests write findings meanwhile: retry until four reads agree.
  let bodies: string[] = [];
  for (let attempt = 0; attempt < 5; attempt++) {
    const results = [];
    for (const role of ROLES) {
      const r = await call(role, '/api/exposure/summary?days=90');
      assert.equal(r.status, 200, `${role}`);
      results.push(r.json);
    }
    bodies = results.map(({ generated_at: _g, ...rest }) => JSON.stringify(rest));
    if (new Set(bodies).size === 1) break;
  }
  assert.equal(new Set(bodies).size, 1, 'identical for admin, operator, analyst and viewer');

  const s = (await call('viewer', '/api/exposure/summary')).json as ExposureSummary;
  assert.equal(s.window.days, 90, 'the default window');
  // The live invariants hold on whatever the database holds.
  const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
  assert.equal(sum(Object.values(s.open.by_severity)), s.open.total);
  assert.equal(s.trend.at(-1)!.open_at_end, s.open.total);

  // No secret-like key, apart from the two that name what was exposed.
  const allowed = new Set(['credentials', 'credential_exposures']);
  const flagged = [...keysOf(s)].filter((k) => SECRET_KEY_PATTERN.test(k) && !allowed.has(k));
  assert.deepEqual(flagged, []);

  for (const bad of ['?days=7', '?days=90abc', '?days=90&days=30', '?days=1e2', '?days=-90']) {
    const r = await call('viewer', `/api/exposure/summary${bad}`);
    assert.equal(r.status, 400, bad);
    assert.equal(r.json.message, 'days must be one of 30, 90, 180, 365');
  }
});

// ---- /findings filters ----------------------------------------------------------------------

async function findingKeys(query: string, role: Role = 'viewer'): Promise<string[]> {
  const r = await call(role, `/api/exposure/findings?limit=200&${query}`);
  assert.equal(r.status, 200, query);
  const byId = new Map(Object.entries(ids.findings).map(([k, id]) => [id, k]));
  return (r.json.findings as Array<{ id: number }>).map((f) => byId.get(f.id) ?? `other:${f.id}`);
}

test('GET /findings: event_type, category, since_days, since, alert_id and sort', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const d = `domain_id=${ids.domain}`;
  assert.deepEqual(await findingKeys(`${d}&event_type=lookalike_registered`), ['lookalike']);
  assert.deepEqual((await findingKeys(`${d}&category=impersonation`)).sort(), ['lookalike', 'lookalikeCert']);
  assert.deepEqual(
    (await findingKeys(`${d}&category=domain_changes&event_type=new_cert`)).sort(),
    ['ownCert'],
    "a certificate for the watched domain itself"
  );
  assert.deepEqual(await findingKeys(`identity_id=${ids.identity}&category=credentials`), ['breach']);
  assert.deepEqual((await findingKeys(`${d}&since_days=7`)).sort(), ['literal', 'lookalikeOfLiteral', 'ownCert']);
  const since = new Date(Date.now() - 25 * DAY * 1000).toISOString();
  assert.deepEqual((await findingKeys(`${d}&since=${encodeURIComponent(since)}`)).sort(), ['literal', 'lookalikeCert', 'lookalikeOfLiteral', 'ownCert']);
  assert.deepEqual(await findingKeys(`alert_id=${ids.alert}`), ['lookalike']);
  assert.deepEqual(await findingKeys(`${d}&sort=severity`), ['critical', 'lookalike', 'ownCert', 'lookalikeCert', 'literal', 'lookalikeOfLiteral']);
  // No new parameter: the order is unchanged (newest first, then id).
  assert.deepEqual(await findingKeys(d), ['ownCert', 'literal', 'lookalikeOfLiteral', 'lookalikeCert', 'lookalike', 'critical']);
  assert.deepEqual(await findingKeys(`${d}&sort=newest`), await findingKeys(d));
});

test('GET /findings: search is case-insensitive and literal', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const i = `identity_id=${ids.identity}`;
  const d = `domain_id=${ids.domain}`;
  assert.deepEqual(await findingKeys(`${i}&search=${encodeURIComponent(`alice-${tag}@example.TEST`)}`), ['breach'], 'account');
  assert.deepEqual(await findingKeys(`${i}&search=${encodeURIComponent(`mega${tag}corp`)}`), ['breach'], 'breach title');
  assert.deepEqual(await findingKeys(`${i}&search=${encodeURIComponent(`MAIL-${tag}`)}`), ['breach'], 'identity');
  assert.deepEqual((await findingKeys(`search=${encodeURIComponent(`LOOK-${tag}.example`)}`)).sort(), ['lookalike', 'lookalikeCert'], 'lookalike');
  assert.equal((await findingKeys(`search=${encodeURIComponent(`watch-${tag}.siembox-test`)}`)).length, 6, 'watched domain');
  assert.deepEqual(await findingKeys(`${d}&search=${encodeURIComponent('50%_off')}`), ['literal'], '% and _ are literal');
  assert.deepEqual(await findingKeys(`${d}&search=${encodeURIComponent('.*(')}`), ['literal'], 'regex characters are literal');
  assert.deepEqual(await findingKeys(`${d}&search=${encodeURIComponent('   ')}`), await findingKeys(d), 'blank is ignored');
});

test('GET /findings: account and lookalike match the whole value, case-insensitively', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const i = `identity_id=${ids.identity}`;
  assert.deepEqual(await findingKeys(`${i}&account=${encodeURIComponent(`ALICE-${tag}@example.test`)}`), ['breach']);
  assert.deepEqual(await findingKeys(`${i}&account=${encodeURIComponent(`alice-${tag}@example.tes`)}`), [], 'a prefix is not the account');
  assert.deepEqual(
    (await findingKeys(`lookalike=${encodeURIComponent(`LOOK-${tag}.Example`)}`)).sort(),
    ['lookalike', 'lookalikeCert']
  );
  assert.deepEqual(await findingKeys(`lookalike=${encodeURIComponent(`look-${tag}.exampl`)}`), [], 'a prefix is not the lookalike');
  assert.deepEqual(await findingKeys(`domain_id=${ids.domain}&lookalike=${encodeURIComponent('50%_off')}`), [], 'literal, and no title match');
});

test('GET /findings: rows carry category and alert_status', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await call('analyst', `/api/exposure/findings?domain_id=${ids.domain}&limit=200`);
  const byId = new Map((r.json.findings as any[]).map((f) => [f.id, f]));
  const linked = byId.get(ids.findings.lookalike);
  assert.deepEqual([linked.category, linked.alert_id, linked.alert_status], ['impersonation', ids.alert, 'closed']);
  const own = byId.get(ids.findings.ownCert);
  assert.deepEqual([own.category, own.alert_id, own.alert_status], ['domain_changes', null, null]);
  assert.equal(r.json.total, 6, 'the alert join does not multiply rows');
});

test('GET /findings: invalid filters are 400', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const cases: Array<[string, string]> = [
    ['event_type=bogus', 'event_type must be one of: breach, new_cert, unexpected_ca, lookalike_registered, rdap_change, dns_drift, expiry_warning'],
    ['event_type=breach&event_type=dns_drift', 'event_type must be given once'],
    ['category=lookalikes', 'category must be one of: credentials, impersonation, domain_changes'],
    ['since_days=0', 'since_days must be a whole number from 1 to 365'],
    ['since_days=366', 'since_days must be a whole number from 1 to 365'],
    ['since_days=1e2', 'since_days must be a whole number from 1 to 365'],
    ['since_days=7&since_days=8', 'since_days must be given once'],
    ['since=yesterday', 'since must be an ISO 8601 timestamp such as 2026-07-13T00:00:00.000Z'],
    ['since=2026-13-45T00:00:00Z', 'since must be an ISO 8601 timestamp such as 2026-07-13T00:00:00.000Z'],
    ['alert_id=abc', 'Invalid alert id'],
    ['alert_id=0', 'Invalid alert id'],
    [`search=${'x'.repeat(201)}`, 'search must be at most 200 characters'],
    ['search=a&search=b', 'search must be given once'],
    [`account=${'a'.repeat(255)}`, 'account must be at most 254 characters'],
    ['account=a@b.test&account=c@d.test', 'account must be given once'],
    [`lookalike=${'l'.repeat(254)}`, 'lookalike must be at most 253 characters'],
    ['lookalike=a.test&lookalike=b.test', 'lookalike must be given once'],
    ['sort=oldest', 'sort must be one of: newest, severity'],
  ];
  for (const [query, message] of cases) {
    const r = await call('viewer', `/api/exposure/findings?${query}`);
    assert.equal(r.status, 400, query);
    assert.equal(r.json.message, message, query);
  }
});
