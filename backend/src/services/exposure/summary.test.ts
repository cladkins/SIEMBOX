/**
 * The Digital Risk summary's pure folds (no database): the ?days= whitelist,
 * the breakdown and trend folds, the accounts list and the lookalike
 * inventory, read through the collectors' own snapshot parsers. The queries
 * and their exact counts are covered by routes/exposureSummary.db.test.ts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError } from '../../middleware/errorHandler';
import {
  KNOWN_FINDING_TYPES,
  LOOKALIKE_TOP,
  buildAccounts,
  buildLookalikeInventory,
  foldBreakdown,
  foldTrend,
  parseSummaryDays,
  severityFromRank,
  type BreakdownRow,
  type LookalikeDomainInput,
} from './summary';

const NOW = Math.floor(Date.parse('2026-10-14T12:00:00Z') / 1000);
const DAY = 86_400;

test('parseSummaryDays: the four windows, the default, and nothing else', () => {
  assert.equal(parseSummaryDays('30'), 30);
  assert.equal(parseSummaryDays('90'), 90);
  assert.equal(parseSummaryDays('180'), 180);
  assert.equal(parseSummaryDays('365'), 365);
  assert.equal(parseSummaryDays(undefined), 90);
  assert.equal(parseSummaryDays(''), 90);
  for (const bad of ['7', '90abc', '1e2', '-90', ' 90', '90 ', '090', ['90', '30'], 90, null, {}]) {
    assert.throws(
      () => parseSummaryDays(bad),
      (err: unknown) =>
        err instanceof ApiError && err.statusCode === 400 && err.message === 'days must be one of 30, 90, 180, 365',
      `rejects ${JSON.stringify(bad)}`
    );
  }
});

test('severityFromRank maps SEV_RANK_SQL back, anything odd reads as low', () => {
  assert.deepEqual([4, 3, 2, 1, 0, null, 'x'].map(severityFromRank), [
    'critical',
    'high',
    'medium',
    'low',
    'low',
    'low',
    'low',
  ]);
});

function row(partial: Partial<BreakdownRow>): BreakdownRow {
  return {
    source: 'domain-monitor',
    event_type: 'dns_drift',
    category: 'domain_changes',
    severity: 'medium',
    open_n: 0,
    new_n: 0,
    resolved_n: 0,
    prev_new_n: 0,
    oldest_open: null,
    ...partial,
  };
}

test('foldBreakdown: zero-filled totals, sources and known types', () => {
  const empty = foldBreakdown([]);
  assert.deepEqual(empty.open, {
    total: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    by_source: { 'leaked-creds': 0, 'domain-monitor': 0 },
    oldest_critical_high_first_seen: null,
  });
  assert.deepEqual(empty.in_window, {
    new: 0,
    new_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    resolved: 0,
    prev_new: 0,
  });
  assert.equal(empty.by_type.length, KNOWN_FINDING_TYPES.length);
  assert.ok(empty.by_type.every((t) => t.open === 0 && t.new === 0 && t.resolved === 0));
  assert.deepEqual(
    empty.by_type.map((t) => t.category),
    ['credentials', 'impersonation', 'impersonation', 'domain_changes', 'domain_changes', 'domain_changes', 'domain_changes', 'domain_changes']
  );
});

test('foldBreakdown: sums, the oldest open critical/high, and unknown types passed through', () => {
  const result = foldBreakdown([
    row({ source: 'leaked-creds', event_type: 'breach', category: 'credentials', severity: 'high', open_n: 3, new_n: 2, resolved_n: 1, prev_new_n: 1, oldest_open: '2026-05-01T00:00:00Z' }),
    row({ source: 'leaked-creds', event_type: 'breach', category: 'credentials', severity: 'low', open_n: 1, oldest_open: '2025-01-01T00:00:00Z' }),
    row({ event_type: 'new_cert', category: 'impersonation', severity: 'medium', open_n: 2, new_n: 2, oldest_open: new Date('2024-01-01T00:00:00Z') }),
    row({ event_type: 'dns_drift', severity: 'critical', open_n: 1, new_n: 1, oldest_open: '2026-06-01T00:00:00Z' }),
    row({ event_type: 'dns_drift', severity: 'critical', open_n: 0, resolved_n: 4, prev_new_n: 2, oldest_open: null }),
    row({ event_type: 'brand_new_thing', severity: 'low', open_n: 5, new_n: 5 }),
  ]);
  assert.equal(result.open.total, 12);
  assert.deepEqual(result.open.by_severity, { critical: 1, high: 3, medium: 2, low: 6 });
  assert.equal(
    Object.values(result.open.by_severity).reduce((a, b) => a + b, 0),
    result.open.total,
    'severities sum to the total'
  );
  assert.deepEqual(result.open.by_source, { 'leaked-creds': 4, 'domain-monitor': 8 });
  assert.equal(
    result.open.oldest_critical_high_first_seen,
    '2026-05-01T00:00:00.000Z',
    'medium and low ignored, however old'
  );
  assert.deepEqual(result.in_window, {
    new: 10,
    new_by_severity: { critical: 1, high: 2, medium: 2, low: 5 },
    resolved: 5,
    prev_new: 3,
  });

  const byKey = new Map(result.by_type.map((t) => [`${t.event_type}/${t.category}`, t]));
  assert.equal(byKey.get('breach/credentials')!.open, 4);
  assert.deepEqual(byKey.get('breach/credentials')!.open_by_severity, { critical: 0, high: 3, medium: 0, low: 1 });
  assert.equal(byKey.get('new_cert/impersonation')!.open, 2);
  assert.equal(byKey.get('new_cert/domain_changes')!.open, 0, 'own-domain certificates are counted apart');
  assert.deepEqual([byKey.get('dns_drift/domain_changes')!.open, byKey.get('dns_drift/domain_changes')!.resolved], [1, 4]);
  const unknown = byKey.get('brand_new_thing/domain_changes')!;
  assert.equal(unknown.open, 5);
  // Known pairs first, in their order; the unknown type stays inside its category.
  assert.equal(result.by_type.at(-1), unknown);
  assert.deepEqual(
    result.by_type.map((t) => t.category),
    [...result.by_type.map((t) => t.category)].sort(
      (a, b) => ['credentials', 'impersonation', 'domain_changes'].indexOf(a) - ['credentials', 'impersonation', 'domain_changes'].indexOf(b)
    ),
    'category order is kept'
  );
});

test('foldTrend: bucket order, zero-filled categories and the running backlog', () => {
  const starts = ['2026-09-28T00:00:00Z', '2026-10-05T00:00:00Z', '2026-10-12T00:00:00Z'];
  const trend = foldTrend(
    starts.map((s) => new Date(s)),
    [
      { kind: 'new', start: new Date('2026-09-28T00:00:00Z'), category: 'credentials', n: 4 },
      { kind: 'new', start: '2026-10-12T00:00:00Z', category: 'impersonation', n: 2 },
      { kind: 'new', start: '2026-10-12T00:00:00Z', category: 'domain_changes', n: 1 },
      { kind: 'resolved', start: '2026-10-05T00:00:00Z', category: null, n: 3 },
      { kind: 'identities', start: '2026-09-28T00:00:00Z', category: null, n: 1 },
      { kind: 'domains', start: '2026-10-12T00:00:00Z', category: null, n: 2 },
      // A row whose bucket is past the last one lands in the last bucket.
      { kind: 'new', start: '2026-10-19T00:00:00Z', category: 'credentials', n: 1 },
    ],
    10
  );
  assert.deepEqual(
    trend.map((b) => b.start),
    starts.map((s) => new Date(s).toISOString())
  );
  assert.deepEqual(trend[0].new, { credentials: 4, impersonation: 0, domain_changes: 0 });
  assert.deepEqual(trend[1].new, { credentials: 0, impersonation: 0, domain_changes: 0 });
  assert.deepEqual(trend[2].new, { credentials: 1, impersonation: 2, domain_changes: 1 });
  assert.deepEqual(trend.map((b) => b.resolved), [0, 3, 0]);
  assert.deepEqual(trend.map((b) => b.open_at_end), [14, 11, 15]);
  assert.deepEqual(trend[0].monitoring_added, { identities: 1, domains: 0 });
  assert.deepEqual(trend[2].monitoring_added, { identities: 0, domains: 2 });
  assert.deepEqual(foldTrend([], [{ kind: 'new', start: starts[0], category: 'credentials', n: 1 }], 3), []);
});

test('buildAccounts: three distinct breaches, numbers coerced, severity from rank', () => {
  const [account] = buildAccounts([
    {
      account: 'alice@example.com',
      identity_id: '7',
      open_n: 5,
      credential_exposures: 2,
      stealer_log: null,
      worst_rank: 3,
      breaches: [
        { title: 'Zeta', date: '2024-01-02' },
        { title: 'Zeta', date: '2024-01-02' },
        { title: 'Alpha', date: null },
        'junk',
        { title: '' },
        { title: 'Beta', date: '' },
        { title: 'Gamma', date: '2019-01-01' },
      ],
      last_detected: new Date('2026-10-01T00:00:00Z'),
    },
  ]);
  assert.deepEqual(account, {
    account: 'alice@example.com',
    identity_id: 7,
    open: 5,
    credential_exposures: 2,
    stealer_log: false,
    worst_severity: 'high',
    breaches: [
      { title: 'Zeta', date: '2024-01-02' },
      { title: 'Alpha', date: null },
      { title: 'Beta', date: null },
    ],
    last_detected: '2026-10-01T00:00:00.000Z',
  });
});

// ---- Lookalike inventory -------------------------------------------------------------

function lookalikeSnapshot(registered: Record<string, unknown>): unknown {
  return { v: 1, registered, unregistered: {}, dropped: {} };
}

function info(partial: Record<string, unknown> = {}) {
  return { mx: false, addr: false, fuzzer: 'omission', since: null, seen_at: NOW - DAY, prior_drop: null, ...partial };
}

function ctSnapshot(lookalikes: Record<string, Record<string, number>>): unknown {
  return {
    v: 1,
    lookalikes: Object.fromEntries(
      Object.entries(lookalikes).map(([name, certs]) => [name, { certs, names: [name], issuers: ['R3'], checked_at: NOW - DAY }])
    ),
  };
}

function domain(partial: Partial<LookalikeDomainInput> = {}): LookalikeDomainInput {
  return {
    id: 1,
    domain: 'acme.com',
    scope: 'own',
    collectors: { ct: true, lookalike: true, rdap: true, dns: true },
    last_summary: { collectors: { lookalike: { status: 'ok', details: { candidates: 120 } } } },
    lookalike: null,
    ct: null,
    ...partial,
  };
}

test('lookalikes: states not_watched, not_checked and checked', () => {
  assert.equal(buildLookalikeInventory([], [], NOW).state, 'not_watched');
  const off = buildLookalikeInventory([domain({ collectors: { ct: true, lookalike: false, rdap: true, dns: true }, lookalike: lookalikeSnapshot({ 'acme.co': info() }) })], [], NOW);
  assert.equal(off.state, 'not_watched', 'a domain with the lookalike check off is not eligible');
  assert.equal(off.registered, 0);

  const pending = buildLookalikeInventory([domain()], [], NOW);
  assert.equal(pending.state, 'not_checked');
  assert.equal(pending.candidates_checked, 120);

  const checked = buildLookalikeInventory([domain({ lookalike: lookalikeSnapshot({}) })], [], NOW);
  assert.equal(checked.state, 'checked');
  assert.deepEqual([checked.registered, checked.top], [0, []]);
});

test('lookalikes: fields, certificate states and open findings', () => {
  const inv = buildLookalikeInventory(
    [
      domain({
        lookalike: lookalikeSnapshot({
          'acme.co': info({ mx: true, addr: true, fuzzer: 'tld-swap', since: NOW - 3 * DAY }),
          'acrne.com': info({ mx: null, addr: null, fuzzer: 'unknown' }),
          'acm.com': info({ addr: true }),
        }),
        ct: ctSnapshot({ 'acme.co': { a: NOW + 30 * DAY, b: NOW - DAY }, 'acm.com': { c: NOW - DAY } }),
      }),
    ],
    [
      { domain_id: 1, lookalike: 'acme.co', n: 2, worst_rank: 3 },
      { domain_id: 2, lookalike: 'acm.com', n: 1, worst_rank: 4 }, // another domain's finding
    ],
    NOW
  );
  assert.equal(inv.state, 'checked');
  assert.deepEqual(
    [inv.registered, inv.with_mx, inv.with_address, inv.with_current_cert],
    [3, 1, 2, 1]
  );
  const byName = new Map(inv.top.map((r) => [r.lookalike, r]));
  assert.deepEqual(byName.get('acme.co'), {
    lookalike: 'acme.co',
    domain_id: 1,
    watched_domain: 'acme.com',
    scope: 'own',
    technique: 'tld-swap',
    has_mx: true,
    has_address: true,
    certs: 'current',
    reported_at: new Date((NOW - 3 * DAY) * 1000).toISOString(),
    open_findings: { count: 2, worst_severity: 'high' },
  });
  const unknown = byName.get('acrne.com')!;
  assert.deepEqual(
    [unknown.technique, unknown.has_mx, unknown.has_address, unknown.certs, unknown.reported_at, unknown.open_findings],
    [null, null, null, 'not_checked', null, null],
    'already registered when first checked: no report time, and no CT entry yet'
  );
  assert.equal(byName.get('acm.com')!.certs, 'none', 'only an expired certificate');
  assert.equal(byName.get('acm.com')!.open_findings, null, 'findings match on the domain too');
});

test('lookalikes: malformed snapshots and entries are skipped without throwing', () => {
  const inv = buildLookalikeInventory(
    [
      domain({ id: 1, lookalike: { v: 2, registered: { 'a.com': info() } } }),
      domain({ id: 2, domain: 'b.com', lookalike: { v: 1, registered: 'nope' } }),
      domain({
        id: 3,
        domain: 'c.com',
        lookalike: lookalikeSnapshot({ 'c.co': 'junk', 'c.net': info({ since: 'yesterday', mx: 'yes' }) }),
        ct: { v: 1, lookalikes: { 'c.net': { certs: { k: 'soon' }, checked_at: NOW } } },
        last_summary: { collectors: { lookalike: { details: { candidates: 'many' } } } },
      }),
      domain({ id: 4, domain: 'd.com', lookalike: 'not json', ct: 42, last_summary: null }),
    ],
    [],
    NOW
  );
  assert.equal(inv.state, 'checked');
  assert.equal(inv.registered, 1);
  assert.equal(inv.candidates_checked, 120 + 120, 'domains 1 and 2 report 120 each; junk counts are ignored');
  assert.deepEqual(
    [inv.top[0].lookalike, inv.top[0].reported_at, inv.top[0].has_mx, inv.top[0].certs],
    ['c.net', null, null, 'none']
  );
});

test('lookalikes: riskiest first (mail, then a current certificate), then capped with full totals', () => {
  const registered: Record<string, unknown> = {
    'z-mx.com': info({ mx: true }),
    'y-cert.com': info({ addr: true }),
    'x-addr.com': info({ addr: true }),
    'w-finding.com': info(),
    'v-new.com': info({ since: NOW - DAY }),
    'u-old.com': info({ since: NOW - 9 * DAY }),
    'a-plain.com': info(),
    'b-plain.com': info(),
  };
  const inv = buildLookalikeInventory(
    [
      domain({
        lookalike: lookalikeSnapshot(registered),
        ct: ctSnapshot({ 'y-cert.com': { k: NOW + DAY } }),
      }),
      domain({ id: 2, domain: 'acme.net', scope: 'brand', lookalike: lookalikeSnapshot({ 'a-plain.com': info() }) }),
    ],
    [{ domain_id: 1, lookalike: 'w-finding.com', n: 1, worst_rank: 2 }],
    NOW
  );
  assert.deepEqual(
    inv.top.map((r) => `${r.lookalike}@${r.watched_domain}`),
    [
      'z-mx.com@acme.com',
      'y-cert.com@acme.com',
      'x-addr.com@acme.com',
      'w-finding.com@acme.com',
      'v-new.com@acme.com',
      'u-old.com@acme.com',
      'a-plain.com@acme.com',
      'a-plain.com@acme.net',
      'b-plain.com@acme.com',
    ]
  );

  const many: Record<string, unknown> = {};
  for (let i = 0; i < 40; i++) many[`l${String(i).padStart(2, '0')}.com`] = info({ mx: i % 4 === 0 });
  const capped = buildLookalikeInventory([domain({ lookalike: lookalikeSnapshot(many) })], [], NOW);
  assert.equal(capped.top.length, LOOKALIKE_TOP);
  assert.equal(capped.registered, 40);
  assert.equal(capped.with_mx, 10);
  assert.ok(capped.top.slice(0, 10).every((r) => r.has_mx === true), 'mail first');
});
