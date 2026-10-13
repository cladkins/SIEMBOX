/**
 * The verified-domain snapshot without a database: name normalization, the
 * per-identity state table, the key binding, parsing hand-edited rows, the
 * refresh policy, how a failed listing is classified, and the write queue.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HibpError, type HibpSubscribedDomain, type HibpSubscribedDomainList } from './hibpClient';
import {
  HIBP_DOMAINS_DASHBOARD_URL,
  HIBP_DOMAINS_MAX_STORED,
  buildSnapshot,
  createHibpDomainSnapshotStore,
  domainListErrorKind,
  failedSnapshot,
  hibpDomainStatus,
  hibpKeyRef,
  needsDomainRefresh,
  normalizeHibpDomainName,
  parseHibpDomainSnapshot,
  planCoverage,
  serializeHibpDomainSnapshot,
  skipNote,
  toDomainListError,
  toHibpVerifiedDomainsView,
  type HibpDomainSnapshot,
  type HibpPlanSnapshot,
} from './hibpDomains';

const KEY_REF = '0123456789abcdef';
const NOW = Date.parse('2026-10-12T12:00:00.000Z');
const MIN = 60_000;
const HOUR = 60 * MIN;

const plan = (max: number | null = 100): HibpPlanSnapshot => ({
  name: 'Core 2',
  domain_search_max_breached_accounts: max,
  max_breached_domains: 3,
  subscribed_until: '2027-01-01T00:00:00',
});

const hibpEntry = (name: string, counts: Partial<HibpSubscribedDomain> = {}): HibpSubscribedDomain => ({
  DomainName: name,
  PwnCount: 40,
  PwnCountExcludingSpamLists: 38,
  PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 35,
  NextSubscriptionRenewal: '2027-01-01T00:00:00',
  ...counts,
});

const listOf = (names: string[], extra: Partial<HibpSubscribedDomainList> = {}): HibpSubscribedDomainList => ({
  domains: names.map((n) => hibpEntry(n)),
  unreadable: 0,
  overLimit: 0,
  ...extra,
});

/** A successful snapshot listing `names`, `ageMs` old. */
function listed(names: string[], ageMs = 0, overrides: Partial<HibpDomainSnapshot> = {}): HibpDomainSnapshot {
  return {
    ...buildSnapshot(listOf(names), plan(), [], KEY_REF, new Date(NOW - ageMs)),
    ...overrides,
  };
}

// ---- names ---------------------------------------------------------------------------

test('normalizeHibpDomainName: lowercase punycode without the root dot, or null', () => {
  assert.equal(normalizeHibpDomainName('Example.COM.'), 'example.com');
  assert.equal(normalizeHibpDomainName('MÜNCHEN.de'), 'xn--mnchen-3ya.de');
  assert.equal(normalizeHibpDomainName('straße.de'), 'xn--strae-oqa.de');
  assert.equal(normalizeHibpDomainName(' example.com '), 'example.com');
  for (const bad of ['example.com..', '*.example.com', 'a_b.com', 'localhost', '', '   ', 42, null, undefined, {}]) {
    assert.equal(normalizeHibpDomainName(bad), null, JSON.stringify(bad));
  }
});

// ---- mapping ------------------------------------------------------------------------

test('mapping: exact match only; each subdomain is its own HIBP domain', () => {
  const snapshot = listed(['example.com', 'shop.other.org']);
  assert.equal(hibpDomainStatus('example.com', snapshot, true).state, 'verified');

  const sub = hibpDomainStatus('mail.example.com', snapshot, true);
  assert.equal(sub.state, 'not_verified', 'a parent does not cover its subdomains');
  assert.equal(sub.verified_parent, 'example.com');
  assert.match(sub.message, /^HIBP verifies each domain separately: example\.com is verified, mail\.example\.com isn't\. /);

  const parent = hibpDomainStatus('other.org', snapshot, true);
  assert.equal(parent.state, 'not_verified', 'a subdomain does not cover its parent');
  assert.equal(parent.verified_parent, null);
  assert.ok(parent.message.includes(HIBP_DOMAINS_DASHBOARD_URL));
});

test('coverage: the at-renewal count is preferred; unknown counts or limits never warn', () => {
  const entry = (current: number | null, atRenewal: number | null) => ({
    pwn_count_excluding_spam_lists: current,
    pwn_count_excluding_spam_lists_at_last_subscription_renewal: atRenewal,
  });
  assert.equal(planCoverage(entry(150, 90), plan(100)), true, 'locked in at renewal: still covered');
  assert.equal(planCoverage(entry(90, 150), plan(100)), false);
  assert.equal(planCoverage(entry(150, null), plan(100)), false, 'falls back to the current count');
  assert.equal(planCoverage(entry(100, null), plan(100)), true);
  assert.equal(planCoverage(entry(null, null), plan(100)), null);
  assert.equal(planCoverage(entry(5, null), plan(null)), null);
  assert.equal(planCoverage(entry(5, null), plan(0)), null);
  assert.equal(planCoverage(entry(5, null), null), null);

  const big = buildSnapshot(
    { domains: [hibpEntry('big.example', { PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 500 })], unreadable: 0, overLimit: 0 },
    plan(100),
    [],
    KEY_REF,
    new Date(NOW)
  );
  const limited = hibpDomainStatus('big.example', big, true);
  assert.equal(limited.state, 'verified_limited');
  assert.match(limited.message, /may be larger than your HIBP plan covers/);
  assert.equal(hibpDomainStatus('big.example', { ...big, plan: plan(null) }, true).state, 'verified');
  assert.equal(hibpDomainStatus('big.example', { ...big, plan: plan(0) }, true).state, 'verified');

  const view = toHibpVerifiedDomainsView({
    snapshot: { ...big, plan: plan(0) },
    keyUsable: true,
    identities: [],
    now: NOW,
    attribution: 'https://haveibeenpwned.com',
  });
  assert.equal(view.domains?.[0].within_plan, null);
});

// ---- the state table (§3.4), in order ---------------------------------------------------

test('state table: no key, not checked, forbidden, never listed, listed, incomplete, absent', () => {
  const ok = listed(['example.com']);
  // 1. no usable key wins over everything
  assert.deepEqual(hibpDomainStatus('example.com', ok, false), {
    state: 'unknown',
    reason: 'no_key',
    verified_parent: null,
    listed_at: null,
    message: "No usable HIBP API key is saved, so verification can't be checked.",
  });
  // 2. no snapshot
  assert.deepEqual(
    [hibpDomainStatus('example.com', null, true).state, hibpDomainStatus('example.com', null, true).reason],
    ['unknown', 'not_checked']
  );
  // 3. the latest attempt was refused (403): unavailable, even over an older list
  const forbidden = failedSnapshot(ok, toDomainListError(new HibpError('auth', 'x', { status: 403 }), NOW), KEY_REF, new Date(NOW));
  const unavailable = hibpDomainStatus('example.com', forbidden, true);
  assert.equal(unavailable.state, 'unavailable');
  assert.match(unavailable.message, /doesn't include domain search/);
  // 4. never listed: unknown with the failure's kind
  for (const [err, reason] of [
    [new HibpError('auth', 'x', { status: 401 }), 'auth'],
    [new HibpError('transient', 'x'), 'network'],
    [new HibpError('transient', 'x', { status: 503 }), 'hibp_unavailable'],
    [new HibpError('transient', 'x', { status: 404 }), 'bad_response'],
  ] as const) {
    const s = hibpDomainStatus('example.com', failedSnapshot(null, toDomainListError(err, NOW), KEY_REF, new Date(NOW)), true);
    assert.deepEqual([s.state, s.reason], ['unknown', reason]);
  }
  // auth after an older list: the list decides
  const authLater = failedSnapshot(ok, toDomainListError(new HibpError('auth', 'x', { status: 401 }), NOW), KEY_REF, new Date(NOW));
  assert.equal(hibpDomainStatus('example.com', authLater, true).state, 'verified');
  assert.equal(hibpDomainStatus('other.com', authLater, true).state, 'not_verified');
  // 5/6. listed
  assert.equal(hibpDomainStatus('example.com', ok, true).state, 'verified');
  assert.equal(hibpDomainStatus('example.com', ok, true).listed_at, ok.listed_at);
  // 7. absent from an incomplete list
  for (const incomplete of [{ ...ok, skipped_entries: 1 }, { ...ok, truncated: true }]) {
    const s = hibpDomainStatus('other.com', incomplete, true);
    assert.deepEqual([s.state, s.reason], ['unknown', 'list_incomplete']);
    assert.equal(hibpDomainStatus('example.com', incomplete, true).state, 'verified', 'listed still counts');
  }
  // 8. absent from a complete list, an empty one included
  const empty = listed([]);
  assert.equal(hibpDomainStatus('example.com', empty, true).state, 'not_verified');
});

test('skip notes name the domain and the list time, without milliseconds', () => {
  const s = hibpDomainStatus('example.org', listed([], 0), true);
  assert.equal(
    skipNote('example.org', s),
    "Skipped: example.org isn't verified on your HIBP account (as of 2026-10-12T12:00:00Z). Verify it in the HIBP dashboard, then re-check verification."
  );
  assert.equal(
    skipNote('example.org', { ...s, state: 'unavailable' }),
    "Skipped: your HIBP plan doesn't include domain search."
  );
});

// ---- key binding ------------------------------------------------------------------------

test('key_ref: hashes the stored envelope, differs per save, and binds the snapshot', () => {
  const envelopeA = JSON.stringify({ encrypted: 'aa', iv: 'iv-1', authTag: 't' });
  const envelopeA2 = JSON.stringify({ encrypted: 'aa', iv: 'iv-2', authTag: 't' }); // same key, new IV
  const ref = hibpKeyRef(envelopeA);
  assert.match(ref ?? '', /^[0-9a-f]{16}$/);
  assert.equal(hibpKeyRef(envelopeA), ref, 'deterministic');
  assert.notEqual(hibpKeyRef(envelopeA2), ref, 'every save gets a new ref');
  assert.equal(hibpKeyRef(''), null);

  const raw = serializeHibpDomainSnapshot({ ...listed(['example.com']), key_ref: ref! });
  assert.ok(parseHibpDomainSnapshot(raw, ref));
  assert.equal(parseHibpDomainSnapshot(raw, hibpKeyRef(envelopeA2)), null, "another key's list reads as absent");
  assert.equal(parseHibpDomainSnapshot(raw, null), null);
});

test('parseHibpDomainSnapshot tolerates garbage and hand edits', () => {
  for (const raw of ['', 'not json', '[]', 'null', '42', JSON.stringify({ v: 2, key_ref: KEY_REF })]) {
    assert.equal(parseHibpDomainSnapshot(raw, KEY_REF), null, raw);
  }
  const edited = parseHibpDomainSnapshot(
    JSON.stringify({
      v: 1,
      key_ref: KEY_REF,
      checked_at: 'yesterday',
      listed_at: '2026-10-12T10:00:00Z',
      stale: 'yes',
      error: { kind: 'weird', status: '500', message: 7 },
      plan: 'Core 9',
      domains: [{ domain: 'Example.COM.', pwn_count: -3 }, { domain: '*.bad' }, 'junk', { domain: 'example.com' }],
      truncated: 0,
      skipped_entries: 'two',
    }),
    KEY_REF
  );
  assert.ok(edited);
  assert.equal(edited.checked_at, new Date(0).toISOString(), 'an unreadable time counts as long ago');
  assert.equal(edited.stale, false);
  assert.deepEqual(edited.error, {
    kind: 'bad_response',
    status: null,
    message: 'The verified-domain list could not be read',
    retry_after: null,
  });
  assert.equal(edited.plan, null);
  assert.deepEqual(
    edited.domains?.map((d) => [d.domain, d.pwn_count]),
    [['example.com', null]]
  );
  assert.equal(edited.skipped_entries, 2, 'unreadable entries make the list incomplete');
  assert.equal(edited.truncated, false);
});

// ---- building -----------------------------------------------------------------------

test('buildSnapshot: normalizes, de-duplicates, keeps monitored domains first and caps the list', () => {
  const names = Array.from({ length: HIBP_DOMAINS_MAX_STORED + 5 }, (_, i) => `d${String(i).padStart(5, '0')}.example`);
  const list = listOf([...names, 'ZZZ.Monitored.Example.', 'zzz.monitored.example', 'bad_name.example'], { unreadable: 2 });
  const snapshot = buildSnapshot(list, plan(), ['zzz.monitored.example'], KEY_REF, new Date(NOW));
  assert.equal(snapshot.domains?.length, HIBP_DOMAINS_MAX_STORED);
  assert.equal(snapshot.domains?.[0].domain, 'zzz.monitored.example', 'monitored first');
  assert.equal(snapshot.domains?.[1].domain, 'd00000.example', 'then alphabetical');
  assert.equal(snapshot.truncated, true);
  assert.equal(snapshot.skipped_entries, 3, 'two unreadable entries plus one name that did not normalize');
  assert.equal(snapshot.listed_at, new Date(NOW).toISOString());
  assert.deepEqual([snapshot.stale, snapshot.error], [false, null]);

  const overLimit = buildSnapshot(listOf(['a.example'], { overLimit: 1 }), plan(), [], KEY_REF, new Date(NOW));
  assert.equal(overLimit.truncated, true, 'entries HIBP sent beyond the parse cap make the list incomplete');
});

test('failedSnapshot keeps the last good list and plan, and records the failure', () => {
  const ok = listed(['example.com'], 2 * HOUR, { stale: true });
  const failed = failedSnapshot(ok, toDomainListError(new HibpError('transient', 'down', { status: 503 }), NOW), KEY_REF, new Date(NOW));
  assert.deepEqual(failed.domains, ok.domains);
  assert.equal(failed.listed_at, ok.listed_at);
  assert.equal(failed.checked_at, new Date(NOW).toISOString());
  assert.equal(failed.stale, true);
  assert.deepEqual(failed.plan, ok.plan);
  assert.equal(failed.error?.kind, 'hibp_unavailable');
});

// ---- refresh policy -------------------------------------------------------------------

test('needsDomainRefresh: the run policy', () => {
  const run = { mode: 'run' as const };
  assert.equal(needsDomainRefresh(null, NOW, run), true, 'no snapshot');
  assert.equal(needsDomainRefresh(listed([], 5 * HOUR), NOW, run), false);
  assert.equal(needsDomainRefresh(listed([], 6 * HOUR), NOW, run), true, '≥6 h old');
  assert.equal(needsDomainRefresh(listed([], 59 * MIN, { stale: true }), NOW, run), false, 'stale but under an hour');
  assert.equal(needsDomainRefresh(listed([], HOUR, { stale: true }), NOW, run), true, 'stale and ≥1 h');
  assert.equal(needsDomainRefresh(listed([], HOUR), NOW, { mode: 'run', skipPending: true }), true, 'a due domain would be skipped');
  assert.equal(needsDomainRefresh(listed([], 59 * MIN), NOW, { mode: 'run', skipPending: true }), false);

  const failedAt = (err: HibpError, ageMs: number) =>
    failedSnapshot(null, toDomainListError(err, NOW - ageMs), KEY_REF, new Date(NOW - ageMs));
  const down = new HibpError('transient', 'x', { status: 503 });
  assert.equal(needsDomainRefresh(failedAt(down, 29 * MIN), NOW, run), false);
  assert.equal(needsDomainRefresh(failedAt(down, 30 * MIN), NOW, run), true, 'failures retry after 30 min');
  const badKey = new HibpError('auth', 'x', { status: 401 });
  assert.equal(needsDomainRefresh(failedAt(badKey, 5 * HOUR), NOW, run), false);
  assert.equal(needsDomainRefresh(failedAt(badKey, 6 * HOUR), NOW, run), true, 'a 401 retries after 6 h');
  const limited = new HibpError('rate_limited', 'x', { status: 429, retryAfterSeconds: 120 });
  assert.equal(needsDomainRefresh(failedAt(limited, MIN), NOW, run), false, 'before retry-after');
  assert.equal(needsDomainRefresh(failedAt(limited, 3 * MIN), NOW, run), true, 'after retry-after');
});

test('needsDomainRefresh: force and manual re-check at most once a minute, never inside a 429 wait', () => {
  for (const mode of ['force', 'manual'] as const) {
    assert.equal(needsDomainRefresh(null, NOW, { mode }), true);
    assert.equal(needsDomainRefresh(listed([], 59_000), NOW, { mode }), false);
    assert.equal(needsDomainRefresh(listed([], 60_000), NOW, { mode }), true);
    const limited = failedSnapshot(
      null,
      toDomainListError(new HibpError('rate_limited', 'x', { status: 429, retryAfterSeconds: 300 }), NOW - 2 * MIN),
      KEY_REF,
      new Date(NOW - 2 * MIN)
    );
    assert.equal(needsDomainRefresh(limited, NOW, { mode }), false);
  }
});

// ---- failure classification (§3.5) ---------------------------------------------------

test('domainListErrorKind: every row of the table', () => {
  const cases: Array<[unknown, string]> = [
    [new HibpError('auth', 'x', { status: 401 }), 'auth'],
    [new HibpError('auth', 'No HIBP API key is configured'), 'auth'],
    [new HibpError('auth', 'x', { status: 403 }), 'forbidden'],
    [new HibpError('rate_limited', 'x', { status: 429, retryAfterSeconds: 5 }), 'rate_limited'],
    [new HibpError('transient', 'x', { status: 500 }), 'hibp_unavailable'],
    [new HibpError('transient', 'x', { status: 503 }), 'hibp_unavailable'],
    [new HibpError('transient', 'HIBP could not be reached'), 'network'],
    [new HibpError('transient', 'HIBP request timed out'), 'network'],
    [new HibpError('transient', 'x', { status: 404 }), 'bad_response'],
    [new HibpError('transient', 'x', { status: 200 }), 'bad_response'],
    [new HibpError('transient', 'x', { status: 301 }), 'bad_response'],
    [new HibpError('bad_request', 'x', { status: 400 }), 'bad_response'],
    [new HibpError('transient', 'x', { status: 418 }), 'bad_response'],
    [new Error('boom'), 'bad_response'],
  ];
  for (const [err, kind] of cases) assert.equal(domainListErrorKind(err), kind, String((err as Error).message));

  const stored = toDomainListError(new HibpError('rate_limited', 'slow down', { status: 429, retryAfterSeconds: 30 }), NOW);
  assert.deepEqual(stored, {
    kind: 'rate_limited',
    status: 429,
    message: 'slow down',
    retry_after: new Date(NOW + 31_000).toISOString(),
  });
});

// ---- the write queue -----------------------------------------------------------------

function memoryIO(envelope = 'envelope-A') {
  const state = { envelope, snapshot: '', writes: [] as string[] };
  let delay = Promise.resolve();
  return {
    state,
    /** Hold every read until `release` is called. */
    hold() {
      let release!: () => void;
      delay = new Promise<void>((resolve) => (release = resolve));
      return () => release();
    },
    io: {
      readKeyEnvelope: async () => {
        await delay;
        return state.envelope;
      },
      readSnapshot: async () => {
        await delay;
        return state.snapshot;
      },
      writeSnapshot: async (value: string) => {
        state.snapshot = value;
        state.writes.push(value);
      },
      keyUsable: (e: string) => e !== '',
    },
  };
}

test('write queue: a refresh started under another key is dropped', async () => {
  const mem = memoryIO('envelope-A');
  const store = createHibpDomainSnapshotStore(mem.io);
  const refA = hibpKeyRef('envelope-A')!;
  mem.state.envelope = 'envelope-B'; // the key was saved again while the refresh ran
  const written = await store.update(refA, () => ({ ...listed(['example.com']), key_ref: refA }));
  assert.equal(written, null);
  assert.equal(mem.state.writes.length, 0);
  assert.equal((await store.read()).snapshot, null);
});

test('write queue: markStale and a refresh write are serialized, never lost', async () => {
  const mem = memoryIO();
  const ref = hibpKeyRef('envelope-A')!;
  const store = createHibpDomainSnapshotStore(mem.io);
  await store.update(ref, () => ({ ...listed(['example.com']), key_ref: ref }));

  // A failure write (read-modify-write) and markStale race: both must land.
  const release = mem.hold();
  const failure = store.update(ref, (previous) =>
    failedSnapshot(previous, toDomainListError(new HibpError('transient', 'x'), NOW), ref, new Date(NOW))
  );
  const stale = store.markStale();
  release();
  await Promise.all([failure, stale]);

  const after = (await store.read()).snapshot;
  assert.equal(after?.error?.kind, 'network');
  assert.equal(after?.stale, true, 'the stale mark was applied on top of the failure, not overwritten');
  assert.deepEqual(after?.domains?.map((d) => d.domain), ['example.com']);

  await store.clear();
  assert.equal(mem.state.snapshot, '');
});

// ---- the admin view ---------------------------------------------------------------------

test('view: states, identity links and when a re-check may call HIBP', () => {
  const base = { identities: [{ id: 12, value: 'example.com' }], now: NOW, attribution: 'https://haveibeenpwned.com' };
  assert.equal(toHibpVerifiedDomainsView({ ...base, snapshot: listed(['example.com']), keyUsable: false }).state, 'no_key');
  const notChecked = toHibpVerifiedDomainsView({ ...base, snapshot: null, keyUsable: true });
  assert.deepEqual([notChecked.state, notChecked.next_refresh_allowed_at], ['not_checked', null]);

  const fresh = toHibpVerifiedDomainsView({ ...base, snapshot: listed(['example.com', 'other.com'], 10_000), keyUsable: true });
  assert.equal(fresh.state, 'listed');
  assert.equal(fresh.next_refresh_allowed_at, new Date(NOW + 50_000).toISOString());
  assert.deepEqual(
    fresh.domains?.map((d) => [d.domain, d.identity_id, d.within_plan]),
    [
      ['example.com', 12, true],
      ['other.com', null, true],
    ]
  );
  assert.deepEqual(Object.keys(fresh).sort(), [
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
  ]);

  const failed = failedSnapshot(null, toDomainListError(new HibpError('auth', 'x', { status: 401 }), NOW), KEY_REF, new Date(NOW - HOUR));
  assert.equal(toHibpVerifiedDomainsView({ ...base, snapshot: failed, keyUsable: true }).state, 'error');
  // A hand-edited row with neither a list nor a failure: nothing learned yet, not an error without one.
  const empty = { ...failed, error: null };
  assert.deepEqual(
    [toHibpVerifiedDomainsView({ ...base, snapshot: empty, keyUsable: true }).state, empty.domains],
    ['not_checked', null]
  );
  const paused = toHibpVerifiedDomainsView({ ...base, snapshot: listed([], HOUR), keyUsable: true, pausedUntil: NOW + 5000 });
  assert.equal(paused.next_refresh_allowed_at, new Date(NOW + 5000).toISOString());
});
