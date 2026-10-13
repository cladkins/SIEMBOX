/**
 * Leaked-credential checks without a database: severity mapping, fingerprint
 * stability (re-checks must hit the same finding), the finding we build from a
 * breach, the HIBP source (domain-search expansion, pacing, 403 meaning), the
 * run loop's handling of rate limits, rejected keys and flaky providers, and
 * verified HIBP domains (skips, list refreshes, the admin's re-check) —
 * driven through an in-memory store. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTRADICTION_NOTE,
  ExposureSourceError,
  FALLBACK_403_NOTE,
  HibpDomainsRefreshError,
  HibpSource,
  LEAKED_CREDS_ALREADY_RUNNING,
  breachFingerprint,
  breachSeverity,
  buildBreachFinding,
  describeRunSummary,
  getLeakedCredentialRunState,
  getLeakedCredentialSkipReason,
  refreshHibpVerifiedDomains,
  resetLeakedCredentialPause,
  runLeakedCredentialChecks,
  spacingForRpm,
  toBreachRecord,
  type BreachRecord,
  type ExposureHit,
  type ExposureSource,
  type IdentityRef,
  type LeakedCredentialStore,
  type VerifiedDomainListing,
} from './leakedCredentialService';
import { HibpError, type HibpBreach } from './hibpClient';
import { buildSnapshot, failedSnapshot, toDomainListError, type HibpDomainSnapshot } from './hibpDomains';
import { SECRET_KEY_PATTERN, type FindingInput } from './findingWriter';
import type { MonitoredIdentity } from '../../models/Exposure';
import type { ExposureNotice } from '../notifications/notificationService';

const breach = (overrides: Partial<BreachRecord> = {}): BreachRecord => ({
  name: 'Example',
  title: 'Example',
  domain: 'example.com',
  breachDate: '2020-01-01',
  addedDate: '2020-02-01',
  dataClasses: ['Email addresses', 'Names'],
  isVerified: true,
  isSensitive: false,
  isStealerLog: false,
  isSpamList: false,
  isFabricated: false,
  ...overrides,
});

beforeEach(() => resetLeakedCredentialPause());

// ---- severity / fingerprint / finding --------------------------------------------

test('severity: credential material, stealer logs and sensitive breaches are high', () => {
  assert.equal(breachSeverity(breach({ dataClasses: ['Email addresses', 'Passwords'] })), 'high');
  assert.equal(breachSeverity(breach({ dataClasses: ['Historical passwords'] })), 'high');
  assert.equal(breachSeverity(breach({ dataClasses: ['auth tokens'] })), 'high');
  assert.equal(
    breachSeverity(breach({ isStealerLog: true, dataClasses: ['Email addresses'] })),
    'high'
  );
  assert.equal(breachSeverity(breach({ isSensitive: true })), 'high');
});

test('severity: spam lists and fabricated breaches are low unless they hold credentials', () => {
  assert.equal(
    breachSeverity(breach({ isSpamList: true, dataClasses: ['Email addresses'] })),
    'low'
  );
  assert.equal(breachSeverity(breach({ isFabricated: true })), 'low');
  // Onliner Spambot is a spam list that also leaked passwords: the passwords win.
  assert.equal(
    breachSeverity(breach({ isSpamList: true, dataClasses: ['Email addresses', 'Passwords'] })),
    'high'
  );
});

test('severity: other personal data is medium; password hints are not passwords', () => {
  assert.equal(breachSeverity(breach()), 'medium');
  assert.equal(
    breachSeverity(breach({ dataClasses: ['Email addresses', 'Password hints'] })),
    'medium'
  );
  assert.equal(breachSeverity(breach({ isVerified: false })), 'medium');
});

test('fingerprints are stable for the same input and differ for anything that matters', () => {
  const email: IdentityRef = { kind: 'email', value: 'alice@example.com' };
  const domain: IdentityRef = { kind: 'email_domain', value: 'example.com' };
  const fp = breachFingerprint(email, 'Adobe');

  assert.match(fp, /^[0-9a-f]{64}$/);
  assert.equal(breachFingerprint(email, 'Adobe'), fp, 'same input, same fingerprint');
  assert.equal(
    breachFingerprint({ kind: 'email', value: 'Alice@Example.com' }, 'Adobe'),
    fp,
    'value case-insensitive'
  );
  assert.notEqual(breachFingerprint(email, 'LinkedIn'), fp);
  assert.notEqual(breachFingerprint({ kind: 'email', value: 'bob@example.com' }, 'Adobe'), fp);
  assert.equal(
    breachFingerprint(domain, 'Adobe', 'alice'),
    breachFingerprint(domain, 'Adobe', 'ALICE')
  );
  assert.notEqual(
    breachFingerprint(domain, 'Adobe', 'alice'),
    breachFingerprint(domain, 'Adobe', 'bob')
  );
  assert.notEqual(
    breachFingerprint(domain, 'Adobe', 'alice'),
    fp,
    'email and email-domain monitors are distinct'
  );
});

test('a breach hit becomes a leaked-creds finding with attribution and no secret-like keys', () => {
  const source = {
    id: 'hibp',
    label: 'Have I Been Pwned',
    attribution: 'https://haveibeenpwned.com',
  };
  const identity = { id: 7, kind: 'email_domain' as const, value: 'example.com' };
  const hit: ExposureHit = {
    account: 'alice@example.com',
    alias: 'alice',
    breach: breach({
      name: 'Adobe',
      title: 'Adobe',
      dataClasses: ['Email addresses', 'Passwords'],
    }),
  };
  const finding = buildBreachFinding(source, identity, hit);

  assert.equal(finding.source, 'leaked-creds');
  assert.equal(finding.identityId, 7);
  assert.equal(finding.eventType, 'breach');
  assert.equal(finding.title, 'alice@example.com found in Adobe breach');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.fingerprint, breachFingerprint(identity, 'Adobe', 'alice'));
  assert.match(finding.description ?? '', /haveibeenpwned\.com/);
  assert.match(finding.description ?? '', /Change this password/);
  assert.equal('breach_attribution' in finding.detail, false, 'only when HIBP sent one');
  assert.equal(finding.detail.source, 'hibp');
  assert.equal(finding.detail.attribution, 'https://haveibeenpwned.com');
  assert.deepEqual(finding.detail.data_classes, ['Email addresses', 'Passwords']);
  for (const key of [
    'account',
    'breach_name',
    'breach_title',
    'breach_domain',
    'breach_date',
    'added_date',
    'is_verified',
    'is_sensitive',
    'is_stealer_log',
  ]) {
    assert.ok(key in finding.detail, `detail.${key}`);
  }
  assert.deepEqual(
    Object.keys(finding.detail).filter((k) => SECRET_KEY_PATTERN.test(k)),
    []
  );
});

test('HIBP breach models map to records defensively', () => {
  const record = toBreachRecord({
    Name: 'Adobe',
    DataClasses: ['Passwords', 3 as unknown as string],
  } as HibpBreach);
  assert.equal(record.title, 'Adobe', 'title falls back to the name');
  assert.equal(record.domain, null);
  assert.deepEqual(record.dataClasses, ['Passwords']);
  assert.equal(record.isSensitive, false);
});

// ---- HIBP source ----------------------------------------------------------------------

function fakeHibpClient(
  overrides: Partial<Record<string, (...args: string[]) => Promise<unknown>>> = {}
) {
  const calls: string[] = [];
  const client = {
    subscriptionStatus: async () => {
      calls.push('subscriptionStatus');
      return overrides.subscriptionStatus ? overrides.subscriptionStatus() : { Rpm: 60 };
    },
    breachedAccount: async (account: string) => {
      calls.push(`breachedAccount:${account}`);
      return overrides.breachedAccount ? overrides.breachedAccount(account) : [];
    },
    breachedDomain: async (domain: string) => {
      calls.push(`breachedDomain:${domain}`);
      return overrides.breachedDomain ? overrides.breachedDomain(domain) : {};
    },
    allBreaches: async () => {
      calls.push('allBreaches');
      return overrides.allBreaches ? overrides.allBreaches() : [];
    },
  };
  return { client: client as never, calls };
}

function makeHibpSource(client: never, sleeps: number[] = []) {
  let now = 1_000_000;
  return new HibpSource({
    getApiKey: async () => '0123456789abcdef0123456789abcdef',
    isEnabled: async () => true,
    createClient: () => client,
    sleep: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
    now: () => now,
  });
}

test('HibpSource: a domain search becomes one hit per alias+breach, enriched from the catalog', async () => {
  const { client, calls } = fakeHibpClient({
    breachedDomain: async () => ({ Alice: ['Adobe'], bob: ['Adobe', 'Gawker', 'Adobe'] }),
    allBreaches: async () => [
      { Name: 'Adobe', Title: 'Adobe', DataClasses: ['Passwords'], IsVerified: true },
      { Name: 'Gawker', Title: 'Gawker', DataClasses: ['Email addresses'], IsSensitive: true },
    ],
  });
  const hits = await makeHibpSource(client).check({ kind: 'email_domain', value: 'example.com' });

  assert.deepEqual(
    hits.map((h) => [h.account, h.alias, h.breach.name, breachSeverity(h.breach)]),
    [
      ['alice@example.com', 'alice', 'Adobe', 'high'],
      ['bob@example.com', 'bob', 'Adobe', 'high'],
      ['bob@example.com', 'bob', 'Gawker', 'high'],
    ]
  );
  assert.deepEqual(calls, ['subscriptionStatus', 'breachedDomain:example.com', 'allBreaches']);
});

test('HibpSource: a failed plan lookup never blocks the check (the breach call decides)', async () => {
  // HIBP's own test key gets a 401 from subscription/status but works on the
  // breach endpoints; a real bad key is caught by the breach call itself.
  const sleeps: number[] = [];
  const { client, calls } = fakeHibpClient({
    subscriptionStatus: async () => {
      throw new HibpError('auth', 'HIBP rejected the API key (HTTP 401)', { status: 401 });
    },
    breachedAccount: async () => [{ Name: 'Adobe', DataClasses: ['Passwords'] }],
  });
  const hits = await makeHibpSource(client, sleeps).check({ kind: 'email', value: 'a@example.com' });
  assert.equal(hits.length, 1);
  assert.deepEqual(calls, ['subscriptionStatus', 'breachedAccount:a@example.com']);
  assert.deepEqual(sleeps, [spacingForRpm(null)], 'paced for the smallest plan');

  const limited = fakeHibpClient({
    subscriptionStatus: async () => {
      throw new HibpError('rate_limited', 'slow down', { status: 429, retryAfterSeconds: 3 });
    },
  });
  await assert.rejects(
    makeHibpSource(limited.client).check({ kind: 'email', value: 'a@example.com' }),
    (err: unknown) => err instanceof ExposureSourceError && err.kind === 'rate_limited'
  );
  assert.deepEqual(limited.calls, ['subscriptionStatus'], 'a 429 stops before the breach call');
});

test('HibpSource: a breach missing from the catalog still yields a (medium) hit', async () => {
  const { client } = fakeHibpClient({ breachedDomain: async () => ({ carol: ['BrandNew'] }) });
  const [hit] = await makeHibpSource(client).check({ kind: 'email_domain', value: 'example.com' });
  assert.equal(hit.breach.name, 'BrandNew');
  assert.equal(breachSeverity(hit.breach), 'medium');
});

test('HibpSource: a 403 on a domain search is about the domain; a 401 is about the key', async () => {
  const forbidden = fakeHibpClient({
    breachedDomain: async () => {
      throw new HibpError('auth', 'forbidden', { status: 403 });
    },
  });
  await assert.rejects(
    makeHibpSource(forbidden.client).check({ kind: 'email_domain', value: 'example.com' }),
    (err: unknown) =>
      err instanceof ExposureSourceError && err.kind === 'unverified' && err.message === FALLBACK_403_NOTE
  );
  assert.doesNotMatch(FALLBACK_403_NOTE, /plan covers its number/, 'an over-size domain is not refused');

  const badKey = fakeHibpClient({
    breachedAccount: async () => {
      throw new HibpError('auth', 'HIBP rejected the API key (HTTP 401)', { status: 401 });
    },
  });
  await assert.rejects(
    makeHibpSource(badKey.client).check({ kind: 'email', value: 'alice@example.com' }),
    (err: unknown) => err instanceof ExposureSourceError && err.kind === 'auth'
  );

  const limited = fakeHibpClient({
    breachedAccount: async () => {
      throw new HibpError('rate_limited', 'slow down', { status: 429, retryAfterSeconds: 7 });
    },
  });
  await assert.rejects(
    makeHibpSource(limited.client).check({ kind: 'email', value: 'alice@example.com' }),
    (err: unknown) =>
      err instanceof ExposureSourceError &&
      err.kind === 'rate_limited' &&
      err.retryAfterSeconds === 7
  );
});

test('HibpSource: keyed calls are paced to the plan’s requests per minute', async () => {
  assert.equal(spacingForRpm(10), 6100);
  assert.equal(spacingForRpm(60), 1100);
  assert.equal(spacingForRpm(null), 6100, 'unknown plan: pace for the smallest one');

  const sleeps: number[] = [];
  const { client, calls } = fakeHibpClient({ subscriptionStatus: async () => ({ Rpm: 60 }) });
  const source = makeHibpSource(client, sleeps);
  await source.check({ kind: 'email', value: 'a@example.com' });
  await source.check({ kind: 'email', value: 'b@example.com' });

  assert.equal(calls.filter((c) => c === 'subscriptionStatus').length, 1, 'the plan is cached');
  assert.deepEqual(sleeps, [1100, 1100], 'one plan-sized gap before each breach search');
});

// ---- run loop ---------------------------------------------------------------------------

function identity(id: number, value = `user${id}@example.com`): MonitoredIdentity {
  return {
    id,
    kind: 'email',
    value,
    enabled: true,
    interval_minutes: 1440,
    last_checked_at: null,
    last_status: null,
    last_error: null,
    created_at: '',
    updated_at: '',
  };
}

function memoryStore(
  identities: MonitoredIdentity[],
  options: { enabled?: boolean; snapshot?: HibpDomainSnapshot | null; keyRef?: string | null } = {}
) {
  const due = new Set(identities.map((i) => i.id));
  const fingerprints = new Set<string>();
  const byId = new Map(identities.map((i) => [i.id, i]));
  const domains = {
    keyRef: options.keyRef === undefined ? KEY_REF : options.keyRef,
    snapshot: options.snapshot ?? null,
  };
  const log = {
    checked: [] as number[],
    failed: [] as Array<{ id: number; error: string; advance: boolean }>,
    unverified: [] as Array<{ id: number; note: string }>,
    findings: [] as FindingInput[],
    notifications: [] as ExposureNotice[][],
    snapshotSaves: 0,
    staleMarks: 0,
    requeued: [] as number[][],
  };
  const setStatus = (id: number, status: string | null) => {
    const row = byId.get(id);
    if (row) row.last_status = status;
  };
  const store: LeakedCredentialStore = {
    isEnabled: async () => options.enabled ?? true,
    // Copies, as rows read from the database are: later writes don't show through.
    findDue: async (limit, force) =>
      identities
        .filter((i) => i.enabled && (force || due.has(i.id)))
        .slice(0, limit)
        .map((i) => ({ ...i })),
    countDue: async (force) => (force ? identities.filter((i) => i.enabled).length : due.size),
    markChecked: async (id) => {
      log.checked.push(id);
      setStatus(id, 'ok');
      due.delete(id);
    },
    markFailed: async (id, error, advance) => {
      log.failed.push({ id, error, advance });
      setStatus(id, 'error');
      if (advance) due.delete(id);
    },
    markUnverified: async (id, note) => {
      log.unverified.push({ id, note });
      setStatus(id, 'unverified');
      const row = byId.get(id);
      if (row) row.last_checked_at = new Date().toISOString();
      due.delete(id);
    },
    loadDomainSnapshot: async () => ({
      keyRef: domains.keyRef,
      keyUsable: domains.keyRef !== null,
      snapshot: domains.snapshot,
    }),
    saveDomainSnapshot: async (keyRef, build) => {
      if (keyRef !== domains.keyRef) return null;
      domains.snapshot = build(domains.snapshot);
      log.snapshotSaves++;
      return domains.snapshot;
    },
    markDomainSnapshotStale: async () => {
      log.staleMarks++;
      if (domains.snapshot) domains.snapshot = { ...domains.snapshot, stale: true };
    },
    requeueVerified: async (values) => {
      const rows = identities.filter(
        (i) => i.kind === 'email_domain' && i.last_status === 'unverified' && values.includes(i.value)
      );
      for (const row of rows) {
        row.last_status = null;
        row.last_checked_at = null;
        if (row.enabled) due.add(row.id);
      }
      log.requeued.push(rows.map((r) => r.id));
      return rows.map((r) => ({ id: r.id, enabled: r.enabled }));
    },
    listEmailDomains: async () =>
      identities.filter((i) => i.kind === 'email_domain').map((i) => ({ id: i.id, value: i.value, enabled: i.enabled })),
    recordFinding: async (input) => {
      log.findings.push(input);
      const isNew = !fingerprints.has(input.fingerprint);
      fingerprints.add(input.fingerprint);
      return {
        findingId: log.findings.length,
        isNew,
        alertId: isNew ? log.findings.length : null,
        alertCreated: isNew,
      };
    },
    notify: async (notices) => {
      log.notifications.push(notices);
    },
  };
  return { store, log, due, domains };
}

function scriptedSource(
  script: Record<string, () => ExposureHit[] | Error>
): ExposureSource & { seen: string[] } {
  const seen: string[] = [];
  return {
    id: 'test',
    label: 'Test source',
    attribution: 'https://example.test',
    seen,
    isConfigured: async () => true,
    check: async (i) => {
      seen.push(i.value);
      const outcome = script[i.value]?.() ?? [];
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  };
}

const hitFor = (account: string, name: string, dataClasses = ['Email addresses']): ExposureHit => ({
  account,
  breach: breach({ name, title: name, dataClasses }),
});

test('run: each breach is recorded once, and an identity’s new findings are one notification', async () => {
  const { store, log } = memoryStore([identity(1, 'a@example.com'), identity(2, 'b@example.com')]);
  const source = scriptedSource({
    'a@example.com': () => [
      hitFor('a@example.com', 'Adobe', ['Passwords']),
      hitFor('a@example.com', 'Canva'),
    ],
    'b@example.com': () => [],
  });

  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(summary, {
    checked: 2,
    newFindings: 2,
    failed: 0,
    unverified: 0,
    remaining: 0,
    skipped: false,
  });
  assert.deepEqual(log.checked, [1, 2]);
  assert.equal(log.notifications.length, 1, 'grouped per identity, not per finding');
  assert.deepEqual(
    log.notifications[0].map((n) => n.severity),
    ['high', 'medium']
  );

  // Nothing is due any more, so a normal run is a no-op...
  const idle = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual([idle.skipped, idle.reason], [true, 'no identities are due']);

  // ...and a forced re-check finds the same breaches: nothing new, nobody notified again.
  const again = await runLeakedCredentialChecks({ source, store, force: true });
  assert.deepEqual([again.skipped, again.checked, again.newFindings], [false, 2, 0]);
  assert.equal(
    log.findings.length,
    4,
    'the same two findings were recorded again (deduped downstream)'
  );
  assert.equal(log.notifications.length, 1);
});

test('run: a 429 pauses every check, ends the cycle and leaves the identity due', async () => {
  const { store, log, due } = memoryStore([identity(1), identity(2), identity(3)]);
  const source = scriptedSource({
    'user2@example.com': () =>
      new ExposureSourceError('rate_limited', 'HIBP rate limit exceeded', 30),
  });

  const summary = await runLeakedCredentialChecks({ source, store });
  assert.equal(summary.checked, 1);
  assert.match(summary.error ?? '', /rate limit/);
  assert.ok(summary.rateLimitedUntil && Date.parse(summary.rateLimitedUntil) > Date.now() + 29_000);
  assert.deepEqual(source.seen, ['user1@example.com', 'user2@example.com'], 'user3 was not tried');
  assert.deepEqual([...due], [2, 3], 'the rate-limited identity is still due');
  assert.deepEqual(log.failed, [], 'a rate limit is not the identity’s fault');
  assert.equal(summary.remaining, 2);

  // Until retry-after passes, runs are skipped without touching the provider.
  assert.match((await getLeakedCredentialSkipReason({ source, store })) ?? '', /rate limit/);
  const next = await runLeakedCredentialChecks({ source, store });
  assert.equal(next.skipped, true);
  assert.equal(source.seen.length, 2);
  assert.ok(getLeakedCredentialRunState().paused_until);

  resetLeakedCredentialPause(); // e.g. the admin saved a new key
  assert.equal(await getLeakedCredentialSkipReason({ source, store }), null);
});

test('run: a rejected key ends the cycle and pauses checks', async () => {
  const { store, due } = memoryStore([identity(1), identity(2)]);
  const source = scriptedSource({
    'user1@example.com': () =>
      new ExposureSourceError('auth', 'HIBP rejected the API key (HTTP 401)'),
  });
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.equal(summary.checked, 0);
  assert.match(summary.error ?? '', /401/);
  assert.equal(summary.rateLimitedUntil, undefined);
  assert.equal(due.size, 2);
  assert.match(getLeakedCredentialRunState().pause_reason ?? '', /paused for an hour/);
});

test('run: an identity-level failure is recorded and skipped until its next interval', async () => {
  const { store, log, due } = memoryStore([identity(1), identity(2)]);
  const source = scriptedSource({
    'user1@example.com': () =>
      new ExposureSourceError('identity', 'HIBP refused the domain search (HTTP 403)'),
    'user2@example.com': () => [hitFor('user2@example.com', 'Adobe')],
  });
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(
    {
      checked: summary.checked,
      failed: summary.failed,
      newFindings: summary.newFindings,
      error: summary.error,
    },
    { checked: 1, failed: 1, newFindings: 1, error: undefined }
  );
  assert.deepEqual(log.failed, [
    { id: 1, error: 'HIBP refused the domain search (HTTP 403)', advance: true },
  ]);
  assert.equal(due.size, 0);
});

test('run: transient failures leave identities due, and two in a row end the cycle', async () => {
  const { store, log, due } = memoryStore([identity(1), identity(2), identity(3)]);
  const down = () =>
    new ExposureSourceError('transient', 'HIBP is temporarily unavailable (HTTP 503)');
  const source = scriptedSource({ 'user1@example.com': down, 'user2@example.com': down });

  const summary = await runLeakedCredentialChecks({ source, store });
  assert.equal(summary.failed, 2);
  assert.match(summary.error ?? '', /looks unavailable/);
  assert.deepEqual(source.seen, ['user1@example.com', 'user2@example.com']);
  assert.deepEqual(
    log.failed.map((f) => f.advance),
    [false, false],
    'still due for the next cycle'
  );
  assert.equal(due.size, 3);
});

test('run: skips, with a reason, when disabled, unconfigured, or nothing is due', async () => {
  const source = scriptedSource({});
  const disabled = await runLeakedCredentialChecks({
    source,
    store: memoryStore([identity(1)], { enabled: false }).store,
  });
  assert.deepEqual(
    [disabled.skipped, disabled.reason],
    [true, 'leaked-credential checks are disabled in settings']
  );

  const unconfigured = { ...source, isConfigured: async () => false };
  const noProvider = await runLeakedCredentialChecks({
    source: unconfigured,
    store: memoryStore([identity(1)]).store,
  });
  assert.match(noProvider.reason ?? '', /no breach-data provider is configured/);

  const nothing = await runLeakedCredentialChecks({ source, store: memoryStore([]).store });
  assert.deepEqual([nothing.skipped, nothing.reason], [true, 'no identities are due']);
  assert.equal(source.seen.length, 0);
});

test('run: overlapping runs do not overlap', async () => {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const source: ExposureSource = {
    ...scriptedSource({}),
    check: async () => {
      await gate;
      return [];
    },
  };
  const { store } = memoryStore([identity(1)]);
  const first = runLeakedCredentialChecks({ source, store });
  await new Promise((resolve) => setImmediate(resolve));
  const second = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual([second.skipped, second.reason], [true, LEAKED_CREDS_ALREADY_RUNNING]);
  release();
  assert.equal((await first).checked, 1);
});

// ---- verified HIBP domains --------------------------------------------------------------

const KEY_REF = 'aaaaaaaaaaaaaaaa';
const HOUR = 60 * 60 * 1000;

function domainIdentity(id: number, value: string, overrides: Partial<MonitoredIdentity> = {}): MonitoredIdentity {
  return { ...identity(id, value), kind: 'email_domain', ...overrides };
}

const listing = (names: string[]): VerifiedDomainListing => ({
  list: {
    domains: names.map((DomainName) => ({
      DomainName,
      PwnCount: 3,
      PwnCountExcludingSpamLists: 3,
      PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 3,
      NextSubscriptionRenewal: null,
    })),
    unreadable: 0,
    overLimit: 0,
  },
  plan: { name: 'Core 2', domain_search_max_breached_accounts: 100, max_breached_domains: 3, subscribed_until: null },
});

/** A successful listing of `names`, `ageMs` old (relative to the real clock the run uses). */
function listedSnapshot(names: string[], ageMs = 0, overrides: Partial<HibpDomainSnapshot> = {}): HibpDomainSnapshot {
  return { ...buildSnapshot(listing(names).list, listing(names).plan, [], KEY_REF, new Date(Date.now() - ageMs)), ...overrides };
}

/**
 * A source that lists verified domains (`verified` names, or an error to throw)
 * and answers checks from `script`. Records the order of calls.
 */
function domainSource(
  verified: string[] | (() => string[] | Error),
  script: Record<string, () => ExposureHit[] | Error> = {}
) {
  const calls: string[] = [];
  const listOptions: Array<{ refreshPlan: boolean }> = [];
  const source: ExposureSource & { calls: string[]; listOptions: typeof listOptions } = {
    ...scriptedSource({}),
    calls,
    listOptions,
    check: async (i) => {
      calls.push(`check:${i.value}`);
      const outcome = script[i.value]?.() ?? [];
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
    listVerifiedDomains: async (options) => {
      calls.push('list');
      listOptions.push(options);
      const result = typeof verified === 'function' ? verified() : verified;
      if (result instanceof Error) throw result;
      return listing(result);
    },
  };
  return source;
}

const unverified403 = () => new ExposureSourceError('unverified', FALLBACK_403_NOTE);

test('domains: unverified ones are skipped without a call, verified ones and emails are checked', async () => {
  const ids = [domainIdentity(1, 'good.example'), domainIdentity(2, 'nope.example'), identity(3, 'a@example.com')];
  const { store, log } = memoryStore(ids, { snapshot: listedSnapshot(['good.example']) });
  const source = domainSource(['good.example']);

  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(source.calls, ['check:good.example', 'check:a@example.com'], 'fresh list: no list call, no search for nope');
  assert.deepEqual(
    { checked: summary.checked, unverified: summary.unverified, failed: summary.failed },
    { checked: 2, unverified: 1, failed: 0 }
  );
  assert.equal(log.unverified.length, 1);
  assert.equal(log.unverified[0].id, 2);
  assert.match(
    log.unverified[0].note,
    /^Skipped: nope\.example isn't verified on your HIBP account \(as of \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\)\. Verify it in the HIBP dashboard, then re-check verification\.$/
  );
  assert.match(describeRunSummary(summary), /1 skipped \(not verified on HIBP\)/);
});

test('domains: without a snapshot the list is fetched once, before any search, and saved', async () => {
  const ids = [domainIdentity(1, 'good.example'), domainIdentity(2, 'other.example')];
  const { store, log, domains } = memoryStore(ids);
  const source = domainSource(['GOOD.example.']);
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(source.calls, ['list', 'check:good.example']);
  assert.deepEqual(source.listOptions, [{ refreshPlan: false }], 'a run uses the cached plan');
  assert.equal(log.snapshotSaves, 1);
  assert.deepEqual(domains.snapshot?.domains?.map((d) => d.domain), ['good.example']);
  assert.equal(summary.unverified, 1);
});

test('domains: a fresh list is reused; a stale one is re-read after an hour; a pending skip shortens the wait', async () => {
  const run = async (snapshot: HibpDomainSnapshot, ids: MonitoredIdentity[]) => {
    resetLeakedCredentialPause();
    const source = domainSource(['good.example']);
    await runLeakedCredentialChecks({ source, store: memoryStore(ids, { snapshot }).store });
    return source.calls.filter((c) => c === 'list').length;
  };
  const verifiedOnly = () => [domainIdentity(1, 'good.example')];
  const withUnverified = () => [domainIdentity(1, 'good.example'), domainIdentity(2, 'nope.example')];

  assert.equal(await run(listedSnapshot(['good.example'], 5 * HOUR), verifiedOnly()), 0, 'fresh');
  assert.equal(await run(listedSnapshot(['good.example'], 6 * HOUR), verifiedOnly()), 1, '6 h old');
  assert.equal(await run(listedSnapshot(['good.example'], HOUR + 1000, { stale: true }), verifiedOnly()), 1, 'stale, an hour old');
  assert.equal(await run(listedSnapshot(['good.example'], 30 * 60 * 1000, { stale: true }), verifiedOnly()), 0, 'stale, under an hour');
  assert.equal(await run(listedSnapshot(['good.example'], 2 * HOUR), withUnverified()), 1, 'a due domain would be skipped');
  assert.equal(await run(listedSnapshot(['good.example'], 2 * HOUR), verifiedOnly()), 0);
});

test('domains: a failed listing is recorded; without a list the domain is searched, except after a 403', async () => {
  const failures: Array<[HibpError, string, boolean]> = [
    [new HibpError('auth', 'HIBP rejected the API key (HTTP 401)', { status: 401 }), 'auth', true],
    [new HibpError('auth', 'refused', { status: 403 }), 'forbidden', false],
    [new HibpError('transient', 'HIBP could not be reached'), 'network', true],
    [new HibpError('transient', 'HIBP is temporarily unavailable (HTTP 503)', { status: 503 }), 'hibp_unavailable', true],
    [new HibpError('transient', 'HIBP answered HTTP 404 for the verified-domain list', { status: 404 }), 'bad_response', true],
  ];
  for (const [err, kind, searched] of failures) {
    resetLeakedCredentialPause();
    const { store, domains, log } = memoryStore([domainIdentity(1, 'x.example')]);
    const source = domainSource(() => err);
    const summary = await runLeakedCredentialChecks({ source, store });
    assert.equal(domains.snapshot?.error?.kind, kind);
    assert.equal(domains.snapshot?.domains, null);
    assert.equal(source.calls.includes('check:x.example'), searched, kind);
    assert.equal(summary.unverified, searched ? 0 : 1, kind);
    if (!searched) assert.equal(log.unverified[0].note, "Skipped: your HIBP plan doesn't include domain search.");
  }

  // With an older list, the list decides — except after a 403, which skips everything.
  for (const [err, kind, listDecides] of failures) {
    resetLeakedCredentialPause();
    const old = listedSnapshot(['x.example'], 7 * HOUR);
    const { store } = memoryStore([domainIdentity(1, 'x.example'), domainIdentity(2, 'y.example')], { snapshot: old });
    const source = domainSource(() => err);
    await runLeakedCredentialChecks({ source, store });
    assert.equal(source.calls.includes('check:x.example'), listDecides, `${kind}: listed domain`);
    assert.equal(source.calls.includes('check:y.example'), false, `${kind}: unlisted domain is skipped either way`);
  }
});

test('domains: a 429 while listing pauses every check and searches nothing', async () => {
  const { store, domains } = memoryStore([domainIdentity(1, 'x.example'), identity(2, 'a@example.com')]);
  const source = domainSource(() => new HibpError('rate_limited', 'HIBP rate limit exceeded; retry after 30s', { status: 429, retryAfterSeconds: 30 }));
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(source.calls, ['list']);
  assert.ok(summary.rateLimitedUntil && Date.parse(summary.rateLimitedUntil) > Date.now() + 29_000);
  assert.match(summary.error ?? '', /rate limit/);
  assert.equal(domains.snapshot?.error?.kind, 'rate_limited', 'the failure is recorded before the pause');
  assert.ok(getLeakedCredentialRunState().paused_until);

  const next = await runLeakedCredentialChecks({ source, store });
  assert.equal(next.skipped, true);
  assert.match(next.reason ?? '', /rate limit reached/);
  assert.deepEqual(source.calls, ['list']);
});

test('domains: a 403 search while verification is unknown reads as unverified and marks the list stale', async () => {
  const ids = [domainIdentity(1, 'x.example'), domainIdentity(2, 'y.example')];
  const { store, log, domains } = memoryStore(ids, {
    snapshot: listedSnapshot([], 0, { skipped_entries: 1 }), // incomplete: absence proves nothing
  });
  const source = domainSource([], { 'x.example': unverified403, 'y.example': () => [] });
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(source.calls, ['check:x.example', 'check:y.example'], 'the loop carries on');
  assert.deepEqual(log.unverified, [{ id: 1, note: FALLBACK_403_NOTE }]);
  assert.deepEqual(log.failed, []);
  assert.deepEqual([summary.unverified, summary.failed, summary.checked], [1, 0, 1]);
  assert.equal(log.staleMarks, 1);
  assert.equal(domains.snapshot?.stale, true);
});

test('domains: a 403 for a domain listed as verified is an error, and a re-list does not re-queue it', async () => {
  const ids = [domainIdentity(1, 'x.example')];
  const { store, log, due } = memoryStore(ids, { snapshot: listedSnapshot(['x.example']) });
  const source = domainSource(['x.example'], { 'x.example': unverified403 });
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(log.failed, [{ id: 1, error: CONTRADICTION_NOTE, advance: true }]);
  assert.deepEqual([summary.failed, summary.unverified], [1, 0]);
  assert.equal(log.staleMarks, 1);
  assert.equal(due.size, 0, 'it waits its interval');

  // An admin's re-check that still lists it: nothing to re-queue (no loop).
  const refreshed = await refreshHibpVerifiedDomains({ source, store: memoryStore(ids, { snapshot: listedSnapshot(['x.example'], 2 * 60_000) }).store });
  assert.deepEqual(refreshed.becameDue, []);
  assert.equal(ids[0].last_status, 'error');
});

test('domains: no email domain due means no list call; an old source checks every domain', async () => {
  const emailsOnly = domainSource(['x.example']);
  await runLeakedCredentialChecks({ source: emailsOnly, store: memoryStore([identity(1, 'a@example.com')]).store });
  assert.deepEqual(emailsOnly.calls, ['check:a@example.com']);

  const oldSource = scriptedSource({});
  const { store, log } = memoryStore([domainIdentity(1, 'x.example'), domainIdentity(2, 'y.example')], {
    snapshot: listedSnapshot([]),
  });
  const summary = await runLeakedCredentialChecks({ source: oldSource, store });
  assert.deepEqual(oldSource.seen, ['x.example', 'y.example']);
  assert.deepEqual([summary.checked, summary.unverified, log.snapshotSaves], [2, 0, 0]);
});

test('domains: a refresh that re-queues identities searches them in the same run', async () => {
  const ids = [
    domainIdentity(1, 'now-verified.example', { last_status: 'unverified', last_checked_at: new Date().toISOString() }),
    domainIdentity(2, 'still-not.example'),
  ];
  const { store, log, due } = memoryStore(ids, { snapshot: listedSnapshot([], 2 * HOUR) });
  due.delete(1); // checked (skipped) recently: not due by its interval
  const source = domainSource(['now-verified.example']);
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(log.requeued, [[1]]);
  assert.deepEqual(source.calls, ['list', 'check:now-verified.example']);
  assert.deepEqual([summary.checked, summary.unverified], [1, 1]);
});

test('HibpSource: listing and searching share one pacer; concurrent plan lookups make one call', async () => {
  let now = 1_000_000;
  const at: Array<[string, number]> = [];
  let statusCalls = 0;
  const client = {
    subscriptionStatus: async () => {
      statusCalls++;
      at.push(['status', now]);
      await new Promise((resolve) => setImmediate(resolve));
      return { Rpm: 60, SubscriptionName: 'Core 3', DomainSearchMaxBreachedAccounts: 500, MaxBreachedDomains: 5 };
    },
    subscribedDomains: async () => {
      at.push(['list', now]);
      return { domains: [], unreadable: 0, overLimit: 0 };
    },
    breachedAccount: async () => {
      at.push(['account', now]);
      return [];
    },
    breachedDomain: async () => ({}),
    allBreaches: async () => [],
  };
  const source = new HibpSource({
    getApiKey: async () => '0123456789abcdef0123456789abcdef',
    isEnabled: async () => true,
    createClient: () => client as never,
    sleep: async (ms) => {
      await new Promise((resolve) => setImmediate(resolve));
      now += ms;
    },
    now: () => now,
  });

  const [listed] = await Promise.all([
    source.listVerifiedDomains({ refreshPlan: false }),
    source.check({ kind: 'email', value: 'a@example.com' }),
    source.check({ kind: 'email', value: 'b@example.com' }),
  ]);
  assert.equal(statusCalls, 1, 'one shared plan lookup');
  assert.deepEqual(listed.plan, {
    name: 'Core 3',
    domain_search_max_breached_accounts: 500,
    max_breached_domains: 5,
    subscribed_until: null,
  });
  const times = at.map(([, t]) => t);
  for (let i = 1; i < times.length; i++) {
    assert.ok(times[i] - times[i - 1] >= spacingForRpm(60), `call ${i} came ${times[i] - times[i - 1]} ms after the previous one`);
  }
  assert.equal(at.length, 4);

  // A manual re-check re-reads the plan even though it is cached.
  await source.listVerifiedDomains({ refreshPlan: true });
  assert.equal(statusCalls, 2);
  await source.listVerifiedDomains({ refreshPlan: false });
  assert.equal(statusCalls, 2);
});

test('refreshHibpVerifiedDomains: cooldown, shared calls, key changes, pauses and re-queues', async () => {
  // No usable key.
  await assert.rejects(
    refreshHibpVerifiedDomains({ source: domainSource([]), store: memoryStore([], { keyRef: null }).store }),
    (err: unknown) => err instanceof HibpDomainsRefreshError && err.kind === 'no_key'
  );

  // Inside the cooldown: the cached answer, no call.
  const cooled = domainSource(['x.example']);
  const recent = await refreshHibpVerifiedDomains({
    source: cooled,
    store: memoryStore([], { snapshot: listedSnapshot(['x.example'], 10_000) }).store,
  });
  assert.deepEqual([recent.refreshed, cooled.calls.length, recent.view.state], [false, 0, 'listed']);

  // Two at once share one call, and a manual re-check re-reads the plan.
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const ids = [domainIdentity(1, 'x.example', { last_status: 'unverified' }), domainIdentity(2, 'y.example', { enabled: false, last_status: 'unverified' })];
  const shared = memoryStore(ids, { snapshot: listedSnapshot([], 5 * 60_000) });
  let lists = 0;
  const slow: ExposureSource = {
    ...domainSource([]),
    listVerifiedDomains: async (options) => {
      lists++;
      assert.deepEqual(options, { refreshPlan: true });
      await gate;
      return listing(['x.example', 'y.example']);
    },
  };
  const first = refreshHibpVerifiedDomains({ source: slow, store: shared.store });
  const second = refreshHibpVerifiedDomains({ source: slow, store: shared.store });
  await new Promise((resolve) => setImmediate(resolve));
  // A key saved meanwhile: a re-check for the new key doesn't join the old one.
  const otherKey = memoryStore([], { keyRef: 'bbbbbbbbbbbbbbbb' });
  const forNewKey = refreshHibpVerifiedDomains({ source: domainSource(['z.example']), store: otherKey.store });
  release();
  const [a, b, c] = await Promise.all([first, second, forNewKey]);
  assert.equal(lists, 1, 'one HIBP round trip for both');
  assert.deepEqual([a.refreshed, b.refreshed], [true, true]);
  assert.deepEqual(a.becameDue, [1], 'enabled identities that turned verified are due again');
  assert.deepEqual(shared.log.requeued, [[1, 2]], 're-queued once, the disabled one included');
  assert.deepEqual(c.view.domains?.map((d) => d.domain), ['z.example']);

  // An auth pause is lifted by a successful listing (the key works)...
  const authStore = memoryStore([identity(9, 'a@example.com')]);
  await runLeakedCredentialChecks({
    source: scriptedSource({ 'a@example.com': () => new ExposureSourceError('auth', 'HIBP rejected the API key (HTTP 401)') }),
    store: authStore.store,
  });
  assert.ok(getLeakedCredentialRunState().paused_until);
  await refreshHibpVerifiedDomains({ source: domainSource([]), store: authStore.store });
  assert.equal(getLeakedCredentialRunState().paused_until, null);

  // ...a rate-limit pause is not: the re-check is refused and nothing is sent.
  const limitedStore = memoryStore([identity(9, 'a@example.com')]);
  await runLeakedCredentialChecks({
    source: scriptedSource({ 'a@example.com': () => new ExposureSourceError('rate_limited', 'slow down', 30) }),
    store: limitedStore.store,
  });
  const refused = domainSource([]);
  await assert.rejects(
    refreshHibpVerifiedDomains({ source: refused, store: limitedStore.store }),
    (err: unknown) => err instanceof HibpDomainsRefreshError && err.kind === 'rate_limited' && !!err.retryAt
  );
  assert.equal(refused.calls.length, 0);
  assert.ok(getLeakedCredentialRunState().paused_until);

  // A 429 recorded in the snapshot (e.g. before a restart) is honoured too.
  resetLeakedCredentialPause();
  const recorded = failedSnapshot(
    null,
    toDomainListError(new HibpError('rate_limited', 'x', { status: 429, retryAfterSeconds: 120 }), Date.now()),
    KEY_REF,
    new Date()
  );
  await assert.rejects(
    refreshHibpVerifiedDomains({ source: refused, store: memoryStore([], { snapshot: recorded }).store }),
    (err: unknown) => err instanceof HibpDomainsRefreshError && err.kind === 'rate_limited'
  );
});

/** Hold the check of `value` until release(); `started` resolves when that check begins. */
function holdCheck(source: ExposureSource, value: string) {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let begin!: () => void;
  const started = new Promise<void>((resolve) => (begin = resolve));
  const check = source.check.bind(source);
  source.check = async (i) => {
    if (i.value === value) {
      begin();
      await gate;
    }
    return check(i);
  };
  return { started, release };
}

test('domains: a Re-check during a run is not undone: the skip is decided on the list as it is now', async () => {
  const ids = [
    identity(1, 'a@example.com'),
    domainIdentity(2, 'd.example', {
      last_status: 'unverified',
      last_checked_at: new Date(Date.now() - 2 * 24 * HOUR).toISOString(), // due again by its interval
    }),
  ];
  // Listed two minutes ago without d.example: fresh for the run, past the re-check's cooldown.
  const { store, log, due } = memoryStore(ids, { snapshot: listedSnapshot([], 2 * 60_000) });
  const source = domainSource(['d.example']);
  const held = holdCheck(source, 'a@example.com');

  const run = runLeakedCredentialChecks({ source, store });
  await held.started;
  // Meanwhile the admin verifies d.example at HIBP and clicks Re-check.
  const recheck = await refreshHibpVerifiedDomains({ source, store });
  assert.deepEqual(recheck.becameDue, [2]);
  held.release();
  const summary = await run;

  assert.deepEqual(source.calls, ['list', 'check:a@example.com', 'check:d.example'], 'd.example is searched in this run');
  assert.deepEqual(log.unverified, [], 'the re-queue is not overwritten with "unverified"');
  assert.deepEqual([summary.checked, summary.unverified, summary.failed], [2, 0, 0]);
  assert.equal(ids[1].last_status, 'ok');
  assert.equal(due.has(2), false);
});

test('domains: a Re-check landing between the skip decision and its write still re-queues the domain', async () => {
  const ids = [
    domainIdentity(1, 'd.example', {
      last_status: 'unverified',
      last_checked_at: new Date(Date.now() - 2 * 24 * HOUR).toISOString(),
    }),
  ];
  const { store, due, domains } = memoryStore(ids, { snapshot: listedSnapshot([], 2 * 60_000) });
  const write = store.markUnverified.bind(store);
  // The admin's re-check writes its list and re-queues just before the run's write lands.
  store.markUnverified = async (id, note) => {
    domains.snapshot = listedSnapshot(['d.example']);
    await store.requeueVerified(['d.example']);
    await write(id, note);
  };
  const source = domainSource(['d.example']);
  const summary = await runLeakedCredentialChecks({ source, store });
  assert.deepEqual(source.calls, [], 'skipped on the list it read');
  assert.equal(summary.unverified, 0, 'not counted as skipped: it is due again');
  assert.equal(ids[0].last_status, null, 'back to "not checked yet", not "Not verified"');
  assert.equal(due.has(1), true, 'due again, so the next run searches it');
});

test('run: a 429 from a concurrent Re-check stops a run in progress: nothing more is sent', async () => {
  const { store, due } = memoryStore([identity(1), identity(2), identity(3)]);
  const source = domainSource(
    () => new HibpError('rate_limited', 'HIBP rate limit exceeded; retry after 120s', { status: 429, retryAfterSeconds: 120 })
  );
  const held = holdCheck(source, 'user1@example.com');

  const run = runLeakedCredentialChecks({ source, store });
  await held.started;
  const recheck = await refreshHibpVerifiedDomains({ source, store });
  assert.equal(recheck.view.error?.kind, 'rate_limited');
  assert.ok(getLeakedCredentialRunState().paused_until, 'the shared pause is set');
  held.release();
  const summary = await run;

  assert.deepEqual(source.calls, ['list', 'check:user1@example.com'], 'user2 and user3 are not sent inside retry-after');
  assert.equal(summary.checked, 1);
  assert.match(summary.error ?? '', /rate limit/);
  assert.ok(summary.rateLimitedUntil && Date.parse(summary.rateLimitedUntil) > Date.now() + 100_000);
  assert.deepEqual([...due], [2, 3], 'the rest stay due');
});

test('HibpSource: no keyed call is sent while a rate-limit pause is on, even one already waiting its turn', async () => {
  let now = 1_000_000;
  let pausedUntil = 0;
  let pauseWhileWaiting = true;
  const sent: string[] = [];
  const client = {
    subscriptionStatus: async () => {
      sent.push('status');
      return { Rpm: 60 };
    },
    subscribedDomains: async () => {
      sent.push('list');
      return { domains: [], unreadable: 0, overLimit: 0 };
    },
    breachedAccount: async () => {
      sent.push('account');
      return [];
    },
    breachedDomain: async () => ({}),
    allBreaches: async () => [],
  };
  const source = new HibpSource({
    getApiKey: async () => '0123456789abcdef0123456789abcdef',
    isEnabled: async () => true,
    createClient: () => client as never,
    sleep: async (ms) => {
      now += ms;
      // A 429 elsewhere (a run, or an admin's re-check) while this call waits its turn.
      if (pauseWhileWaiting) pausedUntil = now + 60_000;
    },
    now: () => now,
    pausedUntil: () => pausedUntil,
  });

  // The plan lookup goes out at once; the search waits its turn, and the pause starts meanwhile.
  await assert.rejects(
    source.check({ kind: 'email', value: 'a@example.com' }),
    (err: unknown) => err instanceof ExposureSourceError && err.kind === 'rate_limited' && (err.retryAfterSeconds ?? 0) >= 59
  );
  assert.deepEqual(sent, ['status']);
  await assert.rejects(
    source.listVerifiedDomains({ refreshPlan: true }),
    (err: unknown) => err instanceof HibpError && err.kind === 'rate_limited'
  );
  assert.deepEqual(sent, ['status'], 'neither the plan nor the list is asked for');

  // Once it has passed, calls flow again.
  pauseWhileWaiting = false;
  now = pausedUntil + 1;
  await source.check({ kind: 'email', value: 'a@example.com' });
  assert.deepEqual(sent, ['status', 'account']);
});

test('findings carry HIBP’s per-breach attribution as plain text, and descriptions the licence', () => {
  const source = new HibpSource({ getApiKey: async () => undefined });
  const record = toBreachRecord({
    Name: 'Combo',
    Title: 'Combo list',
    Attribution: ' @someone\u0000\nvia https://t.me/x\u202e ',
  } as HibpBreach);
  assert.equal(record.attribution, '@someone  via https://t.me/x', 'control and bidi characters removed');
  assert.equal(toBreachRecord({ Name: 'A', Attribution: '   ' } as HibpBreach).attribution, null);
  assert.equal(toBreachRecord({ Name: 'A', Attribution: 'x'.repeat(400) } as HibpBreach).attribution?.length, 300);
  assert.equal(toBreachRecord({ Name: 'A', Attribution: 7 } as unknown as HibpBreach).attribution, null);

  const finding = buildBreachFinding(source, { id: 1, kind: 'email', value: 'a@example.com' }, {
    account: 'a@example.com',
    breach: record,
  });
  assert.equal(finding.detail.breach_attribution, record.attribution);
  assert.match(
    finding.description ?? '',
    /Source: Have I Been Pwned \(https:\/\/haveibeenpwned\.com\), licensed under CC BY 4\.0 \(https:\/\/creativecommons\.org\/licenses\/by\/4\.0\/\)\.$/
  );
  assert.ok(!(finding.description ?? '').includes('@someone'), 'not added to descriptions or notifications');
});
