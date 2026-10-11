/**
 * Leaked-credential checks without a database: severity mapping, fingerprint
 * stability (re-checks must hit the same finding), the finding we build from a
 * breach, the HIBP source (domain-search expansion, pacing, 403 meaning), and
 * the run loop's handling of rate limits, rejected keys and flaky providers —
 * driven through an in-memory store. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  ExposureSourceError,
  HibpSource,
  LEAKED_CREDS_ALREADY_RUNNING,
  breachFingerprint,
  breachSeverity,
  buildBreachFinding,
  getLeakedCredentialRunState,
  getLeakedCredentialSkipReason,
  resetLeakedCredentialPause,
  runLeakedCredentialChecks,
  spacingForRpm,
  toBreachRecord,
  type BreachRecord,
  type ExposureHit,
  type ExposureSource,
  type IdentityRef,
  type LeakedCredentialStore,
} from './leakedCredentialService';
import { HibpError, type HibpBreach } from './hibpClient';
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
      err instanceof ExposureSourceError &&
      err.kind === 'identity' &&
      /verify this domain/.test(err.message)
  );

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

function memoryStore(identities: MonitoredIdentity[], options: { enabled?: boolean } = {}) {
  const due = new Set(identities.map((i) => i.id));
  const fingerprints = new Set<string>();
  const log = {
    checked: [] as number[],
    failed: [] as Array<{ id: number; error: string; advance: boolean }>,
    findings: [] as FindingInput[],
    notifications: [] as ExposureNotice[][],
  };
  const store: LeakedCredentialStore = {
    isEnabled: async () => options.enabled ?? true,
    findDue: async (limit, force) =>
      identities.filter((i) => force || due.has(i.id)).slice(0, limit),
    countDue: async (force) => (force ? identities.length : due.size),
    markChecked: async (id) => {
      log.checked.push(id);
      due.delete(id);
    },
    markFailed: async (id, error, advance) => {
      log.failed.push({ id, error, advance });
      if (advance) due.delete(id);
    },
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
  return { store, log, due };
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
