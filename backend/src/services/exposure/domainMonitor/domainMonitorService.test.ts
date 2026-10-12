/**
 * The domain-monitor run loop without a database or network: the REAL
 * collectors over scripted DNS / CT / RDAP sources, driven through an
 * in-memory store. Covers first-run baseline silence, findings on later
 * changes, fingerprint stability (re-runs and replays never re-alert),
 * collector isolation, scope handling, retry scheduling, skip reasons and
 * overlapping runs. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DOMAIN_MONITOR_ALREADY_RUNNING,
  DOMAIN_MONITOR_DISABLED,
  describeDomainMonitorRun,
  domainMonitorCycleFailure,
  getDomainMonitorSkipReason,
  retryDelayMinutes,
  runDomainChecks,
  runDomainNow,
  type DomainMonitorStore,
} from './domainMonitorService';
import { createCtCollector, type CertificateSource, type CtCertificate } from './ct';
import { createDnsCollector } from './dns';
import { createLookalikeCollector } from './lookalike';
import { createRdapCollector, parseRdapDomain, type RdapSource } from './rdap';
import type { DnsResolverLike } from './resolver';
import { CollectorError, type Collector, type CollectorName } from './types';
import { ErrorLogService } from '../../errors/errorLogService';
import type { FindingInput } from '../findingWriter';
import type { ExposureNotice } from '../../notifications/notificationService';
import type { DomainBaseline, DomainRunRecord, WatchedDomain } from '../../../models/Exposure';

// ---- in-memory store -----------------------------------------------------------------------

function domainRow(
  id: number,
  domain: string,
  overrides: Partial<WatchedDomain> = {}
): WatchedDomain {
  return {
    id,
    domain,
    scope: 'own',
    enabled: true,
    interval_minutes: 1440,
    collectors: { ct: true, lookalike: true, rdap: true, dns: true },
    expected_cas: [],
    last_checked_at: null,
    next_run_at: null,
    last_status: null,
    last_error: null,
    last_summary: null,
    created_at: '',
    updated_at: '',
    ...overrides,
  };
}

function memoryStore(
  domains: WatchedDomain[],
  clock: { now: number },
  options: { enabled?: boolean } = {}
) {
  const baselines = new Map<string, DomainBaseline>();
  const fingerprints = new Set<string>();
  const log = {
    findings: [] as FindingInput[],
    alerts: [] as FindingInput[],
    notifications: [] as ExposureNotice[][],
    runs: [] as Array<{ id: number; run: DomainRunRecord }>,
    saved: [] as string[],
  };
  const isDue = (d: WatchedDomain) =>
    d.enabled && (!d.next_run_at || Date.parse(d.next_run_at) <= clock.now);
  const store: DomainMonitorStore = {
    isEnabled: async () => options.enabled ?? true,
    getConfig: async (trigger) => ({
      expiryWarningDays: 30,
      lookalikeMaxCandidates: 40,
      secondaryResolver: null,
      lookalikeCtChecksPerRun: trigger === 'manual' ? 2 : 3,
    }),
    findDue: async (limit) => domains.filter(isDue).slice(0, limit),
    countDue: async () => domains.filter(isDue).length,
    findById: async (id) => domains.find((d) => d.id === id) ?? null,
    listDomainNames: async () => domains.map((d) => d.domain),
    getBaselines: async (id) =>
      new Map(
        [...baselines]
          .filter(([key]) => key.startsWith(`${id}:`))
          .map(([key, value]) => [key.slice(key.indexOf(':') + 1), value])
      ),
    saveBaseline: async (id, collector, snapshot) => {
      log.saved.push(`${id}:${collector}`);
      // A JSON round trip, like JSONB.
      baselines.set(`${id}:${collector}`, {
        snapshot: JSON.parse(JSON.stringify(snapshot)),
        updated_at: new Date(clock.now).toISOString(),
      });
    },
    recordFinding: async (input) => {
      log.findings.push(input);
      const isNew = !fingerprints.has(input.fingerprint);
      fingerprints.add(input.fingerprint);
      if (isNew) log.alerts.push(input);
      return {
        findingId: log.findings.length,
        isNew,
        alertId: isNew ? log.alerts.length : null,
        alertCreated: isNew,
      };
    },
    notify: async (notices) => {
      log.notifications.push(notices);
    },
    markRun: async (id, run) => {
      log.runs.push({ id, run });
      const d = domains.find((x) => x.id === id) as WatchedDomain;
      d.last_checked_at = new Date(clock.now).toISOString();
      d.next_run_at = new Date(clock.now + run.nextRunMinutes * 60_000).toISOString();
      d.last_status = run.status;
      d.last_error = run.error;
      d.last_summary = JSON.parse(JSON.stringify(run.summary));
    },
  };
  return { store, log, baselines };
}

// ---- scripted network ------------------------------------------------------------------------

/** `servfail`: the name exists, but every lookup for it fails (e.g. a lame delegation). */
type Zone = Record<
  string,
  { a?: string[]; ns?: string[]; mx?: string[]; txt?: string[]; servfail?: boolean }
>;

function zoneResolver(zone: Zone): DnsResolverLike {
  const fail = (code: string) => Object.assign(new Error(code), { code });
  const get = (name: string, type: 'a' | 'ns' | 'mx' | 'txt') => {
    const entry = zone[name];
    if (!entry) throw fail('ENOTFOUND');
    if (entry.servfail) throw fail('ESERVFAIL');
    const value = entry[type];
    if (!value) throw fail('ENODATA');
    return value;
  };
  return {
    resolve4: async (n) => get(n, 'a'),
    resolve6: async (n) => {
      if (!zone[n]) throw fail('ENOTFOUND');
      if (zone[n].servfail) throw fail('ESERVFAIL');
      throw fail('ENODATA');
    },
    resolveNs: async (n) => get(n, 'ns'),
    resolveMx: async (n) => get(n, 'mx').map((exchange) => ({ priority: 10, exchange })),
    resolveTxt: async (n) => get(n, 'txt').map((t) => [t]),
  };
}

const LE = "C=US, O=Let's Encrypt, CN=R11";
const cert = (key: string, names: string[]): CtCertificate => ({
  key,
  crtshId: 1,
  issuer: LE,
  issuerKey: 'letsencrypt',
  issuerLabel: "Let's Encrypt",
  serial: key,
  commonName: names[0],
  names,
  notBefore: '2026-10-01T00:00:00.000Z',
  notAfter: '2027-01-01T00:00:00.000Z',
});

const RDAP = {
  objectClassName: 'domain',
  ldhName: 'EXAMPLE.COM',
  status: ['client transfer prohibited'],
  entities: [
    {
      roles: ['registrar'],
      publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }],
      vcardArray: ['vcard', [['fn', {}, 'text', 'Good Registrar']]],
    },
  ],
  events: [{ eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }],
  nameservers: [{ ldhName: 'a.iana-servers.net' }, { ldhName: 'b.iana-servers.net' }],
};

function world() {
  const zone: Zone = {
    'example.com': {
      a: ['192.0.2.10'],
      ns: ['a.iana-servers.net', 'b.iana-servers.net'],
      mx: ['mx.example.com'],
    },
    'example.net': { ns: ['ns.someone-else.net'], a: ['198.51.100.1'] }, // an old lookalike
  };
  const certs: Record<string, CtCertificate[]> = {
    'example.com': [cert('c1', ['example.com', 'www.example.com'])],
  };
  let rdap: unknown = RDAP;
  const ctSource: CertificateSource = { certificatesFor: async (name) => certs[name] ?? [] };
  const rdapSource: RdapSource = {
    lookup: async () => ({ kind: 'ok', info: parseRdapDomain(rdap), server: 'rdap.verisign.com' }),
  };
  const resolver = zoneResolver(zone);
  const collectors: Record<CollectorName, Collector> = {
    dns: createDnsCollector({ resolver, secondary: null }),
    rdap: createRdapCollector({ source: rdapSource }),
    lookalike: createLookalikeCollector({ resolver, dnstwist: null }),
    ct: createCtCollector({ source: ctSource }),
  };
  return {
    zone,
    certs,
    setRdap: (value: unknown) => {
      rdap = value;
    },
    collectors,
  };
}

// ---- tests -----------------------------------------------------------------------------------

test('end to end: the first run is silent, later changes alert once, replays never re-alert', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com')];
  const { store, log, baselines } = memoryStore(domains, clock);
  const w = world();

  const first = await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now });
  assert.deepEqual([first.checked, first.newFindings, first.failed], [1, 0, 0]);
  assert.deepEqual(log.alerts, [], 'first run: baselines only');
  assert.deepEqual([...baselines.keys()].sort(), ['1:ct', '1:dns', '1:lookalike', '1:rdap']);
  const summary = domains[0].last_summary as { collectors: Record<string, { status: string }> };
  assert.deepEqual(
    Object.fromEntries(Object.entries(summary.collectors).map(([k, v]) => [k, v.status])),
    { dns: 'baseline', rdap: 'baseline', lookalike: 'baseline', ct: 'baseline' }
  );
  assert.equal(domains[0].last_status, 'ok');
  assert.equal(Date.parse(domains[0].next_run_at as string), clock.now + 1440 * 60_000);
  const firstBaselines = new Map(baselines);

  // Nothing is due until the interval has passed.
  assert.equal(
    (await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now })).reason,
    'no watched domains are due'
  );

  // A day later: hijacked NS, a new lookalike, a certificate for a new host, a new registrar.
  clock.now += 1440 * 60_000;
  w.zone['example.com'].ns = ['ns1.attacker.example'];
  w.zone['examp1e.com'] = { ns: ['ns1.bad-host.net'], a: ['203.0.113.66'], mx: ['mx.examp1e.com'] };
  w.certs['example.com'] = [...w.certs['example.com'], cert('c2', ['vpn.example.com'])];
  w.setRdap({
    ...RDAP,
    entities: [
      {
        roles: ['registrar'],
        publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }],
        vcardArray: ['vcard', [['fn', {}, 'text', 'Other Registrar']]],
      },
    ],
  });
  const second = await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now });
  assert.equal(second.newFindings, 4);
  assert.deepEqual(log.alerts.map((f) => [f.eventType, f.severity]).sort(), [
    ['dns_drift', 'critical'],
    ['lookalike_registered', 'high'],
    ['new_cert', 'low'],
    ['rdap_change', 'critical'],
  ]);
  assert.ok(log.alerts.every((f) => f.source === 'domain-monitor' && f.domainId === 1));
  assert.equal(log.notifications.length, 1, 'one grouped notification for the domain run');
  assert.equal(log.notifications[0].length, 4);

  // Same world, next day: nothing new.
  clock.now += 1440 * 60_000;
  const third = await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now });
  assert.equal(third.newFindings, 0);
  assert.equal(log.alerts.length, 4);

  // Replay the same change against the day-1 baselines (as if saving them had failed):
  // the same fingerprints come out, so nothing is alerted twice.
  for (const [key, value] of firstBaselines) baselines.set(key, value);
  clock.now += 1440 * 60_000;
  const replay = await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now });
  assert.equal(replay.newFindings, 0);
  assert.equal(log.alerts.length, 4);
  assert.ok(log.findings.length > 4, 'the findings were seen again, and deduped');
});

test('isolation: one collector throwing does not stop the others or the cycle', async (t) => {
  const logged: string[] = [];
  t.mock.method(
    ErrorLogService,
    'logBackgroundError',
    (_source: string, _err: unknown, ctx: { dedupeKey?: string }) => {
      logged.push(ctx.dedupeKey ?? '');
    }
  );
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com'), domainRow(2, 'example.org')];
  const { store, baselines } = memoryStore(domains, clock);
  const ran: string[] = [];
  const ok =
    (name: CollectorName): Collector =>
    async (ctx) => {
      ran.push(`${ctx.domain.id}:${name}`);
      return { snapshot: { v: 1 }, findings: [], status: 'baseline', note: 'ok' };
    };
  const collectors: Record<CollectorName, Collector> = {
    dns: ok('dns'),
    rdap: async () => {
      throw new TypeError('cannot read properties of undefined');
    },
    lookalike: ok('lookalike'),
    ct: async () => {
      throw new CollectorError('crt.sh is temporarily unavailable (HTTP 502); will retry', true);
    },
  };

  const summary = await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual([summary.checked, summary.failed], [2, 2], 'both domains ran, both had errors');
  assert.deepEqual(ran, ['1:dns', '1:lookalike', '2:dns', '2:lookalike']);
  assert.deepEqual([...baselines.keys()].sort(), ['1:dns', '1:lookalike', '2:dns', '2:lookalike']);
  assert.equal(domains[0].last_status, 'error');
  assert.match(domains[0].last_error ?? '', /rdap: cannot read properties/);
  assert.match(domains[0].last_error ?? '', /ct: crt\.sh is temporarily unavailable/);
  // A bug is surfaced on the dashboard; a flaky upstream is not.
  assert.deepEqual(logged, ['collector-rdap', 'collector-rdap']);
  // Both failures bring the domain back early (an unexpected error may be a database blip).
  assert.equal(Date.parse(domains[0].next_run_at as string), clock.now + 60 * 60_000);
  assert.deepEqual((domains[0].last_summary as { retry: string[] }).retry, ['rdap', 'ct']);
});

test('isolation: a permanent collector failure waits for the next regular run', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com')];
  const { store } = memoryStore(domains, clock);
  const fine: Collector = async () => ({ snapshot: {}, findings: [], status: 'ok', note: '' });
  await runDomainChecks({
    store,
    collectors: {
      dns: fine,
      lookalike: fine,
      ct: fine,
      rdap: async () => {
        throw new CollectorError('the registry has no record of example.com', false);
      },
    },
    now: () => clock.now,
  });
  assert.equal(domains[0].last_status, 'error');
  assert.deepEqual((domains[0].last_summary as { retry: string[] }).retry, []);
  assert.equal(Date.parse(domains[0].next_run_at as string), clock.now + 1440 * 60_000);
});

test('retry: the early run repeats only the failed collectors, backing off', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com')];
  const { store } = memoryStore(domains, clock);
  const ran: string[] = [];
  let ctUp = false;
  const collectors: Record<CollectorName, Collector> = Object.fromEntries(
    (['dns', 'rdap', 'lookalike', 'ct'] as const).map((name) => [
      name,
      (async () => {
        ran.push(name);
        if (name === 'ct' && !ctUp) throw new CollectorError('crt.sh timed out; will retry', true);
        return { snapshot: { v: 1 }, findings: [], status: 'ok', note: `${name} fine` };
      }) as Collector,
    ])
  ) as Record<CollectorName, Collector>;

  const firstRun = clock.now;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(ran, ['dns', 'rdap', 'lookalike', 'ct']);

  ran.length = 0;
  clock.now += 61 * 60_000;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(ran, ['ct'], 'only the failed collector is retried');
  assert.equal((domains[0].last_summary as { retry_attempt: number }).retry_attempt, 2);
  assert.equal(
    Date.parse(domains[0].next_run_at as string),
    clock.now + 120 * 60_000,
    'backing off'
  );
  const carried = (domains[0].last_summary as { collectors: Record<string, { note?: string }> })
    .collectors;
  assert.equal(carried.dns.note, 'dns fine', 'the other collectors keep their last outcome');

  ran.length = 0;
  ctUp = true;
  clock.now += 121 * 60_000;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(ran, ['ct']);
  assert.equal(domains[0].last_status, 'ok');
  assert.equal(
    Date.parse(domains[0].next_run_at as string),
    firstRun + 1440 * 60_000,
    'back on its regular schedule: the last full run + the interval'
  );

  ran.length = 0;
  clock.now = firstRun + 1440 * 60_000;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(ran, ['dns', 'rdap', 'lookalike', 'ct'], 'the full run, on time');

  assert.equal(retryDelayMinutes(1440, 1), 60);
  assert.equal(retryDelayMinutes(1440, 3), 240);
  assert.equal(retryDelayMinutes(90, 5), 90, 'never later than the interval');
});

test('retry: a collector that keeps failing never holds back the others’ regular runs', async () => {
  for (const interval of [1440, 10_080]) {
    const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
    const start = clock.now;
    const domains = [domainRow(1, 'example.com', { interval_minutes: interval })];
    const { store } = memoryStore(domains, clock);
    const fullRuns: number[] = [];
    const collectors = Object.fromEntries(
      (['dns', 'rdap', 'lookalike', 'ct'] as const).map((name) => [
        name,
        (async () => {
          if (name === 'dns') fullRuns.push(clock.now);
          if (name === 'ct') throw new CollectorError('crt.sh timed out; will retry', true);
          return { snapshot: { v: 1 }, findings: [], status: 'ok', note: '' };
        }) as Collector,
      ])
    ) as Record<CollectorName, Collector>;

    // Three intervals of wall time, waking whenever the domain is due (like the job's tick).
    while (clock.now < start + 3 * interval * 60_000) {
      await runDomainChecks({ store, collectors, now: () => clock.now });
      clock.now = Math.max(clock.now + 60_000, Date.parse(domains[0].next_run_at as string));
    }
    assert.deepEqual(
      fullRuns.map((at) => (at - start) / 60_000),
      [0, interval, 2 * interval],
      `interval ${interval}: the other collectors still run every interval`
    );
    const summary = domains[0].last_summary as { full_run_at: string; retry: string[] };
    assert.deepEqual(summary.retry, ['ct']);
    assert.equal(Date.parse(summary.full_run_at), start + 2 * interval * 60_000);
  }
});

test('a failed collector’s progress (bookkeeping only) is stored, and it is still retried', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'brand.com', { scope: 'brand' })];
  const { store, baselines } = memoryStore(domains, clock);
  const fine: Collector = async () => ({
    snapshot: { v: 1 },
    findings: [],
    status: 'ok',
    note: '',
  });
  await runDomainChecks({
    store,
    collectors: {
      dns: fine,
      rdap: fine,
      lookalike: fine,
      ct: async () => {
        throw new CollectorError('crt.sh timed out; will retry', true, {
          progress: {
            v: 1,
            lookalike_failures: { 'exmple.com': { at: 1, count: 1, transient: true } },
          },
        });
      },
    },
    now: () => clock.now,
  });
  assert.deepEqual(baselines.get('1:ct')?.snapshot, {
    v: 1,
    lookalike_failures: { 'exmple.com': { at: 1, count: 1, transient: true } },
  });
  assert.deepEqual((domains[0].last_summary as { retry: string[] }).retry, ['ct']);
  assert.equal(domains[0].last_status, 'error');
});

test('end to end: a new lookalike’s certificates are still judged when CT fails that day', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com')];
  const { store, log } = memoryStore(domains, clock);
  const w = world();
  let crtshUp = true;
  const ct = createCtCollector({
    source: {
      certificatesFor: async (name) => {
        if (!crtshUp) {
          throw new CollectorError(
            'crt.sh is temporarily unavailable (HTTP 502); will retry',
            true
          );
        }
        return w.certs[name] ?? [];
      },
    },
  });
  const collectors = { ...w.collectors, ct };
  await runDomainChecks({ store, collectors, now: () => clock.now }); // baselines

  // Next day a lookalike goes up, with a certificate, and crt.sh is down.
  clock.now += 1440 * 60_000;
  w.zone['examp1e.com'] = { ns: ['ns1.bad-host.net'], a: ['203.0.113.66'] };
  w.certs['examp1e.com'] = [cert('p1', ['examp1e.com', 'login.examp1e.com'])];
  crtshUp = false;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(
    log.alerts.map((f) => f.eventType),
    ['lookalike_registered']
  );

  // The early retry re-runs CT alone; the hand-off comes from the stored lookalike baseline.
  crtshUp = true;
  clock.now = Date.parse(domains[0].next_run_at as string);
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(
    log.alerts.map((f) => [f.eventType, f.title]),
    [
      ['lookalike_registered', 'Lookalike domain registered: examp1e.com (looks like example.com)'],
      ['new_cert', 'Newly registered lookalike examp1e.com already has 1 TLS certificate'],
    ]
  );
});

test('end to end: crt.sh failing on a new lookalike (not on the domain) gets it judged on the next run', async () => {
  // Weekly checks, with four older lookalikes in CT's rotation (3 checks per run).
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [domainRow(1, 'example.com', { interval_minutes: 7 * 1440 })];
  const { store, log } = memoryStore(domains, clock);
  const w = world();
  for (const old of ['example.org', 'example.co', 'example.io']) {
    w.zone[old] = { ns: ['ns.someone-else.net'], a: ['198.51.100.1'] };
  }
  const failing = new Set<string>();
  const ct = createCtCollector({
    source: {
      certificatesFor: async (name) => {
        if (failing.has(name)) {
          throw new CollectorError('crt.sh did not answer in time; will retry', true);
        }
        return w.certs[name] ?? [];
      },
    },
  });
  const collectors = { ...w.collectors, ct };
  const nextRun = async () => {
    await runDomainChecks({ store, collectors, now: () => clock.now });
    clock.now = Date.parse(domains[0].next_run_at as string);
  };
  await nextRun(); // baselines
  await nextRun(); // a week later: the rotation is under way

  // examp1e.com goes up with a certificate; crt.sh answers for everything but it.
  w.zone['examp1e.com'] = { ns: ['ns1.bad-host.net'], a: ['203.0.113.66'] };
  w.certs['examp1e.com'] = [cert('p1', ['examp1e.com', 'login.examp1e.com'])];
  failing.add('examp1e.com');
  await nextRun();
  assert.deepEqual(
    log.alerts.map((f) => f.eventType),
    ['lookalike_registered']
  );
  assert.equal(domains[0].last_status, 'ok', 'CT itself succeeded: no early retry');

  failing.clear();
  await nextRun(); // the next weekly run checks it before the rotation
  assert.deepEqual(
    log.alerts.map((f) => [f.eventType, f.title]),
    [
      ['lookalike_registered', 'Lookalike domain registered: examp1e.com (looks like example.com)'],
      ['new_cert', 'Newly registered lookalike examp1e.com already has 1 TLS certificate'],
    ]
  );
});

test('end to end: a new lookalike crt.sh failed on that goes NXDOMAIN for a run is still judged as new', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const start = clock.now;
  const domains = [domainRow(1, 'example.com')];
  const { store, log } = memoryStore(domains, clock);
  const w = world();
  const failing = new Set<string>();
  const ct = createCtCollector({
    source: {
      certificatesFor: async (name) => {
        if (failing.has(name)) {
          throw new CollectorError('crt.sh did not answer in time; will retry', true);
        }
        return w.certs[name] ?? [];
      },
    },
  });
  const collectors = { ...w.collectors, ct };
  const runOnDay = async (day: number) => {
    clock.now = start + day * 86_400_000;
    await runDomainChecks({ store, collectors, now: () => clock.now });
  };
  await runOnDay(0); // baselines: exmple.com is confirmed unregistered

  // exmple.com goes up with a certificate, but crt.sh times out on it — for over
  // a month, so the lookalike collector no longer lists it as newly registered.
  const squatter = { ns: ['ns1.bad-host.net'], a: ['203.0.113.66'] };
  w.zone['exmple.com'] = squatter;
  w.certs['exmple.com'] = [cert('p1', ['exmple.com'])];
  failing.add('exmple.com');
  await runOnDay(10);
  await runOnDay(45);
  // One NXDOMAIN answer (a registrar hold), and then it is back: the same registration.
  failing.clear();
  delete w.zone['exmple.com'];
  await runOnDay(46);
  w.zone['exmple.com'] = squatter;
  await runOnDay(47);
  assert.deepEqual(
    log.alerts.map((f) => [f.eventType, f.title]),
    [
      ['lookalike_registered', 'Lookalike domain registered: exmple.com (looks like example.com)'],
      ['new_cert', 'Newly registered lookalike exmple.com already has 1 TLS certificate'],
    ]
  );
});

test('end to end: a lookalike registered again after the grace (a possible new owner) gets its own certificate alerts, also when CT last saw it on hold', async () => {
  // Fortnightly checks. Owner A's exmple.com lapses: NXDOMAIN on two runs, both
  // within 30 days of when it was last seen registered (on hold, for all anyone
  // can tell), so CT keeps what it knows about it. The next run finds it
  // registered again, past that grace: owner B, a drop-catcher, whose
  // certificate for the same names from the same CA is not a renewal of A's.
  type World = ReturnType<typeof world>;
  const run = async (script: Record<number, (w: World) => void>) => {
    const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
    const start = clock.now;
    const domains = [domainRow(1, 'example.com', { interval_minutes: 14 * 1440 })];
    const { store, log } = memoryStore(domains, clock);
    const w = world();
    for (const [day, change] of Object.entries(script)) {
      change(w);
      clock.now = start + Number(day) * 86_400_000;
      await runDomainChecks({ store, collectors: w.collectors, now: () => clock.now });
      assert.equal(domains[0].last_status, 'ok', `day ${day}`);
    }
    return log.alerts.map((f) => [f.eventType, f.severity, f.title]);
  };
  const names = ['exmple.com', 'www.exmple.com'];
  const same = () => undefined;
  const ownerA = (w: World) => {
    w.zone['exmple.com'] = { ns: ['ns1.owner-a.example'], a: ['203.0.113.66'] };
    w.certs['exmple.com'] = [cert('a1', names)];
  };
  const lapse = (w: World) => {
    delete w.zone['exmple.com'];
    w.certs['exmple.com'] = []; // A's certificate has expired by now
  };
  const ownerB = (w: World) => {
    w.zone['exmple.com'] = { ns: ['ns1.owner-b.example'], a: ['198.51.100.7'] };
    w.certs['exmple.com'] = [cert('b1', names)];
  };
  const registered = (severity: string) => [
    'lookalike_registered',
    severity,
    'Lookalike domain registered: exmple.com (looks like example.com)',
  ];
  const goingUp = [
    'new_cert',
    'medium',
    'Newly registered lookalike exmple.com already has 1 TLS certificate',
  ];

  // B's site is up, with its certificate, when the registration is found.
  assert.deepEqual(await run({ 0: same, 14: ownerA, 28: same, 42: lapse, 56: same, 70: ownerB }), [
    registered('high'),
    goingUp,
    registered('high'),
    goingUp,
  ]);
  // B parks the name first (no address yet) and gets its certificate a run later.
  const parked = (w: World) => {
    w.zone['exmple.com'] = { ns: ['ns1.owner-b.example'] };
  };
  assert.deepEqual(
    await run({ 0: same, 14: ownerA, 28: same, 42: lapse, 56: same, 70: parked, 84: ownerB }),
    [
      registered('high'),
      goingUp,
      registered('medium'),
      ['new_cert', 'medium', "TLS certificate issued for lookalike exmple.com (Let's Encrypt)"],
    ]
  );
  // A's DNS failed for a run before the lapse, so A stayed registered and CT
  // checked it after A was last seen registered.
  const failing = (w: World) => {
    w.zone['exmple.com'].servfail = true;
  };
  assert.deepEqual(await run({ 0: same, 14: ownerA, 28: failing, 42: lapse, 56: ownerB }), [
    registered('high'),
    goingUp,
    registered('high'),
    goingUp,
  ]);
});

test('the job fails a cycle only when nothing worked for any domain', async (t) => {
  t.mock.method(ErrorLogService, 'logBackgroundError', () => undefined);
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const fine: Collector = async () => ({
    snapshot: { v: 1 },
    findings: [],
    status: 'ok',
    note: '',
  });
  const down: Collector = async () => {
    throw new CollectorError('crt.sh is temporarily unavailable (HTTP 502); will retry', true);
  };
  const ctDown = { dns: fine, rdap: fine, lookalike: fine, ct: down };
  const allDown = { dns: down, rdap: down, lookalike: down, ct: down };
  const run = (store: DomainMonitorStore, collectors: Record<CollectorName, Collector>) =>
    runDomainChecks({ store, collectors, now: () => clock.now });
  const crashing = (store: DomainMonitorStore, ids: number[]): DomainMonitorStore => ({
    ...store,
    getBaselines: async (id) => {
      if (ids.includes(id)) throw new Error('Connection terminated unexpectedly');
      return store.getBaselines(id);
    },
  });

  // One domain (the common install) with crt.sh down: not a failed job — neither
  // the full run nor the early retry that re-runs CT alone.
  const single = [domainRow(1, 'example.com')];
  const singleStore = memoryStore(single, clock).store;
  const full = await run(singleStore, ctDown);
  assert.deepEqual([full.checked, full.failed, full.down], [1, 1, 0]);
  assert.equal(domainMonitorCycleFailure(full), null);
  clock.now = Date.parse(single[0].next_run_at as string);
  const retry = await run(singleStore, ctDown);
  assert.deepEqual((single[0].last_summary as { retry: string[] }).retry, ['ct']);
  assert.deepEqual([retry.checked, retry.failed, retry.down], [1, 1, 0]);
  assert.equal(domainMonitorCycleFailure(retry), null);

  // One domain whose run could not complete does not make the others' look failed.
  const mixed = crashing(
    memoryStore([domainRow(1, 'ok.com'), domainRow(2, 'threw.com')], clock).store,
    [2]
  );
  const partial = await run(mixed, { dns: fine, rdap: fine, lookalike: fine, ct: fine });
  assert.deepEqual([partial.checked, partial.failed, partial.crashed], [1, 0, 1]);
  assert.equal(domainMonitorCycleFailure(partial), null);
  assert.equal(
    describeDomainMonitorRun(partial),
    'checked 1 domain, 0 new findings, 1 could not be checked, 1 still due'
  );

  // Nothing working anywhere (no network or DNS) fails the cycle; so does no run completing.
  const everything = memoryStore(
    [domainRow(1, 'example.com'), domainRow(2, 'brand.com', { scope: 'brand' })],
    clock
  ).store;
  const nothing = await run(everything, allDown);
  assert.deepEqual([nothing.checked, nothing.failed, nothing.down], [2, 2, 2]);
  assert.match(domainMonitorCycleFailure(nothing) ?? '', /nothing worked for any domain/);
  // "unsupported" needs no network (RDAP's bootstrap file is cached for days), so
  // a domain under a TLD without RDAP doesn't hide the outage.
  const unsupported: Collector = async () => ({
    findings: [],
    status: 'unsupported',
    note: 'no RDAP service is published for .kg',
  });
  const noRdap = memoryStore(
    [domainRow(1, 'example.kg'), domainRow(2, 'example.com')],
    clock
  ).store;
  const offline = await run(noRdap, { ...allDown, rdap: unsupported });
  assert.deepEqual([offline.checked, offline.failed, offline.down], [2, 2, 2]);
  assert.match(domainMonitorCycleFailure(offline) ?? '', /nothing worked for any domain/);
  const dead = crashing(memoryStore([domainRow(1, 'example.com')], clock).store, [1]);
  const crashed = await run(dead, ctDown);
  assert.deepEqual([crashed.checked, crashed.crashed], [0, 1]);
  assert.notEqual(domainMonitorCycleFailure(crashed), null);
  assert.equal(domainMonitorCycleFailure({ ...crashed, skipped: true, reason: 'x' }), null);
});

test('scope and switches: brand domains run lookalike + ct; switched-off collectors never run', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const domains = [
    domainRow(1, 'brand.com', { scope: 'brand' }),
    domainRow(2, 'own.com', { collectors: { ct: false, lookalike: true, rdap: false, dns: true } }),
  ];
  const { store } = memoryStore(domains, clock);
  const ran: string[] = [];
  const collectors = Object.fromEntries(
    (['dns', 'rdap', 'lookalike', 'ct'] as const).map((name) => [
      name,
      (async (ctx) => {
        ran.push(`${ctx.domain.domain}:${name}`);
        return { snapshot: {}, findings: [], status: 'ok', note: '' };
      }) as Collector,
    ])
  ) as Record<CollectorName, Collector>;
  await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual(ran, [
    'brand.com:lookalike',
    'brand.com:ct',
    'own.com:dns',
    'own.com:lookalike',
  ]);
  const statuses = (d: WatchedDomain) =>
    Object.fromEntries(
      Object.entries(
        (d.last_summary as { collectors: Record<string, { status: string }> }).collectors
      ).map(([k, v]) => [k, v.status])
    );
  assert.deepEqual(statuses(domains[0]), {
    dns: 'not_applicable',
    rdap: 'not_applicable',
    lookalike: 'ok',
    ct: 'ok',
  });
  assert.deepEqual(statuses(domains[1]), {
    dns: 'ok',
    rdap: 'disabled',
    lookalike: 'ok',
    ct: 'disabled',
  });
});

test('skips with a reason; overlapping runs do not overlap', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const off = memoryStore([domainRow(1, 'example.com')], clock, { enabled: false });
  assert.equal(await getDomainMonitorSkipReason({ store: off.store }), DOMAIN_MONITOR_DISABLED);
  const cycle = await runDomainChecks({ store: off.store });
  assert.deepEqual([cycle.skipped, cycle.reason], [true, DOMAIN_MONITOR_DISABLED]);
  assert.equal(describeDomainMonitorRun(cycle), `skipped: ${DOMAIN_MONITOR_DISABLED}`);
  assert.deepEqual(await runDomainNow(1, { store: off.store }), {
    kind: 'disabled',
    reason: DOMAIN_MONITOR_DISABLED,
  });

  const { store } = memoryStore([domainRow(1, 'example.com')], clock);
  assert.deepEqual(await runDomainNow(99, { store }), { kind: 'not_found' });

  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const slow: Collector = async () => {
    await gate;
    return { snapshot: {}, findings: [], status: 'ok', note: '' };
  };
  const collectors = { dns: slow, rdap: slow, lookalike: slow, ct: slow };
  const firstCycle = runDomainChecks({ store, collectors, now: () => clock.now });
  await new Promise((resolve) => setImmediate(resolve));
  const overlap = await runDomainChecks({ store, collectors, now: () => clock.now });
  assert.deepEqual([overlap.skipped, overlap.reason], [true, DOMAIN_MONITOR_ALREADY_RUNNING]);
  assert.deepEqual(
    await runDomainNow(1, { store, collectors }),
    { kind: 'busy' },
    'the cycle holds this domain'
  );
  release();
  assert.equal((await firstCycle).checked, 1);
});

test('run now: every applicable collector runs whatever the schedule, and the result is returned', async () => {
  const clock = { now: Date.parse('2026-10-11T00:00:00Z') };
  const future = new Date(clock.now + 86_400_000).toISOString();
  const domains = [
    domainRow(1, 'example.com', {
      enabled: false,
      next_run_at: future,
      last_checked_at: new Date(clock.now).toISOString(),
    }),
  ];
  const { store } = memoryStore(domains, clock);
  const w = world();
  const result = await runDomainNow(1, { store, collectors: w.collectors, now: () => clock.now });
  assert.equal(result.kind, 'ok');
  if (result.kind !== 'ok') return;
  assert.equal(result.summary.trigger, 'manual');
  assert.equal(result.summary.status, 'ok');
  assert.deepEqual(Object.keys(result.summary.collectors).sort(), [
    'ct',
    'dns',
    'lookalike',
    'rdap',
  ]);
  assert.equal(result.summary.collectors.lookalike?.status, 'baseline');
  const registered = new Set(
    result.summary.collectors.lookalike?.details?.registered_lookalikes as string[]
  );
  assert.ok(registered.has('example.net'));
});
