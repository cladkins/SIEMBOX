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

type Zone = Record<string, { a?: string[]; ns?: string[]; mx?: string[]; txt?: string[] }>;

function zoneResolver(zone: Zone): DnsResolverLike {
  const fail = (code: string) => Object.assign(new Error(code), { code });
  const get = (name: string, type: 'a' | 'ns' | 'mx' | 'txt') => {
    const entry = zone[name];
    if (!entry) throw fail('ENOTFOUND');
    const value = entry[type];
    if (!value) throw fail('ENODATA');
    return value;
  };
  return {
    resolve4: async (n) => get(n, 'a'),
    resolve6: async (n) => {
      if (!zone[n]) throw fail('ENOTFOUND');
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
    clock.now + 1440 * 60_000,
    'back on its interval'
  );

  assert.equal(retryDelayMinutes(1440, 1), 60);
  assert.equal(retryDelayMinutes(1440, 3), 240);
  assert.equal(retryDelayMinutes(90, 5), 90, 'never later than the interval');
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
