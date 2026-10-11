/**
 * DNS drift without a network: record normalisation, what counts as an empty
 * answer versus a failure, the failure sentinel (never "unchanged", never
 * "removed"), severities and SPF/DKIM/DMARC call-outs, CDN-style address
 * rotation, and the optional second resolver. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DNS_DRIFT_SEVERITY,
  classifyTxt,
  combineRecordSets,
  createDnsCollector,
  diffDns,
  dmarcPolicy,
  lookupRecordSet,
  parseDnsSnapshot,
  type DnsRecordType,
  type RecordSet,
} from './dns';
import type { DnsResolverLike } from './resolver';
import { CollectorError, type CollectorContext } from './types';

type Answer = unknown[] | { code: string };
type Zone = Record<string, Partial<Record<'a' | 'aaaa' | 'mx' | 'ns' | 'txt', Answer>>>;

/** Names missing from the zone are NXDOMAIN; types missing from a name are NODATA. */
function zoneResolver(zone: Zone): DnsResolverLike {
  const answer = async <T>(type: 'a' | 'aaaa' | 'mx' | 'ns' | 'txt', name: string): Promise<T> => {
    const entry = Object.prototype.hasOwnProperty.call(zone, name) ? zone[name] : undefined;
    const fail = (code: string) => Object.assign(new Error(code), { code });
    if (!entry) throw fail('ENOTFOUND');
    const value = entry[type];
    if (value === undefined) throw fail('ENODATA');
    if (!Array.isArray(value)) throw fail(value.code);
    return value as T;
  };
  return {
    resolve4: (n) => answer('a', n),
    resolve6: (n) => answer('aaaa', n),
    resolveMx: (n) => answer('mx', n),
    resolveNs: (n) => answer('ns', n),
    resolveTxt: (n) => answer('txt', n),
  };
}

const ZONE: Zone = {
  'example.com': {
    a: ['93.184.215.14', '93.184.215.13'],
    aaaa: ['2606:2800:21F:CB07:6820:80DA:AF6B:8B2C'],
    mx: [
      { priority: 20, exchange: 'MX2.Example.com.' },
      { priority: 10, exchange: 'mx1.example.com' },
    ],
    ns: ['B.IANA-SERVERS.NET.', 'a.iana-servers.net'],
    txt: [['v=spf1 include:_spf.example.net ', '-all'], ['google-site-verification=abc']],
  },
  '_dmarc.example.com': { txt: [['v=DMARC1; p=reject; rua=mailto:d@example.com']] },
  'www.example.com': { a: ['93.184.215.14'] },
};

// ---- lookups ------------------------------------------------------------------------------

test('lookup: values are normalised and sorted; TXT chunks are joined', async () => {
  const r = zoneResolver(ZONE);
  const get = (type: DnsRecordType) => lookupRecordSet(r, 'example.com', type, { apex: true });
  assert.deepEqual(await get('A'), { ok: true, values: ['93.184.215.13', '93.184.215.14'] });
  assert.deepEqual(await get('AAAA'), {
    ok: true,
    values: ['2606:2800:21f:cb07:6820:80da:af6b:8b2c'],
  });
  assert.deepEqual(await get('MX'), {
    ok: true,
    values: ['10 mx1.example.com', '20 mx2.example.com'],
  });
  assert.deepEqual(await get('NS'), {
    ok: true,
    values: ['a.iana-servers.net', 'b.iana-servers.net'],
  });
  assert.deepEqual(await get('TXT'), {
    ok: true,
    values: ['google-site-verification=abc', 'v=spf1 include:_spf.example.net -all'],
  });
  assert.deepEqual(await get('DMARC'), {
    ok: true,
    values: ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
  });
});

test('lookup: NODATA is empty, failures are sentinels, and the special cases hold', async () => {
  const r = zoneResolver({
    ...ZONE,
    'broken.com': { a: { code: 'ESERVFAIL' }, ns: { code: 'ETIMEOUT' } },
  });
  // A subdomain normally has no NS or MX of its own: empty, not failed.
  assert.deepEqual(await lookupRecordSet(r, 'www.example.com', 'NS', { apex: false }), {
    ok: true,
    values: [],
  });
  assert.deepEqual(await lookupRecordSet(r, 'www.example.com', 'MX', { apex: false }), {
    ok: true,
    values: [],
  });
  // No _dmarc name at all simply means no DMARC record.
  assert.deepEqual(await lookupRecordSet(r, 'www.example.com', 'DMARC', { apex: false }), {
    ok: true,
    values: [],
  });
  // A delegated domain always has NS records: NODATA there is the resolver's fault.
  const noNs = await lookupRecordSet(
    zoneResolver({ 'hidden.com': { a: ['192.0.2.1'] } }),
    'hidden.com',
    'NS',
    {
      apex: true,
    }
  );
  assert.equal(noNs.ok, false);
  // The watched name not existing, or the resolver failing, is never an empty answer.
  assert.equal((await lookupRecordSet(r, 'gone.com', 'A', { apex: true })).ok, false);
  assert.deepEqual(await lookupRecordSet(r, 'broken.com', 'A', { apex: true }), {
    ok: false,
    error: 'ESERVFAIL',
  });
  assert.deepEqual(await lookupRecordSet(r, 'broken.com', 'NS', { apex: true }), {
    ok: false,
    error: 'ETIMEOUT',
  });
});

// ---- diff -----------------------------------------------------------------------------------

const okSet = (...values: string[]): RecordSet => ({ ok: true, values: [...values].sort() });
const failed: RecordSet = { ok: false, error: 'ETIMEOUT' };
const NOW = 1_800_000_000;

test('diff: the first answer for a type is the baseline; later changes carry the right severity', () => {
  const first = diffDns(
    null,
    { NS: okSet('a.ns.example.net'), MX: okSet('10 mx.example.com'), A: okSet('192.0.2.1') },
    NOW
  );
  assert.deepEqual(first.changes, [], 'first run: silent');
  const second = diffDns(
    first.next,
    {
      NS: okSet('ns1.attacker.example'),
      MX: okSet('10 mx.attacker.example'),
      TXT: okSet('v=spf1 -all'), // first good answer for TXT: baseline
      A: okSet('198.51.100.66'),
    },
    NOW + 60
  );
  assert.deepEqual(
    second.changes.map((c) => [c.type, c.severity, c.added, c.removed]),
    [
      ['NS', 'critical', ['ns1.attacker.example'], ['a.ns.example.net']],
      ['MX', 'critical', ['10 mx.attacker.example'], ['10 mx.example.com']],
      ['A', 'medium', ['198.51.100.66'], ['192.0.2.1']],
    ]
  );
  assert.deepEqual(DNS_DRIFT_SEVERITY, {
    NS: 'critical',
    MX: 'critical',
    TXT: 'high',
    DMARC: 'high',
    A: 'medium',
    AAAA: 'medium',
  });
});

test('diff: a failed lookup is neither "unchanged" nor "removed", and keeps the last good value', () => {
  const base = diffDns(
    null,
    { NS: okSet('a.ns.example.net'), MX: okSet('10 mx.example.com') },
    NOW
  ).next;

  const duringOutage = diffDns(base, { NS: failed, MX: failed }, NOW + 60);
  assert.deepEqual(duringOutage.changes, [], 'no "all records removed" alert');
  assert.deepEqual(duringOutage.next.records, base.records, 'the baseline is not overwritten');

  // After the outage the comparison is against the value from BEFORE it.
  const after = diffDns(
    duringOutage.next,
    { NS: okSet('ns1.attacker.example'), MX: okSet('10 mx.example.com') },
    NOW + 120
  );
  assert.deepEqual(
    after.changes.map((c) => c.type),
    ['NS']
  );
  assert.deepEqual(after.changes[0].before, ['a.ns.example.net']);
});

test('diff: addresses rotating within a recently seen pool are quiet; a new address is drift', () => {
  let snap = diffDns(null, { A: okSet('192.0.2.1', '192.0.2.2') }, NOW).next;
  snap = diffDns(snap, { A: okSet('192.0.2.3', '192.0.2.4') }, NOW + 60).next; // drift (alerted), now known
  const rotate = diffDns(snap, { A: okSet('192.0.2.1', '192.0.2.4') }, NOW + 120);
  assert.deepEqual(rotate.changes, [], 'all addresses seen within 90 days');
  const fresh = diffDns(rotate.next, { A: okSet('203.0.113.50') }, NOW + 180);
  assert.deepEqual(
    fresh.changes.map((c) => [c.type, c.added]),
    [['A', ['203.0.113.50']]]
  );
  const vanished = diffDns(fresh.next, { A: okSet() }, NOW + 240);
  assert.deepEqual(
    vanished.changes.map((c) => [c.type, c.after]),
    [['A', []]],
    'all addresses gone'
  );
  // Long-unseen addresses age out of the pool.
  const later = diffDns(vanished.next, { A: okSet('192.0.2.1') }, NOW + 100 * 86_400);
  assert.equal(later.changes.length, 1);
});

test('TXT: SPF, DKIM and DMARC are called out', async () => {
  assert.equal(classifyTxt('v=spf1 include:_spf.google.com ~all'), 'spf');
  assert.equal(classifyTxt('v=DMARC1; p=none'), 'dmarc');
  assert.equal(classifyTxt('v=DKIM1; k=rsa; p=MIIBIjAN'), 'dkim');
  assert.equal(classifyTxt('google-site-verification=xyz'), 'verification');
  assert.equal(classifyTxt('hello world'), 'other');
  assert.equal(dmarcPolicy(['v=DMARC1; p=quarantine; pct=100']), 'quarantine');
  assert.equal(dmarcPolicy(['not dmarc; p=reject']), null);

  const zone: Zone = JSON.parse(JSON.stringify(ZONE));
  const collector = createDnsCollector({ resolver: zoneResolver(zone), secondary: null });
  const first = await collector(ctx(null));
  zone['example.com'].txt = [
    ['v=spf1 include:_spf.example.net include:evil.example ~all'],
    ['google-site-verification=abc'],
  ];
  zone['_dmarc.example.com'].txt = [['v=DMARC1; p=none']];
  const second = await collector(ctx(first.snapshot));
  assert.deepEqual(
    second.findings.map((f) => [f.eventType, f.severity, f.title]),
    [
      ['dns_drift', 'high', 'SPF record changed for example.com'],
      ['dns_drift', 'high', 'DMARC policy changed for example.com: reject -> none'],
    ]
  );
  assert.deepEqual(second.findings[0].detail.txt_kinds, ['spf']);
});

// ---- second resolver -----------------------------------------------------------------------------

test('second resolver: agreement is required; one failing falls back to the other', () => {
  const a = okSet('192.0.2.1');
  assert.deepEqual(combineRecordSets(a, null), a);
  assert.deepEqual(combineRecordSets(a, okSet('192.0.2.1')), a);
  assert.deepEqual(combineRecordSets(a, okSet('203.0.113.9')), {
    ok: false,
    error: 'the two resolvers disagree',
  });
  assert.deepEqual(combineRecordSets(a, failed), a);
  assert.deepEqual(combineRecordSets(failed, a), a);
  assert.deepEqual(combineRecordSets(failed, failed), failed);
});

// ---- collector -------------------------------------------------------------------------------------

function ctx(previous: unknown, domain = 'example.com'): CollectorContext {
  return {
    domain: {
      id: 5,
      domain,
      scope: 'own',
      expected_cas: [],
      collectors: { ct: true, lookalike: true, rdap: true, dns: true },
    },
    previous,
    config: {
      expiryWarningDays: 30,
      lookalikeMaxCandidates: 300,
      secondaryResolver: null,
      lookalikeCtChecksPerRun: 3,
    },
    now: new Date(NOW * 1000),
    trigger: 'schedule',
    earlier: {},
    baselines: {},
  };
}

test('collector: the first run is a silent baseline; the same zone again changes nothing', async () => {
  const collector = createDnsCollector({ resolver: zoneResolver(ZONE), secondary: null });
  const first = await collector(ctx(null));
  assert.equal(first.status, 'baseline');
  assert.deepEqual(first.findings, []);
  assert.deepEqual(first.details?.records, { NS: 2, MX: 2, TXT: 2, DMARC: 1, A: 2, AAAA: 1 });
  const second = await collector(ctx(first.snapshot));
  assert.equal(second.status, 'ok');
  assert.deepEqual(second.findings, []);
  assert.deepEqual(
    parseDnsSnapshot(second.snapshot)?.records,
    parseDnsSnapshot(first.snapshot)?.records
  );
});

test('collector: every lookup failing is a transient error; some failing is a warning', async () => {
  const dead: DnsResolverLike = {
    resolve4: async () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
    resolve6: async () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
    resolveMx: async () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
    resolveNs: async () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
    resolveTxt: async () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
  };
  await assert.rejects(
    createDnsCollector({ resolver: dead, secondary: null })(ctx(null)),
    (err: unknown) => err instanceof CollectorError && err.transient
  );

  const base = await createDnsCollector({ resolver: zoneResolver(ZONE), secondary: null })(
    ctx(null)
  );
  const partial = { ...ZONE, 'example.com': { ...ZONE['example.com'], ns: { code: 'ETIMEOUT' } } };
  const out = await createDnsCollector({ resolver: zoneResolver(partial), secondary: null })(
    ctx(base.snapshot)
  );
  assert.deepEqual(out.findings, []);
  assert.deepEqual(out.warnings, ['NS: ETIMEOUT']);
  assert.deepEqual(parseDnsSnapshot(out.snapshot)?.records.NS, [
    'a.iana-servers.net',
    'b.iana-servers.net',
  ]);
});

test('collector: with a second resolver, a disagreement is not reported as drift', async () => {
  const first = await createDnsCollector({
    resolver: zoneResolver(ZONE),
    secondary: zoneResolver(ZONE),
  })(ctx(null));
  const poisoned = {
    ...ZONE,
    'example.com': { ...ZONE['example.com'], ns: ['ns1.attacker.example'] },
  };
  const out = await createDnsCollector({
    resolver: zoneResolver(poisoned),
    secondary: zoneResolver(ZONE),
  })(ctx(first.snapshot));
  assert.deepEqual(out.findings, [], 'one resolver alone is not believed');
  assert.match((out.warnings ?? []).join(' '), /NS: the two resolvers disagree/);
});
