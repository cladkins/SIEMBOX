/**
 * The lookalike engine without a network: the permutation generator
 * (determinism, the hard cap, the domain itself excluded, known permutations
 * from every fuzzer), the DNS registration check against a scripted resolver
 * (NXDOMAIN, delegations, failures, concurrency, per-query timeouts, wildcard
 * suffixes), and the collector's baseline/diff behaviour.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  FUZZER_ORDER,
  MAX_CANDIDATES_CEILING,
  NEW_REGISTRATION_WINDOW_DAYS,
  checkRegistration,
  checkRegistrations,
  createLookalikeCollector,
  diffLookalikes,
  findOnPath,
  generateLookalikes,
  lookalikeStateFromSnapshot,
  ownDomainNames,
  parseLookalikeSnapshot,
  registeredFromSnapshot,
  type LookalikeCandidate,
  type LookalikeSnapshot,
  type RegisteredInfo,
} from './lookalike';
import { isValidHostname } from './names';
import type { DnsResolverLike } from './resolver';
import type { CollectorContext, DomainMonitorConfig } from './types';

// ---- generator -----------------------------------------------------------------------

test('generator: deterministic, de-duplicated, and never the domain itself', () => {
  const a = generateLookalikes('example.com');
  const b = generateLookalikes('example.com');
  assert.deepEqual(a, b, 'same input, same list, same order');
  const names = a.map((c) => c.domain);
  const nameSet = new Set(names);
  assert.equal(nameSet.size, names.length, 'no duplicates');
  assert.ok(!nameSet.has('example.com'));
  assert.ok(names.every(isValidHostname), 'every candidate is a valid host name');
  // Fuzzers appear in priority order (most likely first).
  const firstIndex = FUZZER_ORDER.map((f) => a.findIndex((c) => c.fuzzer === f)).filter(
    (i) => i >= 0
  );
  assert.deepEqual(
    firstIndex,
    [...firstIndex].sort((x, y) => x - y)
  );
});

test('generator: known permutations from every fuzzer are present', () => {
  const names = new Set(generateLookalikes('example.com', { max: 1000 }).map((c) => c.domain));
  const expected: Record<string, string> = {
    omission: 'exmple.com',
    repetition: 'exxample.com',
    transposition: 'examlpe.com',
    'adjacent key': 'wxample.com',
    'homoglyph rn/m': 'exarnple.com',
    'homoglyph 1/l': 'examp1e.com',
    'homoglyph i/l': 'exampie.com',
    hyphenation: 'ex-ample.com',
    'vowel swap': 'exampla.com',
    bitsquat: 'dxample.com', // 'e' (0x65) with bit 0 flipped is 'd'
    addition: 'examplea.com',
    'tld swap': 'example.net',
  };
  for (const [kind, name] of Object.entries(expected))
    assert.ok(names.has(name), `${kind}: ${name}`);

  const google = new Set(generateLookalikes('google.com').map((c) => c.domain));
  assert.ok(
    google.has('g0ogle.com') && google.has('g00gle.com'),
    'o -> 0, one and all occurrences'
  );
  assert.ok(
    new Set(generateLookalikes('wiki.com').map((c) => c.domain)).has('vviki.com'),
    'w -> vv'
  );
  assert.ok(
    new Set(generateLookalikes('modern.com').map((c) => c.domain)).has('modem.com'),
    'rn -> m'
  );
  assert.ok(
    new Set(generateLookalikes('my-company.io').map((c) => c.domain)).has('mycompany.io'),
    'dropping the hyphen'
  );
});

test('generator: the cap is a hard limit, applied after the most likely candidates', () => {
  const ten = generateLookalikes('example.com', { max: 10 });
  assert.equal(ten.length, 10);
  assert.deepEqual(
    ten.map((c) => c.domain),
    generateLookalikes('example.com')
      .slice(0, 10)
      .map((c) => c.domain),
    'a smaller cap is a prefix of the full list'
  );
  assert.equal(ten[0].fuzzer, 'homoglyph');
  assert.equal(generateLookalikes('example.com', { max: 0 }).length, 0);

  // However much dnstwist adds, the ceiling holds.
  const extra = Array.from({ length: 2500 }, (_v, i) => `extra${i}-example.com`);
  const capped = generateLookalikes('example.com', { max: 999_999, extra });
  assert.equal(capped.length, MAX_CANDIDATES_CEILING);
  assert.ok(capped.findIndex((c) => c.fuzzer === 'dnstwist') > 100, 'native candidates come first');
});

test('generator: excluded names (the org’s other domains) are skipped before the cap', () => {
  const all = generateLookalikes('example.com', { max: 5 }).map((c) => c.domain);
  const excluded = generateLookalikes('example.com', {
    max: 5,
    exclude: [all[0], 'example.net'],
  }).map((c) => c.domain);
  assert.equal(excluded.length, 5, 'the cap still yields a full list');
  const left = new Set(excluded);
  assert.ok(!left.has(all[0]) && !left.has('example.net'));
});

test('generator: registrable part, multi-label suffixes and punycode', () => {
  const uk = generateLookalikes('mail.example.co.uk').map((c) => c.domain);
  const ukSet = new Set(uk);
  assert.ok(ukSet.has('exmple.co.uk'), 'permutes the registrable label, not "mail"');
  assert.ok(ukSet.has('example.uk') && ukSet.has('example.com'), 'suffix swaps');
  assert.ok(!uk.some((n) => n.startsWith('mail.')));

  const idn = generateLookalikes('xn--bcher-kva.de');
  assert.ok(
    idn.length > 0 && idn.every((c) => c.fuzzer === 'tld-swap'),
    'punycode is not permuted'
  );
});

// ---- registration check ---------------------------------------------------------------

type Answer = string[] | { code: string } | 'hang';
interface Entry {
  ns?: Answer;
  a?: Answer;
  aaaa?: Answer;
  mx?: Answer;
}

/** A scripted resolver: unknown names are NXDOMAIN; known names lack unlisted types (NODATA). */
function fakeResolver(table: Record<string, Entry>, options: { delayMs?: number } = {}) {
  const queries: Array<{ type: string; name: string }> = [];
  let inFlight = new Map<string, number>();
  let maxNamesInFlight = 0;
  const answer = async (type: keyof Entry, name: string): Promise<string[]> => {
    queries.push({ type, name });
    inFlight.set(name, (inFlight.get(name) ?? 0) + 1);
    maxNamesInFlight = Math.max(maxNamesInFlight, inFlight.size);
    try {
      if (options.delayMs) await new Promise((r) => setTimeout(r, options.delayMs));
      const entry = Object.entries(table).find(([key]) => key === name)?.[1];
      const value = entry?.[type];
      if (value === 'hang') return await new Promise<string[]>(() => undefined);
      const fail = (code: string) => Object.assign(new Error(code), { code });
      if (!entry) throw fail('ENOTFOUND');
      if (value === undefined) throw fail('ENODATA');
      if (!Array.isArray(value)) throw fail(value.code);
      return value;
    } finally {
      const left = (inFlight.get(name) ?? 1) - 1;
      if (left === 0) inFlight.delete(name);
      else inFlight.set(name, left);
    }
  };
  const resolver: DnsResolverLike = {
    resolveNs: (n) => answer('ns', n),
    resolve4: (n) => answer('a', n),
    resolve6: (n) => answer('aaaa', n),
    resolveMx: async (n) =>
      (await answer('mx', n)).map((exchange, i) => ({ priority: 10 * (i + 1), exchange })),
    resolveTxt: async () => [],
  };
  return {
    resolver,
    queries,
    maxNamesInFlight: () => maxNamesInFlight,
    reset: () => {
      queries.length = 0;
      inFlight = new Map();
    },
  };
}

test('registration: NXDOMAIN is unregistered after one query; a delegation is registered', async () => {
  const fake = fakeResolver({
    'parked.com': { ns: ['ns1.parking.example'] },
    'phish.com': { ns: ['ns1.host.example'], a: ['203.0.113.7'], mx: ['mx.phish.com'] },
    'nullmx.com': { ns: ['ns1.host.example'], mx: [''] },
  });
  assert.deepEqual(await checkRegistration('free.com', fake.resolver), { state: 'unregistered' });
  assert.deepEqual(fake.queries, [{ type: 'ns', name: 'free.com' }], 'one query for a free name');

  assert.deepEqual(await checkRegistration('parked.com', fake.resolver), {
    state: 'registered',
    ns: true,
    addr: false,
    mx: false,
  });
  assert.deepEqual(await checkRegistration('phish.com', fake.resolver), {
    state: 'registered',
    ns: true,
    addr: true,
    mx: true,
  });
  const nullMx = await checkRegistration('nullmx.com', fake.resolver);
  assert.equal(nullMx.state === 'registered' && nullMx.mx, false, 'a null MX accepts no mail');
});

test('registration: resolvers that hide NS still work; failures are unknown, never a guess', async () => {
  const fake = fakeResolver({
    // NODATA for NS (as some filtering resolvers answer) but an address.
    'a-only.com': { a: ['198.51.100.1'] },
    // The name exists but publishes nothing yet.
    'empty.com': {},
    'broken.com': { ns: { code: 'ESERVFAIL' }, a: { code: 'ETIMEOUT' } },
    // NS NODATA, but A says the name does not exist: NXDOMAIN wins.
    'conflict.com': { a: { code: 'ENOTFOUND' } },
  });
  assert.deepEqual(await checkRegistration('a-only.com', fake.resolver), {
    state: 'registered',
    ns: false,
    addr: true,
    mx: false,
  });
  assert.equal((await checkRegistration('empty.com', fake.resolver)).state, 'registered');
  const broken = await checkRegistration('broken.com', fake.resolver);
  assert.equal(broken.state, 'unknown');
  assert.equal((await checkRegistration('conflict.com', fake.resolver)).state, 'unregistered');
});

test('registration: concurrency is capped and every query has a hard deadline', async () => {
  const table: Record<string, Entry> = {};
  const names = Array.from({ length: 30 }, (_v, i) => `cand${i}.com`);
  for (const name of names) table[name] = { ns: ['ns.example.net'] };
  table['slow.com'] = { ns: 'hang' };
  const fake = fakeResolver(table, { delayMs: 5 });

  const started = Date.now();
  const states = await checkRegistrations([...names, 'slow.com'], {
    resolver: fake.resolver,
    concurrency: 4,
    queryTimeoutMs: 50,
  });
  assert.ok(
    fake.maxNamesInFlight() <= 4,
    `at most 4 candidates in flight, saw ${fake.maxNamesInFlight()}`
  );
  assert.equal(states.get('slow.com')?.state, 'unknown', 'a hung query times out');
  assert.equal(states.get('cand0.com')?.state, 'registered');
  assert.ok(Date.now() - started < 5_000);
});

test('registration: under a suffix that answers for random names, only NS proves a registration', async () => {
  // A wildcard suffix, or a resolver rewriting NXDOMAIN to an ad server.
  const wildcard: DnsResolverLike = {
    resolveNs: async (n) => {
      if (n === 'real.ws') return ['ns1.real.ws'];
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolve4: async () => ['192.0.2.53'],
    resolve6: async () => {
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolveMx: async () => {
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolveTxt: async () => [],
  };
  const states = await checkRegistrations(['real.ws', 'fake.ws'], { resolver: wildcard });
  assert.equal(states.get('real.ws')?.state, 'registered');
  assert.equal(states.get('fake.ws')?.state, 'unknown', 'an A answer alone proves nothing here');
});

test('registration: a wildcard probe that fails leaves the suffix unproven, not clean', async () => {
  // A wildcard suffix whose probe query is lost (timeout): candidates without an
  // NS delegation must not all turn into registrations.
  const probeTimesOut: DnsResolverLike = {
    resolveNs: async (n) => {
      if (n === 'real.ws') return ['ns1.real.ws'];
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolve4: async (n) => {
      if (n.startsWith('siembox-nx-')) throw Object.assign(new Error('t'), { code: 'ETIMEOUT' });
      return ['192.0.2.53'];
    },
    resolve6: async () => {
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolveMx: async () => {
      throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
    },
    resolveTxt: async () => [],
  };
  const states = await checkRegistrations(['real.ws', 'fake.ws'], { resolver: probeTimesOut });
  assert.equal(states.get('real.ws')?.state, 'registered');
  assert.equal(states.get('fake.ws')?.state, 'unknown');
});

test('registration: an address or MX lookup that fails is unknown (null), never "none"', async () => {
  const fake = fakeResolver({
    'mx-timeout.com': { ns: ['ns1.host.example'], a: ['203.0.113.7'], mx: { code: 'ETIMEOUT' } },
    'addr-fail.com': {
      ns: ['ns1.host.example'],
      a: { code: 'ESERVFAIL' },
      mx: ['mx.addr-fail.com'],
    },
    'none.com': { ns: ['ns1.host.example'] },
  });
  assert.deepEqual(await checkRegistration('mx-timeout.com', fake.resolver), {
    state: 'registered',
    ns: true,
    addr: true,
    mx: null,
  });
  assert.deepEqual(await checkRegistration('addr-fail.com', fake.resolver), {
    state: 'registered',
    ns: true,
    addr: null,
    mx: true,
  });
  assert.deepEqual(await checkRegistration('none.com', fake.resolver), {
    state: 'registered',
    ns: true,
    addr: false,
    mx: false,
  });
});

// ---- snapshot & collector -----------------------------------------------------------------

const config: DomainMonitorConfig = {
  expiryWarningDays: 30,
  lookalikeMaxCandidates: 300,
  secondaryResolver: null,
  lookalikeCtChecksPerRun: 3,
};

function ctx(previous: unknown, domain = 'example.com'): CollectorContext {
  return {
    domain: {
      id: 7,
      domain,
      scope: 'own',
      expected_cas: [],
      collectors: { ct: true, lookalike: true, rdap: true, dns: true },
    },
    previous,
    config,
    now: new Date('2026-10-11T00:00:00Z'),
    trigger: 'schedule',
    earlier: {},
    baselines: {},
  };
}

test('collector: the first run is a silent baseline; later registrations and new MX are findings', async () => {
  const table: Record<string, Entry> = {
    'example.net': { ns: ['ns1.other.example'], a: ['198.51.100.2'] }, // registered long ago
    'exmple.com': { ns: ['ns1.parking.example'] }, // parked, no address or MX
  };
  const fake = fakeResolver(table);
  const collector = createLookalikeCollector({ resolver: fake.resolver, dnstwist: null });

  const first = await collector(ctx(null));
  assert.equal(first.status, 'baseline');
  assert.deepEqual(first.findings, [], 'existing lookalikes are the baseline, not news');
  assert.deepEqual(registeredFromSnapshot(first.snapshot), ['example.net', 'exmple.com']);

  // Since then: a phishing domain went up and the parked one grew an MX record.
  table['examp1e.com'] = { ns: ['ns1.host.example'], a: ['203.0.113.9'], mx: ['mx.examp1e.com'] };
  table['exmple.com'] = { ns: ['ns1.parking.example'], mx: ['mx.exmple.com'] };
  const second = await collector(ctx(first.snapshot));
  assert.equal(second.status, 'ok');
  const byLookalike = Object.fromEntries(
    second.findings.map((f) => [
      f.detail.lookalike,
      { severity: f.severity, change: f.detail.change },
    ])
  );
  assert.deepEqual(byLookalike, {
    'examp1e.com': { severity: 'high', change: undefined },
    'exmple.com': { severity: 'high', change: 'mx_added' },
  });
  assert.ok(second.findings.every((f) => f.eventType === 'lookalike_registered'));
  assert.ok(second.findings.every((f) => f.source === 'domain-monitor' && f.domainId === 7));
  assert.deepEqual(second.lookalikes?.newlyRegistered, ['examp1e.com']);

  // Same state again: nothing new, and the fingerprints would dedupe anyway.
  const third = await collector(ctx(second.snapshot));
  assert.deepEqual(third.findings, []);
  const fp = (f: { fingerprint: string }) => f.fingerprint;
  const fourth = await collector(ctx(first.snapshot));
  assert.deepEqual(
    fourth.findings.map(fp).sort(),
    second.findings.map(fp).sort(),
    'stable fingerprints'
  );
});

test('collector: the organization’s own watched domains are never reported as lookalikes', async () => {
  const table: Record<string, Entry> = {};
  const fake = fakeResolver(table);
  const collector = createLookalikeCollector({ resolver: fake.resolver, dnstwist: null });
  const watched = ['example.com', 'mail.example.net'];
  const baseline = (await collector({ ...ctx(null), watchedDomains: watched })).snapshot;
  // The org registers example.net (and watches it); a squatter registers example.org.
  table['example.net'] = { ns: ['ns1.our-dns.net'], a: ['192.0.2.1'] };
  table['example.org'] = { ns: ['ns1.squatter.net'], a: ['203.0.113.2'] };
  const out = await collector({ ...ctx(baseline), watchedDomains: watched });
  assert.deepEqual(
    out.findings.map((f) => f.detail.lookalike),
    ['example.org']
  );
  assert.ok(!fake.queries.some((q) => q.name === 'example.net'), 'never even resolved');
});

test('collector: names answered for the first time are recorded silently, whenever that happens', async () => {
  // Registered long ago, but their lookups time out on the baseline run.
  const table: Record<string, Entry> = {
    'exmple.com': { ns: { code: 'ETIMEOUT' } },
    'examp1e.com': { ns: { code: 'ETIMEOUT' } },
  };
  const fake = fakeResolver(table);
  const collector = createLookalikeCollector({ resolver: fake.resolver, dnstwist: null });
  const narrow = (previous: unknown, max: number) => ({
    ...ctx(previous),
    config: { ...config, lookalikeMaxCandidates: max },
  });
  const baseline = await collector(narrow(null, 40));
  assert.deepEqual(registeredFromSnapshot(baseline.snapshot), []);

  // Next day the resolver answers, and the operator raises the candidate cap.
  table['exmple.com'] = { ns: ['ns1.parked.example'], a: ['198.51.100.9'] };
  table['examp1e.com'] = { ns: ['ns1.parked.example'], a: ['198.51.100.9'] };
  table['exampleu.com'] = { ns: ['ns1.parked.example'], a: ['198.51.100.9'] }; // beyond the old cap
  const next = await collector(narrow(baseline.snapshot, 300));
  assert.deepEqual(next.findings, [], 'nobody knows when these were registered');
  assert.deepEqual(next.lookalikes?.newlyRegistered, []);
  assert.deepEqual(registeredFromSnapshot(next.snapshot), [
    'examp1e.com',
    'exampleu.com',
    'exmple.com',
  ]);

  // A name confirmed free on an earlier run that gets registered is news.
  table['exampie.com'] = { ns: ['ns1.bad.example'], a: ['203.0.113.5'] };
  const later = await collector(narrow(next.snapshot, 300));
  assert.deepEqual(
    later.findings.map((f) => [f.detail.lookalike, f.severity]),
    [['exampie.com', 'high']]
  );
  assert.deepEqual(later.lookalikes?.newlyRegistered, ['exampie.com']);
});

test('collector: a watched domain left over in an old baseline is dropped from it', async () => {
  const fake = fakeResolver({ 'example.net': { ns: ['ns1.our-dns.net'], a: ['192.0.2.1'] } });
  const collector = createLookalikeCollector({ resolver: fake.resolver, dnstwist: null });
  const baseline = (await collector(ctx(null))).snapshot;
  assert.ok(new Set(registeredFromSnapshot(baseline)).has('example.net'));
  // The organization now watches example.net as well.
  const out = await collector({ ...ctx(baseline), watchedDomains: ['example.com', 'example.net'] });
  assert.ok(!new Set(registeredFromSnapshot(out.snapshot)).has('example.net'));
  assert.ok(!new Set(out.lookalikes?.registered ?? []).has('example.net'));
  assert.deepEqual(parseLookalikeSnapshot(out.snapshot)?.unregistered['example.net'], undefined);
});

test('collector: a registration with neither address nor MX is medium', async () => {
  const fake = fakeResolver({});
  const collector = createLookalikeCollector({ resolver: fake.resolver, dnstwist: null });
  const baseline = (await collector(ctx(null))).snapshot;
  const later = fakeResolver({ 'exmple.com': { ns: ['ns1.registrar-parking.example'] } });
  const out = await createLookalikeCollector({ resolver: later.resolver, dnstwist: null })(
    ctx(baseline)
  );
  assert.deepEqual(
    out.findings.map((f) => [f.detail.lookalike, f.severity]),
    [['exmple.com', 'medium']]
  );
});

/** ctx() `days` after its usual date. */
const onDay = (previous: unknown, days: number, domain = 'example.com'): CollectorContext => ({
  ...ctx(previous, domain),
  now: new Date(Date.parse('2026-10-11T00:00:00Z') + days * 86_400_000),
});

test('collector: a lookalike registered again after a drop alerts again, with its own fingerprints', async () => {
  const table: Record<string, Entry> = {};
  const collector = createLookalikeCollector({
    resolver: fakeResolver(table).resolver,
    dnstwist: null,
  });
  let snap = (await collector(onDay(null, 0))).snapshot; // exmple.com confirmed free
  table['exmple.com'] = { ns: ['ns1.squatter-a.example'], a: ['203.0.113.1'] };
  const ownerA = await collector(onDay(snap, 10));
  table['exmple.com'] = { ...table['exmple.com'], mx: ['mx.exmple.com'] };
  const mxA = await collector(onDay(ownerA.snapshot, 20));
  delete table['exmple.com']; // it lapses
  snap = (await collector(onDay(mxA.snapshot, 100))).snapshot;
  snap = (await collector(onDay(snap, 200))).snapshot;

  // A drop-catcher registers it a year later.
  table['exmple.com'] = { ns: ['ns1.dropcatcher-b.example'], a: ['198.51.100.7'] };
  const ownerB = await collector(onDay(snap, 450));
  const fp = (out: { findings: Array<{ fingerprint: string; title: string }> }) =>
    out.findings.map((f) => f.fingerprint);
  assert.deepEqual(
    ownerB.findings.map((f) => f.title),
    ['Lookalike domain registered: exmple.com (looks like example.com)']
  );
  assert.notDeepEqual(fp(ownerB), fp(ownerA), 'not deduplicated against the first owner');
  assert.ok(ownerB.lookalikes?.priorDrops?.['exmple.com'], 'handed to CT');
  // A re-run against the same baseline (a crash before it was saved) dedupes.
  assert.deepEqual(fp(await collector(onDay(snap, 451))), fp(ownerB));

  table['exmple.com'] = { ...table['exmple.com'], mx: ['mx.exmple.com'] };
  const mxB = await collector(onDay(ownerB.snapshot, 460));
  assert.deepEqual(
    mxB.findings.map((f) => f.detail.change),
    ['mx_added']
  );
  assert.notDeepEqual(fp(mxB), fp(mxA));
  assert.equal(fp(mxA).length, 1);
});

test('collector: a re-registered lookalike that goes NXDOMAIN for a run keeps its own fingerprints', async () => {
  const table: Record<string, Entry> = {};
  const collector = createLookalikeCollector({
    resolver: fakeResolver(table).resolver,
    dnstwist: null,
  });
  const fp = (out: { findings: Array<{ fingerprint: string }> }) =>
    out.findings.map((f) => f.fingerprint);
  let snap = (await collector(onDay(null, 0))).snapshot;
  table['exmple.com'] = { ns: ['ns1.squatter-a.example'], a: ['203.0.113.1'] };
  snap = (await collector(onDay(snap, 10))).snapshot;
  table['exmple.com'] = { ...table['exmple.com'], mx: ['mx.exmple.com'] };
  const mxA = await collector(onDay(snap, 20));
  delete table['exmple.com']; // it lapses
  snap = (await collector(onDay(mxA.snapshot, 100))).snapshot;
  const ownerBZone: Entry = { ns: ['ns1.dropcatcher-b.example'], a: ['198.51.100.7'] };
  table['exmple.com'] = ownerBZone;
  const ownerB = await collector(onDay(snap, 450));
  const ownerBInfo = parseLookalikeSnapshot(ownerB.snapshot)?.registered['exmple.com'];
  assert.ok(ownerBInfo?.prior_drop && ownerBInfo.since);

  // A registrar hold (unverified registrant contact) for one run, then back.
  delete table['exmple.com'];
  const held = await collector(onDay(ownerB.snapshot, 451));
  assert.deepEqual(registeredFromSnapshot(held.snapshot), []);
  table['exmple.com'] = ownerBZone;
  const back = await collector(onDay(held.snapshot, 452));
  assert.deepEqual(back.findings, [], 'the same registration: silent');
  const restored = parseLookalikeSnapshot(back.snapshot)?.registered['exmple.com'];
  assert.equal(restored?.prior_drop, ownerBInfo.prior_drop, 'still the new owner’s registration');
  assert.equal(restored?.since, ownerBInfo.since, 'still newly registered for CT');
  assert.deepEqual(back.lookalikes?.newlyRegistered, ['exmple.com']);

  table['exmple.com'] = { ...ownerBZone, mx: ['mx.exmple.com'] };
  const mxB = await collector(onDay(back.snapshot, 460));
  assert.deepEqual(
    mxB.findings.map((f) => f.detail.change),
    ['mx_added']
  );
  assert.notDeepEqual(fp(mxB), fp(mxA), 'not deduplicated against the first owner’s MX finding');
});

test('collector: one failed dnstwist run keeps what was known about its candidates', async () => {
  const table: Record<string, Entry> = {};
  let dnstwistUp = true;
  const collector = createLookalikeCollector({
    resolver: fakeResolver(table).resolver,
    dnstwist: async () => {
      if (!dnstwistUp) throw new Error('dnstwist failed: timed out');
      return ['example-login.com'];
    },
  });
  const wide = (previous: unknown, days: number) => ({
    ...onDay(previous, days),
    config: { ...config, lookalikeMaxCandidates: 1000 },
  });
  let snap = (await collector(wide(null, 0))).snapshot;
  assert.ok(parseLookalikeSnapshot(snap)?.unregistered['example-login.com'] !== undefined);
  dnstwistUp = false;
  const failed = await collector(wide(snap, 1));
  assert.match((failed.warnings ?? []).join(' '), /dnstwist failed/);
  snap = failed.snapshot;
  assert.ok(
    parseLookalikeSnapshot(snap)?.unregistered['example-login.com'] !== undefined,
    'a failed lookup is not a state change'
  );
  dnstwistUp = true;
  table['example-login.com'] = { ns: ['ns1.evil.example'], a: ['203.0.113.9'] };
  const later = await collector(wide(snap, 2));
  assert.deepEqual(
    later.findings.map((f) => f.detail.lookalike),
    ['example-login.com']
  );
});

/** brand.ws: .ws answers A for every name; only delegated names have NS records. */
function wildcardTld(
  delegated: Set<string>,
  options: { stripsNs?: boolean } = {}
): DnsResolverLike {
  const fail = (code: string) => Object.assign(new Error(code), { code });
  const underWs = (n: string) => n.endsWith('.ws');
  const noRecords = async (n: string): Promise<never> => {
    throw fail(underWs(n) ? 'ENODATA' : 'ENOTFOUND');
  };
  return {
    resolveNs: async (n) => {
      if (options.stripsNs) throw fail('ENODATA'); // a resolver that answers NODATA for every non-A type
      if (n === 'ws') return ['a.dns.ws', 'b.dns.ws'];
      if (delegated.has(n)) return ['ns1.squatter.example'];
      return noRecords(n);
    },
    resolve4: async (n) => (underWs(n) ? ['64.70.19.203'] : noRecords(n)),
    resolve6: noRecords,
    resolveMx: noRecords,
    resolveTxt: async () => [],
  };
}

test('collector: under a wildcard TLD, no delegation confirms a name free, so a later delegation alerts', async () => {
  const delegated = new Set<string>();
  const collector = createLookalikeCollector({ resolver: wildcardTld(delegated), dnstwist: null });
  const baseline = await collector(onDay(null, 0, 'brand.ws'));
  assert.ok(parseLookalikeSnapshot(baseline.snapshot)?.unregistered['brnad.ws'] !== undefined);
  delegated.add('brnad.ws');
  const out = await collector(onDay(baseline.snapshot, 1, 'brand.ws'));
  assert.deepEqual(
    out.findings.map((f) => [f.detail.lookalike, f.severity]),
    [['brnad.ws', 'high']]
  );
  // A registered lookalike without a delegation is kept, never dropped on that alone.
  delegated.delete('brnad.ws');
  const after = await collector(onDay(out.snapshot, 2, 'brand.ws'));
  assert.ok(new Set(registeredFromSnapshot(after.snapshot)).has('brnad.ws'));

  // A resolver that hides every NS record proves nothing there: the names stay
  // unknown, so long-standing delegations it hid are not "new" once it is replaced.
  const hidden = await createLookalikeCollector({
    resolver: wildcardTld(new Set(), { stripsNs: true }),
    dnstwist: null,
  })(onDay(null, 0, 'brand.ws'));
  assert.equal(parseLookalikeSnapshot(hidden.snapshot)?.unregistered['brnad.ws'], undefined);
  const replaced = await createLookalikeCollector({
    resolver: wildcardTld(new Set(['brnad.ws'])),
    dnstwist: null,
  })(onDay(hidden.snapshot, 1, 'brand.ws'));
  assert.deepEqual(replaced.findings, []);
  assert.ok(new Set(registeredFromSnapshot(replaced.snapshot)).has('brnad.ws'));
});

const NOW_S = Math.floor(Date.parse('2026-10-11T00:00:00Z') / 1000);
const DAY = 86_400;
const info = (overrides: Partial<RegisteredInfo> = {}): RegisteredInfo => ({
  mx: false,
  addr: true,
  fuzzer: 'omission',
  since: null,
  seen_at: null,
  prior_drop: null,
  ...overrides,
});

test('diff: unknown keeps the previous state; unregistered drops it; nothing is invented', () => {
  const previous: LookalikeSnapshot = {
    v: 1,
    registered: {
      'flaky.com': info(),
      'gone.com': info(),
      'not-rechecked.com': info({ mx: true, fuzzer: 'addition' }),
    },
    unregistered: {},
    dropped: {},
  };
  const diff = diffLookalikes(
    previous,
    [
      { domain: 'flaky.com', fuzzer: 'omission' },
      { domain: 'gone.com', fuzzer: 'omission' },
    ],
    new Map([
      ['flaky.com', { state: 'unknown', reason: 'ETIMEOUT' }],
      ['gone.com', { state: 'unregistered' }],
    ]),
    { nowSeconds: NOW_S }
  );
  assert.deepEqual(Object.keys(diff.next.registered).sort(), ['flaky.com', 'not-rechecked.com']);
  assert.deepEqual([diff.unknown, diff.dropped, diff.newlyRegistered.length], [1, 1, 0]);
  assert.deepEqual(diff.next.dropped, { 'gone.com': NOW_S });
});

test('diff: only a name confirmed unregistered before can be "newly registered"', () => {
  const previous: LookalikeSnapshot = {
    v: 1,
    registered: {},
    unregistered: { 'free-then-taken.com': NOW_S - 5 * DAY },
    dropped: {},
  };
  const candidates: LookalikeCandidate[] = [
    { domain: 'free-then-taken.com', fuzzer: 'omission' },
    // Never answered before: unknown on the baseline run, a raised cap, dnstwist appearing.
    { domain: 'first-answer.com', fuzzer: 'addition' },
  ];
  const registered = { state: 'registered', ns: true, addr: true, mx: false } as const;
  const diff = diffLookalikes(
    previous,
    candidates,
    new Map([
      ['free-then-taken.com', registered],
      ['first-answer.com', registered],
    ]),
    { nowSeconds: NOW_S }
  );
  assert.deepEqual(
    diff.newlyRegistered.map((c) => c.domain),
    ['free-then-taken.com']
  );
  assert.equal(diff.next.registered['free-then-taken.com'].since, NOW_S, 'remembered for CT');
  assert.equal(diff.next.registered['first-answer.com'].since, null, 'recorded silently');
  assert.deepEqual(diff.next.unregistered, {});
});

test('diff: a lookalike that goes NXDOMAIN and comes back soon is the same registration', () => {
  const candidates: LookalikeCandidate[] = [{ domain: 'held.com', fuzzer: 'omission' }];
  const nx = new Map([['held.com', { state: 'unregistered' } as const]]);
  const back = new Map([
    ['held.com', { state: 'registered', ns: true, addr: true, mx: false } as const],
  ]);
  const base: LookalikeSnapshot = {
    v: 1,
    registered: { 'held.com': info() },
    unregistered: {},
    dropped: {},
  };
  // A registry hold (or one flapping NXDOMAIN), lifted a week later: silent.
  const held = diffLookalikes(base, candidates, nx, { nowSeconds: NOW_S });
  assert.deepEqual(held.next.registered, {});
  const lifted = diffLookalikes(held.next, candidates, back, { nowSeconds: NOW_S + 7 * DAY });
  assert.deepEqual(lifted.newlyRegistered, []);
  assert.ok(lifted.next.registered['held.com']);
  // Gone for longer than the grace period: it can have been re-registered by
  // someone else (a lapsed name caught on release), so it is reported.
  const stillGone = diffLookalikes(held.next, candidates, nx, { nowSeconds: NOW_S + 20 * DAY });
  assert.deepEqual(stillGone.next.dropped, { 'held.com': NOW_S }, 'the drop time is kept');
  const reRegistered = diffLookalikes(stillGone.next, candidates, back, {
    nowSeconds: NOW_S + 45 * DAY,
  });
  assert.deepEqual(
    reRegistered.newlyRegistered.map((c) => c.domain),
    ['held.com']
  );
});

test('diff: the comeback grace runs from when the name was last seen registered', () => {
  // A 14-day interval: last seen registered at T, NXDOMAIN noticed at T+14d. A
  // new owner can register it from T+35d at the earliest; it is seen at T+42d.
  const candidates: LookalikeCandidate[] = [{ domain: 'held.com', fuzzer: 'omission' }];
  const nx = new Map([['held.com', { state: 'unregistered' } as const]]);
  const back = new Map([
    ['held.com', { state: 'registered', ns: true, addr: true, mx: true } as const],
  ]);
  let snap: LookalikeSnapshot = {
    v: 1,
    registered: { 'held.com': info() },
    unregistered: {},
    dropped: {},
  };
  snap = diffLookalikes(snap, candidates, back, { nowSeconds: NOW_S }).next;
  assert.equal(snap.registered['held.com'].seen_at, NOW_S);
  snap = diffLookalikes(snap, candidates, nx, { nowSeconds: NOW_S + 14 * DAY }).next;
  assert.deepEqual(snap.dropped, { 'held.com': NOW_S }, 'when it was last seen registered');
  // Back within 30 days of that: the same registration (a hold lifted).
  assert.deepEqual(
    diffLookalikes(snap, candidates, back, { nowSeconds: NOW_S + 21 * DAY }).newlyRegistered,
    []
  );
  snap = diffLookalikes(snap, candidates, nx, { nowSeconds: NOW_S + 28 * DAY }).next;
  const later = diffLookalikes(snap, candidates, back, { nowSeconds: NOW_S + 42 * DAY });
  assert.deepEqual(
    later.newlyRegistered.map((c) => c.domain),
    ['held.com']
  );
});

test('diff: back from a hold, a lookalike carries on from what was known when it dropped', () => {
  const candidates: LookalikeCandidate[] = [{ domain: 'held.com', fuzzer: 'addition' }];
  const nx = new Map([['held.com', { state: 'unregistered' } as const]]);
  const back = (mx: boolean | null) =>
    new Map([['held.com', { state: 'registered', ns: true, addr: true, mx } as const]]);
  const base: LookalikeSnapshot = {
    v: 1,
    registered: {
      'held.com': info({ fuzzer: 'omission', since: NOW_S - DAY, prior_drop: NOW_S - 400 * DAY }),
    },
    unregistered: {},
    dropped: {},
  };
  const dropped = diffLookalikes(base, candidates, nx, { nowSeconds: NOW_S }).next;
  assert.deepEqual(dropped.dropped_info?.['held.com'], base.registered['held.com']);
  // A JSON round trip (JSONB), and one run in which the name could not be resolved.
  const stored = parseLookalikeSnapshot(JSON.parse(JSON.stringify(dropped))) as LookalikeSnapshot;
  const unresolved = new Map([['held.com', { state: 'unknown', reason: 'ETIMEOUT' } as const]]);
  const still = diffLookalikes(stored, candidates, unresolved, { nowSeconds: NOW_S + DAY }).next;
  assert.deepEqual(still.dropped_info, dropped.dropped_info, 'kept while it is gone');

  // It gained an MX record during the hold: that is reported like any other.
  const lifted = diffLookalikes(still, candidates, back(true), { nowSeconds: NOW_S + 7 * DAY });
  assert.deepEqual(lifted.newlyRegistered, []);
  assert.deepEqual(
    lifted.mxAdded.map((c) => [c.domain, c.info.prior_drop]),
    [['held.com', NOW_S - 400 * DAY]]
  );
  assert.deepEqual(lifted.next.registered['held.com'], {
    ...base.registered['held.com'],
    mx: true,
    seen_at: NOW_S + 7 * DAY,
  });
  assert.equal(lifted.next.dropped_info, undefined, 'only dropped names keep one');
  // An MX lookup failing on the way back keeps what was known: nothing "added".
  assert.deepEqual(
    diffLookalikes(still, candidates, back(null), { nowSeconds: NOW_S + 7 * DAY }).mxAdded,
    []
  );
});

test('diff: a failed MX lookup is "unknown", never "no MX" — so it can’t fake an MX being added', () => {
  const candidates: LookalikeCandidate[] = [{ domain: 'phish.com', fuzzer: 'homoglyph' }];
  const withMx = (mx: boolean | null) =>
    new Map([['phish.com', { state: 'registered', ns: true, addr: true, mx } as const]]);
  const base: LookalikeSnapshot = {
    v: 1,
    registered: { 'phish.com': info({ mx: true }) },
    unregistered: {},
    dropped: {},
  };
  const mxTimedOut = diffLookalikes(base, candidates, withMx(null), { nowSeconds: NOW_S });
  assert.equal(mxTimedOut.next.registered['phish.com'].mx, true, 'keeps what was known');
  const again = diffLookalikes(mxTimedOut.next, candidates, withMx(true), { nowSeconds: NOW_S });
  assert.deepEqual(again.mxAdded, []);

  // Unknown since the baseline: an MX showing up is not "added" either; a definite
  // "no MX" followed by an MX is.
  const unknownAtFirst: LookalikeSnapshot = {
    ...base,
    registered: { 'phish.com': info({ mx: null }) },
  };
  assert.deepEqual(
    diffLookalikes(unknownAtFirst, candidates, withMx(true), { nowSeconds: NOW_S }).mxAdded,
    []
  );
  const noMx = diffLookalikes(unknownAtFirst, candidates, withMx(false), { nowSeconds: NOW_S });
  assert.deepEqual(
    diffLookalikes(noMx.next, candidates, withMx(true), { nowSeconds: NOW_S }).mxAdded.map(
      (c) => c.domain
    ),
    ['phish.com']
  );
});

test('diff: the organization’s own names never stay in the registered list', () => {
  const previous: LookalikeSnapshot = {
    v: 1,
    registered: { 'example.net': info(), 'exmple.com': info() },
    unregistered: {},
    dropped: {},
  };
  // example.net is now watched too, so it is no longer a candidate and is excluded.
  const diff = diffLookalikes(previous, [], new Map(), {
    nowSeconds: NOW_S,
    exclude: ownDomainNames(['example.com', 'shop.example.net']),
  });
  assert.deepEqual(Object.keys(diff.next.registered), ['exmple.com']);
});

test('state for CT: newly registered within the window, from the stored snapshot', () => {
  const snapshot: LookalikeSnapshot = {
    v: 1,
    registered: {
      'new.com': info({ since: NOW_S - DAY }),
      'old-news.com': info({ since: NOW_S - (NEW_REGISTRATION_WINDOW_DAYS + 1) * DAY }),
      'baseline.com': info(),
      // Registered again (reported 2 days ago) after it dropped, last seen registered 50 days ago.
      'again.com': info({ since: NOW_S - 2 * DAY, prior_drop: NOW_S - 50 * DAY }),
    },
    unregistered: {},
    // On hold (last seen registered within the comeback grace), and gone for good.
    dropped: { 'on-hold.com': NOW_S - 5 * DAY, 'long-gone.com': NOW_S - 31 * DAY },
  };
  assert.deepEqual(lookalikeStateFromSnapshot(snapshot, NOW_S), {
    registered: ['again.com', 'baseline.com', 'new.com', 'old-news.com'],
    newlyRegistered: ['again.com', 'new.com'],
    priorDrops: { 'again.com': NOW_S - 50 * DAY },
    reregisteredAt: { 'again.com': NOW_S - 2 * DAY },
    held: ['on-hold.com'],
  });
  assert.deepEqual(lookalikeStateFromSnapshot(null, NOW_S), {
    registered: [],
    newlyRegistered: [],
  });
});

test('collector: every lookup failing is a transient error, not "nothing registered"', async () => {
  const down: DnsResolverLike = {
    resolveNs: async () => {
      throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    },
    resolve4: async () => {
      throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    },
    resolve6: async () => {
      throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    },
    resolveMx: async () => {
      throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
    },
    resolveTxt: async () => [],
  };
  const collector = createLookalikeCollector({ resolver: down, dnstwist: null });
  await assert.rejects(collector(ctx(null)), (err: unknown) => {
    assert.ok(err instanceof Error && err.name === 'CollectorError');
    assert.equal((err as { transient?: boolean }).transient, true);
    return true;
  });
});

test('dnstwist: its permutations join under the same cap; its absence is fine', async () => {
  const fake = fakeResolver({ 'example-login.com': { ns: ['ns1.evil.example'] } });
  const withDnstwist = createLookalikeCollector({
    resolver: fake.resolver,
    dnstwist: async () => ['example.com', 'example-login.com', 'not a domain', 'exmple.com'],
  });
  const out = await withDnstwist({
    ...ctx(null),
    config: { ...config, lookalikeMaxCandidates: 1000 },
  });
  assert.equal(out.details?.dnstwist, true);
  assert.ok(new Set(out.details?.registered_lookalikes as string[]).has('example-login.com'));

  const failing = createLookalikeCollector({
    resolver: fakeResolver({}).resolver,
    dnstwist: async () => {
      throw new Error('dnstwist failed: boom');
    },
  });
  const degraded = await failing(ctx(null));
  assert.match((degraded.warnings ?? []).join(' '), /dnstwist failed/);

  // Detection only ever looks at absolute PATH entries for an executable file.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-dnstwist-'));
  try {
    const bin = path.join(dir, 'dnstwist');
    fs.writeFileSync(bin, '#!/bin/sh\n', { mode: 0o755 });
    assert.equal(findOnPath('dnstwist', `relative/dir${path.delimiter}${dir}`), bin);
    assert.equal(findOnPath('dnstwist', 'relative/dir'), null);
    assert.equal(findOnPath('definitely-not-installed-xyz', dir), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
