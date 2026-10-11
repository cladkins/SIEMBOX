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
  checkRegistration,
  checkRegistrations,
  createLookalikeCollector,
  diffLookalikes,
  findOnPath,
  generateLookalikes,
  registeredFromSnapshot,
  type LookalikeSnapshot,
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
  assert.equal(new Set(names).size, names.length, 'no duplicates');
  assert.ok(!names.includes('example.com'));
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
  assert.ok(!excluded.includes(all[0]) && !excluded.includes('example.net'));
});

test('generator: registrable part, multi-label suffixes and punycode', () => {
  const uk = generateLookalikes('mail.example.co.uk').map((c) => c.domain);
  assert.ok(uk.includes('exmple.co.uk'), 'permutes the registrable label, not "mail"');
  assert.ok(uk.includes('example.uk') && uk.includes('example.com'), 'suffix swaps');
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

test('diff: unknown keeps the previous state; unregistered drops it; nothing is invented', () => {
  const previous: LookalikeSnapshot = {
    v: 1,
    registered: {
      'flaky.com': { mx: false, addr: true, fuzzer: 'omission' },
      'gone.com': { mx: false, addr: true, fuzzer: 'omission' },
      'not-rechecked.com': { mx: true, addr: true, fuzzer: 'addition' },
    },
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
    ])
  );
  assert.deepEqual(Object.keys(diff.next.registered).sort(), ['flaky.com', 'not-rechecked.com']);
  assert.deepEqual([diff.unknown, diff.dropped, diff.newlyRegistered.length], [1, 1, 0]);
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
  assert.ok((out.details?.registered_lookalikes as string[]).includes('example-login.com'));

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
