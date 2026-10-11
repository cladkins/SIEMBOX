/**
 * Certificate Transparency without crt.sh: parsing crt.sh's JSON, issuer/CA
 * matching, the request the client sends and how it maps failures (transient,
 * never "no certificates"), the snapshot diff (union, renewals, new names,
 * new issuers, pruning), and the collector's findings — first-run silence,
 * unexpected CAs, policy changes, lookalike certificates and grouping.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CRTSH_BASE,
  CRTSH_RESULT_LIMIT,
  CtClient,
  MAX_INDIVIDUAL_FINDINGS,
  MAX_PENDING_ATTEMPTS,
  createCtCollector,
  createPacer,
  crtshQueryUrl,
  diffCertificates,
  issuerIdentity,
  issuerMatchesExpected,
  parseCrtshResponse,
  parseCtSnapshot,
  parseDistinguishedName,
  selectLookalikesForCt,
  type CertificateSource,
  type CtCertificate,
} from './ct';
import { HttpError, type HttpGet, type HttpGetResult } from './http';
import { CollectorError, type CollectorContext, type CollectorOutput } from './types';
import { SECRET_KEY_PATTERN } from '../findingWriter';

const LE = "C=US, O=Let's Encrypt, CN=R11";
const SECTIGO =
  'C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA';
const CLOUDFLARE = 'C=US, O="Cloudflare, Inc.", CN=Cloudflare Inc ECC CA-3';

// ---- parsing -----------------------------------------------------------------------------

test('parse: crt.sh rows become certificates keyed on issuer + serial', () => {
  const rows = [
    // A precertificate and its certificate: same issuer and serial, two crt.sh ids.
    {
      issuer_ca_id: 295814,
      issuer_name: LE,
      common_name: 'example.com',
      name_value: 'example.com\nwww.example.com',
      id: 1002,
      entry_timestamp: '2026-09-01T10:00:00.123',
      not_before: '2026-09-01T09:00:00',
      not_after: '2026-11-30T09:00:00',
      serial_number: '03ab',
      result_count: 2,
    },
    {
      issuer_ca_id: 295814,
      issuer_name: LE,
      name_value: 'example.com',
      id: 1001,
      serial_number: '0003AB',
    },
    // A wildcard, a foreign SAN and an e-mail identity.
    {
      issuer_ca_id: 1,
      issuer_name: SECTIGO,
      name_value: '*.example.com\nother.org\nalice@example.com',
      id: 2000,
      serial_number: 'ff',
    },
    // No serial: falls back to the crt.sh id.
    { issuer_name: CLOUDFLARE, name_value: 'shop.example.com', id: 3000 },
    // Junk the parser must survive.
    { id: 'nope' },
    null,
    'string',
    { id: 4000, name_value: 'unrelated.org', issuer_name: LE, serial_number: '01' },
  ];
  const certs = parseCrtshResponse(rows, 'example.com');
  assert.deepEqual(
    certs.map((c) => [c.key, c.crtshId, c.names]),
    [
      ['1:ff', 2000, ['*.example.com']],
      ['295814:3ab', 1001, ['example.com', 'www.example.com']],
      ['crtsh:3000', 3000, ['shop.example.com']],
    ]
  );
  const le = certs.find((c) => c.key === '295814:3ab') as CtCertificate;
  assert.equal(le.notAfter, '2026-11-30T09:00:00.000Z', 'zone-less timestamps are UTC');
  assert.equal(le.issuerLabel, "Let's Encrypt");
  assert.equal(certs.find((c) => c.crtshId === 3000)?.issuerLabel, 'Cloudflare, Inc.');

  assert.throws(
    () => parseCrtshResponse({ error: 'busy' }, 'example.com'),
    (err: unknown) => {
      return err instanceof CollectorError && err.transient;
    }
  );
});

test('issuer DNs: quoted values, organisations, and the expected-CA match', () => {
  assert.deepEqual(parseDistinguishedName(CLOUDFLARE), [
    ['C', 'US'],
    ['O', 'Cloudflare, Inc.'],
    ['CN', 'Cloudflare Inc ECC CA-3'],
  ]);
  assert.equal(issuerIdentity(SECTIGO).label, 'Sectigo Limited');
  assert.equal(issuerIdentity('CN=Some Root').label, 'Some Root');

  const cases: Array<[string, string[], boolean]> = [
    [LE, ["Let's Encrypt"], true],
    [LE, ['lets encrypt'], true], // case and punctuation don't matter
    [LE, ['R11'], true], // an intermediate's CN
    [SECTIGO, ['Sectigo'], true],
    [SECTIGO, ["Let's Encrypt", 'DigiCert'], false],
    [CLOUDFLARE, ['Cloudflare'], true],
    [LE, [''], false],
    [LE, [], false],
  ];
  for (const [dn, expected, matches] of cases) {
    assert.equal(issuerMatchesExpected(dn, expected), matches, `${dn} vs ${expected.join('|')}`);
  }
});

// ---- client --------------------------------------------------------------------------------

const ok = (body: unknown): HttpGetResult => ({
  status: 200,
  headers: {},
  body: Buffer.from(JSON.stringify(body)),
});
const noPacing = createPacer(0, async () => undefined);

test('client: constant host, the identity only in encoded query parameters, one query per name', async () => {
  const urls: URL[] = [];
  const transport: HttpGet = async (url) => {
    urls.push(url);
    return ok([]);
  };
  await new CtClient({ transport, pacer: noPacing }).certificatesFor('my-company.example');
  // With match=ILIKE crt.sh matches '%name%' (it rewrites "%.name" to "name"),
  // so one request covers the name, its subdomains and wildcards.
  assert.equal(urls.length, 1);
  const [url] = urls;
  assert.equal(url.origin, new URL(CRTSH_BASE).origin);
  assert.equal(url.pathname, '/');
  assert.equal(url.searchParams.get('q'), 'my-company.example');
  assert.equal(url.searchParams.get('output'), 'json');
  assert.equal(url.searchParams.get('exclude'), 'expired');
  assert.equal(url.searchParams.get('deduplicate'), 'Y');
  assert.equal(url.searchParams.get('match'), 'ILIKE', 'explicit: hyphens change the auto mode');
  assert.match(crtshQueryUrl('%.example.com').search, /q=%25\.example\.com/);
});

test('client: an answer cut off at crt.sh’s 10,000-row limit is refused, not diffed', async () => {
  const row = (id: number, resultCount: number) => ({
    issuer_ca_id: 1,
    issuer_name: LE,
    name_value: `host${id}.example.com`,
    id,
    serial_number: id.toString(16),
    result_count: resultCount,
  });
  // The rows' result_count values add up to how many matching names crt.sh returned.
  const under = [row(1, 9_000), row(2, 999)];
  assert.equal(parseCrtshResponse(under, 'example.com').length, 2);
  const truncated = [row(1, 9_000), row(2, 1_000)];
  assert.equal(CRTSH_RESULT_LIMIT, 10_000);
  assert.throws(
    () => parseCrtshResponse(truncated, 'example.com'),
    (err: unknown) =>
      err instanceof CollectorError &&
      !err.transient &&
      /only part of the certificates/.test(err.message)
  );
  // Rows that don't match the domain still count: crt.sh's limit applies before our filter.
  const foreign = Array.from({ length: CRTSH_RESULT_LIMIT }, (_v, i) => ({
    id: i + 1,
    issuer_name: LE,
    name_value: `x${i}.unrelated.org`,
  }));
  assert.throws(() => parseCrtshResponse(foreign, 'example.com'), CollectorError);
  await assert.rejects(
    new CtClient({ transport: async () => ok(truncated), pacer: noPacing }).certificatesFor(
      'example.com'
    ),
    (err: unknown) => err instanceof CollectorError && !err.transient
  );
});

test('client: 5xx, 429, timeouts and non-JSON are transient — never "no certificates"', async () => {
  const transient: HttpGet[] = [
    async () => ({ status: 502, headers: {}, body: Buffer.alloc(0) }),
    async () => ({ status: 503, headers: {}, body: Buffer.alloc(0) }),
    async () => ({ status: 429, headers: {}, body: Buffer.alloc(0) }),
    async () => ({ status: 200, headers: {}, body: Buffer.from('<html>busy</html>') }),
    async () => ({
      status: 301,
      headers: { location: 'https://elsewhere.example/' },
      body: Buffer.alloc(0),
    }),
    async () => {
      throw new HttpError('timeout', 'no complete response within 45000 ms');
    },
    async () => {
      throw new HttpError('network', 'ECONNRESET');
    },
  ];
  for (const transport of transient) {
    await assert.rejects(
      new CtClient({ transport, pacer: noPacing }).certificatesFor('example.com'),
      (err: unknown) => err instanceof CollectorError && err.transient,
      String(transport)
    );
  }
  // A connection that never got made points at the network, not at crt.sh being busy.
  await assert.rejects(
    new CtClient({
      transport: async () => {
        throw new HttpError('timeout', 'could not connect within 45000 ms', 'connect');
      },
      pacer: noPacing,
    }).certificatesFor('example.com'),
    (err: unknown) =>
      err instanceof CollectorError &&
      err.transient &&
      /could not connect to crt\.sh within 45 s \(is outbound HTTPS blocked\?\)/.test(err.message)
  );
  // Too much data is not going to get better by retrying.
  await assert.rejects(
    new CtClient({
      transport: async () => {
        throw new HttpError('too_large', 'the response is larger than 10485760 bytes');
      },
      pacer: noPacing,
    }).certificatesFor('example.com'),
    (err: unknown) => err instanceof CollectorError && !err.transient
  );
});

test('pacer: requests are spaced out, also when callers overlap', async () => {
  let clock = 0;
  const waits: number[] = [];
  const pacer = createPacer(
    3000,
    async (ms) => {
      waits.push(ms);
    },
    () => clock
  );
  await Promise.all([pacer.wait(), pacer.wait(), pacer.wait()]);
  assert.deepEqual(waits, [3000, 6000], 'the 2nd and 3rd caller wait their turn');
  clock = 20_000;
  await pacer.wait();
  assert.equal(waits.length, 2, 'no wait after a long gap');
});

// ---- diff ----------------------------------------------------------------------------------------

const NOW = Math.floor(Date.parse('2026-10-11T00:00:00Z') / 1000);

function cert(
  key: string,
  names: string[],
  issuer = LE,
  notAfter = '2026-12-31T00:00:00.000Z'
): CtCertificate {
  const { key: issuerKey, label } = issuerIdentity(issuer);
  return {
    key,
    crtshId: Number(key.replace(/\D/g, '')) || 1,
    issuer,
    issuerKey,
    issuerLabel: label,
    serial: key,
    commonName: names[0],
    names,
    notBefore: '2026-10-01T00:00:00.000Z',
    notAfter,
  };
}

test('diff: renewals are recognised, new names and new issuers are not renewals', () => {
  const base = diffCertificates(null, [cert('a1', ['example.com', 'www.example.com'])], NOW);
  assert.equal(
    base.fresh.length,
    1,
    'with no snapshot everything is fresh (the caller stays silent)'
  );

  const next = diffCertificates(
    base.next,
    [
      cert('a1', ['example.com', 'www.example.com']),
      cert('a2', ['example.com', 'www.example.com']), // renewal
      cert('a3', ['shop.example.com']), // new name
      cert('a4', ['www.example.com'], SECTIGO), // new issuer
    ],
    NOW
  );
  assert.deepEqual(
    next.fresh.map((f) => [f.cert.key, f.newNames, f.newIssuer]),
    [
      ['a2', [], false],
      ['a3', ['shop.example.com'], false],
      ['a4', [], true],
    ]
  );
  assert.equal(next.renewals, 1);
});

test('diff: the snapshot is a union, so a partial crt.sh answer never makes old certificates new', () => {
  const full = diffCertificates(
    null,
    [cert('a1', ['example.com']), cert('a2', ['www.example.com'])],
    NOW
  );
  const partial = diffCertificates(full.next, [cert('a1', ['example.com'])], NOW);
  assert.deepEqual(Object.keys(partial.next.certs).sort(), ['a1', 'a2']);
  const again = diffCertificates(
    partial.next,
    [cert('a1', ['example.com']), cert('a2', ['www.example.com'])],
    NOW
  );
  assert.equal(again.fresh.length, 0);
});

test('diff: certificates expired for over a week are pruned from the snapshot', () => {
  const old = diffCertificates(
    null,
    [cert('old', ['example.com'], LE, '2026-09-01T00:00:00.000Z')],
    NOW
  );
  const next = diffCertificates(old.next, [cert('new', ['example.com'])], NOW);
  assert.deepEqual(Object.keys(next.next.certs), ['new']);
  assert.deepEqual(next.next.names, ['example.com'], 'known names survive pruning');
});

test('diff: renewals stay quiet when the snapshot’s name list was cut short', () => {
  // A snapshot that lost zzz.example.com from its (bounded) name list, while the
  // certificate covering it was seen and is still current.
  const previous = {
    certs: { old: Math.floor(Date.parse('2026-12-31T00:00:00Z') / 1000) },
    names: ['aaa.example.com'],
    issuers: ['letsencrypt'],
  };
  const certs = [
    cert('old', ['aaa.example.com', 'zzz.example.com']),
    cert('renewal', ['zzz.example.com']), // same name, same issuer
  ];
  const diff = diffCertificates(previous, certs, NOW);
  assert.deepEqual(
    diff.fresh.map((f) => [f.cert.key, f.newNames]),
    [['renewal', []]]
  );
  assert.equal(diff.renewals, 1);
  assert.deepEqual(
    diff.next.names,
    ['aaa.example.com', 'zzz.example.com'],
    'current names are kept'
  );

  // Names covered by current certificates are kept even beyond the cap for older names.
  const many = Array.from({ length: 6_000 }, (_v, i) => cert(`m${i}`, [`h${i}.example.com`]));
  const big = diffCertificates(null, many, NOW);
  assert.equal(big.next.names.length, 6_000);
});

// ---- collector ---------------------------------------------------------------------------------------

function source(
  table: Record<string, CtCertificate[] | Error>
): CertificateSource & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    certificatesFor: async (name) => {
      asked.push(name);
      const entry = table[name] ?? [];
      if (entry instanceof Error) throw entry;
      return entry;
    },
  };
}

function ctx(
  overrides: Partial<CollectorContext> & { expectedCas?: string[]; scope?: 'own' | 'brand' } = {}
): CollectorContext {
  return {
    domain: {
      id: 9,
      domain: 'example.com',
      scope: overrides.scope ?? 'own',
      expected_cas: overrides.expectedCas ?? [],
      collectors: { ct: true, lookalike: true, rdap: true, dns: true },
    },
    previous: overrides.previous ?? null,
    config: {
      expiryWarningDays: 30,
      lookalikeMaxCandidates: 300,
      secondaryResolver: null,
      lookalikeCtChecksPerRun: 3,
    },
    now: overrides.now ?? new Date(NOW * 1000),
    trigger: 'schedule',
    earlier: overrides.earlier ?? {},
    baselines: overrides.baselines ?? {},
    ...(overrides.watchedDomains ? { watchedDomains: overrides.watchedDomains } : {}),
  };
}

const kinds = (out: CollectorOutput) => out.findings.map((f) => [f.eventType, f.severity, f.title]);

test('collector: the first run is silent, except certificates from a CA outside expected_cas', async () => {
  const certs = [
    cert('a1', ['example.com']),
    cert('a2', ['www.example.com']),
    cert('s1', ['mail.example.com'], SECTIGO),
    cert('s2', ['vpn.example.com'], SECTIGO),
  ];
  const quiet = await createCtCollector({ source: source({ 'example.com': certs }) })(ctx());
  assert.equal(quiet.status, 'baseline');
  assert.deepEqual(
    quiet.findings,
    [],
    'no expected_cas: the existing certificates are just the baseline'
  );

  const policed = await createCtCollector({ source: source({ 'example.com': certs }) })(
    ctx({ expectedCas: ["Let's Encrypt"] })
  );
  assert.deepEqual(kinds(policed), [
    [
      'unexpected_ca',
      'high',
      '2 current certificates for example.com issued by Sectigo Limited, which is not an expected CA',
    ],
  ]);
  assert.equal(policed.findings[0].detail.certificate_count, 2);
});

test('collector: later runs flag unexpected CAs (high) and new hosts (low); renewals are quiet', async () => {
  const day1 = [cert('a1', ['example.com', 'www.example.com'])];
  const first = await createCtCollector({ source: source({ 'example.com': day1 }) })(
    ctx({ expectedCas: ["Let's Encrypt"] })
  );
  const day2 = [
    ...day1,
    cert('a2', ['example.com', 'www.example.com']), // renewal
    cert('a3', ['shop.example.com']), // new host, expected CA
    cert('s9', ['www.example.com'], SECTIGO), // mis-issuance
  ];
  const second = await createCtCollector({ source: source({ 'example.com': day2 }) })(
    ctx({ expectedCas: ["Let's Encrypt"], previous: first.snapshot })
  );
  assert.equal(second.status, 'ok');
  assert.deepEqual(
    second.findings.map((f) => [f.eventType, f.severity, f.detail.serial]),
    [
      ['unexpected_ca', 'high', 's9'],
      ['new_cert', 'low', 'a3'],
    ]
  );
  assert.deepEqual(second.details, { certificates: 4, new_certificates: 3, renewals: 1 });
  for (const finding of second.findings) {
    assert.equal(finding.source, 'domain-monitor');
    assert.deepEqual(
      Object.keys(finding.detail).filter((k) => SECRET_KEY_PATTERN.test(k)),
      [],
      'no detail key the privacy scrub would drop'
    );
  }

  // Same answer again: nothing new; and the same change always has the same fingerprint.
  const third = await createCtCollector({ source: source({ 'example.com': day2 }) })(
    ctx({ expectedCas: ["Let's Encrypt"], previous: second.snapshot })
  );
  assert.deepEqual(third.findings, []);
  const replay = await createCtCollector({ source: source({ 'example.com': day2 }) })(
    ctx({ expectedCas: ["Let's Encrypt"], previous: first.snapshot })
  );
  assert.deepEqual(
    replay.findings.map((f) => f.fingerprint),
    second.findings.map((f) => f.fingerprint)
  );
});

test('collector: changing expected_cas re-judges the certificates already known', async () => {
  const certs = [cert('a1', ['example.com']), cert('s1', ['mail.example.com'], SECTIGO)];
  const first = await createCtCollector({ source: source({ 'example.com': certs }) })(ctx());
  assert.deepEqual(first.findings, []);
  const tightened = await createCtCollector({ source: source({ 'example.com': certs }) })(
    ctx({ expectedCas: ["Let's Encrypt"], previous: first.snapshot })
  );
  assert.deepEqual(
    tightened.findings.map((f) => [f.eventType, f.detail.issuer_org]),
    [['unexpected_ca', 'Sectigo Limited']]
  );
  const unchanged = await createCtCollector({ source: source({ 'example.com': certs }) })(
    ctx({ expectedCas: ["Let's Encrypt"], previous: tightened.snapshot })
  );
  assert.deepEqual(unchanged.findings, [], 'judged once per policy change');
});

test('collector: many new certificates in one run become one grouped finding', async () => {
  const first = await createCtCollector({
    source: source({ 'example.com': [cert('a0', ['example.com'])] }),
  })(ctx());
  const burst = Array.from({ length: MAX_INDIVIDUAL_FINDINGS + 5 }, (_v, i) =>
    cert(`n${i}`, [`host${i}.example.com`])
  );
  const second = await createCtCollector({ source: source({ 'example.com': burst }) })(
    ctx({ previous: first.snapshot })
  );
  assert.equal(second.findings.length, 1);
  assert.equal(second.findings[0].eventType, 'new_cert');
  assert.equal(second.findings[0].detail.certificate_count, MAX_INDIVIDUAL_FINDINGS + 5);
});

test('collector: certificates for registered lookalikes (medium), rotating under a cap', async () => {
  const lookalikeRun = (
    registered: string[],
    newlyRegistered: string[]
  ): CollectorContext['earlier'] => ({
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      lookalikes: { registered, newlyRegistered },
    },
  });
  const certsFor = source({
    'example.com': [cert('a1', ['example.com'])],
    'examp1e.com': [cert('p1', ['examp1e.com', 'login.examp1e.com'])],
    'exmple.com': [cert('x1', ['exmple.com'])],
  });

  // Run 1: known lookalikes are baselined silently.
  const first = await createCtCollector({ source: certsFor })(
    ctx({ earlier: lookalikeRun(['exmple.com'], []) })
  );
  assert.deepEqual(first.findings, []);

  // Run 2: a lookalike registered since the last run already has a certificate.
  const second = await createCtCollector({ source: certsFor })(
    ctx({
      previous: first.snapshot,
      earlier: lookalikeRun(['exmple.com', 'examp1e.com'], ['examp1e.com']),
    })
  );
  assert.deepEqual(kinds(second), [
    ['new_cert', 'medium', 'Newly registered lookalike examp1e.com already has 1 TLS certificate'],
  ]);

  // Run 3: a new certificate on a known lookalike.
  const more = source({
    'example.com': [cert('a1', ['example.com'])],
    'exmple.com': [cert('x1', ['exmple.com']), cert('x2', ['secure.exmple.com'])],
    'examp1e.com': [cert('p1', ['examp1e.com', 'login.examp1e.com'])],
  });
  const third = await createCtCollector({ source: more })(
    ctx({ previous: second.snapshot, earlier: lookalikeRun(['exmple.com', 'examp1e.com'], []) })
  );
  assert.deepEqual(
    third.findings.map((f) => [f.eventType, f.severity, f.detail.lookalike]),
    [['new_cert', 'medium', 'exmple.com']]
  );

  // Selection: newly registered first, then never checked, then least recently checked.
  const order = selectLookalikesForCt(
    { registered: ['a.com', 'b.com', 'c.com', 'd.com'], newlyRegistered: ['d.com'] },
    { 'a.com': { checked_at: 200 }, 'b.com': { checked_at: 100 } },
    3
  );
  assert.deepEqual(order, ['d.com', 'c.com', 'b.com']);
  // A new one whose check failed transiently stays ahead of the rotation, for
  // MAX_PENDING_ATTEMPTS tries; then it takes its turn like the others.
  const withFailures = selectLookalikesForCt(
    {
      registered: ['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com'],
      newlyRegistered: ['d.com', 'e.com', 'f.com'],
    },
    { 'a.com': { checked_at: 200 }, 'b.com': { checked_at: 100 } },
    6,
    {
      'd.com': { at: 300, count: 1, transient: true },
      'e.com': { at: 50, count: MAX_PENDING_ATTEMPTS, transient: true },
    },
    1_000
  );
  assert.deepEqual(withFailures, ['f.com', 'd.com', 'c.com', 'e.com', 'b.com', 'a.com']);
});

test('collector: a new lookalike that missed the per-run cap still counts as new on its first check', async () => {
  const lookalikeRun = (
    registered: string[],
    newlyRegistered: string[]
  ): CollectorContext['earlier'] => ({
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      lookalikes: { registered, newlyRegistered },
    },
  });
  const certsFor = source({
    'aaa-example.com': [cert('p1', ['aaa-example.com'])],
    'bbb-example.com': [cert('p2', ['bbb-example.com'])],
  });
  const withCap = (c: CollectorContext): CollectorContext => ({
    ...c,
    config: { ...c.config, lookalikeCtChecksPerRun: 1 },
  });
  const first = await createCtCollector({ source: certsFor })(
    withCap(ctx({ earlier: lookalikeRun([], []) }))
  );
  // Both registered since the last run, but only one can be checked per run.
  const both = ['aaa-example.com', 'bbb-example.com'];
  const second = await createCtCollector({ source: certsFor })(
    withCap(ctx({ previous: first.snapshot, earlier: lookalikeRun(both, both) }))
  );
  assert.deepEqual(
    second.findings.map((f) => f.detail.lookalike),
    ['aaa-example.com']
  );
  // Next run: the lookalike snapshot still lists both as newly registered (for
  // 30 days); the one CT has already checked is judged normally, the other
  // still counts as new on its first check.
  const third = await createCtCollector({ source: certsFor })(
    withCap(ctx({ previous: second.snapshot, earlier: lookalikeRun(both, both) }))
  );
  assert.deepEqual(
    third.findings.map((f) => f.detail.lookalike),
    ['bbb-example.com']
  );
  const fourth = await createCtCollector({ source: certsFor })(
    withCap(ctx({ previous: third.snapshot, earlier: lookalikeRun(both, both) }))
  );
  assert.deepEqual(fourth.findings, [], 'each is "newly registered" once');
});

test('collector: the "newly registered" hand-off survives a run in which CT did not run or failed', async () => {
  // CT runs without this run's lookalike output (a retry of CT alone, or CT
  // failing on the day the lookalike collector found the registration): the
  // stored lookalike snapshot still says which ones are new.
  const lookalikeSnapshot = {
    v: 1,
    registered: {
      'examp1e.com': { mx: false, addr: true, fuzzer: 'homoglyph', since: NOW - 3_600 },
      'exmple.com': { mx: false, addr: true, fuzzer: 'omission', since: null }, // baseline
      'exampel.com': { mx: false, addr: true, fuzzer: 'transposition', since: NOW - 40 * 86_400 },
    },
    unregistered: {},
    dropped: {},
  };
  const certsFor = source({
    'examp1e.com': [cert('p1', ['examp1e.com'])],
    'exmple.com': [cert('x1', ['exmple.com'])],
    'exampel.com': [cert('e1', ['exampel.com'])],
  });
  const out = await createCtCollector({ source: certsFor })(
    ctx({ scope: 'brand', baselines: { lookalike: lookalikeSnapshot } })
  );
  assert.deepEqual(kinds(out), [
    ['new_cert', 'medium', 'Newly registered lookalike examp1e.com already has 1 TLS certificate'],
  ]);
  assert.equal(certsFor.asked[0], 'examp1e.com', 'checked first');
});

const DAY = 86_400;
const crtsh502 = () =>
  new CollectorError('crt.sh is temporarily unavailable (HTTP 502); will retry', true);

/** A stored lookalike snapshot: `others` registered long ago, `fresh` reported new at `since`. */
function lookalikeBaseline(others: string[], fresh: Record<string, number>, priorDrop?: number) {
  return {
    v: 1,
    registered: {
      ...Object.fromEntries(
        others.map((n) => [n, { mx: false, addr: true, fuzzer: 'addition', since: null }])
      ),
      ...Object.fromEntries(
        Object.entries(fresh).map(([n, since]) => [
          n,
          { mx: false, addr: true, fuzzer: 'homoglyph', since, prior_drop: priorDrop ?? null },
        ])
      ),
    },
    unregistered: {},
    dropped: {},
  };
}

/** A CT snapshot in which every one of `names` was checked already (oldest first). */
function checkedAlready(names: string[], at: number) {
  return {
    v: 1,
    domain: { certs: {}, names: [], issuers: [] },
    lookalikes: Object.fromEntries(
      names.map((n, i) => [n, { certs: {}, names: [], issuers: [], checked_at: at + i }])
    ),
  };
}

const goingUp = 'Newly registered lookalike examp1e.com already has 1 TLS certificate';

test('collector: a new lookalike whose own check fails is retried first next run, however long since it was found', async () => {
  // Own scope: crt.sh answers for the domain but not for the new lookalike, so
  // the collector itself succeeds (no early retry). 15 lookalikes are in rotation.
  const others = Array.from(
    { length: 15 },
    (_v, i) => `r${String(i).padStart(2, '0')}-example.com`
  );
  const table: Record<string, CtCertificate[] | Error> = { 'examp1e.com': crtsh502() };
  const baselines = { lookalike: lookalikeBaseline(others, { 'examp1e.com': NOW }) };
  const day0 = await createCtCollector({ source: source(table) })(
    ctx({ previous: checkedAlready(others, NOW - 30 * DAY), baselines })
  );
  assert.deepEqual(day0.findings, []);
  assert.deepEqual(parseCtSnapshot(day0.snapshot)?.pending_new, ['examp1e.com']);

  // A week later crt.sh answers: the new lookalike is checked first, and judged as new.
  table['examp1e.com'] = [cert('p1', ['examp1e.com'])];
  const s7 = source(table);
  const day7 = await createCtCollector({ source: s7 })(
    ctx({ previous: day0.snapshot, baselines, now: new Date((NOW + 7 * DAY) * 1000) })
  );
  assert.equal(s7.asked[1], 'examp1e.com', 'ahead of the 15 in rotation');
  assert.deepEqual(kinds(day7), [['new_cert', 'medium', goingUp]]);
  assert.equal(parseCtSnapshot(day7.snapshot)?.pending_new, undefined, 'checked once, judged once');

  // With the longest interval (30 days) the next run is past the lookalike
  // snapshot's 30-day "new" window: the CT snapshot still remembers it.
  table['examp1e.com'] = crtsh502();
  const alone = { lookalike: lookalikeBaseline([], { 'examp1e.com': NOW }) };
  const first = await createCtCollector({ source: source(table) })(
    ctx({ previous: checkedAlready([], NOW), baselines: alone })
  );
  table['examp1e.com'] = [cert('p1', ['examp1e.com'])];
  const day31 = await createCtCollector({ source: source(table) })(
    ctx({ previous: first.snapshot, baselines: alone, now: new Date((NOW + 31 * DAY) * 1000) })
  );
  assert.deepEqual(kinds(day31), [['new_cert', 'medium', goingUp]]);
});

test('collector: brand scope — the early retry tries the new lookalike again first', async () => {
  const others = ['a.example.org', 'b.example.org', 'c.example.org', 'd.example.org'];
  const table: Record<string, CtCertificate[] | Error> = { 'examp1e.com': crtsh502() };
  const baselines = { lookalike: lookalikeBaseline(others, { 'examp1e.com': NOW }) };
  let progress: unknown;
  await assert.rejects(
    createCtCollector({ source: source(table) })(
      ctx({ scope: 'brand', previous: checkedAlready(others, NOW - 10 * DAY), baselines })
    ),
    (err: unknown) => {
      assert.ok(err instanceof CollectorError && err.transient);
      progress = err.progress;
      return true;
    }
  );
  assert.deepEqual(parseCtSnapshot(progress)?.pending_new, ['examp1e.com']);
  table['examp1e.com'] = [cert('p1', ['examp1e.com'])];
  const retry = source(table);
  const out = await createCtCollector({ source: retry })(
    ctx({ scope: 'brand', previous: progress, baselines, now: new Date((NOW + 3_600) * 1000) })
  );
  assert.equal(retry.asked[0], 'examp1e.com');
  assert.deepEqual(kinds(out), [['new_cert', 'medium', goingUp]]);
});

test('collector: a new lookalike crt.sh keeps failing on joins the rotation, and is still judged as new later', async () => {
  const others = ['a.example.org', 'b.example.org'];
  const table: Record<string, CtCertificate[] | Error> = { 'examp1e.com': crtsh502() };
  const baselines = { lookalike: lookalikeBaseline(others, { 'examp1e.com': NOW }) };
  const oneCheck = (c: CollectorContext): CollectorContext => ({
    ...c,
    config: { ...c.config, lookalikeCtChecksPerRun: 1 },
  });
  let previous: unknown = checkedAlready(others, NOW - 10 * DAY);
  const asked: string[] = [];
  const run = async (day: number) => {
    const s = source(table);
    const out = await createCtCollector({ source: s })(
      oneCheck(ctx({ previous, baselines, now: new Date((NOW + day * DAY) * 1000) }))
    );
    previous = out.snapshot;
    asked.push(s.asked[1]);
    return out;
  };
  for (let day = 0; day < MAX_PENDING_ATTEMPTS; day++) await run(day);
  await run(3);
  await run(4);
  assert.deepEqual(asked, [
    ...Array<string>(MAX_PENDING_ATTEMPTS).fill('examp1e.com'),
    'a.example.org',
    'b.example.org',
  ]);
  table['examp1e.com'] = [cert('p1', ['examp1e.com'])];
  const later = await run(5);
  assert.equal(asked[5], 'examp1e.com', 'its turn in the rotation');
  assert.deepEqual(kinds(later), [['new_cert', 'medium', goingUp]]);
});

test('collector: an own-domain answer too large to monitor is a warning; lookalike checks still run', async () => {
  const tooMany = new CollectorError(
    'crt.sh returned only part of the certificates for example.com: too many to monitor reliably',
    false
  );
  const table: Record<string, CtCertificate[] | Error> = {
    'example.com': tooMany,
    'examp1e.com': [cert('p1', ['examp1e.com'])],
  };
  const baselines = { lookalike: lookalikeBaseline([], { 'examp1e.com': NOW - 3_600 }) };
  const previous = {
    v: 1,
    domain: { certs: { a1: NOW + 30 * DAY }, names: ['example.com'], issuers: ['letsencrypt'] },
    expected_cas: ['letsencrypt'],
  };
  const s = source(table);
  const out = await createCtCollector({ source: s })(ctx({ previous, baselines }));
  assert.deepEqual(s.asked, ['example.com', 'examp1e.com']);
  assert.deepEqual(kinds(out), [['new_cert', 'medium', goingUp]]);
  assert.match(String(out.details?.own_domain_error), /too many to monitor/);
  assert.match((out.warnings ?? []).join(' '), /^example\.com: crt\.sh returned only part/);
  const next = parseCtSnapshot(out.snapshot);
  assert.deepEqual(next?.domain, previous.domain, 'the own baseline is kept as it was');
  assert.deepEqual(next?.expected_cas, previous.expected_cas);

  // crt.sh merely struggling still fails the collector, so it is retried soon.
  table['example.com'] = crtsh502();
  await assert.rejects(
    createCtCollector({ source: source(table) })(ctx({ previous, baselines })),
    (err: unknown) => err instanceof CollectorError && err.transient
  );
});

test('collector: a lookalike registered again after a drop is a new "site going up", not a duplicate', async () => {
  const table: Record<string, CtCertificate[] | Error> = {
    'examp1e.com': [cert('p1', ['examp1e.com'])],
  };
  const firstOwner = await createCtCollector({ source: source(table) })(
    ctx({ baselines: { lookalike: lookalikeBaseline([], { 'examp1e.com': NOW }) } })
  );
  // Long after it dropped, someone else registers it (and CT forgot the old entry).
  table['examp1e.com'] = [cert('p9', ['examp1e.com'])];
  const later = NOW + 400 * DAY;
  const newOwner = await createCtCollector({ source: source(table) })(
    ctx({
      now: new Date(later * 1000),
      baselines: { lookalike: lookalikeBaseline([], { 'examp1e.com': later }, NOW + 60 * DAY) },
    })
  );
  assert.deepEqual(kinds(newOwner), [['new_cert', 'medium', goingUp]]);
  assert.notEqual(newOwner.findings[0].fingerprint, firstOwner.findings[0].fingerprint);
});

test('collector: the organization’s own watched domains are never checked as lookalikes', async () => {
  const certsFor = source({ 'example.net': [cert('own1', ['shop.example.net'])] });
  const earlier: CollectorContext['earlier'] = {
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      // An old baseline that still lists example.net, which the org now watches too.
      lookalikes: { registered: ['example.net', 'exmple.com'], newlyRegistered: ['example.net'] },
    },
  };
  const out = await createCtCollector({ source: certsFor })(
    ctx({ earlier, watchedDomains: ['example.com', 'shop.example.net'] })
  );
  assert.ok(!certsFor.asked.includes('example.net'));
  assert.deepEqual(out.findings, []);
  assert.equal(out.details?.lookalikes_registered, 1);
});

test('collector: a lookalike crt.sh can’t answer for moves to the back of the rotation', async () => {
  const lookalikes = ['a.example.org', 'b.example.org', 'c.example.org', 'd.example.org'];
  const earlier: CollectorContext['earlier'] = {
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      lookalikes: { registered: lookalikes, newlyRegistered: [] },
    },
  };
  const timeout = new CollectorError('crt.sh did not answer in time; will retry', true);
  const table = { 'a.example.org': timeout as CtCertificate[] | Error };
  const at = (hours: number) => new Date((NOW + hours * 3_600) * 1000);

  // Own scope: a.example.org fails (crt.sh struggling: stop asking this run), the run still succeeds.
  const s1 = source(table);
  const first = await createCtCollector({ source: s1 })(ctx({ earlier, now: at(0) }));
  assert.deepEqual(s1.asked, ['example.com', 'a.example.org']);
  assert.equal(parseCtSnapshot(first.snapshot)?.lookalike_failures?.['a.example.org']?.count, 1);
  // Next run: the others first, the failed one last.
  const s2 = source(table);
  const second = await createCtCollector({ source: s2 })(
    ctx({ earlier, previous: first.snapshot, now: at(24) })
  );
  assert.deepEqual(s2.asked, ['example.com', 'b.example.org', 'c.example.org', 'd.example.org']);
  // And then it comes round again; a good answer clears its failure record.
  const s3 = source({});
  const third = await createCtCollector({ source: s3 })(
    ctx({ earlier, previous: second.snapshot, now: at(48) })
  );
  assert.equal(s3.asked[1], 'a.example.org');
  assert.equal(parseCtSnapshot(third.snapshot)?.lookalike_failures, undefined);

  // Brand scope: nothing checked is an error (retried), but what was tried is kept,
  // so the retry starts with the other lookalikes instead of failing the same way forever.
  const b1 = source(table);
  let progress: unknown;
  await assert.rejects(
    createCtCollector({ source: b1 })(ctx({ scope: 'brand', earlier, now: at(0) })),
    (err: unknown) => {
      assert.ok(err instanceof CollectorError && err.transient);
      progress = err.progress;
      return true;
    }
  );
  assert.equal(parseCtSnapshot(progress)?.lookalike_failures?.['a.example.org']?.transient, true);
  const b2 = source(table);
  const retried = await createCtCollector({ source: b2 })(
    ctx({ scope: 'brand', earlier, previous: progress, now: at(1) })
  );
  assert.deepEqual(b2.asked, ['b.example.org', 'c.example.org', 'd.example.org']);
  assert.equal(retried.details?.lookalikes_checked, 3);
});

test('collector: a lookalike that fails for good is skipped for a week, without stopping the run', async () => {
  const lookalikes = ['a.example.org', 'b.example.org'];
  const earlier: CollectorContext['earlier'] = {
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      lookalikes: { registered: lookalikes, newlyRegistered: [] },
    },
  };
  const tooBig = new CollectorError('crt.sh returned only part of the certificates', false);
  const table = { 'a.example.org': tooBig as CtCertificate[] | Error };
  const at = (days: number) => new Date((NOW + days * 86_400) * 1000);

  const s1 = source(table);
  const first = await createCtCollector({ source: s1 })(ctx({ earlier, now: at(0) }));
  assert.deepEqual(
    s1.asked,
    ['example.com', 'a.example.org', 'b.example.org'],
    'not a reason to stop'
  );
  const s2 = source(table);
  const second = await createCtCollector({ source: s2 })(
    ctx({ earlier, previous: first.snapshot, now: at(1) })
  );
  assert.deepEqual(s2.asked, ['example.com', 'b.example.org'], 'backing off');
  const s3 = source(table);
  await createCtCollector({ source: s3 })(ctx({ earlier, previous: second.snapshot, now: at(8) }));
  assert.ok(s3.asked.includes('a.example.org'), 'tried again after a week');
});

test('collector: brand domains check lookalikes only; crt.sh trouble stops further requests', async () => {
  const flaky = source({
    'exmple.com': new CollectorError(
      'crt.sh is temporarily unavailable (HTTP 502); will retry',
      true
    ),
    'examp1e.com': [],
  });
  const earlier: CollectorContext['earlier'] = {
    lookalike: {
      findings: [],
      status: 'ok',
      note: '',
      lookalikes: { registered: ['examp1e.com', 'exmple.com'], newlyRegistered: ['exmple.com'] },
    },
  };
  // Nothing could be checked: the collector fails (and will be retried) instead of baselining nothing.
  await assert.rejects(
    createCtCollector({ source: flaky })(ctx({ scope: 'brand', earlier })),
    (err: unknown) => err instanceof CollectorError && err.transient && err.progress !== undefined
  );
  assert.deepEqual(
    flaky.asked,
    ['exmple.com'],
    'the brand domain itself is never queried; one failure stops the run'
  );

  // Without the lookalike collector, CT has nothing to do for a brand domain.
  const idle = await createCtCollector({ source: source({}) })({
    ...ctx({ scope: 'brand' }),
    domain: {
      ...ctx().domain,
      scope: 'brand',
      collectors: { ct: true, lookalike: false, rdap: true, dns: true },
    },
  });
  assert.equal(idle.status, 'unsupported');
});

test('snapshot: unreadable snapshots read as "no baseline"', () => {
  assert.equal(parseCtSnapshot(null), null);
  assert.equal(parseCtSnapshot({ v: 2 }), null);
  assert.deepEqual(
    parseCtSnapshot({ v: 1, domain: { certs: { a: 1, b: 'x' }, names: ['x', 3], issuers: [] } }),
    {
      v: 1,
      domain: { certs: { a: 1 }, names: ['x'], issuers: [] },
    }
  );
});
