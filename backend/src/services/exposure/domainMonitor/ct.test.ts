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
  CtClient,
  MAX_INDIVIDUAL_FINDINGS,
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

test('client: constant host, the identity only in encoded query parameters, bare + subdomain queries', async () => {
  const urls: URL[] = [];
  const transport: HttpGet = async (url) => {
    urls.push(url);
    return ok([]);
  };
  await new CtClient({ transport, pacer: noPacing }).certificatesFor('my-company.example');
  assert.equal(urls.length, 2);
  for (const url of urls) {
    assert.equal(url.origin, new URL(CRTSH_BASE).origin);
    assert.equal(url.pathname, '/');
    assert.equal(url.searchParams.get('output'), 'json');
    assert.equal(url.searchParams.get('exclude'), 'expired');
    assert.equal(url.searchParams.get('deduplicate'), 'Y');
    assert.equal(url.searchParams.get('match'), 'ILIKE', 'explicit: hyphens change the auto mode');
  }
  assert.deepEqual(
    urls.map((u) => u.searchParams.get('q')),
    ['my-company.example', '%.my-company.example']
  );
  assert.match(crtshQueryUrl('%.example.com').search, /q=%25\.example\.com/);
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
    now: new Date(NOW * 1000),
    trigger: 'schedule',
    earlier: overrides.earlier ?? {},
    baselines: overrides.baselines ?? {},
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
  const second = await createCtCollector({ source: certsFor })(
    withCap(
      ctx({
        previous: first.snapshot,
        earlier: lookalikeRun(
          ['aaa-example.com', 'bbb-example.com'],
          ['aaa-example.com', 'bbb-example.com']
        ),
      })
    )
  );
  assert.deepEqual(
    second.findings.map((f) => f.detail.lookalike),
    ['aaa-example.com']
  );
  assert.deepEqual(parseCtSnapshot(second.snapshot)?.pending_new, ['bbb-example.com']);
  // Next run: the lookalike collector no longer calls it new, but CT still does.
  const third = await createCtCollector({ source: certsFor })(
    withCap(
      ctx({
        previous: second.snapshot,
        earlier: lookalikeRun(['aaa-example.com', 'bbb-example.com'], []),
      })
    )
  );
  assert.deepEqual(
    third.findings.map((f) => f.detail.lookalike),
    ['bbb-example.com']
  );
  assert.equal(parseCtSnapshot(third.snapshot)?.pending_new, undefined);
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
    (err: unknown) => err instanceof CollectorError && err.transient
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
