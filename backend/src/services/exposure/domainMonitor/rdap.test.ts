/**
 * RDAP without the network: IANA bootstrap parsing, longest-suffix lookup and
 * caching; the base-URL SSRF validator (an accept/reject table, with an
 * injected resolver); response parsing; the snapshot diff and its severities;
 * expiry warnings and their per-expiry-date fingerprint; and the client's
 * request and error mapping. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  IANA_RDAP_BOOTSTRAP_URL,
  RdapClient,
  createRdapCollector,
  diffRdap,
  expiryFingerprint,
  expiryState,
  mergeRdapSnapshot,
  normalizeRdapStatus,
  parseBootstrap,
  parseRdapDomain,
  rdapDomainUrl,
  rdapServersFor,
  validateRdapBaseUrl,
  type RdapDomainInfo,
  type RdapSnapshot,
  type RdapSource,
} from './rdap';
import type { HttpGet, HttpGetOptions, HttpGetResult } from './http';
import type { LookupAllFn } from './netSafety';
import { CollectorError, type CollectorContext } from './types';

const BOOTSTRAP = {
  version: '1.0',
  publication: '2026-09-30T23:00:03Z',
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['uk'], ['https://rdap.nominet.uk/uk/']],
    [['kg'], ['http://rdap.cctld.kg/']],
    [['multi'], ['http://rdap.multi.example/', 'https://rdap.nic.multi/']],
    'junk',
    [['broken']],
  ],
};

// ---- bootstrap ---------------------------------------------------------------------------

test('bootstrap: parsed defensively; the longest matching suffix wins', () => {
  const bootstrap = parseBootstrap(BOOTSTRAP);
  assert.deepEqual(rdapServersFor(bootstrap, 'example.com'), {
    suffix: 'com',
    urls: ['https://rdap.verisign.com/com/v1/'],
  });
  assert.equal(rdapServersFor(bootstrap, 'example.co.uk')?.suffix, 'uk');
  assert.equal(rdapServersFor(bootstrap, 'example.zz'), null);

  const withSecondLevel = parseBootstrap({
    services: [...BOOTSTRAP.services, [['co.uk'], ['https://rdap.example-sld.uk/']]],
  });
  assert.equal(rdapServersFor(withSecondLevel, 'example.co.uk')?.suffix, 'co.uk');

  assert.throws(() => parseBootstrap({ services: [] }), CollectorError);
  assert.throws(() => parseBootstrap('nope'), CollectorError);
});

function counter(responses: Array<HttpGetResult | Error>) {
  const calls: Array<{ url: URL; options: HttpGetOptions }> = [];
  const transport: HttpGet = async (url, options) => {
    calls.push({ url, options });
    const next = responses.length > 1 ? responses.shift() : responses[0];
    if (next instanceof Error) throw next;
    return next as HttpGetResult;
  };
  return { transport, calls };
}

const json = (body: unknown, status = 200): HttpGetResult => ({
  status,
  headers: {},
  body: Buffer.from(JSON.stringify(body)),
});

test('bootstrap: cached for a day, served stale for a week when IANA is unreachable', async () => {
  let now = 0;
  const responses: Array<HttpGetResult | Error> = [json(BOOTSTRAP)];
  const { transport, calls } = counter(responses);
  const client = new RdapClient({ transport, now: () => now });
  await client.bootstrap();
  now = 23 * 3600_000;
  await client.bootstrap();
  assert.equal(calls.length, 1, 'cached');
  assert.equal(calls[0].url.href, IANA_RDAP_BOOTSTRAP_URL);

  responses[0] = new Error('network down');
  now = 25 * 3600_000;
  assert.ok((await client.bootstrap()).services.has('com'), 'stale copy while IANA is down');
  now = 8 * 24 * 3600_000;
  await assert.rejects(
    client.bootstrap(),
    (err: unknown) => err instanceof CollectorError && err.transient
  );
});

// ---- SSRF: the base-URL validator ------------------------------------------------------------

/** Resolves names from a table; unknown names fail like NXDOMAIN. */
function resolverFrom(table: Record<string, string[]>): LookupAllFn {
  return async (hostname) => {
    const addresses = table[hostname];
    if (!addresses) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
}

const RESOLVER = resolverFrom({
  'rdap.verisign.com': ['72.13.58.112', '2620:74:1b::1:1'],
  'rdap.nat64-registry.net': ['64:ff9b::480d:3a70'], // NAT64 of a public IPv4
  'rdap.private-registry.net': ['10.1.2.3'],
  'rdap.loopback-registry.net': ['127.0.0.1'],
  'rdap.metadata-registry.net': ['169.254.169.254'],
  'rdap.cgnat-registry.net': ['100.64.0.10'],
  'rdap.ula-registry.net': ['fd12:3456:789a::1'],
  'rdap.v6loop-registry.net': ['::1'],
  'rdap.mapped-registry.net': ['::ffff:10.0.0.1'],
  'rdap.nat64private-registry.net': ['64:ff9b::a00:1'],
  'rdap.mixed-registry.net': ['72.13.58.112', '192.168.1.10'],
  'rdap.reserved-registry.net': ['240.0.0.1'],
});

test('SSRF: the RDAP base-URL validator accepts only https on public hosts', async () => {
  const table: Array<[string, boolean, RegExp?]> = [
    ['https://rdap.verisign.com/com/v1/', true],
    ['https://rdap.nat64-registry.net/', true],
    ['http://rdap.verisign.com/com/v1/', false, /not https/],
    ['ftp://rdap.verisign.com/', false, /not https/],
    ['https://user:pw@rdap.verisign.com/', false, /credentials/],
    ['https://rdap.verisign.com:8443/', false, /port/],
    ['https://93.184.216.34/rdap/', false, /IP-address/],
    ['https://[2606:2800:220:1::]/rdap/', false, /IP-address/],
    ['https://2130706433/', false, /IP-address/], // the URL parser turns this into 127.0.0.1
    ['https://localhost/', false, /single-label|internal/],
    ['https://rdap.localhost/', false, /internal-only/],
    ['https://rdap.corp.local/', false, /internal-only/],
    ['https://rdap.internal/', false, /internal-only/],
    ['https://registry.lan/', false, /internal-only/],
    ['not a url', false, /not a valid URL/],
    ['https://rdap.private-registry.net/', false, /non-public/],
    ['https://rdap.loopback-registry.net/', false, /non-public/],
    ['https://rdap.metadata-registry.net/', false, /non-public/],
    ['https://rdap.cgnat-registry.net/', false, /non-public/],
    ['https://rdap.ula-registry.net/', false, /non-public/],
    ['https://rdap.v6loop-registry.net/', false, /non-public/],
    ['https://rdap.mapped-registry.net/', false, /non-public/],
    ['https://rdap.nat64private-registry.net/', false, /non-public/],
    ['https://rdap.mixed-registry.net/', false, /non-public/],
    ['https://rdap.reserved-registry.net/', false, /non-public/],
    ['https://rdap.unresolvable-registry.net/', false, /could not resolve/],
  ];
  for (const [raw, accepted, reason] of table) {
    const check = await validateRdapBaseUrl(raw, RESOLVER);
    assert.equal(check.ok, accepted, `${raw}: ${check.ok ? 'accepted' : check.reason}`);
    if (!check.ok && reason) assert.match(check.reason, reason, raw);
  }

  // Why it failed decides what happens next: unsupported, a visible error, or a retry.
  const kind = async (raw: string) => {
    const check = await validateRdapBaseUrl(raw, RESOLVER);
    return check.ok ? 'ok' : check.kind;
  };
  assert.equal(await kind('http://rdap.verisign.com/'), 'unusable');
  assert.equal(await kind('https://rdap.private-registry.net/'), 'unsafe');
  assert.equal(await kind('https://rdap.unresolvable-registry.net/'), 'unresolvable');
});

test('SSRF: the domain fills one path segment under the base and never changes the host', () => {
  const base = new URL('https://rdap.verisign.com/com/v1/');
  assert.equal(
    rdapDomainUrl(base, 'example.com').href,
    'https://rdap.verisign.com/com/v1/domain/example.com'
  );
  for (const hostile of ['../../evil', 'example.com/../../x', 'a@b.com', '//evil.example/x', '']) {
    assert.throws(() => rdapDomainUrl(base, hostile), /not a domain name/, hostile);
  }
});

// ---- response parsing -------------------------------------------------------------------------

const VERISIGN_SAMPLE = {
  objectClassName: 'domain',
  handle: '2336799_DOMAIN_COM-VRSN',
  ldhName: 'EXAMPLE.COM',
  status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited'],
  entities: [
    {
      objectClassName: 'entity',
      handle: '376',
      roles: ['registrar'],
      publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }],
      vcardArray: [
        'vcard',
        [
          ['version', {}, 'text', '4.0'],
          ['fn', {}, 'text', 'RESERVED-Internet Assigned Numbers Authority'],
        ],
      ],
    },
  ],
  events: [
    { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
    { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' },
    { eventAction: 'last changed', eventDate: '2026-08-14T08:01:43Z' },
    { eventAction: 'last update of RDAP database', eventDate: '2026-10-11T01:02:53Z' },
  ],
  secureDNS: { delegationSigned: true },
  nameservers: [
    { objectClassName: 'nameserver', ldhName: 'HERA.NS.CLOUDFLARE.COM' },
    { objectClassName: 'nameserver', ldhName: 'ELLIOTT.NS.CLOUDFLARE.COM.' },
  ],
};

test('parse: registrar, sorted lowercase nameservers, status, DNSSEC and events', () => {
  const info = parseRdapDomain(VERISIGN_SAMPLE);
  assert.deepEqual(info, {
    ldhName: 'example.com',
    registrar: { name: 'RESERVED-Internet Assigned Numbers Authority', iana_id: '376' },
    nameservers: ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com'],
    status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited'],
    dnssec: true,
    registeredAt: '1995-08-14T04:00:00.000Z',
    expiresAt: '2027-08-13T04:00:00.000Z',
    lastChangedAt: '2026-08-14T08:01:43.000Z',
  });
  assert.equal(normalizeRdapStatus('clientTransferProhibited'), 'client transfer prohibited');
  assert.equal(normalizeRdapStatus('ok'), 'active');

  const sparse = parseRdapDomain({ objectClassName: 'domain', nameservers: [], status: [] });
  assert.deepEqual(
    [sparse.registrar, sparse.nameservers, sparse.status, sparse.dnssec, sparse.expiresAt],
    [null, null, null, null, null],
    'fields a server leaves out are "not reported", not empty'
  );
  assert.throws(() => parseRdapDomain({ objectClassName: 'entity' }), CollectorError);
  assert.throws(() => parseRdapDomain([]), CollectorError);
});

// ---- diff & expiry --------------------------------------------------------------------------------

const baseInfo = (): RdapDomainInfo => parseRdapDomain(VERISIGN_SAMPLE);
const baseSnapshot = (): RdapSnapshot => mergeRdapSnapshot(null, baseInfo());

test('diff: nameserver and registrar changes are critical, status and DNSSEC high', () => {
  const info = baseInfo();
  info.nameservers = ['ns1.attacker.example', 'ns2.attacker.example'];
  info.registrar = { name: 'Other Registrar LLC', iana_id: '9999' };
  info.status = ['client delete prohibited', 'client update prohibited']; // transfer lock removed
  info.dnssec = false;
  assert.deepEqual(
    diffRdap(baseSnapshot(), info).map((c) => [c.field, c.severity]),
    [
      ['nameservers', 'critical'],
      ['registrar', 'critical'],
      ['status', 'high'],
      ['dnssec', 'high'],
    ]
  );
});

test('diff: renames, grace periods and missing fields are not changes', () => {
  const info = baseInfo();
  info.registrar = { name: 'IANA (renamed)', iana_id: '376' }; // same IANA id
  info.status = [...(info.status ?? []), 'auto renew period'];
  info.expiresAt = '2028-08-13T04:00:00.000Z'; // renewed
  assert.deepEqual(diffRdap(baseSnapshot(), info), []);

  const missing: RdapDomainInfo = {
    ...baseInfo(),
    nameservers: null,
    registrar: null,
    status: null,
    dnssec: null,
  };
  assert.deepEqual(diffRdap(baseSnapshot(), missing), []);
  const merged = mergeRdapSnapshot(baseSnapshot(), missing);
  assert.deepEqual(
    merged.nameservers,
    baseSnapshot().nameservers,
    'the baseline keeps the last known value'
  );
});

test('expiry: warns inside the window (medium; high once expired), once per expiry date', () => {
  const now = new Date('2026-10-11T00:00:00Z');
  assert.equal(expiryState('2026-12-31T00:00:00Z', now, 30), null, 'outside the window');
  assert.deepEqual(expiryState('2026-10-23T00:00:00Z', now, 30), { daysLeft: 12, expired: false });
  assert.deepEqual(expiryState('2026-10-01T00:00:00Z', now, 30), { daysLeft: -10, expired: true });
  assert.equal(expiryState(null, now, 30), null);

  const fp = expiryFingerprint('example.com', '2026-10-23T00:00:00.000Z');
  assert.equal(
    expiryFingerprint('example.com', '2026-10-23T04:00:00Z'),
    fp,
    'same date, same fingerprint'
  );
  assert.notEqual(
    expiryFingerprint('example.com', '2027-10-23T00:00:00Z'),
    fp,
    'a renewal is a new term'
  );
  assert.notEqual(expiryFingerprint('example.org', '2026-10-23T00:00:00Z'), fp);
});

// ---- collector ---------------------------------------------------------------------------------------

function ctx(previous: unknown, now = '2026-10-11T00:00:00Z'): CollectorContext {
  return {
    domain: {
      id: 3,
      domain: 'www.example.com',
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
    now: new Date(now),
    trigger: 'schedule',
    earlier: {},
    baselines: {},
  };
}

const fixed = (info: RdapDomainInfo): RdapSource & { asked: string[] } => {
  const asked: string[] = [];
  return {
    asked,
    lookup: async (name) => {
      asked.push(name);
      return { kind: 'ok', info, server: 'rdap.verisign.com' };
    },
  };
};

test('collector: the first run is a silent baseline, but an expiring domain warns at once', async () => {
  const source = fixed(baseInfo());
  const first = await createRdapCollector({ source })(ctx(null));
  assert.deepEqual(source.asked, ['example.com'], 'RDAP is asked about the registered name');
  assert.equal(first.status, 'baseline');
  assert.deepEqual(first.findings, []);

  const expiring = await createRdapCollector({ source })(ctx(null, '2027-08-01T00:00:00Z'));
  assert.deepEqual(
    expiring.findings.map((f) => [f.eventType, f.severity, f.title]),
    [['expiry_warning', 'medium', 'example.com registration expires in 12 days (2027-08-13)']]
  );
  // The next run in the same term: same fingerprint, so no second alert.
  const again = await createRdapCollector({ source })(
    ctx(expiring.snapshot, '2027-08-02T00:00:00Z')
  );
  assert.equal(again.findings[0].fingerprint, expiring.findings[0].fingerprint);
});

test('collector: a hijack-shaped change becomes rdap_change findings', async () => {
  const first = await createRdapCollector({ source: fixed(baseInfo()) })(ctx(null));
  const hijacked = { ...baseInfo(), nameservers: ['ns1.attacker.example'] };
  const second = await createRdapCollector({ source: fixed(hijacked) })(ctx(first.snapshot));
  assert.deepEqual(
    second.findings.map((f) => [f.eventType, f.severity, f.title]),
    [['rdap_change', 'critical', 'Nameservers changed for example.com']]
  );
  assert.deepEqual(second.findings[0].detail.added, ['ns1.attacker.example']);
});

test('collector: TLDs without (usable) RDAP degrade to "unsupported" with no findings', async () => {
  const { transport } = counter([json(BOOTSTRAP)]);
  const client = new RdapClient({ transport, lookup: RESOLVER });
  for (const [domain, reason] of [
    ['example.zz', /no RDAP service is published for \.zz/],
    ['example.kg', /not https/],
  ] as const) {
    const out = await createRdapCollector({ source: client })({
      ...ctx(null),
      domain: { ...ctx(null).domain, domain },
    });
    assert.equal(out.status, 'unsupported');
    assert.match(out.note, reason);
    assert.deepEqual(out.findings, []);
    assert.equal(out.snapshot, undefined, 'no baseline is written');
  }
});

test('client: a server resolving privately is an error; one not resolving now is retried', async () => {
  const bootstrap = parseBootstrap({
    services: [
      [['bad'], ['https://rdap.private-registry.net/']],
      [['flaky'], ['https://rdap.unresolvable-registry.net/']],
    ],
  });
  const client = new RdapClient({
    transport: async () => json({}),
    lookup: RESOLVER,
  });
  client.bootstrap = async () => bootstrap;
  await assert.rejects(
    client.lookup('example.bad'),
    (err: unknown) =>
      err instanceof CollectorError && !err.transient && /refused to contact/.test(err.message)
  );
  await assert.rejects(
    client.lookup('example.flaky'),
    (err: unknown) => err instanceof CollectorError && err.transient
  );
});

test('client: the request goes to the validated server, pinned, and failures map sensibly', async () => {
  const bootstrap = json(BOOTSTRAP);
  const run = async (answer: HttpGetResult | Error) => {
    const { transport, calls } = counter([bootstrap, answer]);
    const client = new RdapClient({ transport, lookup: RESOLVER });
    const result = client.lookup('example.com');
    return { result, calls };
  };

  const good = await run(json(VERISIGN_SAMPLE));
  const ok = await good.result;
  assert.equal(ok.kind, 'ok');
  const rdapCall = good.calls[1];
  assert.equal(rdapCall.url.href, 'https://rdap.verisign.com/com/v1/domain/example.com');
  assert.ok(rdapCall.options.resolve, 'the connection is pinned to vetted addresses');
  await assert.rejects(
    rdapCall.options.resolve?.('rdap.private-registry.net') as Promise<unknown>,
    /non-public/
  );
  assert.ok(rdapCall.options.maxBytes <= 1024 * 1024);

  const cases: Array<[HttpGetResult, boolean]> = [
    [json({}, 404), false],
    [json({}, 503), true],
    [json({}, 429), true],
    [{ status: 302, headers: { location: 'https://evil.example/' }, body: Buffer.alloc(0) }, false],
    [{ status: 200, headers: {}, body: Buffer.from('<html>') }, true],
  ];
  for (const [answer, transient] of cases) {
    const { result } = await run(answer);
    await assert.rejects(
      result,
      (err: unknown) => err instanceof CollectorError && err.transient === transient,
      `HTTP ${answer.status}`
    );
  }
});
