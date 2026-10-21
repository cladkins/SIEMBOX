/**
 * Cert Spotter as the CT collector's fallback, without the network: parsing
 * real Cert Spotter pages (serial and issuer from the DER), malformed rows,
 * pagination, 429 / Retry-After and the process-wide pause, the API key (sent
 * only when set, never in a message), the fallback decision, and — with
 * fixtures describing the same certificates as crt.sh and Cert Spotter each
 * do — that alternating sources raises nothing new while a genuinely new
 * certificate seen through either one still alerts.
 * Fixtures: testdata/ct-sources.json. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import util from 'util';
import {
  CERTSPOTTER_BASE,
  CERTSPOTTER_DEFAULT_RETRY_AFTER_SECONDS,
  CertSpotterClient,
  CertSpotterError,
  certSpotterPausedUntil,
  parseCertSpotterResponse,
  parseRetryAfterSeconds,
  resetCertSpotterRateLimit,
} from './certSpotter';
import {
  CtTooLargeError,
  createCtCollector,
  createPacer,
  parseCrtshResponse,
  parseCtSnapshot,
  type CertificateSource,
  type CtCertificate,
} from './ct';
import { FallbackCertificateSource } from './ctFallback';
import { HttpError, type HttpGet, type HttpGetOptions, type HttpGetResult } from './http';
import { CollectorError, type CollectorContext, type CollectorOutput } from './types';

const fixtures = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'testdata', 'ct-sources.json'), 'utf8')
) as {
  real_certspotter_page: Array<Record<string, unknown>>;
  certspotter: Record<string, Record<string, unknown>>;
  crtsh: Record<string, Record<string, unknown>>;
};
const KNOWN = ['c1', 'c2', 'c3', 'c4'] as const;
const spotterRows = (...names: string[]) => names.map((n) => fixtures.certspotter[n]);
const crtshRows = (...names: string[]) => names.map((n) => fixtures.crtsh[n]);

const API_KEY = '4242_k3y-ThatMustNeverLeak.abc';
const noPacing = createPacer(0, async () => undefined);
const json = (body: unknown, headers: Record<string, string> = {}): HttpGetResult => ({
  status: 200,
  headers,
  body: Buffer.from(JSON.stringify(body)),
});
const status = (code: number, headers: Record<string, string> = {}): HttpGetResult => ({
  status: code,
  headers,
  body: Buffer.alloc(0),
});

interface Recorded {
  url: URL;
  options: HttpGetOptions;
}
/** A transport answering from a queue of responses (or errors), recording each request. */
function scripted(...answers: Array<HttpGetResult | Error>): HttpGet & { calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fn = (async (url: URL, options: HttpGetOptions) => {
    calls.push({ url, options });
    const next = answers.shift();
    if (next === undefined) throw new Error('unexpected request');
    if (next instanceof Error) throw next;
    return next;
  }) as HttpGet & { calls: Recorded[] };
  fn.calls = calls;
  return fn;
}

/** One page of the given fixture rows, then the empty last page. */
const pages = (...rows: Array<Record<string, unknown>[]>) =>
  scripted(...rows.map((r) => json(r)), json([], { 'retry-after': '3600' }));

beforeEach(() => resetCertSpotterRateLimit());

// ---- parsing -----------------------------------------------------------------------

test('parse: a real Cert Spotter page — serial and issuer come from the DER', () => {
  const certs = parseCertSpotterResponse(fixtures.real_certspotter_page, 'discord.com');
  assert.equal(certs.length, 2);
  for (const [i, cert] of certs.entries()) {
    const row = fixtures.real_certspotter_page[i];
    assert.equal(cert.source, 'certspotter');
    assert.equal(cert.crtshId, null);
    assert.equal(cert.certspotterId, row.id);
    assert.equal(cert.certSha256, row.cert_sha256);
    assert.equal(cert.issuerLabel, 'Google Trust Services');
    assert.equal(cert.issuerKey, 'googletrustservices');
    assert.match(cert.serial ?? '', /^[1-9a-f][0-9a-f]*$/, 'lowercase, no leading zeros');
    assert.equal(cert.key, `googletrustservices:${cert.serial}`);
    assert.deepEqual(cert.names, ['*.discord.com', 'discord.com']);
    assert.equal(cert.commonName, 'discord.com');
    assert.equal(cert.notAfter, new Date(String(row.not_after)).toISOString());
  }
  assert.equal(certs[0].serial, 'f98b6d21edd4131a0efcbca43ee1ff85');
});

test('parse: malformed rows are skipped; unreadable DER falls back to the TBS hash', () => {
  const good = fixtures.certspotter.c1;
  const rows = [
    null,
    'nope',
    { ...good, id: 7 }, // id must be a string
    { ...good, id: 'x y' },
    { ...good, tbs_sha256: 'not-hex' },
    { ...good, dns_names: ['other.org'], cert_der: undefined }, // nothing under the domain
    { ...good, id: '900', dns_names: 'example.com', cert_der: 42 }, // no names at all
    // Unreadable DER: the TBS hash identifies it, the API's issuer names it.
    { ...good, id: '901', cert_der: 'AAAA', tbs_sha256: 'ab'.repeat(32) },
    // dns_names not expanded: the DER's DNS SANs stand in.
    { ...fixtures.certspotter.c3, dns_names: undefined },
  ];
  const certs = parseCertSpotterResponse(rows, 'example.com');
  assert.deepEqual(
    certs.map((c) => [c.key, c.names]),
    [
      [`certspotter:${'ab'.repeat(32)}`, ['example.com', 'www.example.com']],
      ['sectigolimited:7d1f00000000000000000000000000c3', ['mail.example.com']],
    ]
  );
  assert.equal(certs[0].serial, null);
  assert.equal(certs[0].issuerLabel, "Let's Encrypt");
  for (const body of [{ code: 'internal_error' }, 'busy', null]) {
    assert.throws(
      () => parseCertSpotterResponse(body, 'example.com'),
      (err: unknown) => err instanceof CertSpotterError && err.transient
    );
  }
});

test('identity: crt.sh and Cert Spotter give the same certificates the same keys', () => {
  const fromCrtsh = parseCrtshResponse(crtshRows(...KNOWN), 'example.com');
  const fromSpotter = parseCertSpotterResponse(spotterRows(...KNOWN), 'example.com');
  const view = (certs: CtCertificate[]) =>
    certs
      .map((c) => [c.key, c.issuerKey, c.serial, c.names.join(' '), c.notAfter])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  assert.deepEqual(view(fromSpotter), view(fromCrtsh));
  // Including "Cloudflare, Inc." (quoted by crt.sh, escaped in the DER) and a
  // serial crt.sh prints with a leading 00 byte (c2, a precertificate).
  const keys = fromCrtsh.map((c) => c.key).sort();
  assert.deepEqual(keys, [
    'cloudflareinc:a0b0c0d0e0f10111213141516171819',
    'letsencrypt:3ab5f1e2d3c4b5a69788796a5b4c3d2e1f0',
    'letsencrypt:f1e2d3c4b5a6978877665544332211aa',
    'sectigolimited:7d1f00000000000000000000000000c3',
  ]);
  const cf = fromSpotter.find((c) => c.issuerKey === 'cloudflareinc') as CtCertificate;
  assert.equal(cf.issuerLabel, 'Cloudflare, Inc.');
  assert.equal(cf.crtshId, null);
});

// ---- client -------------------------------------------------------------------------

test('client: constant host, encoded parameters, every page until the empty one', async () => {
  const transport = pages(spotterRows('c1', 'c2'), spotterRows('c3', 'c4'));
  const certs = await new CertSpotterClient({ transport, pacer: noPacing }).certificatesFor(
    'example.com'
  );
  assert.equal(certs.length, 4);
  assert.equal(transport.calls.length, 3);
  const [first, second, last] = transport.calls.map((c) => c.url);
  for (const url of [first, second, last]) {
    assert.equal(url.origin + url.pathname, CERTSPOTTER_BASE);
    assert.equal(url.searchParams.get('domain'), 'example.com');
    assert.equal(url.searchParams.get('include_subdomains'), 'true');
    assert.deepEqual(url.searchParams.getAll('expand'), ['dns_names', 'issuer', 'cert_der']);
  }
  assert.equal(first.searchParams.get('after'), null);
  assert.equal(second.searchParams.get('after'), fixtures.certspotter.c2.id, 'after = last id');
  assert.equal(last.searchParams.get('after'), fixtures.certspotter.c4.id);
});

test('client: too many pages is "too large"; a page that does not advance is transient', async () => {
  const looping = scripted(json(spotterRows('c1')), json(spotterRows('c1')));
  const client = (transport: HttpGet) =>
    new CertSpotterClient({ transport, pacer: noPacing, maxPages: 3 });
  let calls = 0;
  // Every page holds another issuance, and the last (empty) page never comes.
  const endless: HttpGet = async () => {
    calls++;
    return json([{ ...fixtures.certspotter.c1, id: String(100 + calls) }]);
  };
  await assert.rejects(
    client(endless).certificatesFor('example.com'),
    (err: unknown) => err instanceof CtTooLargeError && !err.transient && /3 pages/.test(err.message)
  );
  assert.equal(calls, 3);
  await assert.rejects(
    client(looping).certificatesFor('example.com'),
    (err: unknown) => err instanceof CertSpotterError && err.transient && /continued/.test(err.message)
  );
});

test('client: the API key goes in the Authorization header, only when set, and never in a message', async () => {
  const anonymous = pages(spotterRows('c1'));
  await new CertSpotterClient({ transport: anonymous, pacer: noPacing }).certificatesFor('example.com');
  for (const call of anonymous.calls) assert.equal(call.options.headers, undefined, 'no key, no header');

  const keyed = pages(spotterRows('c1'));
  const client = new CertSpotterClient({ apiKey: ` ${API_KEY} `, transport: keyed, pacer: noPacing });
  await client.certificatesFor('example.com');
  for (const call of keyed.calls) {
    assert.deepEqual(call.options.headers, { Authorization: `Bearer ${API_KEY}` });
    assert.ok(!call.url.href.includes(API_KEY), 'never in the URL');
  }
  assert.equal(client.hasApiKey, true);
  assert.ok(!JSON.stringify(client).includes(API_KEY), 'not in a JSON dump of the client');
  const quiet = new CertSpotterClient({ apiKey: API_KEY });
  assert.ok(!JSON.stringify(quiet).includes(API_KEY), 'not in a JSON dump of the client');
  assert.ok(!util.inspect(quiet, { depth: 5, showHidden: true }).includes(API_KEY), 'not in util.inspect');

  // A value that could break the header is never sent.
  const bad = pages([]);
  const refused = new CertSpotterClient({ apiKey: 'abc\r\nX-Evil: 1', transport: bad, pacer: noPacing });
  assert.equal(refused.hasApiKey, false);
  await refused.certificatesFor('example.com');
  assert.equal(bad.calls[0].options.headers, undefined);

  // Every failure message, with a key set: none of them carries it.
  const failures: Array<HttpGetResult | Error> = [
    status(401),
    status(402),
    status(403),
    status(404),
    status(500),
    status(429, { 'retry-after': '900' }),
    { status: 200, headers: {}, body: Buffer.from('<html>') },
    new HttpError('timeout', 'no complete response within 30000 ms', 'response'),
    new HttpError('network', 'ECONNRESET'),
  ];
  for (const failure of failures) {
    resetCertSpotterRateLimit();
    await assert.rejects(
      new CertSpotterClient({
        apiKey: API_KEY,
        transport: scripted(failure),
        pacer: noPacing,
      }).certificatesFor('example.com'),
      (err: unknown) =>
        err instanceof CollectorError && !err.message.includes(API_KEY) && !err.message.includes('4242')
    );
  }
});

test('client: status codes — auth and refusals are not transient, 5xx and bad bodies are', async () => {
  const cases: Array<[HttpGetResult | Error, string, boolean, RegExp]> = [
    [status(401), 'auth', false, /rejected the API key \(HTTP 401\).*Settings → Digital Risk/],
    [status(402), 'auth', false, /HTTP 402/],
    [status(403), 'refused', false, /refused the query for example\.com \(HTTP 403/],
    [status(400), 'refused', false, /HTTP 400/],
    [status(503), 'transient', true, /temporarily unavailable \(HTTP 503\)/],
    [{ status: 200, headers: {}, body: Buffer.from('<html>') }, 'transient', true, /not JSON/],
    [json({ code: 'service_outage' }), 'transient', true, /unexpected format/],
    [new HttpError('timeout', 't', 'connect'), 'transient', true, /did not answer in time/],
    [new HttpError('network', 'ECONNREFUSED'), 'transient', true, /could not be reached \(ECONNREFUSED\)/],
  ];
  for (const [answer, kind, transient, message] of cases) {
    await assert.rejects(
      new CertSpotterClient({ apiKey: API_KEY, transport: scripted(answer), pacer: noPacing }).certificatesFor(
        'example.com'
      ),
      (err: unknown) =>
        err instanceof CertSpotterError &&
        err.kind === kind &&
        err.transient === transient &&
        message.test(err.message),
      `${kind} ${message}`
    );
  }
  await assert.rejects(
    new CertSpotterClient({
      transport: scripted(new HttpError('too_large', 'big')),
      pacer: noPacing,
    }).certificatesFor('example.com'),
    (err: unknown) => err instanceof CtTooLargeError
  );
});

test('rate limit: a short Retry-After is waited out once; a long one pauses every request', async () => {
  let clock = Date.parse('2026-10-21T12:00:00Z');
  const slept: number[] = [];
  const options = {
    pacer: noPacing,
    now: () => clock,
    sleep: async (ms: number) => {
      slept.push(ms);
      clock += ms;
    },
  };
  // 429 with Retry-After: 2 -> wait 2 s, same page again, then carry on.
  const short = scripted(status(429, { 'retry-after': '2' }), json(spotterRows('c1')), json([]));
  const certs = await new CertSpotterClient({ ...options, transport: short }).certificatesFor('example.com');
  assert.equal(certs.length, 1);
  assert.deepEqual(slept, [2000]);
  assert.equal(short.calls[0].url.href, short.calls[1].url.href, 'the same page is asked again');

  // A second 429 in a row is not waited out in place.
  const twice = scripted(status(429, { 'retry-after': '1' }), status(429, { 'retry-after': '1' }));
  await assert.rejects(
    new CertSpotterClient({ ...options, transport: twice }).certificatesFor('example.com'),
    (err: unknown) => err instanceof CertSpotterError && err.kind === 'rate_limited' && err.transient
  );
  resetCertSpotterRateLimit();

  // Retry-After: 3600 without a key: transient, says when, suggests a key.
  const long = scripted(status(429, { 'retry-after': '3600' }));
  await assert.rejects(
    new CertSpotterClient({ ...options, transport: long }).certificatesFor('example.com'),
    (err: unknown) =>
      err instanceof CertSpotterError &&
      err.kind === 'rate_limited' &&
      err.transient &&
      err.retryAtMs === clock + 3_600_000 &&
      /add one in Settings → Digital Risk/.test(err.message) &&
      err.message.includes(new Date(clock + 3_600_000).toISOString())
  );
  assert.equal(certSpotterPausedUntil(clock), clock + 3_600_000);

  // While paused nothing is sent, for any name, with or without a key.
  const idle = scripted();
  for (const apiKey of [undefined, API_KEY]) {
    await assert.rejects(
      new CertSpotterClient({ ...options, apiKey, transport: idle }).certificatesFor('other.example'),
      (err: unknown) =>
        err instanceof CertSpotterError &&
        err.kind === 'rate_limited' &&
        (apiKey ? /this API key's limit/ : /add one/).test(err.message)
    );
  }
  assert.equal(idle.calls.length, 0);

  // Once the pause is over, requests go out again.
  clock += 3_600_001;
  assert.equal(certSpotterPausedUntil(clock), null);
  const after = pages(spotterRows('c1'));
  assert.equal(
    (await new CertSpotterClient({ ...options, transport: after }).certificatesFor('example.com')).length,
    1
  );
});

test('rate limit: Retry-After parsing', () => {
  const now = Date.parse('2026-10-21T12:00:00Z');
  assert.equal(parseRetryAfterSeconds('120', now), 120);
  assert.equal(parseRetryAfterSeconds(['30'], now), 30);
  assert.equal(parseRetryAfterSeconds('Wed, 21 Oct 2026 12:05:00 GMT', now), 300);
  assert.equal(parseRetryAfterSeconds('0', now), 1, 'at least a second');
  assert.equal(parseRetryAfterSeconds('99999999', now), 86_400, 'at most a day');
  for (const junk of [undefined, '', 'soon', '-5']) {
    assert.equal(parseRetryAfterSeconds(junk, now), CERTSPOTTER_DEFAULT_RETRY_AFTER_SECONDS);
  }
});

// ---- fallback decision ----------------------------------------------------------------

/** A source answering (or failing) from a table, counting what it was asked. */
function fake(table: Record<string, CtCertificate[] | Error>): CertificateSource & { asked: string[] } {
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

const crtshCerts = () => parseCrtshResponse(crtshRows(...KNOWN), 'example.com');
const spotterCerts = () => parseCertSpotterResponse(spotterRows(...KNOWN), 'example.com');
const busy = () => new CollectorError('crt.sh is temporarily unavailable (HTTP 502); will retry', true);

test('fallback: crt.sh answers -> crt.sh; Cert Spotter is not asked', async () => {
  const primary = fake({ 'example.com': crtshCerts() });
  const fallback = fake({});
  const answer = await new FallbackCertificateSource(primary, fallback).certificatesFor('example.com');
  assert.equal(answer.source, 'crtsh');
  assert.equal(answer.fallbackReason, undefined);
  assert.equal(answer.certs.length, 4);
  assert.deepEqual(fallback.asked, []);
});

test('fallback: crt.sh failing transiently -> Cert Spotter, and crt.sh is skipped for the rest of the run', async () => {
  const primary = fake({ 'example.com': busy(), 'examp1e.com': [] });
  const fallback = fake({ 'example.com': spotterCerts(), 'examp1e.com': [] });
  const source = new FallbackCertificateSource(primary, fallback);
  const first = await source.certificatesFor('example.com');
  assert.equal(first.source, 'certspotter');
  assert.match(first.fallbackReason ?? '', /HTTP 502/);
  assert.equal(first.certs.length, 4);
  const second = await source.certificatesFor('examp1e.com');
  assert.equal(second.source, 'certspotter');
  assert.deepEqual(primary.asked, ['example.com'], 'crt.sh is not asked again this run');
  assert.deepEqual(fallback.asked, ['example.com', 'examp1e.com']);
  // A new run (a new source) starts with crt.sh again.
  const next = new FallbackCertificateSource(fake({ 'example.com': crtshCerts() }), fallback);
  assert.equal((await next.certificatesFor('example.com')).source, 'crtsh');
});

test('fallback: crt.sh refusing a name as too large -> Cert Spotter, which pages through all of it', async () => {
  const tooLarge = new CtTooLargeError('crt.sh returned only part of the certificates for example.com');
  const answer = await new FallbackCertificateSource(
    fake({ 'example.com': tooLarge, 'other.example': [] }),
    fake({ 'example.com': spotterCerts() })
  ).certificatesFor('example.com');
  assert.equal(answer.source, 'certspotter');
  assert.match(answer.fallbackReason ?? '', /only part/);

  // Too large for both: still the per-name warning (CtTooLargeError), naming both reasons.
  const source = new FallbackCertificateSource(
    fake({ 'example.com': tooLarge, 'other.example': [] }),
    fake({ 'example.com': new CtTooLargeError('Cert Spotter lists more certificates (60 pages)') })
  );
  await assert.rejects(source.certificatesFor('example.com'), (err: unknown) => {
    return (
      err instanceof CtTooLargeError &&
      !err.transient &&
      /only part/.test(err.message) &&
      /Cert Spotter: Cert Spotter lists more/.test(err.message)
    );
  });
  // ... and it doesn't stop crt.sh being asked for the next name.
  assert.equal((await source.certificatesFor('other.example')).source, 'crtsh');
});

test('fallback: crt.sh refusing us (e.g. HTTP 403 from a proxy) is not papered over', async () => {
  const fallback = fake({ 'example.com': spotterCerts() });
  await assert.rejects(
    new FallbackCertificateSource(
      fake({ 'example.com': new CollectorError('crt.sh answered HTTP 403', false) }),
      fallback
    ).certificatesFor('example.com'),
    (err: unknown) => err instanceof CollectorError && !err.transient && err.message === 'crt.sh answered HTTP 403'
  );
  assert.deepEqual(fallback.asked, []);
});

test('fallback: both failing is transient (baseline kept), with both reasons', async () => {
  for (const failure of [
    new CertSpotterError('rate_limited', 'Cert Spotter is rate-limiting requests (add one in Settings → Digital Risk); will retry'),
    new CertSpotterError('auth', 'Cert Spotter rejected the API key (HTTP 401)'),
    new Error('socket hang up'),
  ]) {
    await assert.rejects(
      new FallbackCertificateSource(fake({ 'example.com': busy() }), fake({ 'example.com': failure })).certificatesFor(
        'example.com'
      ),
      (err: unknown) =>
        err instanceof CollectorError &&
        err.transient &&
        err.message.startsWith('crt.sh is temporarily unavailable (HTTP 502); Cert Spotter fallback failed too: ') &&
        err.message.includes(failure.message.replace(/; will retry$/, '')) &&
        err.message.endsWith('; will retry') &&
        err.message.length <= 300
    );
  }
});

// ---- the collector across sources -------------------------------------------------------

const NOW = Math.floor(Date.parse('2026-10-22T00:00:00Z') / 1000);

function ctx(previous: unknown, expectedCas: string[] = ["Let's Encrypt"]): CollectorContext {
  return {
    domain: {
      id: 9,
      domain: 'example.com',
      scope: 'own',
      expected_cas: expectedCas,
      collectors: { ct: true, lookalike: false, rdap: true, dns: true },
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

/** crt.sh up (answering with these rows) or down (502), Cert Spotter answering with these rows. */
function sources(crtsh: string[] | 'down', spotter: string[]): CertificateSource {
  const primary: CertificateSource = {
    certificatesFor: async (name) => {
      if (crtsh === 'down') throw busy();
      return parseCrtshResponse(crtshRows(...crtsh), name);
    },
  };
  const transport = pages(spotterRows(...spotter));
  return new FallbackCertificateSource(primary, new CertSpotterClient({ transport, pacer: noPacing }));
}

async function run(previous: unknown, source: CertificateSource): Promise<CollectorOutput> {
  return createCtCollector({ source })(ctx(previous));
}

test('cross-source: crt.sh -> Cert Spotter -> crt.sh on an unchanged domain raises nothing new', async () => {
  // Baseline via crt.sh: one finding per CA outside expected_cas (Sectigo, Cloudflare).
  const first = await run(null, sources([...KNOWN], []));
  assert.equal(first.status, 'baseline');
  assert.deepEqual(
    first.findings.map((f) => [f.eventType, f.detail.issuer_org]).sort(),
    [
      ['unexpected_ca', 'Cloudflare, Inc.'],
      ['unexpected_ca', 'Sectigo Limited'],
    ]
  );
  // crt.sh down: Cert Spotter describes the same certificates — nothing new.
  const second = await run(first.snapshot, sources('down', [...KNOWN]));
  assert.deepEqual(second.findings, []);
  assert.equal(second.details?.new_certificates, 0);
  assert.match(second.note, /source: Cert Spotter \(crt\.sh failed — crt\.sh is temporarily unavailable \(HTTP 502\)\)/);
  assert.deepEqual(second.details?.ct_sources, ['Cert Spotter']);
  assert.equal(second.details?.ct_fallback_used, 1);
  // Back on crt.sh: still nothing.
  const third = await run(second.snapshot, sources([...KNOWN], []));
  assert.deepEqual(third.findings, []);
  assert.match(third.note, /source: crt\.sh$/);
  // The snapshot holds each certificate once, whichever source last saw it.
  const snap = parseCtSnapshot(third.snapshot);
  assert.equal(Object.keys(snap?.domain?.certs ?? {}).length, 4);
  // A Cert Spotter answer missing some certificates (another log mix) is not a removal either.
  const partial = await run(third.snapshot, sources('down', ['c1']));
  assert.deepEqual(partial.findings, []);
  assert.equal(Object.keys(parseCtSnapshot(partial.snapshot)?.domain?.certs ?? {}).length, 4);
});

test('cross-source: a new certificate alerts once, whichever source sees it first', async () => {
  const base = await run(null, sources([...KNOWN], []));

  // A new host seen first through Cert Spotter (crt.sh down) ...
  const viaSpotter = await run(base.snapshot, sources('down', [...KNOWN, 'n1']));
  assert.deepEqual(
    viaSpotter.findings.map((f) => [f.eventType, f.severity, f.detail.new_names, f.detail.source]),
    [['new_cert', 'low', ['new.example.com'], 'Cert Spotter']]
  );
  const finding = viaSpotter.findings[0];
  assert.match(finding.description, /^Cert Spotter found a new certificate for new\.example\.com/);
  assert.match(finding.description, /https:\/\/crt\.sh\/\?sha256=[0-9a-f]{64}$/);
  assert.equal(finding.detail.crtsh_id, null);
  // ... is not new again when crt.sh catches up.
  const back = await run(viaSpotter.snapshot, sources([...KNOWN, 'n1'], []));
  assert.deepEqual(back.findings, []);

  // The same certificate seen first through crt.sh gets the same fingerprint.
  const viaCrtsh = await run(base.snapshot, sources([...KNOWN, 'n1'], []));
  assert.deepEqual(
    viaCrtsh.findings.map((f) => f.fingerprint),
    viaSpotter.findings.map((f) => f.fingerprint)
  );
  assert.match(viaCrtsh.findings[0].description, /https:\/\/crt\.sh\/\?id=15000000005$/);
});

test('cross-source: an unexpected CA alerts once — no duplicate when the other source reports it', async () => {
  const base = await run(null, sources([...KNOWN], []));
  // n2: a new certificate from Google Trust Services, outside expected_cas.
  const viaCrtsh = await run(base.snapshot, sources([...KNOWN, 'n2'], []));
  assert.deepEqual(
    viaCrtsh.findings.map((f) => [f.eventType, f.severity, f.detail.issuer_org]),
    [['unexpected_ca', 'high', 'Google Trust Services']]
  );
  const thenSpotter = await run(viaCrtsh.snapshot, sources('down', [...KNOWN, 'n2']));
  assert.deepEqual(thenSpotter.findings, [], 'not reported again by Cert Spotter');
  const viaSpotter = await run(base.snapshot, sources('down', [...KNOWN, 'n2']));
  assert.deepEqual(
    viaSpotter.findings.map((f) => f.fingerprint),
    viaCrtsh.findings.map((f) => f.fingerprint),
    'either way, one fingerprint: the finding is deduplicated'
  );
});

/** A snapshot as the collector wrote it before the fallback: keys are crt.sh CA id + serial. */
function legacySnapshot() {
  const certs: Record<string, number> = {};
  for (const name of KNOWN) {
    const row = fixtures.crtsh[name];
    const serial = String(row.serial_number).replace(/^0+(?=.)/, '');
    certs[`${row.issuer_ca_id}:${serial}`] = Math.floor(Date.parse(`${row.not_after}Z`) / 1000);
  }
  return {
    v: 1,
    domain: {
      certs,
      names: ['example.com', 'mail.example.com', 'shop.example.com', '*.shop.example.com', 'www.example.com'].sort(),
      issuers: ['cloudflareinc', 'letsencrypt', 'sectigolimited'],
    },
    expected_cas: ['letsencrypt'],
  };
}

test('upgrade: a snapshot keyed the old way raises nothing, through either source', async () => {
  const viaCrtsh = await run(legacySnapshot(), sources([...KNOWN], []));
  assert.deepEqual(viaCrtsh.findings, []);
  assert.equal(viaCrtsh.details?.new_certificates, 0);
  // The entries are re-keyed, not duplicated.
  assert.deepEqual(
    Object.keys(parseCtSnapshot(viaCrtsh.snapshot)?.domain?.certs ?? {}).sort(),
    parseCrtshResponse(crtshRows(...KNOWN), 'example.com').map((c) => c.key).sort()
  );

  // First run after the upgrade with crt.sh down: Cert Spotter can't name crt.sh's CA
  // id, so a known issuer's serial vouches for the legacy entry.
  const viaSpotter = await run(legacySnapshot(), sources('down', [...KNOWN]));
  assert.deepEqual(viaSpotter.findings, []);
  assert.equal(viaSpotter.details?.new_certificates, 0);
  assert.equal(Object.keys(parseCtSnapshot(viaSpotter.snapshot)?.domain?.certs ?? {}).length, 4);
  const after = await run(viaSpotter.snapshot, sources([...KNOWN], []));
  assert.deepEqual(after.findings, []);
});

test('upgrade: a serial alone never vouches for a certificate from an unknown CA', async () => {
  // A certificate from Google Trust Services reusing c1's serial is not c1.
  const forged = { ...fixtures.crtsh.n2, serial_number: fixtures.crtsh.c1.serial_number };
  const source: CertificateSource = {
    certificatesFor: async (name) => parseCrtshResponse([...crtshRows(...KNOWN), forged], name),
  };
  const out = await run(legacySnapshot(), source);
  assert.deepEqual(
    out.findings.map((f) => [f.eventType, f.detail.issuer_org]),
    [['unexpected_ca', 'Google Trust Services']]
  );
});
