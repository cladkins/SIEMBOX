/**
 * The HIBP v3 HTTP layer, against a mocked fetch: request shape (constant host,
 * user values confined to one encoded path segment, key + User-Agent headers,
 * no redirects) and the error mapping the leaked-credential loop relies on —
 * 404 is "nothing found", 401/403 are auth errors, 429 is rate limiting with
 * HIBP's retry-after, and 5xx/network/timeouts are transient.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import {
  DEFAULT_RETRY_AFTER_SECONDS,
  HibpClient,
  HibpError,
  MAX_SUBSCRIBED_DOMAINS_PARSED,
  parseRetryAfter,
  type FetchFn,
  type HibpErrorKind,
} from './hibpClient';

const KEY = '0123456789abcdef0123456789abcdef';

function fakeFetch(respond: (url: URL) => Response | Promise<Response>) {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  const fetchImpl: FetchFn = async (url, init) => {
    calls.push({ url, init });
    return respond(url);
  };
  return { fetchImpl, calls };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

async function expectHibpError(
  promise: Promise<unknown>,
  kind: HibpErrorKind,
  status: number | null
) {
  await assert.rejects(promise, (err: unknown) => {
    assert.ok(err instanceof HibpError, `expected HibpError, got ${String(err)}`);
    assert.equal(err.kind, kind);
    assert.equal(err.status, status);
    assert.ok(!err.message.includes(KEY), 'the key never appears in an error');
    return true;
  });
}

test('breachedAccount: constant host, encoded account, full models, key and User-Agent', async () => {
  const breach = { Name: 'Adobe', Title: 'Adobe', DataClasses: ['Email addresses', 'Passwords'] };
  const { fetchImpl, calls } = fakeFetch(() => json([breach]));
  const client = new HibpClient({ apiKey: KEY, fetchImpl });

  assert.deepEqual(await client.breachedAccount('alice+tag@example.com'), [breach]);

  const { url, init } = calls[0];
  assert.equal(url.origin, 'https://haveibeenpwned.com');
  assert.equal(url.pathname, '/api/v3/breachedaccount/alice%2Btag%40example.com');
  assert.equal(url.searchParams.get('truncateResponse'), 'false');
  const headers = new Headers(init.headers);
  assert.equal(headers.get('hibp-api-key'), KEY);
  assert.match(headers.get('user-agent') ?? '', /SIEMBox/);
  assert.equal(init.redirect, 'manual', 'redirects are never followed with the key attached');
});

test('a hostile value cannot leave its path segment or change the host', async () => {
  const { fetchImpl, calls } = fakeFetch(() => new Response(null, { status: 404 }));
  const client = new HibpClient({ apiKey: KEY, fetchImpl });
  await client.breachedAccount('x/../../evil?y=1#z@attacker.example');
  await client.breachedDomain('../subscription/status');

  for (const { url } of calls) {
    assert.equal(url.host, 'haveibeenpwned.com');
    const [, api, v3, endpoint, segment, ...rest] = url.pathname.split('/');
    assert.deepEqual([api, v3], ['api', 'v3']);
    assert.ok(['breachedaccount', 'breacheddomain'].includes(endpoint));
    assert.ok(segment.length > 0 && rest.length === 0, `one encoded segment, got ${url.pathname}`);
    assert.equal(url.hash, '');
  }

  // Dot segments would be resolved by the URL parser; they never reach fetch.
  const client2 = new HibpClient({ apiKey: KEY, fetchImpl });
  for (const value of ['..', '.', '']) {
    await expectHibpError(client2.breachedDomain(value), 'bad_request', null);
  }
  assert.equal(calls.length, 2);
});

test('404 means nothing was found: [] for an account, {} for a domain', async () => {
  const { fetchImpl } = fakeFetch(() => new Response(null, { status: 404 }));
  const client = new HibpClient({ apiKey: KEY, fetchImpl });
  assert.deepEqual(await client.breachedAccount('alice@example.com'), []);
  assert.deepEqual(await client.breachedDomain('example.com'), {});
});

test('429 is rate limiting and carries retry-after', async () => {
  const limited = fakeFetch(() =>
    json({ statusCode: 429, message: 'Rate limit is exceeded. Try again in 2 seconds.' }, 429, {
      'retry-after': '2',
    })
  );
  const client = new HibpClient({ apiKey: KEY, fetchImpl: limited.fetchImpl });
  await assert.rejects(client.breachedAccount('alice@example.com'), (err: unknown) => {
    assert.ok(err instanceof HibpError);
    assert.equal(err.kind, 'rate_limited');
    assert.equal(err.status, 429);
    assert.equal(err.retryAfterSeconds, 2);
    return true;
  });

  // Without the header, fall back to a conservative default rather than retrying at once.
  const bare = fakeFetch(() => new Response(null, { status: 429 }));
  await assert.rejects(
    new HibpClient({ apiKey: KEY, fetchImpl: bare.fetchImpl }).breachedDomain('example.com'),
    (err: unknown) => {
      assert.ok(err instanceof HibpError && err.retryAfterSeconds === DEFAULT_RETRY_AFTER_SECONDS);
      return true;
    }
  );
});

test('401 and 403 are auth errors; 400 is a bad request', async () => {
  for (const [status, kind] of [
    [401, 'auth'],
    [403, 'auth'],
    [400, 'bad_request'],
  ] as const) {
    const { fetchImpl } = fakeFetch(() => new Response('denied', { status }));
    await expectHibpError(
      new HibpClient({ apiKey: KEY, fetchImpl }).breachedAccount('alice@example.com'),
      kind,
      status
    );
  }
});

test('5xx, redirects, network failures, timeouts and non-JSON bodies are transient', async () => {
  const transient: FetchFn[] = [
    async () => new Response('Service Unavailable', { status: 503 }),
    async () =>
      new Response(null, { status: 301, headers: { location: 'https://elsewhere.example/' } }),
    async () => {
      throw new TypeError('fetch failed');
    },
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError'))
        );
      }),
    async () => new Response('<html>oops</html>', { status: 200 }),
    async () => json({ not: 'an array' }),
  ];
  for (const fetchImpl of transient) {
    const client = new HibpClient({ apiKey: KEY, fetchImpl, timeoutMs: 20 });
    await assert.rejects(client.breachedAccount('alice@example.com'), (err: unknown) => {
      assert.ok(err instanceof HibpError && err.kind === 'transient', String(err));
      return true;
    });
  }
});

test('breachedDomain keeps the alias -> breach-name map and drops junk', async () => {
  const { fetchImpl, calls } = fakeFetch(() =>
    json({ alias1: ['Adobe'], alias2: ['Adobe', 'Gawker', 7, ''], junk: 'not-a-list', empty: [] })
  );
  const result = await new HibpClient({ apiKey: KEY, fetchImpl }).breachedDomain('example.com');
  assert.deepEqual(result, { alias1: ['Adobe'], alias2: ['Adobe', 'Gawker'] });
  assert.equal(calls[0].url.pathname, '/api/v3/breacheddomain/example.com');
});

test('allBreaches needs no key and never sends one; keyed calls without a key make no request', async () => {
  const { fetchImpl, calls } = fakeFetch(() => json([{ Name: 'Adobe' }, { Title: 'nameless' }]));
  const anonymous = new HibpClient({ fetchImpl });
  assert.deepEqual(await anonymous.allBreaches(), [{ Name: 'Adobe' }]);
  assert.equal(new Headers(calls[0].init.headers).get('hibp-api-key'), null);
  assert.equal(calls[0].url.pathname, '/api/v3/breaches');

  await expectHibpError(anonymous.subscriptionStatus(), 'auth', null);
  assert.equal(calls.length, 1, 'no request was made without a key');
});

test('subscriptionStatus returns the plan (the cheap key check)', async () => {
  const plan = { SubscriptionName: 'Pwned 1', Rpm: 10, DomainSearchMaxBreachedAccounts: 25 };
  const { fetchImpl, calls } = fakeFetch(() => json(plan));
  assert.deepEqual(await new HibpClient({ apiKey: KEY, fetchImpl }).subscriptionStatus(), plan);
  assert.equal(calls[0].url.pathname, '/api/v3/subscription/status');
});

test('parseRetryAfter reads seconds or an HTTP date, and defaults otherwise', () => {
  const now = Date.parse('2026-10-10T12:00:00Z');
  assert.equal(parseRetryAfter('2', now), 2);
  assert.equal(parseRetryAfter(' 1.2 ', now), 2);
  assert.equal(parseRetryAfter('Sat, 10 Oct 2026 12:00:30 GMT', now), 30);
  assert.equal(parseRetryAfter('Sat, 10 Oct 2026 11:00:00 GMT', now), 0);
  assert.equal(parseRetryAfter(null, now), DEFAULT_RETRY_AFTER_SECONDS);
  assert.equal(parseRetryAfter('soon', now), DEFAULT_RETRY_AFTER_SECONDS);
});

// ---- subscribeddomains (the key's verified domains) ---------------------------------

const subscribed = (name: unknown, extra: Record<string, unknown> = {}) => ({
  DomainName: name,
  PwnCount: 40,
  PwnCountExcludingSpamLists: 38,
  PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 35,
  NextSubscriptionRenewal: '2027-01-01T00:00:00',
  ...extra,
});

test('subscribedDomains: constant host, keyed, no redirects; reads the documented fields', async () => {
  const { fetchImpl, calls } = fakeFetch(() => json([subscribed('Example.com')]));
  const result = await new HibpClient({ apiKey: KEY, fetchImpl }).subscribedDomains();

  assert.deepEqual(result, {
    domains: [
      {
        DomainName: 'Example.com',
        PwnCount: 40,
        PwnCountExcludingSpamLists: 38,
        PwnCountExcludingSpamListsAtLastSubscriptionRenewal: 35,
        NextSubscriptionRenewal: '2027-01-01T00:00:00',
      },
    ],
    unreadable: 0,
    overLimit: 0,
  });
  const { url, init } = calls[0];
  assert.equal(url.origin, 'https://haveibeenpwned.com');
  assert.equal(url.pathname, '/api/v3/subscribeddomains');
  assert.equal(url.search, '');
  const headers = new Headers(init.headers);
  assert.equal(headers.get('hibp-api-key'), KEY);
  assert.match(headers.get('user-agent') ?? '', /^SIEMBox-ExposureMonitor\//);
  assert.equal(init.redirect, 'manual');
});

test('subscribedDomains: drops entries without a string DomainName and sanitizes the numbers', async () => {
  const { fetchImpl } = fakeFetch(() =>
    json([
      subscribed('a.example', { PwnCount: null, PwnCountExcludingSpamLists: -1 }),
      subscribed('b.example', {
        PwnCount: 'many',
        PwnCountExcludingSpamListsAtLastSubscriptionRenewal: Infinity,
        NextSubscriptionRenewal: 'not a date',
      }),
      subscribed(42),
      null,
      'c.example',
      { PwnCount: 3 },
    ])
  );
  const result = await new HibpClient({ apiKey: KEY, fetchImpl }).subscribedDomains();
  assert.equal(result.unreadable, 4);
  assert.deepEqual(
    result.domains.map((d) => [d.DomainName, d.PwnCount, d.PwnCountExcludingSpamLists]),
    [
      ['a.example', null, null],
      ['b.example', null, 38],
    ]
  );
  assert.equal(result.domains[1].PwnCountExcludingSpamListsAtLastSubscriptionRenewal, null);
  assert.equal(result.domains[1].NextSubscriptionRenewal, null);
});

test('subscribedDomains: reads at most MAX_SUBSCRIBED_DOMAINS_PARSED entries and counts the rest', async () => {
  const body = Array.from({ length: MAX_SUBSCRIBED_DOMAINS_PARSED + 7 }, (_, i) => subscribed(`d${i}.example`));
  const { fetchImpl } = fakeFetch(() => json(body));
  const result = await new HibpClient({ apiKey: KEY, fetchImpl }).subscribedDomains();
  assert.equal(result.domains.length, MAX_SUBSCRIBED_DOMAINS_PARSED);
  assert.equal(result.overLimit, 7);
  assert.equal(result.unreadable, 0);
});

test('subscribedDomains: an empty array is an answer; 404 and a non-array are errors, never "no domains"', async () => {
  const empty = fakeFetch(() => json([]));
  assert.deepEqual(await new HibpClient({ apiKey: KEY, fetchImpl: empty.fetchImpl }).subscribedDomains(), {
    domains: [],
    unreadable: 0,
    overLimit: 0,
  });

  const notFound = fakeFetch(() => new Response(null, { status: 404 }));
  await expectHibpError(
    new HibpClient({ apiKey: KEY, fetchImpl: notFound.fetchImpl }).subscribedDomains(),
    'transient',
    404
  );
  const notArray = fakeFetch(() => json({ DomainName: 'example.com' }));
  await expectHibpError(
    new HibpClient({ apiKey: KEY, fetchImpl: notArray.fetchImpl }).subscribedDomains(),
    'transient',
    200
  );
  const notJson = fakeFetch(() => new Response('<html>', { status: 200 }));
  await expectHibpError(
    new HibpClient({ apiKey: KEY, fetchImpl: notJson.fetchImpl }).subscribedDomains(),
    'transient',
    200
  );
});

test('subscribedDomains: 401, 403, 429, 503 and network failures map like every keyed call', async () => {
  for (const [status, kind] of [
    [401, 'auth'],
    [403, 'auth'],
    [503, 'transient'],
  ] as const) {
    const { fetchImpl } = fakeFetch(() => new Response('denied', { status }));
    await expectHibpError(new HibpClient({ apiKey: KEY, fetchImpl }).subscribedDomains(), kind, status);
  }
  const limited = fakeFetch(() => new Response(null, { status: 429, headers: { 'retry-after': '9' } }));
  await assert.rejects(
    new HibpClient({ apiKey: KEY, fetchImpl: limited.fetchImpl }).subscribedDomains(),
    (err: unknown) =>
      err instanceof HibpError && err.kind === 'rate_limited' && err.status === 429 && err.retryAfterSeconds === 9
  );
  const down: FetchFn = async () => {
    throw new TypeError('fetch failed');
  };
  await expectHibpError(new HibpClient({ apiKey: KEY, fetchImpl: down }).subscribedDomains(), 'transient', null);
});

test('subscribedDomains without a key is an auth error and makes no request', async () => {
  const { fetchImpl, calls } = fakeFetch(() => json([]));
  await expectHibpError(new HibpClient({ fetchImpl }).subscribedDomains(), 'auth', null);
  assert.equal(calls.length, 0);
});

test('breach models keep HIBP’s per-breach Attribution field', async () => {
  const breach = { Name: 'Combo', Attribution: '@someone' };
  const { fetchImpl } = fakeFetch(() => json([breach]));
  const [model] = await new HibpClient({ apiKey: KEY, fetchImpl }).breachedAccount('a@example.com');
  assert.equal(model.Attribution, '@someone');
});

// The same client against a real HTTP server on 127.0.0.1. The only seam is
// fetchImpl: the client still builds https://haveibeenpwned.com/... (asserted),
// and the seam forwards that path to the local server.
test('against a local fake HIBP server: headers arrive, answers and errors are read', async () => {
  const seen: Array<{ path: string; key: string | undefined; ua: string | undefined }> = [];
  const server = http.createServer((req, res) => {
    seen.push({
      path: req.url ?? '',
      key: req.headers['hibp-api-key'] as string | undefined,
      ua: req.headers['user-agent'],
    });
    if (req.url === '/api/v3/subscribeddomains') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([subscribed('verified.example'), subscribed('Sub.Verified.Example.')]));
    } else if (req.url === '/api/v3/subscription/status') {
      res.writeHead(429, { 'retry-after': '4' });
      res.end();
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const requested: URL[] = [];
  const fetchImpl: FetchFn = (url, init) => {
    requested.push(url);
    return fetch(new URL(url.pathname + url.search, local), init);
  };
  try {
    const client = new HibpClient({ apiKey: KEY, fetchImpl });
    const list = await client.subscribedDomains();
    assert.deepEqual(
      list.domains.map((d) => d.DomainName),
      ['verified.example', 'Sub.Verified.Example.']
    );
    await assert.rejects(client.subscriptionStatus(), (err: unknown) => {
      assert.ok(err instanceof HibpError && err.kind === 'rate_limited' && err.retryAfterSeconds === 4);
      return true;
    });
    assert.ok(requested.every((u) => u.origin === 'https://haveibeenpwned.com'));
    assert.deepEqual(
      seen.map((s) => s.path),
      ['/api/v3/subscribeddomains', '/api/v3/subscription/status']
    );
    for (const s of seen) {
      assert.equal(s.key, KEY);
      assert.match(s.ua ?? '', /^SIEMBox-ExposureMonitor\/1\.0 \(\+https:\/\/github\.com\/cladkins\/siembox\)$/);
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
