/**
 * The collectors' HTTP client against a local server: bodies are returned,
 * redirects come back as a status and are never followed, size caps hold with
 * and without a Content-Length, the deadline covers a server that stalls, a
 * non-HTTPS URL is refused, and the connect-time lookup is the one used (so a
 * refusal there stops the request). The local server speaks plain HTTP; the
 * `request` seam points the client at it. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import type https from 'https';
import type { AddressInfo } from 'net';
import { HttpError, httpsGet, type HttpGetOptions } from './http';
import { UnsafeTargetError } from './netSafety';

let server: http.Server;
let port = 0;
const hits: string[] = [];

before(async () => {
  server = http.createServer((req, res) => {
    hits.push(req.url ?? '');
    switch (req.url) {
      case '/json':
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, ua: req.headers['user-agent'] }));
        return;
      case '/redirect':
        res.writeHead(302, { Location: '/secret' });
        res.end();
        return;
      case '/big-declared':
        res.writeHead(200, { 'Content-Length': String(10_000) });
        res.end('x'.repeat(10_000));
        return;
      case '/big-chunked':
        res.writeHead(200, { 'Content-Type': 'application/json' });
        for (let i = 0; i < 10; i++) res.write('y'.repeat(1_000));
        res.end();
        return;
      case '/stall':
        res.writeHead(200);
        res.write('[');
        return; // never ends
      default:
        res.writeHead(404);
        res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/** Sends the "https" request to the local plain-HTTP server, keeping the client's options (lookup included). */
const toLocal = ((
  url: URL,
  options: http.RequestOptions,
  callback: (res: http.IncomingMessage) => void
) =>
  http.request(
    { ...options, protocol: 'http:', hostname: url.hostname, port, path: url.pathname },
    callback
  )) as unknown as typeof https.request;

const base: HttpGetOptions = {
  timeoutMs: 2_000,
  maxBytes: 4_096,
  request: toLocal,
  resolve: async () => [{ address: '127.0.0.1', family: 4 }],
};

test('returns the body of a 200, with the collectors’ User-Agent', async () => {
  const res = await httpsGet(new URL('https://registry.test-host.net/json'), base);
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body.toString('utf8'));
  assert.equal(body.ok, true);
  assert.match(body.ua, /SIEMBox-DomainMonitor/);
});

test('a redirect is returned as a status and never followed', async () => {
  hits.length = 0;
  const res = await httpsGet(new URL('https://registry.test-host.net/redirect'), base);
  assert.equal(res.status, 302);
  assert.equal(res.body.length, 0);
  assert.deepEqual(hits, ['/redirect'], 'the redirect target was never requested');
});

test('responses over the cap are refused, declared or not', async () => {
  for (const path of ['/big-declared', '/big-chunked']) {
    await assert.rejects(
      httpsGet(new URL(`https://registry.test-host.net${path}`), base),
      (err: unknown) => err instanceof HttpError && err.kind === 'too_large',
      path
    );
  }
});

test('the deadline covers a server that starts answering and then stalls', async () => {
  const started = Date.now();
  await assert.rejects(
    httpsGet(new URL('https://registry.test-host.net/stall'), { ...base, timeoutMs: 150 }),
    (err: unknown) => err instanceof HttpError && err.kind === 'timeout'
  );
  assert.ok(Date.now() - started < 2_000);
});

test('non-HTTPS URLs are refused before any connection', async () => {
  hits.length = 0;
  await assert.rejects(
    httpsGet(new URL(`http://127.0.0.1:${port}/json`), base),
    (err: unknown) => err instanceof HttpError && err.kind === 'blocked'
  );
  assert.deepEqual(hits, []);
});

test('the connect-time lookup decides where the socket goes; a refusal there blocks the request', async () => {
  const asked: string[] = [];
  const res = await httpsGet(new URL('https://pinned.test-host.net/json'), {
    ...base,
    resolve: async (hostname) => {
      asked.push(hostname);
      return [{ address: '127.0.0.1', family: 4 }];
    },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(asked, ['pinned.test-host.net']);

  hits.length = 0;
  await assert.rejects(
    httpsGet(new URL('https://rebound.test-host.net/json'), {
      ...base,
      resolve: async () => {
        throw new UnsafeTargetError(
          'refusing rebound.test-host.net: it resolves to a non-public address (127.0.0.1)'
        );
      },
    }),
    (err: unknown) =>
      err instanceof HttpError && err.kind === 'blocked' && /non-public/.test(err.message)
  );
  assert.deepEqual(hits, [], 'nothing reached the server');

  // A name that merely failed to resolve is a network error (retryable), not a refusal.
  await assert.rejects(
    httpsGet(new URL('https://flaky.test-host.net/json'), {
      ...base,
      resolve: async () => {
        throw new UnsafeTargetError('could not resolve flaky.test-host.net (ETIMEOUT)', true);
      },
    }),
    (err: unknown) => err instanceof HttpError && err.kind === 'network'
  );
});
