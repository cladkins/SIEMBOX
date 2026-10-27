/**
 * Client addresses end to end: the real app (app.ts, every middleware) served
 * by the real listeners, TCP on 127.0.0.1:0 and the proxy socket in a fresh
 * temporary directory, with the general limit lowered to 3 requests so its
 * buckets show which address each request was counted against.
 *
 * - Direct TCP callers are their TCP address: no X-Forwarded-For value, valid,
 *   junk or huge, gets them a fresh bucket.
 * - On the proxy socket the rightmost X-Forwarded-For entry (what nginx appends)
 *   is the client; entries further left are whatever the client sent.
 * - A TRUSTED_PROXIES entry in front of nginx (192.0.2.10 here) passes on its
 *   own client.
 * - A 429 is JSON with Retry-After; enrollment is counted even with X-Agent-ID,
 *   real agent and log-push routes keep their own limiters, and only with the
 *   method they answer: any other method is counted by the general limit.
 * - An untrusted proxy in front of nginx is counted as a proxy whose header was
 *   ignored; requests to the diagnostics endpoint never are.
 *
 * Hermetic like routeAuth.http.test.ts: the database points at a closed port,
 * and every request here is answered before any query. The environment is read
 * when app.ts loads, so it is set first. Run with `npm test` (tsx --test).
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

let tcp: http.Server | undefined;
let socketServer: http.Server | null = null;
let port = 0;
let socketPath = '';
let dir = '';
let closePools: (() => Promise<void>) | undefined;
let resetKey: (key: string) => unknown = () => undefined;

async function closedPort(): Promise<number> {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port: free } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return free;
}

before(async () => {
  const dbPort = await closedPort();
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(dbPort);
  process.env.API_RATE_LIMIT_MAX = '3';
  process.env.TRUSTED_PROXIES = '192.0.2.10';
  const db = await import('../config/database');
  closePools = db.closePools;
  const { host, port: poolPort } = (db.default as unknown as { options: { host?: string; port?: number } }).options;
  assert.deepEqual({ host, port: poolPort }, { host: '127.0.0.1', port: dbPort }, 'the pool must point at the closed port');
  const appModule = await import('../app');
  resetKey = (key) => appModule.apiRateLimiter.resetKey(key);
  const { createApiServer, listenProxySocket } = await import('../net/apiListeners');
  tcp = createApiServer(appModule.default);
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  port = (tcp.address() as AddressInfo).port;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-clientip-'));
  socketPath = path.join(dir, 'api.sock');
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;
  socketServer = (await listenProxySocket(appModule.default, socketPath, quiet)).server;
  assert.ok(socketServer, 'the proxy socket listens');
});

after(async () => {
  for (const server of [tcp, socketServer]) {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  await closePools?.();
});

// Every direct request comes from 127.0.0.1; start each test with its bucket empty.
beforeEach(() => resetKey('127.0.0.1'));

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  json: Record<string, unknown> | null;
}

function parseJson(text: string): Record<string, unknown> | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function send(
  via: 'tcp' | 'socket',
  method: string,
  urlPath: string,
  headers: Record<string, string> = {},
  body?: unknown
): Promise<Reply> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const options: http.RequestOptions = {
    method,
    path: urlPath,
    headers: { ...headers, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
    agent: false,
    ...(via === 'tcp' ? { host: '127.0.0.1', port } : { socketPath }),
  };
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let text = '';
      res.on('data', (chunk) => (text += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, json: parseJson(text) }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

/** GET /api/auth/me without a session: 401 before any query, counted by the general limit. */
const me = (via: 'tcp' | 'socket', headers: Record<string, string> = {}) => send(via, 'GET', '/api/auth/me', headers);

function assertRateLimited(reply: Reply) {
  assert.equal(reply.status, 429);
  assert.match(String(reply.headers['content-type']), /application\/json/);
  assert.equal(reply.json?.status, 'error');
  assert.equal(reply.json?.statusCode, 429);
  assert.equal(reply.json?.code, 'RATE_LIMITED');
  assert.match(String(reply.json?.message), /^Too many requests from your address\. Try again in \d+ (minutes?|seconds?)\.$/);
  const retryAfter = Number(reply.headers['retry-after']);
  assert.ok(retryAfter > 0 && retryAfter <= 900, `Retry-After ${reply.headers['retry-after']}`);
  assert.equal(reply.json?.retryAfter, retryAfter);
}

test('direct TCP: a different X-Forwarded-For on every request still lands in one bucket', async () => {
  const statuses: number[] = [];
  let last: Reply | undefined;
  for (const forwarded of ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4']) {
    last = await me('tcp', { 'X-Forwarded-For': forwarded });
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [401, 401, 401, 429]);
  assertRateLimited(last!);
  assert.equal(last!.headers['x-ratelimit-limit'], '3', 'the X-RateLimit-* headers are kept');
});

test('direct TCP: junk or huge X-Forwarded-For and X-Real-IP never error and never change the bucket', async () => {
  const huge = Array.from({ length: 300 }, (_, i) => `10.${i >> 8}.${i & 255}.1`).join(', ');
  const replies: Reply[] = [];
  for (const forwarded of ['not-an-ip', '<script>alert(1)</script>', huge, '203.0.113.200']) {
    replies.push(await me('tcp', { 'X-Forwarded-For': forwarded, 'X-Real-IP': '203.0.113.99' }));
  }
  assert.deepEqual(replies.map((r) => r.status), [401, 401, 401, 429]);
  assert.deepEqual(replies.slice(0, 3).map((r) => r.headers['x-ratelimit-remaining']), ['2', '1', '0']);
});

test('proxy socket: the rightmost entry is the client; changing what is left of it does not help', async () => {
  const statuses: number[] = [];
  for (const spoofed of ['1.1.1.1', '2.2.2.2', 'junk', '4.4.4.4']) {
    statuses.push((await me('socket', { 'X-Forwarded-For': `${spoofed}, 203.0.113.7`, 'X-Real-IP': '203.0.113.7' })).status);
  }
  assert.deepEqual(statuses, [401, 401, 401, 429]);
});

test('proxy socket: different clients get different buckets', async () => {
  for (const client of ['203.0.113.11', '203.0.113.12', '203.0.113.13', '203.0.113.14', '2001:db8::14']) {
    const reply = await me('socket', { 'X-Forwarded-For': client });
    assert.equal(reply.status, 401, client);
    assert.equal(reply.headers['x-ratelimit-remaining'], '2', `${client} starts a bucket of its own`);
  }
});

test('proxy socket behind a trusted proxy: the proxy\'s client is the address', async () => {
  // nginx appends the outer proxy (192.0.2.10, in TRUSTED_PROXIES); the proxy
  // appended its client 203.0.113.50; 9.9.9.9 is what that client claimed.
  for (const claimed of ['9.9.9.9', '8.8.8.8', '7.7.7.7']) {
    assert.equal((await me('socket', { 'X-Forwarded-For': `${claimed}, 203.0.113.50, 192.0.2.10` })).status, 401);
  }
  // The same client straight through nginx shares that bucket.
  assertRateLimited(await me('socket', { 'X-Forwarded-For': '203.0.113.50' }));
});

test('proxy socket: a client forging the trusted proxy\'s address gains nothing', async () => {
  for (let i = 0; i < 3; i++) {
    assert.equal((await me('socket', { 'X-Forwarded-For': `9.9.9.${i}, 192.0.2.10, 203.0.113.60` })).status, 401);
  }
  assertRateLimited(await me('socket', { 'X-Forwarded-For': '203.0.113.60' }));
});

test('ignored headers: a proxy in front of nginx is counted as forwarded; the diagnostics endpoint is never counted', async () => {
  const { trustedProxies } = await import('../net/trustedProxies');
  const peers = () => trustedProxies.describe().ignoredForwardedFor.peers;
  const directRequests = () => peers().find((p) => p.kind === 'direct' && p.address === '127.0.0.1')?.requests ?? 0;

  // A reverse proxy at 10.20.30.40, not in TRUSTED_PROXIES, in front of the web UI.
  assert.equal((await me('socket', { 'X-Forwarded-For': '198.51.100.70, 10.20.30.40' })).status, 401);
  assert.deepEqual(
    peers()
      .filter((p) => p.address === '10.20.30.40')
      .map((p) => [p.kind, p.requests, p.local]),
    [['forwarded', 1, true]]
  );

  // DEPLOYMENT.md's check from a workstation, straight to the API with a forged
  // header: answered (401 here, no session), but the workstation is not
  // counted as a proxy whose header was ignored. Any other request is.
  const before = directRequests();
  const check = await send('tcp', 'GET', '/api/admin/client-address', { 'X-Forwarded-For': '1.2.3.4' });
  assert.equal(check.status, 401);
  assert.equal(directRequests(), before);
  await me('tcp', { 'X-Forwarded-For': '1.2.3.4' });
  assert.equal(directRequests(), before + 1);
});

test('enrollment is counted by the general limit, even with an X-Agent-ID header', async () => {
  const reply = await send('tcp', 'POST', '/api/edr/agents/enroll', { 'X-Agent-ID': 'anything' }, {});
  assert.equal(reply.status, 401, 'no enrollment token');
  assert.equal(reply.headers['x-ratelimit-limit'], '3');
  assert.equal(reply.headers['x-ratelimit-remaining'], '2');
  for (const variant of ['/api/edr/agents/ENROLL', '/api/edr/agents/enroll/', '/api/edr/agents/enroll?x=1']) {
    const again = await send('tcp', 'POST', variant, { 'X-Agent-ID': 'anything' }, {});
    assert.ok(again.headers['x-ratelimit-limit'], `${variant} is counted`);
  }
});

test('agent and log-push routes with their header skip the general limit but keep their own', async () => {
  const agent = await send('tcp', 'POST', '/api/edr/events', { 'X-Agent-ID': 'agent-1' }, { events: [] });
  assert.equal(agent.status, 401, 'no agent key');
  assert.equal(agent.headers['x-ratelimit-limit'], undefined, 'not counted by the general limit');
  assert.equal(agent.headers['ratelimit-limit'], '30000', 'counted by the agent limiter');

  const metrics = await send('tcp', 'POST', '/api/edr/metrics', { 'X-Agent-ID': 'agent-1' }, { samples: [] });
  assert.equal(metrics.status, 401, 'no agent key');
  assert.equal(metrics.headers['x-ratelimit-limit'], undefined, 'metrics: not counted by the general limit');
  assert.equal(metrics.headers['ratelimit-limit'], '30000', 'metrics: counted by the agent limiter');

  const push = await send('tcp', 'POST', '/api/shippers/logs', { 'X-Shipper-ID': '1' }, { message: 'x' });
  assert.equal(push.status, 401, 'no push key');
  assert.equal(push.headers['x-ratelimit-limit'], undefined);
  assert.equal(push.headers['ratelimit-limit'], '6000');

  // Without the header, or on any other path, the general limit applies.
  const anonymous = await send('tcp', 'POST', '/api/edr/events', {}, { events: [] });
  assert.equal(anonymous.headers['x-ratelimit-limit'], '3');
  const other = await send('tcp', 'GET', '/api/edr/not-a-route', { 'X-Agent-ID': 'agent-1' });
  assert.equal(other.headers['x-ratelimit-limit'], '3');

  // HEAD reaches the GET-only agent routes (and their limiter), so it is exempt too.
  resetKey('127.0.0.1');
  const head = await send('tcp', 'HEAD', '/api/edr/agents/agent-1/config', { 'X-Agent-ID': 'agent-1' });
  assert.equal(head.headers['x-ratelimit-limit'], undefined);
  assert.equal(head.headers['ratelimit-limit'], '30000');
});

test('the wrong method on an agent or log-push path is counted by the general limit, header or not', async () => {
  // None of these reaches an agent or push route (heartbeat and the pushes are
  // POST-only, config and yara GET-only), so no limiter of their own runs: a
  // 404 that is logged to the database, or a management route's session check.
  const wrongMethods: Array<[string, string, Record<string, string>]> = [
    ['POST', '/api/edr/agents/x1/config', { 'X-Agent-ID': 'agent-1' }],
    ['PUT', '/api/edr/agents/x2/yara', { 'X-Agent-ID': 'agent-1' }],
    ['GET', '/api/edr/agents/x3/heartbeat', { 'X-Agent-ID': 'agent-1' }],
    ['GET', '/api/edr/events', { 'X-Agent-ID': 'agent-1' }],
    ['GET', '/api/edr/metrics', { 'X-Agent-ID': 'agent-1' }],
    ['GET', '/api/shippers/logs', { 'X-Shipper-ID': '1' }],
    ['PUT', '/api/shippers/logs', { 'X-Shipper-ID': '1' }],
    ['DELETE', '/api/shippers/logs/', { 'X-Shipper-ID': '1' }],
  ];
  for (const [method, urlPath, headers] of wrongMethods) {
    resetKey('127.0.0.1');
    const reply = await send('tcp', method, urlPath, headers);
    assert.equal(reply.headers['x-ratelimit-limit'], '3', `${method} ${urlPath} is counted`);
    assert.equal(reply.headers['x-ratelimit-remaining'], '2', `${method} ${urlPath} is counted`);
  }
  resetKey('127.0.0.1');
  const statuses: number[] = [];
  for (let i = 0; i < 4; i++) {
    statuses.push((await send('tcp', 'POST', `/api/edr/agents/random-${i}/config`, { 'X-Agent-ID': 'agent-1' })).status);
  }
  assert.deepEqual(statuses, [404, 404, 404, 429]);
});
