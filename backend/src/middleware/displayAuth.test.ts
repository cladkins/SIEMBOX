/**
 * authenticateDisplay and displayTokenLimiter (middleware/displayAuth.ts) on a
 * small Express app, with DisplayLinkModel stubbed:
 *
 * - the refusal order of BIG-DISPLAY.md §4.3, with each refusal's code and
 *   status, uncached; a malformed token is never looked up, and a database
 *   error is 503, never 401; address_allowed null is refused;
 * - Authorization is never read: a display token sent as a Bearer token is
 *   "no display token";
 * - refusals write nothing to application_errors or audit_logs, except the
 *   refused_network row, once per link and address per hour;
 * - a use is written once a minute per (link, address); a new address trims
 *   the link's devices and is audited, at most 10 times per link per hour;
 * - the limiter counts only 401s: 30 of them, then 429 with Retry-After,
 *   while paused, valid and 503 answers never use it up.
 *
 * Hermetic: the pool points at a closed port and is mocked to throw.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';

type LinkAuth = import('../models/DisplayLink').DisplayLinkAuth;
interface Recorder {
  mock: { callCount(): number; resetCalls(): void; calls: Array<{ arguments: unknown[] }> };
}

let server: Server | undefined;
let base = '';
let closePools: (() => Promise<void>) | undefined;
let auth: typeof import('./displayAuth');
let findForAuth: Recorder;
let touch: Recorder;
let touchLastUsed: Recorder;
let trimClients: Recorder;
let auditLog: Recorder;
let errorLog: Recorder;
let poolQuery: Recorder;
const restore: Array<() => void> = [];

const sha = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const tokenOf = (char: string) => 'sbd1_' + char.repeat(43);
const FUTURE = new Date(Date.now() + 86_400_000);
const PAST = new Date(Date.now() - 1000);

/** The links the stubbed model knows, by the hash of their token. */
const LINKS = new Map<string, Omit<LinkAuth, 'address_allowed'> & { allowed: boolean | null }>();
function link(char: string, fields: Partial<LinkAuth> & { allowed?: boolean | null } = {}) {
  const id = LINKS.size + 1;
  LINKS.set(sha(tokenOf(char)), {
    id,
    name: `link-${char}`,
    config: {},
    config_version: 1,
    enabled: true,
    expires_at: null,
    revoked_at: null,
    allowed: true,
    ...fields,
  });
  return { token: tokenOf(char), id };
}
const LIVE = link('L');
const PAUSED = link('P', { enabled: false });
const REVOKED = link('R', { revoked_at: PAST, expires_at: PAST, enabled: false, allowed: false });
const EXPIRED = link('E', { expires_at: PAST, enabled: false, allowed: false });
const PAUSED_ELSEWHERE = link('Q', { enabled: false, allowed: false });
const FENCED = link('F', { allowed: false });
const NO_ADDRESS_ANSWER = link('N', { allowed: null });
const LATER = link('X', { expires_at: FUTURE });
/** Its lookup throws, as when the database is down. */
const BROKEN = tokenOf('D');
/** Its address is new, every time. */
const NEW_EVERY_TIME = link('T');

let firstTimeFor = new Set<number>();

async function closedPort(): Promise<number> {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

before(async () => {
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(await closedPort());
  const db = await import('../config/database');
  closePools = db.closePools;
  const noSql = async () => {
    throw new Error('SQL must not run in displayAuth.test.ts');
  };
  poolQuery = mock.method(db.default, 'query', noSql) as unknown as Recorder;
  mock.method(db.default, 'connect', noSql);

  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restore.push(() => (transport.silent = was));
  }
  const { AuditService } = await import('../services/audit/auditService');
  auditLog = mock.method(AuditService, 'log', async () => undefined) as unknown as Recorder;
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  errorLog = mock.method(ErrorLogService, 'logError', async () => undefined) as unknown as Recorder;

  const { DisplayLinkModel } = await import('../models/DisplayLink');
  findForAuth = mock.method(DisplayLinkModel, 'findForAuth', async (hash: string) => {
    if (hash === sha(BROKEN)) throw new Error('connect ECONNREFUSED');
    const found = LINKS.get(hash);
    if (!found) return null;
    const { allowed, ...rest } = found;
    return { ...rest, address_allowed: allowed } as LinkAuth;
  }) as unknown as Recorder;
  touch = mock.method(DisplayLinkModel, 'touch', async (id: number) => firstTimeFor.has(id)) as unknown as Recorder;
  touchLastUsed = mock.method(DisplayLinkModel, 'touchLastUsed', async () => undefined) as unknown as Recorder;
  trimClients = mock.method(DisplayLinkModel, 'trimClients', async () => 0) as unknown as Recorder;

  auth = await import('./displayAuth');
  const app = express();
  app.set('trust proxy', 'loopback'); // X-Forwarded-For sets each request's address
  app.get('/snapshot', auth.displayTokenLimiter, auth.authenticateDisplay, (req, res) => {
    res.json({ reached: true, link: req.displayLink?.id });
  });
  // Plays the part of authenticate, to show a Bearer header changes nothing.
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  auth?.stopDisplayRefusalSummary();
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await closePools?.();
  for (const undo of restore) undo();
});

beforeEach(() => {
  auth.resetDisplayAuthState();
  firstTimeFor = new Set();
  for (const recorder of [findForAuth, touch, touchLastUsed, trimClients, auditLog, errorLog]) recorder.mock.resetCalls();
});

let nextAddress = 1;
const freshAddress = () => `10.77.${Math.floor(nextAddress / 250)}.${(nextAddress++ % 250) + 1}`;

interface Answer {
  status: number;
  body: Record<string, unknown>;
  headers: Headers;
}

async function get(headers: Record<string, string>, address = freshAddress()): Promise<Answer> {
  const res = await fetch(`${base}/snapshot`, { headers: { 'X-Forwarded-For': address, ...headers } });
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, headers: res.headers };
}
const withToken = (token: string, address?: string) => get({ 'X-Display-Token': token }, address);

/** Wait for the fire-and-forget use record to settle. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 30));

function assertRefused(answer: Answer, status: number, code: string): void {
  assert.equal(answer.status, status, JSON.stringify(answer.body));
  assert.equal(answer.body.code, code);
  assert.equal(answer.body.status, 'error');
  assert.equal(answer.body.statusCode, status);
  assert.equal(typeof answer.body.message, 'string');
  assert.equal(answer.body.reached, undefined);
  assert.equal(answer.headers.get('cache-control'), 'no-store');
}

test('refusal order: no token, malformed, unknown, database down, revoked, expired, paused, network', async () => {
  assertRefused(await get({}), 401, 'DISPLAY_TOKEN_REQUIRED');
  assert.equal(findForAuth.mock.callCount(), 0, 'nothing to look up');

  for (const malformed of ['nope', crypto.randomBytes(32).toString('hex'), tokenOf('L') + 'x', 'sbd1_' + '*'.repeat(43)]) {
    assertRefused(await withToken(malformed), 401, 'DISPLAY_LINK_INVALID');
  }
  assert.equal(findForAuth.mock.callCount(), 0, 'a malformed token is never hashed or looked up');

  const unknown = await withToken(tokenOf('U'));
  assertRefused(unknown, 401, 'DISPLAY_LINK_INVALID');
  const malformed = await withToken('nope');
  assert.deepEqual(unknown.body, malformed.body, 'unknown and malformed get the same answer');

  const down = await withToken(BROKEN);
  assertRefused(down, 503, 'DISPLAY_UNAVAILABLE');
  assert.equal(down.headers.get('retry-after'), '5');

  // Each link fails every later check too, so the first that applies wins.
  assertRefused(await withToken(REVOKED.token), 401, 'DISPLAY_LINK_REVOKED');
  const expired = await withToken(EXPIRED.token);
  assertRefused(expired, 401, 'DISPLAY_LINK_EXPIRED');
  assert.equal(expired.body.expires_at, PAST.toISOString(), 'the screen can say when it expired');
  assertRefused(await withToken(PAUSED_ELSEWHERE.token), 403, 'DISPLAY_LINK_PAUSED');
  assertRefused(await withToken(PAUSED.token), 403, 'DISPLAY_LINK_PAUSED');
  assertRefused(await withToken(FENCED.token), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');
  assertRefused(await withToken(NO_ADDRESS_ANSWER.token), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');

  const ok = await withToken(LATER.token);
  assert.deepEqual([ok.status, ok.body], [200, { reached: true, link: LATER.id }], 'an expiry in the future is no refusal');
  const live = await withToken(LIVE.token, '10.1.2.3');
  assert.deepEqual([live.status, live.body], [200, { reached: true, link: LIVE.id }]);
  const lastLookup = findForAuth.mock.calls.at(-1)!.arguments;
  assert.deepEqual(lastLookup, [sha(LIVE.token), '10.1.2.3'], 'looked up by hash, with the client address');
});

test('Authorization is never read: a display token sent as a Bearer token is no display token', async () => {
  assertRefused(await get({ Authorization: `Bearer ${LIVE.token}` }), 401, 'DISPLAY_TOKEN_REQUIRED');
  // A session token as X-Display-Token is malformed, whatever Authorization says.
  assertRefused(await get({ 'X-Display-Token': crypto.randomBytes(32).toString('hex'), Authorization: `Bearer ${LIVE.token}` }), 401, 'DISPLAY_LINK_INVALID');
  assert.equal(findForAuth.mock.callCount(), 0);
});

test('refusals write no application_errors or audit rows, except refused_network once per link and address per hour', async () => {
  for (const token of ['nope', tokenOf('U'), BROKEN, REVOKED.token, EXPIRED.token, PAUSED.token]) await withToken(token);
  await get({});
  await settle();
  assert.equal(errorLog.mock.callCount(), 0, 'no application_errors row');
  assert.equal(auditLog.mock.callCount(), 0, 'no audit row');
  assert.equal(poolQuery.mock.callCount(), 0, 'no query at all');
  const stats = auth.displayRefusalStats();
  assert.ok(stats.sinceStart >= 7, 'refusals are counted in memory');
  assert.ok((stats.window.DISPLAY_LINK_INVALID ?? 0) >= 2);

  await withToken(FENCED.token, '10.9.9.9');
  await withToken(FENCED.token, '10.9.9.9');
  await withToken(FENCED.token, '10.9.9.9');
  await settle();
  assert.equal(auditLog.mock.callCount(), 1, 'one row per link and address');
  const [entry] = auditLog.mock.calls[0].arguments as [Record<string, unknown>];
  assert.deepEqual(
    { action: entry.action, userId: entry.userId, resourceType: entry.resourceType, resourceId: entry.resourceId, ip: entry.ipAddress, status: entry.responseStatus },
    { action: 'display_link.refused_network', userId: null, resourceType: 'display_link', resourceId: FENCED.id, ip: '10.9.9.9', status: 403 }
  );
  assert.equal(JSON.stringify(entry).includes(FENCED.token), false, 'the token is not in the row');
  assert.equal(JSON.stringify(entry).includes(sha(FENCED.token)), false, 'nor its hash');
  await withToken(FENCED.token, '10.9.9.10');
  await settle();
  assert.equal(auditLog.mock.callCount(), 2, 'another address is another row');
  assert.equal(errorLog.mock.callCount(), 0);
});

test('a use is written once a minute per link and address; a new address trims and is audited, at most 10 an hour', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await withToken(LIVE.token, '10.5.5.5')).status, 200);
  await settle();
  assert.equal(touch.mock.callCount(), 1, 'one write for five polls in a minute');
  assert.deepEqual(touch.mock.calls[0].arguments.slice(0, 2), [LIVE.id, '10.5.5.5']);
  await withToken(LIVE.token, '10.5.5.6');
  await settle();
  assert.equal(touch.mock.callCount(), 2, 'another address is written at once');
  assert.equal(trimClients.mock.callCount(), 0, 'no new address (touch said so): no trim');
  assert.equal(auditLog.mock.callCount(), 0);

  // A minute later the same device is written again.
  const realNow = Date.now;
  const later = mock.method(Date, 'now', () => realNow() + 61_000);
  try {
    await withToken(LIVE.token, '10.5.5.5');
    await settle();
  } finally {
    later.mock.restore();
  }
  assert.equal(touch.mock.callCount(), 3);

  // Every address new: trimmed every time, audited 10 times in the hour.
  firstTimeFor.add(NEW_EVERY_TIME.id);
  for (let i = 0; i < 12; i++) await withToken(NEW_EVERY_TIME.token, `10.6.0.${i + 1}`);
  await settle();
  assert.equal(trimClients.mock.callCount(), 12);
  const firstSeen = auditLog.mock.calls.map((call) => call.arguments[0] as Record<string, unknown>);
  assert.equal(firstSeen.length, auth.FIRST_SEEN_AUDITS_PER_HOUR);
  assert.ok(firstSeen.every((row) => row.action === 'display_link.client_first_seen' && row.resourceId === NEW_EVERY_TIME.id && row.userId === null));
  assert.equal(firstSeen[0].ipAddress, '10.6.0.1');
  assert.equal(errorLog.mock.callCount(), 0);
});

test('a request with no client address only updates last_used_at', async () => {
  // Without trust proxy the address is 127.0.0.1; drive the middleware directly with none.
  const req = { get: () => undefined, ip: undefined, ips: [], socket: { remoteAddress: undefined } } as never;
  auth.touchUsed({ id: LIVE.id, name: 'link-L' } as LinkAuth, req);
  await settle();
  assert.equal(touchLastUsed.mock.callCount(), 1);
  assert.equal(touch.mock.callCount(), 0);
});

test('the limiter counts only 401s: 30 per address, then 429 with Retry-After', async () => {
  const address = '10.88.0.1';
  auth.displayTokenLimiter.resetKey(address);
  // Valid, paused, fenced and database-down answers never count.
  for (let i = 0; i < 40; i++) {
    await withToken(LIVE.token, address);
    await withToken(PAUSED.token, address);
    await withToken(BROKEN, address);
  }
  for (let i = 0; i < 30; i++) {
    const answer = await withToken(i % 2 ? 'nope' : tokenOf('U'), address);
    assert.equal(answer.status, 401, `failure ${i + 1} is answered`);
  }
  const lookups = findForAuth.mock.callCount();
  const limited = await withToken(tokenOf('U'), address);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.code, 'RATE_LIMITED');
  assert.match(String(limited.body.message), /^Too many display link attempts from your address\. Try again in \d+ (minutes?|seconds?)\.$/);
  const retryAfter = Number(limited.headers.get('retry-after'));
  assert.ok(retryAfter > 0 && retryAfter <= 900, `Retry-After ${limited.headers.get('retry-after')}`);
  assert.equal(limited.body.retryAfter, retryAfter);
  assert.equal(findForAuth.mock.callCount(), lookups, 'no lookup once limited');
  assert.equal((await withToken(LIVE.token, address)).status, 429, 'the address is limited for the window');
  // Other addresses are not.
  assert.equal((await withToken(LIVE.token, '10.88.0.2')).status, 200);
  auth.displayTokenLimiter.resetKey(address);
});

test('on the real route the limiter sits in front of the display gate, and nothing else does', async () => {
  const router = (await import('../routes/display')).default as unknown as {
    stack: Array<{ name: string; route?: { path: string; stack: Array<{ name: string; handle: { resetKey?: unknown } }> } }>;
  };
  const route = router.stack.find((layer) => layer.route?.path === '/snapshot')!.route!;
  const names = route.stack.map((layer) => (typeof layer.handle.resetKey === 'function' ? 'limiter' : layer.name));
  assert.deepEqual(names.slice(0, 2), ['limiter', 'authenticateDisplay']);
  assert.equal(names.length, 3, 'then the handler');
  assert.ok(router.stack.some((layer) => !layer.route && layer.name === 'noStore'));
});
