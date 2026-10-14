/**
 * CORS_ORIGIN (net/cors.ts): parsing and normalizing the setting, what startup
 * logs about it, and the headers a browser gets, over HTTP, for each policy:
 * the same-origin default, one origin, a list, `*` and an ignored entry.
 *
 * Hermetic: a small Express app with the middleware in front of two routes,
 * on 127.0.0.1:0. Run with `npm test` (tsx --test).
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { corsHeaders, logCorsPolicy, normalizeOrigin, parseCorsOrigin, type CorsPolicy } from './cors';

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

test('normalizeOrigin: exact http(s) origins, normalized the way browsers send Origin', () => {
  for (const [entry, origin] of [
    ['https://siem.example.com', 'https://siem.example.com'],
    ['HTTPS://SIEM.Example.COM:443/', 'https://siem.example.com'],
    ['http://localhost:5173', 'http://localhost:5173'],
    ['http://LOCALHOST:80', 'http://localhost'],
    ['http://192.168.1.10:8420', 'http://192.168.1.10:8420'],
    ['http://[::1]:8420', 'http://[::1]:8420'],
    ['https://bücher.example', 'https://xn--bcher-kva.example'],
  ]) {
    assert.deepEqual(normalizeOrigin(entry), { origin }, entry);
  }
});

test('normalizeOrigin: anything else is refused with a reason', () => {
  for (const [entry, reason] of [
    ['siem.example.com', /starts with http:\/\/ or https:\/\//],
    ['localhost:5173', /starts with http:\/\/ or https:\/\//],
    ['https://siem.example.com/app', /no path, query or fragment; use https:\/\/siem\.example\.com$/],
    ['https://siem.example.com//', /no path/],
    ['https://siem.example.com/?', /no path/],
    ['https://siem.example.com#top', /no path/],
    ['https://*.example.com', /wildcards are not supported/],
    ['null', /"null"/],
    ['NULL', /"null"/],
    ['ftp://files.example.com', /only http:\/\/ and https:\/\//],
    ['chrome-extension://abcdef', /only http:\/\/ and https:\/\//],
    ['https://user:pw@siem.example.com', /no user name or password/],
    ['http://', /not a valid origin/],
    ['https://exa mple.com', /not a valid origin/],
    ['https://siem.example.com:99999', /not a valid origin/],
  ] as const) {
    const result = normalizeOrigin(entry);
    assert.ok('reason' in result, `${entry} must be refused`);
    assert.match(result.reason, reason, entry);
  }
});

test('parseCorsOrigin: unset, empty or blank means same-origin only', () => {
  for (const spec of [undefined, '', '   ', ' , ,']) {
    assert.deepEqual(parseCorsOrigin(spec), {
      configured: (spec ?? '').trim(),
      mode: 'same-origin',
      origins: [],
      rejected: [],
    });
  }
});

test('parseCorsOrigin: one origin, a list, duplicates after normalizing, and *', () => {
  assert.deepEqual(parseCorsOrigin('http://localhost:5173'), {
    configured: 'http://localhost:5173',
    mode: 'origins',
    origins: ['http://localhost:5173'],
    rejected: [],
  });
  const list = parseCorsOrigin(' https://a.example , https://B.example:8443/,https://a.example:443 ');
  assert.equal(list.mode, 'origins');
  assert.deepEqual(list.origins, ['https://a.example', 'https://b.example:8443']);
  assert.deepEqual(list.rejected, []);

  assert.deepEqual(parseCorsOrigin('*'), { configured: '*', mode: 'any', origins: [], rejected: [] });
  assert.equal(parseCorsOrigin(' * ').mode, 'any');
  assert.equal(parseCorsOrigin('*,*').mode, 'any');
});

test('parseCorsOrigin: an invalid entry is ignored, the others apply', () => {
  const mixed = parseCorsOrigin('https://ok.example,siem.example.com,https://ok.example/app');
  assert.equal(mixed.mode, 'origins');
  assert.deepEqual(mixed.origins, ['https://ok.example']);
  assert.deepEqual(
    mixed.rejected.map((r) => r.entry),
    ['siem.example.com', 'https://ok.example/app']
  );

  // * in a list does not open the API to everyone: it is ignored.
  const star = parseCorsOrigin('*,https://ok.example');
  assert.equal(star.mode, 'origins');
  assert.deepEqual(star.origins, ['https://ok.example']);
  assert.deepEqual(star.rejected, [{ entry: '*', reason: '"*" only works on its own; the other entries apply' }]);

  // Nothing valid: same-origin only.
  const none = parseCorsOrigin('siem.example.com,https://*.example.com');
  assert.equal(none.mode, 'same-origin');
  assert.deepEqual(none.origins, []);
  assert.equal(none.rejected.length, 2);
});

// ---------------------------------------------------------------------------
// Startup log
// ---------------------------------------------------------------------------

function logged(spec: string | undefined) {
  const lines: Array<{ level: 'info' | 'warn'; message: string }> = [];
  logCorsPolicy(parseCorsOrigin(spec), {
    info: (message: string) => lines.push({ level: 'info', message }),
    warn: (message: string) => lines.push({ level: 'warn', message }),
  });
  return lines;
}

test('startup log: * warns every start and names the risk', () => {
  const lines = logged('*');
  assert.equal(lines.length, 1);
  assert.equal(lines[0].level, 'warn');
  assert.match(lines[0].message, /^CORS_ORIGIN=\*: every web page/);
  assert.match(lines[0].message, /try passwords against sign-in/);
  assert.match(lines[0].message, /inside your network/);
  assert.match(lines[0].message, /leave CORS_ORIGIN empty/);
  // Every start: a second policy built from the same value warns again.
  assert.deepEqual(logged('*'), lines);
});

test('startup log: the default and a list are info lines, no warning', () => {
  assert.deepEqual(logged(undefined), [
    { level: 'info', message: 'CORS: same-origin only (CORS_ORIGIN is empty). The web UI does not need CORS.' },
  ]);
  assert.deepEqual(logged('https://a.example,http://localhost:5173'), [
    {
      level: 'info',
      message: 'CORS: browsers may call the API from https://a.example, http://localhost:5173 (CORS_ORIGIN).',
    },
  ]);
});

test('startup log: each ignored entry is a warning naming it', () => {
  assert.deepEqual(logged('https://ok.example,siem.example.com'), [
    {
      level: 'warn',
      message: 'CORS_ORIGIN entry "siem.example.com" ignored: an origin starts with http:// or https://.',
    },
    { level: 'info', message: 'CORS: browsers may call the API from https://ok.example (CORS_ORIGIN).' },
  ]);
  const none = logged('https://siem.example.com/app');
  assert.deepEqual(
    none.map((l) => l.level),
    ['warn', 'warn']
  );
  assert.match(none[0].message, /"https:\/\/siem\.example\.com\/app" ignored: .*use https:\/\/siem\.example\.com\.$/);
  assert.match(none[1].message, /no valid origin, so the API is same-origin only/);
});

// ---------------------------------------------------------------------------
// Over HTTP
// ---------------------------------------------------------------------------

const servers: http.Server[] = [];
after(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
});

interface Answer {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** An app shaped like app.ts: CORS first, then the routes and a 404. */
async function serve(spec: string | undefined) {
  const policy: CorsPolicy = parseCorsOrigin(spec);
  const reached: string[] = [];
  const app = express();
  app.use(corsHeaders(policy));
  app.get('/api/things', (_req, res) => {
    reached.push('GET /api/things');
    res.json({ ok: true });
  });
  app.post('/api/auth/login', (_req, res) => {
    reached.push('POST /api/auth/login');
    res.json({ ok: true });
  });
  app.use((_req, res) => {
    reached.push('404');
    res.status(404).json({ error: 'not found' });
  });
  const server = app.listen(0, '127.0.0.1');
  servers.push(server);
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  const call = (method: string, path: string, headers: Record<string, string> = {}): Promise<Answer> =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      });
      req.on('error', reject);
      req.end();
    });
  return { call, reached };
}

const EVIL = 'http://evil.example';
/** What a browser sends before a JSON sign-in from another origin. */
const preflight = (origin: string) => ({
  Origin: origin,
  'Access-Control-Request-Method': 'POST',
  'Access-Control-Request-Headers': 'authorization,content-type',
});

/** The Access-Control-* headers of an answer. */
function acHeaders(answer: Answer): Record<string, unknown> {
  return Object.fromEntries(Object.entries(answer.headers).filter(([name]) => name.startsWith('access-control-')));
}

function varies(answer: Answer): string[] {
  return String(answer.headers.vary ?? '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

test('default (unset): no CORS headers for another origin, and its preflight is not allowed', async () => {
  const { call, reached } = await serve(undefined);

  const get = await call('GET', '/api/things', { Origin: EVIL });
  assert.equal(get.status, 200, 'the request itself is served; the browser withholds the answer');
  assert.deepEqual(acHeaders(get), {});
  assert.equal(get.headers.vary, undefined);

  const pre = await call('OPTIONS', '/api/auth/login', preflight(EVIL));
  assert.equal(pre.status, 204);
  assert.equal(pre.body, '');
  assert.deepEqual(acHeaders(pre), {}, 'no allow answer: the browser never sends the sign-in');
  assert.equal(pre.headers.vary, undefined);

  // An OPTIONS request that isn't a preflight is answered the same way, as before.
  const bare = await call('OPTIONS', '/api/nowhere');
  assert.equal(bare.status, 204);
  assert.deepEqual(acHeaders(bare), {});

  assert.deepEqual(reached, ['GET /api/things'], 'OPTIONS never reaches a route or the 404 handler');
});

test('default: the bundled UI path (same-origin through nginx) and non-browser callers still work', async () => {
  const { call, reached } = await serve('');
  // What the UI's nginx forwards for a sign-in from http://siem.lan:8420: the
  // browser's own Origin (sent on every POST) and Host, plus X-Forwarded-For.
  // The browser needs no CORS headers for its own origin.
  const login = await call('POST', '/api/auth/login', {
    Origin: 'http://siem.lan:8420',
    Host: 'siem.lan:8420',
    'X-Forwarded-For': '192.168.1.50',
    'Content-Type': 'application/json',
  });
  assert.equal(login.status, 200);
  assert.deepEqual(JSON.parse(login.body), { ok: true });
  assert.deepEqual(acHeaders(login), {});

  // A shipper, an agent or curl sends no Origin at all.
  const curl = await call('GET', '/api/things', { Authorization: 'Bearer x' });
  assert.equal(curl.status, 200);
  assert.deepEqual(acHeaders(curl), {});

  assert.deepEqual(reached, ['POST /api/auth/login', 'GET /api/things']);
});

test('one origin: echoed back with Vary: Origin; other origins get no allow headers', async () => {
  const DEV = 'http://localhost:5173';
  const { call, reached } = await serve(DEV);

  const get = await call('GET', '/api/things', { Origin: DEV });
  assert.equal(get.status, 200);
  assert.deepEqual(acHeaders(get), {
    'access-control-allow-origin': DEV,
    'access-control-allow-credentials': 'true',
  });
  assert.ok(varies(get).includes('origin'));

  const pre = await call('OPTIONS', '/api/auth/login', preflight(DEV));
  assert.equal(pre.status, 204);
  assert.equal(pre.headers['access-control-allow-origin'], DEV);
  assert.match(String(pre.headers['access-control-allow-methods']), /\bPOST\b/);
  assert.equal(pre.headers['access-control-allow-headers'], 'authorization,content-type');
  assert.ok(varies(pre).includes('origin'));

  const evil = await call('GET', '/api/things', { Origin: EVIL });
  assert.deepEqual(acHeaders(evil), {});
  assert.deepEqual(varies(evil), ['origin'], 'answers differ by Origin, so caches must key on it');

  const evilPre = await call('OPTIONS', '/api/auth/login', preflight(EVIL));
  assert.equal(evilPre.status, 204);
  assert.deepEqual(acHeaders(evilPre), {});

  // Exact match on the whole header: no parsing, no prefix or case games.
  for (const origin of ['HTTP://LOCALHOST:5173', 'http://localhost:51730', 'http://localhost:5173.evil.example', 'null']) {
    assert.deepEqual(acHeaders(await call('GET', '/api/things', { Origin: origin })), {}, origin);
  }

  // No Origin (same-origin GET, curl): served, Vary: Origin, nothing else.
  const plain = await call('GET', '/api/things');
  assert.deepEqual(acHeaders(plain), {});
  assert.deepEqual(varies(plain), ['origin']);

  assert.equal(reached.filter((r) => r === 'POST /api/auth/login').length, 0, 'preflights never reach the route');
});

test('a list: each listed origin is echoed, nothing else is', async () => {
  const { call } = await serve('https://a.example, https://B.example:8443/');
  for (const origin of ['https://a.example', 'https://b.example:8443']) {
    const get = await call('GET', '/api/things', { Origin: origin });
    assert.equal(get.headers['access-control-allow-origin'], origin, origin);
    const pre = await call('OPTIONS', '/api/auth/login', preflight(origin));
    assert.equal(pre.headers['access-control-allow-origin'], origin, origin);
  }
  for (const origin of ['https://c.example', 'https://b.example', 'http://a.example', EVIL]) {
    assert.deepEqual(acHeaders(await call('GET', '/api/things', { Origin: origin })), {}, origin);
    assert.deepEqual(acHeaders(await call('OPTIONS', '/api/auth/login', preflight(origin))), {}, origin);
  }
});

test('*: every origin, as before (no credentials header, which browsers refuse with *)', async () => {
  const { call } = await serve('*');
  const get = await call('GET', '/api/things', { Origin: EVIL });
  assert.deepEqual(acHeaders(get), { 'access-control-allow-origin': '*' });
  const pre = await call('OPTIONS', '/api/auth/login', preflight(EVIL));
  assert.equal(pre.status, 204);
  assert.equal(pre.headers['access-control-allow-origin'], '*');
  assert.match(String(pre.headers['access-control-allow-methods']), /\bPOST\b/);
  assert.equal(pre.headers['access-control-allow-headers'], 'authorization,content-type');
});

test('an invalid entry allows nothing; the valid ones still apply', async () => {
  const { call } = await serve('https://ok.example,siem.example.com,https://*.example.com');
  assert.equal(
    (await call('GET', '/api/things', { Origin: 'https://ok.example' })).headers['access-control-allow-origin'],
    'https://ok.example'
  );
  for (const origin of ['https://siem.example.com', 'http://siem.example.com', 'https://x.example.com']) {
    assert.deepEqual(acHeaders(await call('GET', '/api/things', { Origin: origin })), {}, origin);
  }
});
