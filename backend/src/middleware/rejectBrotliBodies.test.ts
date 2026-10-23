/**
 * Brotli request bodies are refused before Express's parsers decompress them
 * (CVE-2026-111497), on the real app: sign-in is unauthenticated, so it is the
 * path that matters. gzip and plain bodies still reach the route. No database:
 * the sign-in route answers 400/401 for these bodies before or without one.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { once } from 'node:events';
import http from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { rejectBrotliBodies } from './rejectBrotliBodies';

let server: Server;
let port = 0;
let parsed: unknown[] = [];

before(async () => {
  // The same order as app.ts: the guard, then a decompressing JSON parser.
  const app = express();
  app.use(rejectBrotliBodies);
  app.use(express.json());
  app.post('/echo', (req, res) => {
    parsed.push(req.body);
    res.json({ ok: true });
  });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = (server.address() as AddressInfo).port;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

function post(body: Buffer, encoding?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string | number> = { 'Content-Type': 'application/json', 'Content-Length': body.length };
    if (encoding) headers['Content-Encoding'] = encoding;
    const req = http.request({ host: '127.0.0.1', port, path: '/echo', method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

const json = Buffer.from(JSON.stringify({ username: 'a', password: 'b' }));

test('a Brotli body is refused with 415 and never parsed, in any spelling', async () => {
  parsed = [];
  for (const enc of ['br', 'BR', ' br ', 'gzip, br', 'identity,br']) {
    const r = await post(zlib.brotliCompressSync(json), enc);
    assert.equal(r.status, 415, `Content-Encoding "${enc}"`);
    assert.match(r.body, /Brotli-encoded request bodies are not accepted/);
  }
  assert.deepEqual(parsed, [], 'no body reached the parser');
});

test('plain, gzip and deflate bodies still parse', async () => {
  parsed = [];
  assert.equal((await post(json)).status, 200);
  assert.equal((await post(zlib.gzipSync(json), 'gzip')).status, 200);
  assert.equal((await post(zlib.deflateSync(json), 'deflate')).status, 200);
  assert.deepEqual(parsed, [{ username: 'a', password: 'b' }, { username: 'a', password: 'b' }, { username: 'a', password: 'b' }]);
});

test('a coding that merely contains "br" is not mistaken for Brotli', async () => {
  parsed = [];
  // Not a real coding: the parser rejects it (415 from body-parser), but the
  // guard must not be what refuses it.
  const r = await post(json, 'brx');
  assert.doesNotMatch(r.body, /Brotli-encoded request bodies/);
});

test('the real app refuses a Brotli sign-in body before any route or parser runs', async () => {
  const { default: app } = await import('../app');
  const real = app.listen(0, '127.0.0.1');
  await once(real, 'listening');
  try {
    const realPort = (real.address() as AddressInfo).port;
    const body = zlib.brotliCompressSync(json);
    const r = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: realPort,
          path: '/api/auth/login',
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'br', 'Content-Length': body.length },
        },
        (res) => {
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
        }
      );
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(r.status, 415);
    assert.match(r.body, /Brotli-encoded request bodies are not accepted/);
  } finally {
    await new Promise<void>((resolve) => real.close(() => resolve()));
  }
});
