/**
 * A malformed JSON body must not put its contents in the logs.
 *
 * V8's JSON.parse error quotes the input (`Unexpected token 'h', ..."assword":
 * hunter2}" is not valid JSON`) and body-parser keeps the raw body on the
 * error. Before bodyParserErrorHandler, that error fell through to
 * errorHandler as an "unexpected" 500 and was logged — console and
 * application_errors — so a malformed login, password-check or API-key request
 * could persist the secret. A compressed body that does not decompress is a
 * client error too, not a logged 500. This drives a real Express app over
 * loopback.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'events';
import type { AddressInfo } from 'net';
import zlib from 'zlib';
import express, { NextFunction, Request, Response } from 'express';
import { bodyParserErrorHandler } from './errorHandler';
import { logger } from '../utils/logger';

const SECRET = 'hunter2-do-not-log';

test('a malformed JSON body gets a 400 and its contents are neither echoed nor logged', async () => {
  const app = express();
  app.use(express.json());
  app.post('/check', (_req, res) => {
    res.json({ ok: true });
  });
  let reachedGenericHandler = false;
  app.use(bodyParserErrorHandler);
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    reachedGenericHandler = true;
    res.status(500).end();
  });

  const logged: string[] = [];
  const target = logger as unknown as Record<string, unknown>;
  const originals = new Map<string, unknown>();
  for (const level of ['error', 'warn', 'info', 'debug']) {
    originals.set(level, target[level]);
    target[level] = (...args: unknown[]) => {
      logged.push(JSON.stringify(args));
      return logger;
    };
  }

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const { port } = server.address() as AddressInfo;
    const res = await fetch(`http://127.0.0.1:${port}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: `{"password": ${SECRET}}`,
    });
    const text = await res.text();

    assert.equal(res.status, 400);
    assert.match(text, /Malformed request body/);
    assert.ok(!text.includes(SECRET), 'the response does not echo the body');
    assert.equal(reachedGenericHandler, false, 'the generic (logging) error handler never sees it');
    assert.ok(logged.length > 0, 'the rejection is still noted');
    assert.deepEqual(
      logged.filter((line) => line.includes(SECRET)),
      [],
      'no log line carries the body'
    );
  } finally {
    server.close();
    for (const [level, fn] of originals) target[level] = fn;
  }
});

// A compressed body that does not decompress reaches the error handlers as
// zlib's own error, which body-parser makes a 400 but gives no `type`.
const JSON_BODY = JSON.stringify({ username: 'admin', password: SECRET });
const UNDECODABLE: Array<[label: string, encoding: string, body: Buffer]> = [
  ['corrupt br', 'br', Buffer.from('not brotli at all')],
  ['truncated br', 'br', zlib.brotliCompressSync(JSON_BODY).subarray(0, 5)],
  ['corrupt gzip', 'gzip', Buffer.from('not gzip at all')],
  ['truncated gzip', 'gzip', zlib.gzipSync(JSON_BODY).subarray(0, 12)],
  ['corrupt deflate', 'deflate', Buffer.from('not deflate at all')],
  ['deflate needing a dictionary', 'deflate', zlib.deflateSync(JSON_BODY, { dictionary: Buffer.from('dict') })],
];

test('a compressed body that does not decompress gets a 400 and never reaches the generic handler', async () => {
  const app = express();
  app.use(express.json());
  app.post('/check', (_req, res) => {
    res.json({ ok: true });
  });
  let reachedGenericHandler = 0;
  app.use(bodyParserErrorHandler);
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    reachedGenericHandler++;
    res.status(500).end();
  });

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const { port } = server.address() as AddressInfo;
    for (const [label, encoding, body] of UNDECODABLE) {
      const res = await fetch(`http://127.0.0.1:${port}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Encoding': encoding },
        body,
      });
      assert.equal(res.status, 400, label);
      assert.deepEqual(await res.json(), { status: 'error', statusCode: 400, message: 'Invalid request body' }, label);
    }
    for (const [label, encoding, body] of [
      ['valid br', 'br', zlib.brotliCompressSync(JSON_BODY)],
      ['valid gzip', 'gzip', zlib.gzipSync(JSON_BODY)],
    ] as const) {
      const res = await fetch(`http://127.0.0.1:${port}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Encoding': encoding },
        body,
      });
      assert.equal(res.status, 200, label);
    }
    assert.equal(reachedGenericHandler, 0, 'the generic (logging) error handler never sees them');
  } finally {
    server.close();
  }
});

test('errors that are not body-parser rejections pass straight through', () => {
  const passed: unknown[] = [];
  const res = {} as Response;
  const errors = [
    new Error('boom'),
    { type: 'entity.parse.failed', status: 500 },
    { status: 400 },
    null,
    // zlib errors from a route handler's own work, not from reading the body
    Object.assign(new Error('incorrect header check'), { code: 'Z_DATA_ERROR' }),
    Object.assign(new Error('Decompression failed'), { code: 'ERR__ERROR_FORMAT_PADDING_2', status: 500, expose: false }),
    { code: 'Z_BUF_ERROR', status: 400 },
    // a 400 with some other code
    { code: 'ECONNRESET', status: 400, expose: true },
  ];
  for (const err of errors) {
    bodyParserErrorHandler(err, {} as Request, res, (e?: unknown) => passed.push(e));
  }
  assert.equal(passed.length, errors.length);
});
