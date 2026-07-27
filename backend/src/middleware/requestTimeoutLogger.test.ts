/**
 * Tests for the request-timeout logger: a client that aborts a slow, still-in-
 * flight request should produce a Recent Errors entry; a finished response or a
 * fast cancel should not. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { requestTimeoutLogger } from './requestTimeoutLogger';
import { ErrorLogService } from '../services/errors/errorLogService';

function makeReqRes(path: string, writableEnded: boolean) {
  const req: any = { path, method: 'GET', user: { id: 1 } };
  const res: any = new EventEmitter();
  res.writableEnded = writableEnded;
  return { req, res };
}

function stubLogger() {
  const calls: any[] = [];
  const orig = ErrorLogService.logBackgroundError;
  (ErrorLogService as any).logBackgroundError = (source: string, error: unknown, context: any) =>
    calls.push({ source, error, context });
  return { calls, restore: () => ((ErrorLogService as any).logBackgroundError = orig) };
}

test('logs a timeout when the client aborts an in-flight API request', () => {
  const { calls, restore } = stubLogger();
  try {
    const { req, res } = makeReqRes('/api/parsers/match-stats', false); // not finished
    requestTimeoutLogger(0)(req, res, () => {});
    res.emit('close');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].source, 'http');
    assert.match(String(calls[0].error.message), /timeout/i);
    assert.equal(calls[0].context.endpoint, '/api/parsers/match-stats');
  } finally {
    restore();
  }
});

test('does not log when the response finished normally', () => {
  const { calls, restore } = stubLogger();
  try {
    const { req, res } = makeReqRes('/api/parsers/match-stats', true); // finished
    requestTimeoutLogger(0)(req, res, () => {});
    res.emit('close');
    assert.equal(calls.length, 0);
  } finally {
    restore();
  }
});

test('ignores fast cancels below the elapsed threshold', () => {
  const { calls, restore } = stubLogger();
  try {
    const { req, res } = makeReqRes('/api/logs/parsed', false);
    requestTimeoutLogger(5000)(req, res, () => {}); // high threshold, ~0ms elapsed
    res.emit('close');
    assert.equal(calls.length, 0);
  } finally {
    restore();
  }
});

test('ignores non-API paths entirely (next called, no close handler)', () => {
  const { calls, restore } = stubLogger();
  try {
    const { req, res } = makeReqRes('/assets/app.js', false);
    let nexted = false;
    requestTimeoutLogger(0)(req, res, () => (nexted = true));
    res.emit('close');
    assert.equal(nexted, true);
    assert.equal(calls.length, 0);
  } finally {
    restore();
  }
});
