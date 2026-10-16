import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyGraphError, graphErrorMessage } from './errors.ts';

test('a cancelled call says nothing', () => {
  assert.equal(classifyGraphError({ code: 'ERR_CANCELED', name: 'CanceledError' }).kind, 'aborted');
  assert.equal(graphErrorMessage({ name: 'AbortError' }), '');
});

test('busy takes Retry-After, capped, with a default', () => {
  const header = classifyGraphError({ response: { status: 503, headers: { 'retry-after': '3' }, data: { code: 'GRAPH_BUSY' } } });
  assert.deepEqual([header.kind, header.retryAfter], ['busy', 3]);
  assert.equal(classifyGraphError({ response: { status: 503, data: { retryAfter: 5 } } }).retryAfter, 5);
  assert.equal(classifyGraphError({ response: { status: 503 } }).retryAfter, 2);
  assert.equal(classifyGraphError({ response: { status: 503, headers: { 'retry-after': '9999' } } }).retryAfter, 30);
});

test('bad input, not available, server, timeout, network', () => {
  const bad = classifyGraphError({ response: { status: 400, data: { code: 'GRAPH_BAD_ENTITY', message: 'not an IP' } } });
  assert.deepEqual([bad.kind, bad.message], ['bad', 'not an IP']);
  assert.equal(classifyGraphError({ response: { status: 404, data: {} } }).kind, 'unavailable');
  assert.equal(classifyGraphError({ response: { status: 500 } }).kind, 'server');
  assert.equal(classifyGraphError({ code: 'ECONNABORTED', message: 'timeout of 8000ms exceeded' }).kind, 'timeout');
  assert.equal(classifyGraphError(new Error('Network Error')).kind, 'network');
  assert.equal(classifyGraphError(undefined).kind, 'network');
});
