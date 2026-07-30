import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapEntry } from './adguardHome';
import { basicAuthHeader } from '../httpFetch';

test('basicAuthHeader builds a standard base64 "user:pass" Basic header', () => {
  assert.equal(basicAuthHeader('admin', 'hunter2'), `Basic ${Buffer.from('admin:hunter2').toString('base64')}`);
  assert.equal(basicAuthHeader('admin', 'hunter2'), 'Basic YWRtaW46aHVudGVyMg==');
});

test('mapEntry produces a pihole-style "query[TYPE] name from client reason=X" message', () => {
  const entry = {
    time: '2024-01-15T12:00:00.123Z',
    client: '203.0.113.5',
    question: { name: 'tracker.example.com', type: 'A' },
    reason: 'NotFilteredNotFound',
  };
  const mapped = mapEntry(entry);
  assert.ok(mapped);
  assert.equal(mapped!.message, 'query[A] tracker.example.com from 203.0.113.5 reason=NotFilteredNotFound');
  assert.equal(mapped!.timestamp?.toISOString(), '2024-01-15T12:00:00.123Z');
});

test('mapEntry tolerates a missing question/reason without throwing', () => {
  const mapped = mapEntry({ time: '2024-01-15T12:00:00Z', client: '203.0.113.5' });
  assert.equal(mapped!.message, 'query[?] ? from 203.0.113.5 reason=?');
});

test('mapEntry returns null when time is missing', () => {
  assert.equal(mapEntry({ client: '203.0.113.5' }), null);
});
