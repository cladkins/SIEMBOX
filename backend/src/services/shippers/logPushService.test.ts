/**
 * validateLogPushEntry is the one DB-free piece of the HTTP log-push path,
 * so it's the one covered by a unit test here (mirrors how syslogFraming and
 * buildRawLogFilters are the only route-adjacent pure functions tested this
 * way). Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateLogPushEntry } from './logPushService';

test('a well-formed entry is accepted with all fields normalized', () => {
  const result = validateLogPushEntry({
    message: 'Failed password for root from 203.0.113.5 port 51515 ssh2',
    hostname: 'nas01',
    app_name: 'sshd',
    timestamp: '2026-07-30T14:22:01Z',
    facility: 4,
    severity: 3,
    event_id: 'abc-123',
  });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.entry.message, 'Failed password for root from 203.0.113.5 port 51515 ssh2');
    assert.equal(result.entry.hostname, 'nas01');
    assert.equal(result.entry.app_name, 'sshd');
    assert.equal(result.entry.facility, 4);
    assert.equal(result.entry.severity, 3);
    assert.equal(result.entry.event_id, 'abc-123');
  }
});

test('only message is required — everything else defaults to null', () => {
  const result = validateLogPushEntry({ message: 'hello' });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.entry, {
      message: 'hello',
      hostname: null,
      app_name: null,
      timestamp: null,
      facility: null,
      severity: null,
      event_id: null,
    });
  }
});

test('a non-object entry is rejected', () => {
  assert.equal(validateLogPushEntry('not an object').ok, false);
  assert.equal(validateLogPushEntry(null).ok, false);
  assert.equal(validateLogPushEntry(42).ok, false);
});

test('a missing, empty, or non-string message is rejected', () => {
  assert.equal(validateLogPushEntry({}).ok, false);
  assert.equal(validateLogPushEntry({ message: '' }).ok, false);
  assert.equal(validateLogPushEntry({ message: '   ' }).ok, false);
  assert.equal(validateLogPushEntry({ message: 12345 }).ok, false);
});

test('an oversized message is rejected', () => {
  const huge = 'x'.repeat(64 * 1024 + 1);
  const result = validateLogPushEntry({ message: huge });

  assert.equal(result.ok, false);
});

test('out-of-range facility/severity are nulled, not rejected', () => {
  const result = validateLogPushEntry({ message: 'hi', facility: 99, severity: -1 });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.entry.facility, null);
    assert.equal(result.entry.severity, null);
  }
});

test('long hostname/app_name are truncated, not rejected', () => {
  const longName = 'h'.repeat(300);
  const result = validateLogPushEntry({ message: 'hi', hostname: longName, app_name: longName });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.entry.hostname!.length, 255);
    assert.equal(result.entry.app_name!.length, 255);
  }
});

test('non-string hostname/app_name/event_id are nulled, not rejected', () => {
  const result = validateLogPushEntry({ message: 'hi', hostname: 123, app_name: {}, event_id: [] });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.entry.hostname, null);
    assert.equal(result.entry.app_name, null);
    assert.equal(result.entry.event_id, null);
  }
});
