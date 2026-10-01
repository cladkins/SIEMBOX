/**
 * validateLogPushEntry is DB-free and tested directly. ingestPushedLogs'
 * database steps are injected (PushDeps), so the batch behaviour -- counting,
 * and not hanging on a dead database -- is tested with stubs.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestPushedLogs, PushDeps, validateLogPushEntry } from './logPushService';
import { isInIngestContext } from '../../config/database';
import type { LogShipper } from '../../models/LogShipper';
import type { RawLog } from '../../models/RawLog';

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

// ---------------------------------------------------------------------------
// ingestPushedLogs -- batch behaviour with stubbed database steps
// ---------------------------------------------------------------------------

const SHIPPER = { id: 7, http_push_key_hash: 'deadbeefcafef00d'.repeat(4) } as unknown as LogShipper;
const entries = (n: number) => Array.from({ length: n }, (_, i) => ({ message: `line ${i}` }));
const stored = { id: 1 } as RawLog;
const refused = () => Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:5432'), { code: 'ECONNREFUSED' });

function deps(overrides: Partial<PushDeps> = {}): PushDeps & { created: number; processed: number } {
  const d = {
    created: 0,
    processed: 0,
    async createRawLog() {
      d.created++;
      return stored;
    },
    async processLog() {
      d.processed++;
    },
    ...overrides,
  };
  return d;
}

test('a healthy batch is stored and processed entry by entry', async () => {
  const d = deps();
  const result = await ingestPushedLogs(SHIPPER, entries(5), '10.0.0.9', d);
  assert.deepEqual(result, { accepted: 5, duplicate: 0, rejected: 0, errors: [] });
  assert.equal(d.created, 5);
  assert.equal(d.processed, 5);
});

test('a deduped entry (create returns null) is counted as a duplicate and not parsed', async () => {
  const d = deps({ createRawLog: async () => null });
  const result = await ingestPushedLogs(SHIPPER, entries(3), '10.0.0.9', d);
  assert.deepEqual(result, { accepted: 0, duplicate: 3, rejected: 0, errors: [] });
  assert.equal(d.processed, 0);
});

test('the batch runs on the ingest pool, and the context does not leak out of the call', async () => {
  const seen: boolean[] = [];
  const d = deps({
    async createRawLog() {
      await new Promise((r) => setTimeout(r, 1)); // across an await, like the real query
      seen.push(isInIngestContext());
      return stored;
    },
    async processLog() {
      seen.push(isInIngestContext());
    },
  });
  assert.equal(isInIngestContext(), false);
  await ingestPushedLogs(SHIPPER, entries(2), '10.0.0.9', d);
  assert.deepEqual(seen, [true, true, true, true]);
  assert.equal(isInIngestContext(), false);
});

test('once the database is unreachable the rest of the batch is rejected WITHOUT trying again', async () => {
  // Each real attempt can wait out the whole connection-retry budget, so a
  // 1000-entry batch must not try every entry.
  const d = deps({
    async createRawLog() {
      d.created++;
      throw refused();
    },
  });
  const result = await ingestPushedLogs(SHIPPER, entries(1000), '10.0.0.9', d);
  assert.equal(d.created, 1, 'only the first entry touched the database');
  assert.equal(result.accepted, 0);
  assert.equal(result.rejected, 1000);
  assert.ok(result.errors.length > 0 && result.errors.every((e) => e.error === 'database unavailable'));
  assert.equal(result.errors.length, 20, 'error list stays capped');
});

test('connection-pool exhaustion counts as unreachable too (pg-pool acquire timeout)', async () => {
  const d = deps({
    async createRawLog() {
      d.created++;
      throw new Error('timeout exceeded when trying to connect');
    },
  });
  const result = await ingestPushedLogs(SHIPPER, entries(10), '10.0.0.9', d);
  assert.equal(d.created, 1);
  assert.equal(result.rejected, 10);
});

test('entries stored before the outage are kept, and only the rest are rejected', async () => {
  const d = deps({
    async createRawLog() {
      d.created++;
      if (d.created > 3) throw refused();
      return stored;
    },
  });
  const result = await ingestPushedLogs(SHIPPER, entries(10), '10.0.0.9', d);
  assert.equal(result.accepted, 3);
  assert.equal(result.rejected, 7);
  assert.equal(d.created, 4, 'three stored, one failed, six never attempted');
});

test('an ordinary (non-connection) error rejects just that entry and the batch carries on', async () => {
  const d = deps({
    async createRawLog() {
      d.created++;
      if (d.created === 2) throw Object.assign(new Error('value too long'), { code: '22001' });
      return stored;
    },
  });
  const result = await ingestPushedLogs(SHIPPER, entries(4), '10.0.0.9', d);
  assert.equal(result.accepted, 3);
  assert.equal(result.rejected, 1);
  assert.deepEqual(result.errors, [{ index: 1, error: 'internal error storing log' }]);
  assert.equal(d.created, 4);
});

test('invalid entries keep their validation message even after the database is marked unavailable', async () => {
  const d = deps({
    async createRawLog() {
      d.created++;
      throw refused();
    },
  });
  const batch = [{ message: 'ok' }, { nope: true }, { message: 'also ok' }];
  const result = await ingestPushedLogs(SHIPPER, batch, '10.0.0.9', d);
  assert.deepEqual(result.errors, [
    { index: 0, error: 'database unavailable' },
    { index: 1, error: 'message is required and must be a non-empty string' },
    { index: 2, error: 'database unavailable' },
  ]);
  assert.equal(d.created, 1);
});
