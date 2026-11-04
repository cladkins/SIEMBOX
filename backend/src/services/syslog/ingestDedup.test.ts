/**
 * IngestDedup: a replayed shipper line is dropped and counted; live repeats,
 * other shippers and direct syslog are kept; the window and key cap bound it.
 * DB-free; `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IngestDedup, type DedupLine } from './ingestDedup';

const T0 = Date.parse('2026-10-28T20:03:31Z');
const HOUR = 3600_000;

function line(overrides: Partial<DedupLine> = {}): DedupLine {
  return {
    shipperId: '4773d12e',
    hostname: 'llm',
    appName: 'siembox-backend',
    timestamp: new Date(T0),
    message: '2026-10-28 20:03:31 [info]: Running migration: 007_fix_vaultwarden_parser.sql',
    ...overrides,
  };
}

test('a replay of an old line is dropped and counted', () => {
  const d = new IngestDedup({}, T0);
  assert.equal(d.isDuplicate(line(), T0 + 1000), false, 'first copy is stored');
  assert.equal(d.isDuplicate(line(), T0 + 37_000), true, 'replay 37 s later');
  assert.equal(d.isDuplicate(line(), T0 + 74_000), true, 'and the next pass');
  assert.equal(d.stats().dropped, 2);
});

test('identical live lines in the same second are kept (no lag)', () => {
  const d = new IngestDedup({}, T0);
  assert.equal(d.isDuplicate(line(), T0 + 200), false);
  assert.equal(d.isDuplicate(line(), T0 + 400), false);
  assert.equal(d.stats().dropped, 0);
});

test('different shipper, container, timestamp or text is a different line', () => {
  const d = new IngestDedup({}, T0);
  d.isDuplicate(line(), T0);
  const later = T0 + HOUR / 2;
  assert.equal(d.isDuplicate(line({ shipperId: 'aaaaaaaa' }), later), false);
  assert.equal(d.isDuplicate(line({ appName: 'siembox-postgres' }), later), false);
  assert.equal(d.isDuplicate(line({ hostname: 'streambox' }), later), false);
  assert.equal(d.isDuplicate(line({ timestamp: new Date(T0 + 1000) }), later), false);
  assert.equal(d.isDuplicate(line({ message: 'other' }), later), false);
  assert.equal(d.isDuplicate(line(), later), true);
});

test('lines without a shipper id (direct syslog) are never deduped', () => {
  const d = new IngestDedup({}, T0);
  assert.equal(d.isDuplicate(line({ shipperId: null }), T0 + HOUR), false);
  assert.equal(d.isDuplicate(line({ shipperId: null }), T0 + HOUR), false);
});

test('keys expire after the window (sliding, two generations)', () => {
  const d = new IngestDedup({ windowMs: HOUR }, T0);
  d.isDuplicate(line(), T0);
  assert.equal(d.isDuplicate(line(), T0 + HOUR + 1), true, 'still remembered just past one window');
  // Two full rotations later the key is gone.
  d.isDuplicate(line({ message: 'tick' }), T0 + 2 * HOUR + 2);
  d.isDuplicate(line({ message: 'tock' }), T0 + 3 * HOUR + 3);
  assert.equal(d.isDuplicate(line(), T0 + 3 * HOUR + 4), false);
});

test('memory is capped at maxKeys', () => {
  const d = new IngestDedup({ maxKeys: 100 }, T0);
  for (let i = 0; i < 1000; i++) d.isDuplicate(line({ message: `m${i}` }), T0 + 60_000);
  assert.ok(d.stats().tracked <= 100, `tracked ${d.stats().tracked}`);
});

test('disabled dedup keeps everything', () => {
  const d = new IngestDedup({ enabled: false }, T0);
  d.isDuplicate(line(), T0);
  assert.equal(d.isDuplicate(line(), T0 + HOUR / 2), false);
});
