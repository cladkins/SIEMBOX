/**
 * Time windows: presets, the alert-centred `around`, the clamps, and the day
 * range the log relationships (PR 3) use. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GraphError } from './errors';
import { dayRange, MAX_WINDOW_MS, resolveWindow, windowCacheKey, WINDOW_PRESETS } from './window';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
// 2026-10-15T14:02:30.500Z
const NOW = Date.UTC(2026, 9, 15, 14, 2, 30, 500);

const isBadParam = (err: unknown) => err instanceof GraphError && err.statusCode === 400 && err.code === 'GRAPH_BAD_PARAM';

test('presets end at now rounded up to the minute; the default is 7d', () => {
  const end = Date.UTC(2026, 9, 15, 14, 3);
  for (const [preset, length] of Object.entries(WINDOW_PRESETS)) {
    const w = resolveWindow({ window: preset }, NOW);
    assert.equal(w.preset, preset);
    assert.equal(w.toMs, end);
    assert.equal(w.toMs - w.fromMs, length);
    assert.ok(w.toMs - w.fromMs <= MAX_WINDOW_MS);
  }
  const fallback = resolveWindow({}, NOW);
  assert.equal(fallback.preset, '7d');
  assert.equal(fallback.to, '2026-10-15T14:03:00.000Z');
  assert.equal(fallback.from, '2026-10-08T14:03:00.000Z');
});

test('requests within one minute share a window (and so a cache entry)', () => {
  const a = resolveWindow({ window: '24h' }, NOW);
  const b = resolveWindow({ window: '24h' }, NOW + 20_000);
  assert.equal(windowCacheKey(a), windowCacheKey(b));
  assert.notEqual(windowCacheKey(a), windowCacheKey(resolveWindow({ window: '24h' }, NOW + 60_000)));
});

test('around=T is T - 24 h to T + 1 h', () => {
  const t = '2026-03-01T09:12:00Z';
  const w = resolveWindow({ around: t }, NOW);
  assert.equal(w.preset, 'around');
  assert.equal(w.from, '2026-02-28T09:12:00.000Z');
  assert.equal(w.to, '2026-03-01T10:12:00.000Z');
  // Offsets and fractions parse too.
  assert.equal(resolveWindow({ around: '2026-03-01T10:12:00.123+01:00' }, NOW).fromMs, Date.parse('2026-03-01T09:12:00.123Z') - DAY);
});

test('around near now: the end is clamped to (rounded) now + 1 h', () => {
  const w = resolveWindow({ around: new Date(NOW + 30 * MIN).toISOString() }, NOW);
  assert.equal(w.toMs, Date.UTC(2026, 9, 15, 14, 3) + HOUR);
  assert.ok(w.fromMs < w.toMs);
  assert.throws(() => resolveWindow({ around: new Date(NOW + 2 * HOUR).toISOString() }, NOW), isBadParam);
});

test('bad windows are a 400 GRAPH_BAD_PARAM', () => {
  for (const input of [
    { window: '1h' },
    { window: '365d' },
    { window: '__proto__' },
    { window: ['7d', '30d'] },
    { window: '7d', around: '2026-10-15T00:00:00Z' },
    { around: 'yesterday' },
    { around: '2026-10-15' },
    { around: '2026-10-15T00:00:00' },
    { around: '1999-12-31T23:59:59Z' },
    { around: '2026-02-30T00:00:00Z' },
    { around: `2026-10-15T00:00:00Z${' '.repeat(50)}` },
  ]) {
    assert.throws(() => resolveWindow(input, NOW), isBadParam, JSON.stringify(input));
  }
});

test('dayRange: the UTC days a window touches, `to` exclusive', () => {
  assert.deepEqual(dayRange(resolveWindow({ window: '24h' }, NOW)), { first: '2026-10-14', last: '2026-10-15' });
  assert.deepEqual(dayRange({ fromMs: Date.UTC(2026, 9, 14), toMs: Date.UTC(2026, 9, 15) }), { first: '2026-10-14', last: '2026-10-14' });
  assert.deepEqual(dayRange(resolveWindow({ window: '90d' }, NOW)).first, '2026-07-17');
});
