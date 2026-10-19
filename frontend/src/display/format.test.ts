import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ageOf, changeText, clockText, compact, countryName, duration, freshnessText } from './format.ts';

describe('compact numbers', () => {
  it('keeps numbers up to 9,999 whole, with separators', () => {
    assert.equal(compact(0), '0');
    assert.equal(compact(2412), '2,412');
    assert.equal(compact(9999), '9,999');
  });
  it('shortens larger numbers to k, M and B', () => {
    assert.equal(compact(10_000), '10k');
    assert.equal(compact(18_149), '18.1k');
    assert.equal(compact(181_234), '181k');
    assert.equal(compact(1_234_567), '1.2M');
    assert.equal(compact(3_000_000_000), '3B');
  });
  it('shows a dash for missing values', () => {
    assert.equal(compact(null), '—');
    assert.equal(compact(undefined), '—');
    assert.equal(compact(Number.NaN), '—');
  });
});

describe('durations and ages', () => {
  it('reads as the wall shows it', () => {
    assert.equal(duration(45_000), '45 s');
    assert.equal(duration(12 * 60_000 + 5_000), '12 m');
    assert.equal(duration((3 * 60 + 12) * 60_000), '3 h 12 m');
    assert.equal(duration(2 * 3_600_000), '2 h');
    assert.equal(duration((2 * 24 + 4) * 3_600_000), '2 d 4 h');
    assert.equal(duration(-5000), '0 s');
  });
  it('measures an ISO time against now', () => {
    const now = Date.parse('2026-10-16T12:00:00Z');
    assert.equal(ageOf('2026-10-16T11:58:00Z', now), '2 m');
    assert.equal(ageOf(null, now), '—');
    assert.equal(ageOf('not a date', now), '—');
  });
  it('says how fresh the data is', () => {
    assert.equal(freshnessText(null, 1000), 'connecting');
    assert.equal(freshnessText(0, 12_000), 'updated 12 s ago');
  });
});

describe('clock', () => {
  it('is HH:MM in 24 h, in the given time zone', () => {
    const t = Date.parse('2026-10-16T14:02:59Z');
    assert.equal(clockText(t, 'UTC'), '14:02');
    assert.equal(clockText(t, 'Asia/Tokyo'), '23:02');
  });
  it('falls back to the screen zone for an unknown zone', () => {
    assert.match(clockText(0, 'Not/AZone'), /^\d\d:\d\d$/);
  });
});

describe('change against the previous window', () => {
  it('shows direction with a shape, not colour alone', () => {
    assert.deepEqual(changeText(108, 100), { text: '▲ 8%', direction: 'up' });
    assert.deepEqual(changeText(88, 100), { text: '▼ 12%', direction: 'down' });
    assert.deepEqual(changeText(100, 100), { text: '= same', direction: 'same' });
    assert.deepEqual(changeText(5, 0), { text: '▲ from 0', direction: 'up' });
    assert.deepEqual(changeText(0, 0), { text: '= same', direction: 'same' });
  });
});

describe('country names', () => {
  it('come from the code on the client', () => {
    assert.equal(countryName('DE'), 'Germany');
    assert.equal(countryName('us'), 'United States');
    assert.equal(countryName('nope'), 'nope');
  });
});
