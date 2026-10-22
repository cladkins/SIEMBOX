import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatAlertRef, parseAlertRef, withAlertRef, MAX_ALERT_ID } from './alertRef';

test('formatAlertRef prefixes the id', () => {
  assert.equal(formatAlertRef(4821), 'ALR-4821');
  assert.equal(formatAlertRef(1), 'ALR-1');
});

test('parseAlertRef accepts every documented form', () => {
  for (const s of ['ALR-4821', 'alr-4821', 'Alr-4821', '4821', '#4821', '  ALR-4821  ', '\tALR-4821\n']) {
    assert.equal(parseAlertRef(s), 4821, s);
  }
  assert.equal(parseAlertRef(4821), 4821);
  assert.equal(parseAlertRef(`ALR-${MAX_ALERT_ID}`), MAX_ALERT_ID);
});

test('parseAlertRef rejects anything that is not exactly one reference', () => {
  const bad: unknown[] = [
    'ALR-0', '0', '#0', 'ALR-00012', '012', 'ALR-abc', 'ALR-', 'ALR', '', '   ', 'ALR -12', 'ALR- 12', 'ALR-12 ALR-13',
    'ALR-12x', 'xALR-12', 'ALR-1.5', '-12', '+12', 'ALR--12', '##12', 'ALR-#12', 'AL-12', 'ALRT-12',
    `ALR-${MAX_ALERT_ID + 1}`, 'ALR-99999999999', '9'.repeat(400), 'ALR-' + '1'.repeat(10_000),
    0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_ALERT_ID + 1, null, undefined, {}, ['12'], true,
  ];
  for (const v of bad) assert.equal(parseAlertRef(v), null, String(v).slice(0, 40));
});

test('parseAlertRef stays fast on hostile input', () => {
  const started = Date.now();
  for (let i = 0; i < 1000; i++) parseAlertRef('ALR-' + '1'.repeat(31) + '!');
  parseAlertRef('#'.repeat(1_000_000));
  assert.ok(Date.now() - started < 500);
});

test('withAlertRef adds ref without touching the row', () => {
  const row = { id: 7, title: 't' };
  assert.deepEqual(withAlertRef(row), { id: 7, title: 't', ref: 'ALR-7' });
  assert.deepEqual(row, { id: 7, title: 't' });
});
