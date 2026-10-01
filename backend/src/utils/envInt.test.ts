/**
 * Tests for the env-int reader. A typo in .env (DB_INGEST_POOL_MAX=ten, or 0)
 * must never turn into NaN/0 and silently wedge ingestion.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { envInt } from './envInt';

const KEY = 'SIEMBOX_TEST_ENV_INT';

function withEnv(value: string | undefined, fn: () => void) {
  const prev = process.env[KEY];
  if (value === undefined) delete process.env[KEY];
  else process.env[KEY] = value;
  try {
    fn();
  } finally {
    if (prev === undefined) delete process.env[KEY];
    else process.env[KEY] = prev;
  }
}

test('unset or blank gives the fallback', () => {
  withEnv(undefined, () => assert.equal(envInt(KEY, 7, 1), 7));
  withEnv('', () => assert.equal(envInt(KEY, 7, 1), 7));
  withEnv('   ', () => assert.equal(envInt(KEY, 7, 1), 7));
});

test('a valid integer is used, including surrounding whitespace and the floor itself', () => {
  withEnv('12', () => assert.equal(envInt(KEY, 7, 1), 12));
  withEnv(' 12 ', () => assert.equal(envInt(KEY, 7, 1), 12));
  withEnv('1', () => assert.equal(envInt(KEY, 7, 1), 1));
  withEnv('0', () => assert.equal(envInt(KEY, 7, 0), 0, 'zero is allowed when the floor is zero'));
});

test('junk, fractions, and below-floor values fall back instead of becoming NaN/0', () => {
  for (const bad of ['ten', '1.5', '12abc', '-3', '0', 'NaN', 'Infinity', '1e3x']) {
    withEnv(bad, () => assert.equal(envInt(KEY, 7, 1), 7, `"${bad}"`));
  }
});
