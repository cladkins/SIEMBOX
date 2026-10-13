/**
 * Getting Started completion without a database: how the one stored value
 * reads, and what each role is told. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { completionValue, parseOnboardingState, toPublicOnboardingState } from './onboardingState';

test('parseOnboardingState: no row, a reopened row, a completion, and unreadable values', () => {
  assert.deepEqual(parseOnboardingState(undefined), {
    completed: false,
    completed_at: null,
    completed_by: null,
    recorded: false,
  });
  assert.deepEqual(parseOnboardingState(''), {
    completed: false,
    completed_at: null,
    completed_by: null,
    recorded: true,
  });
  assert.deepEqual(parseOnboardingState('{"at":"2026-10-12T09:30:00.000Z","by":"admin"}'), {
    completed: true,
    completed_at: '2026-10-12T09:30:00.000Z',
    completed_by: 'admin',
    recorded: true,
  });
  // Any non-empty value counts as completed; unreadable details are just unknown.
  for (const raw of ['1', 'true', 'not json', '[]', 'null', '{"at":"soon","by":""}', '{"at":7,"by":{"x":1}}']) {
    assert.deepEqual(
      parseOnboardingState(raw),
      { completed: true, completed_at: null, completed_by: null, recorded: true },
      raw
    );
  }
  assert.equal(parseOnboardingState(JSON.stringify({ at: '2026-10-12T09:30:00Z', by: 'x'.repeat(256) })).completed_by, null);
  assert.equal(parseOnboardingState(JSON.stringify({ by: 'x'.repeat(255) })).completed_by?.length, 255);
});

test('completionValue round-trips through the parser', () => {
  const at = new Date('2026-10-12T09:30:00.000Z');
  assert.deepEqual(parseOnboardingState(completionValue('alice', at)), {
    completed: true,
    completed_at: at.toISOString(),
    completed_by: 'alice',
    recorded: true,
  });
});

test('toPublicOnboardingState: the admin username is for admins only', () => {
  const state = parseOnboardingState(completionValue('alice', new Date('2026-10-12T09:30:00.000Z')));
  assert.deepEqual(toPublicOnboardingState(state, true), {
    completed: true,
    completed_at: '2026-10-12T09:30:00.000Z',
    completed_by: 'alice',
  });
  assert.deepEqual(toPublicOnboardingState(state, false), {
    completed: true,
    completed_at: '2026-10-12T09:30:00.000Z',
    completed_by: null,
  });
  assert.deepEqual(toPublicOnboardingState(parseOnboardingState(''), true), {
    completed: false,
    completed_at: null,
    completed_by: null,
  });
});
