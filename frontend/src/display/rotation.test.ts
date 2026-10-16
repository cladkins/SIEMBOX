import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  burnInOffset,
  BURN_IN_STEP_MS,
  dwellProgress,
  initialControl,
  step,
  togglePause,
  viewIndex,
  type RotationInput,
} from './rotation.ts';

const at = (seconds: number, extra: Partial<RotationInput> = {}): RotationInput => ({
  serverNow: seconds * 1000,
  dwellSeconds: 20,
  views: 3,
  enabled: true,
  ...extra,
});

describe('rotation', () => {
  it('takes the view from server time, so screens on one link turn in step', () => {
    const c = initialControl();
    assert.equal(viewIndex(c, at(0)), 0);
    assert.equal(viewIndex(c, at(19.9)), 0);
    assert.equal(viewIndex(c, at(20)), 1);
    assert.equal(viewIndex(c, at(40)), 2);
    assert.equal(viewIndex(c, at(60)), 0);
  });

  it('stays on the first view with one view or rotation off', () => {
    const c = initialControl();
    assert.equal(viewIndex(c, at(25, { views: 1 })), 0);
    assert.equal(viewIndex(c, at(25, { enabled: false })), 0);
    assert.equal(dwellProgress(c, at(25, { enabled: false })), null);
  });

  it('reports progress through the dwell', () => {
    assert.equal(dwellProgress(initialControl(), at(25)), 0.25);
  });

  it('arrows shift the rotating index, or move the held view', () => {
    const c = step(initialControl(), at(5), 1);
    assert.equal(viewIndex(c, at(5)), 1);
    assert.equal(viewIndex(c, at(25)), 2); // keeps rotating from there
    const off = at(5, { enabled: false });
    assert.equal(viewIndex(step(initialControl(), off, -1), off), 2);
  });

  it('Space holds the current view and resumes rotating from it', () => {
    const paused = togglePause(initialControl(), at(25));
    assert.equal(paused.paused, true);
    assert.equal(viewIndex(paused, at(25)), 1);
    assert.equal(viewIndex(paused, at(125)), 1);
    assert.equal(dwellProgress(paused, at(125)), null);
    const resumed = togglePause(paused, at(125));
    assert.equal(viewIndex(resumed, at(125)), 1);
    assert.equal(viewIndex(resumed, at(140)), 2);
  });
});

describe('burn-in shift', () => {
  it('moves at most 4 px, one step every 10 minutes, in a cycle', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 8; i += 1) {
      const { x, y } = burnInOffset(i * BURN_IN_STEP_MS + 1);
      assert.ok(x >= 0 && x <= 4 && y >= 0 && y <= 4);
      seen.add(`${x},${y}`);
    }
    assert.equal(seen.size, 8);
    assert.deepEqual(burnInOffset(8 * BURN_IN_STEP_MS), burnInOffset(0));
  });
});
