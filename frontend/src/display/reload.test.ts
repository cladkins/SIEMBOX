import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { nextDailyReload, ReloadPlanner, versionChanged } from './reload.ts';

describe('reloads', () => {
  it('daily: the next 04:00 local time', () => {
    const morning = new Date(2026, 9, 16, 3, 59).getTime();
    assert.equal(nextDailyReload(morning), new Date(2026, 9, 16, 4, 0).getTime());
    const later = new Date(2026, 9, 16, 4, 0).getTime();
    assert.equal(nextDailyReload(later), new Date(2026, 9, 17, 4, 0).getTime());
  });

  it('a new backend version counts only once one is known', () => {
    assert.equal(versionChanged(null, '4.1.0'), false);
    assert.equal(versionChanged('4.0.0', '4.0.0'), false);
    assert.equal(versionChanged('4.0.0', ''), false);
    assert.equal(versionChanged('4.0.0', '4.1.0'), true);
  });

  it('reloads only after a successful snapshot', () => {
    let reloads = 0;
    const now = new Date(2026, 9, 16, 12, 0).getTime();
    const planner = new ReloadPlanner(now, () => (reloads += 1));
    // sessionStorage is absent under node: clearing the flag is a no-op.
    (globalThis as { window?: unknown }).window = {};
    assert.equal(planner.afterSuccess('4.0.0', now), false);
    assert.equal(planner.afterSuccess('4.0.0', now + 1000), false);
    assert.equal(planner.afterSuccess('4.1.0', now + 2000), true);
    assert.equal(reloads, 1);
    const daily = new ReloadPlanner(now, () => (reloads += 1));
    assert.equal(daily.afterSuccess('4.0.0', new Date(2026, 9, 17, 4, 1).getTime()), true);
    delete (globalThis as { window?: unknown }).window;
  });
});
