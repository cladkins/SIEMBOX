/**
 * Coverage cache invalidation (coverageCache.ts): every rule write through
 * DetectionRuleModel bumps the generation and tells the coverage service, and
 * a failing listener never breaks the write. Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { coverageGeneration, invalidateAttackCoverage, onCoverageInvalidated } from './coverageCache';
import * as database from '../../config/database';
import { DetectionRuleModel } from '../../models/DetectionRule';

test('invalidateAttackCoverage bumps the generation and calls listeners; a throwing listener is contained', () => {
  const seen: number[] = [];
  onCoverageInvalidated(() => seen.push(coverageGeneration()));
  onCoverageInvalidated(() => {
    throw new Error('boom');
  });
  const before = coverageGeneration();
  assert.doesNotThrow(() => invalidateAttackCoverage());
  assert.equal(coverageGeneration(), before + 1);
  assert.deepEqual(seen, [before + 1]);
});

test('DetectionRuleModel create, update and delete each invalidate coverage', async () => {
  const q = mock.method(database.default, 'query', (async () => ({ rows: [{ id: 1 }], rowCount: 1 })) as never);
  try {
    let g = coverageGeneration();
    await DetectionRuleModel.create({ name: 'x', severity: 'low', rule_yaml: '', rule_logic: {} });
    assert.equal(coverageGeneration(), ++g);
    await DetectionRuleModel.update(1, { enabled: false });
    assert.equal(coverageGeneration(), ++g);
    await DetectionRuleModel.delete(1);
    assert.equal(coverageGeneration(), ++g);
  } finally {
    q.mock.restore();
    await database.closePools();
  }
});
