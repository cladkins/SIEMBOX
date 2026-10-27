import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assessTarget, findPublicTargets } from './targetSafety.ts';

// The full classifier suite is backend/src/services/scanner/targetSafety.test.ts,
// which also checks this file is a byte-for-byte copy of the backend's. These
// cover what the scan dialogs show.
describe('target safety (scan dialogs)', () => {
  it('flags the incident typo with a hint', () => {
    const a = assessTarget('192.169.1.0/24');
    assert.equal(a.kind, 'public');
    assert.equal(a.suggestion, '192.168.1.0/24');
  });

  it('leaves private ranges alone and only warns about hostnames', () => {
    const report = findPublicTargets(['192.168.1.0/24', '10.0.0.0/8', '172.16.5.0/24', '100.64.1.0/24', 'fd00::/8', 'nas.lan']);
    assert.deepEqual(report.publicTargets, []);
    assert.deepEqual(report.hostnames, ['nas.lan']);
  });

  it('names public targets, including partly public ranges', () => {
    const report = findPublicTargets(['8.8.8.8', '10.0.0.0/7', '172.32.0.0/16']);
    assert.deepEqual(report.publicTargets.map((t) => [t.target, t.suggestion ?? null, t.partlyPrivate ?? false]), [
      ['8.8.8.8', null, false],
      ['10.0.0.0/7', null, true],
      ['172.32.0.0/16', '172.31.0.0/16', false],
    ]);
  });
});
