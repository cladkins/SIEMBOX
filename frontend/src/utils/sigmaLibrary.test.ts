import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  compatibilityText,
  levelType,
  libraryStatus,
  logsourceLabel,
  provenanceBadge,
  sigmaAction,
  type SigmaState,
} from './sigmaLibrary.ts';

const STATE: SigmaState = {
  release_tag: 'r2026-07-01',
  fetched_at: '2026-10-23T10:00:00.000Z',
  last_attempt_at: '2026-10-23T10:00:00.000Z',
  last_error: null,
  last_error_at: null,
  rule_count: 2642,
};
const NOW = new Date('2026-10-23T13:00:00.000Z').getTime();

describe('logsourceLabel / levelType', () => {
  it('joins the parts that are set', () => {
    assert.equal(logsourceLabel({ product: 'linux', category: null, service: 'sshd' }), 'linux · sshd');
    assert.equal(logsourceLabel({ product: null, category: 'proxy', service: null }), 'proxy');
    assert.equal(logsourceLabel(null), '');
  });
  it('maps levels to tag types', () => {
    assert.equal(levelType('critical'), 'danger');
    assert.equal(levelType('medium'), 'warning');
    assert.equal(levelType('informational'), 'info');
  });
});

describe('compatibilityText', () => {
  it('names the parsers and warns when sampled logs already match', () => {
    const t = compatibilityText({
      convertible: true,
      compatibility: {
        compatible: true,
        parsers: [
          { parser_name: 'traefik', parts: [0], matched: 2, sampled: 10 },
          { parser_name: 'caddy', parts: [0], matched: 0, sampled: 5 },
          { parser_name: 'nginx', parts: [0], sampled: 5 },
          { parser_name: 'npm', parts: [0], sampled: 5 },
        ],
      },
    });
    assert.equal(t.label, 'traefik +3');
    assert.equal(t.type, 'success');
    assert.match(t.detail, /2 of 25 sampled logs already match/);
  });
  it('says which field is missing, or that the logsource does not fit', () => {
    assert.match(compatibilityText({ convertible: true, compatibility: { compatible: false, parsers: [], missing_field: 'image' } }).detail, /"image"/);
    assert.match(
      compatibilityText({ convertible: true, compatibility: { compatible: false, parsers: [], logsource_mismatch: 'product github' } }).detail,
      /none is a product github source/
    );
    assert.equal(compatibilityText({ convertible: false, compatibility: null }).label, 'Not convertible');
  });
});

describe('sigmaAction', () => {
  it('update beats added; a refused rule cannot be added', () => {
    assert.equal(sigmaAction({ installed: { rule_ids: [1], enabled: 0, update_available: true }, installable: true }), 'update');
    assert.equal(sigmaAction({ installed: { rule_ids: [1], enabled: 1, update_available: false }, installable: true }), 'added');
    assert.equal(sigmaAction({ installed: null, installable: true }), 'add');
    assert.equal(sigmaAction({ installed: null, installable: false }), 'blocked');
  });
});

describe('libraryStatus', () => {
  it('is empty before the first refresh', () => {
    assert.match(libraryStatus(null).text, /library is empty/);
  });
  it('names the release and its age', () => {
    assert.deepEqual(libraryStatus(STATE, NOW), { type: 'info', text: 'SigmaHQ release r2026-07-01, 2642 rules, fetched 3 h ago.' });
  });
  it('says SigmaHQ is unreachable and that the cache is kept', () => {
    const s = libraryStatus({ ...STATE, last_error: 'timed out after 60 s', last_error_at: '2026-10-23T12:00:00.000Z' }, NOW);
    assert.equal(s.type, 'warning');
    assert.match(s.text, /unreachable \(timed out after 60 s\)\. Showing the cached release r2026-07-01/);
    const never = libraryStatus({ ...STATE, release_tag: null, fetched_at: null, last_error: 'ENOTFOUND github.com', last_error_at: STATE.fetched_at }, NOW);
    assert.equal(never.type, 'error');
  });
  it('an old failure followed by a success is not reported', () => {
    assert.equal(libraryStatus({ ...STATE, last_error: 'old', last_error_at: '2026-10-22T00:00:00.000Z' }, NOW).type, 'info');
  });
});

describe('provenanceBadge', () => {
  const p = { sigma_id: 'x', release: 'r1', url: 'u', author: null, update_available: false, deprecated: false };
  it('deprecated beats update; nothing for a current rule', () => {
    assert.equal(provenanceBadge(p), null);
    assert.deepEqual(provenanceBadge({ ...p, update_available: true }), { label: 'Update available', type: 'warning' });
    assert.deepEqual(provenanceBadge({ ...p, update_available: true, deprecated: true }), { label: 'Deprecated in SigmaHQ', type: 'danger' });
    assert.equal(provenanceBadge(null), null);
  });
});
