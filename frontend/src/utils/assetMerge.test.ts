import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assetLabel,
  canMergeAssets,
  defaultKeepId,
  duplicateReasonLabel,
  mergeFromIds,
  mergeMoveLines,
  type MergeableAsset,
} from './assetMerge.ts';

describe('assetMerge', () => {
  it('only the asset write roles may merge', () => {
    assert.equal(canMergeAssets('admin'), true);
    assert.equal(canMergeAssets('operator'), true);
    assert.equal(canMergeAssets('analyst'), true);
    assert.equal(canMergeAssets('viewer'), false);
    assert.equal(canMergeAssets(undefined), false);
  });

  it('keeps the agent-reported asset by default, else the most recently seen', () => {
    const assets: MergeableAsset[] = [
      { id: 71, ip_address: '192.168.1.253', last_seen: '2026-10-01T00:00:00Z', agent_count: 0 },
      { id: 33, ip_address: '192.168.1.130', last_seen: '2026-09-01T00:00:00Z', agent_count: 1 },
      { id: 72, ip_address: '192.168.1.254', last_seen: '2026-10-02T00:00:00Z' },
    ];
    assert.equal(defaultKeepId(assets), 33);
    assert.equal(defaultKeepId(assets.filter((a) => a.id !== 33)), 72);
    assert.equal(defaultKeepId([{ id: 9, ip_address: 'a' }, { id: 4, ip_address: 'b' }]), 4);
    assert.equal(defaultKeepId([]), null);
    assert.deepEqual(mergeFromIds(assets, 33), [71, 72]);
  });

  it('lists what moves, leaving zero counts out', () => {
    assert.deepEqual(
      mergeMoveLines({ vulnerabilities: 2364, vulnerabilities_combined: 870, services: 1, alerts: 0, agents: 0, application_locations: 3, application_vuln_links: 2 }),
      [
        '2364 vulnerability findings (870 vulnerabilities found on more than one of them become one finding)',
        '1 service',
        '3 Application Monitoring entries',
      ]
    );
    assert.deepEqual(
      mergeMoveLines({ vulnerabilities: 1, vulnerabilities_combined: 0, services: 0, alerts: 1, agents: 1, application_locations: 1, application_vuln_links: 0 }),
      ['1 vulnerability finding', '1 alert', '1 endpoint agent', '1 Application Monitoring entry']
    );
    assert.deepEqual(
      mergeMoveLines({ vulnerabilities: 0, vulnerabilities_combined: 0, services: 0, alerts: 0, agents: 0, application_locations: 0, application_vuln_links: 0 }),
      []
    );
  });

  it('labels', () => {
    assert.equal(assetLabel({ ip_address: '10.0.0.1', hostname: 'mbp.local' }), '10.0.0.1 (mbp.local)');
    assert.equal(assetLabel({ ip_address: '10.0.0.1' }), '10.0.0.1');
    assert.equal(duplicateReasonLabel('same_mac'), 'Same MAC address');
    assert.equal(duplicateReasonLabel('same_hostname'), 'Same host name');
    assert.equal(duplicateReasonLabel('other'), 'other');
  });
});
