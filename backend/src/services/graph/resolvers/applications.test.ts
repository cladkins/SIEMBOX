import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EDGE_VERSIONS, inventoryEdgeFacts, NETWORK_ONLY } from './applications';
import { NETWORK_SOURCES } from '../../applications/rollup';

test('inventory edge facts: versions in version order (newest kept), sanitized, deduplicated; network marked', () => {
  const at = new Date('2026-10-20T10:00:00Z');
  const out = inventoryEdgeFacts(
    {
      events: '42',
      first_seen: at,
      last_seen: '2026-10-26T10:00:00Z',
      sources: ['syslog_program', 'service_scan', 'service_scan'],
      versions: ['1.9', '1.10', '', '1.2', '1.10', '0.9', '2.0‮', '1.3', '1.4'],
    },
    false
  );
  assert.equal(out.count, 42);
  assert.deepEqual(out.versions, ['1.3', '1.4', '1.9', '1.10', '2.0'].slice(-EDGE_VERSIONS));
  assert.deepEqual(out.sources, ['service_scan', 'syslog_program']);
  assert.equal(out.first_seen, '2026-10-20T10:00:00.000Z');
  assert.equal(out.last_seen, '2026-10-26T10:00:00.000Z');
  assert.equal(out.network, undefined);
  assert.equal(inventoryEdgeFacts({ events: 1, first_seen: null, last_seen: null, sources: ['dns'], versions: null }, true).network, true);
  assert.deepEqual(inventoryEdgeFacts({ events: 1, first_seen: null, last_seen: null, sources: null, versions: null }, false).versions, []);
});

test('network-only evidence is what Application Monitoring calls it', () => {
  assert.deepEqual([...NETWORK_ONLY], NETWORK_SOURCES);
});
