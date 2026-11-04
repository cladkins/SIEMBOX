/**
 * The config a shipper agent polls must not change between polls unless the
 * configuration did. Shippers up to 1.4.2 re-apply (and restart `docker logs`
 * from the first line) whenever the JSON differs, and GET /config updates
 * last_seen in the same request. DB-free; `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { agentConfigView, AGENT_CONFIG_VOLATILE_FIELDS } from './LogShipper';

function row(lastSeen: string, extra: Record<string, unknown> = {}) {
  return {
    id: 7,
    name: 'llm',
    api_key: 'k',
    config: null,
    status: 'online',
    last_seen: new Date(lastSeen),
    updated_at: new Date(lastSeen),
    ip_address: '10.0.0.7',
    version: '1.4.2',
    hostname: 'llm',
    metadata: { os: 'Linux' },
    containers_reported_at: new Date(lastSeen),
    containers_available: true,
    containers_unavailable_reason: null,
    http_push_key_hash: 'secret-hash',
    http_push_key_created_at: null,
    http_push_last_seen: new Date(lastSeen),
    created_at: new Date('2026-01-01T00:00:00Z'),
    sources: [{ id: 1, source_type: 'docker', enabled: true, container_name: '', tag: 'docker', facility: 'local0' }],
    volumes: [],
    ...extra,
  };
}

test('two polls 37 s apart serialize identically', () => {
  const a = JSON.stringify(agentConfigView(row('2026-10-29T20:08:00Z')));
  const b = JSON.stringify(agentConfigView(row('2026-10-29T20:08:37Z')));
  assert.equal(a, b);
});

test('a source change still changes the config', () => {
  const a = JSON.stringify(agentConfigView(row('2026-10-29T20:08:00Z')));
  const changed = row('2026-10-29T20:08:00Z', {
    sources: [{ id: 1, source_type: 'docker', enabled: false, container_name: '', tag: 'docker', facility: 'local0' }],
  });
  assert.notEqual(a, JSON.stringify(agentConfigView(changed)));
});

test('volatile fields and the push-key hash are dropped; sources kept', () => {
  const view = agentConfigView(row('2026-10-29T20:08:00Z'));
  for (const f of AGENT_CONFIG_VOLATILE_FIELDS) assert.equal(f in view, false, `${f} should be dropped`);
  assert.equal('http_push_key_hash' in view, false);
  assert.equal(view.http_push_enabled, true);
  assert.equal(view.id, 7);
  assert.ok(Array.isArray(view.sources));
});
