/**
 * Validation for POST /log-discovery/sources/manual. validateManualSourceInput is
 * the pure (DB-free) core of the route, so the body-validation rules are tested
 * here directly — against the real bundled fingerprint library and poll-adapter
 * registry, so "is this a pollable device type / does it declare api_pull" is
 * exercised with real data, not a stub.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateManualSourceInput } from './logDiscovery';

test('a well-formed authentik body is accepted; port + tls default from the fingerprint', () => {
  const r = validateManualSourceInput({ ip_address: '192.168.1.50', fingerprint_id: 'authentik', secret: 'tok' });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.ip_address, '192.168.1.50');
    assert.equal(r.value.fingerprint_id, 'authentik');
    assert.equal(r.value.target_port, 9443, 'defaults to authentik api_pull target_port');
    assert.equal(r.value.tls, true, 'authentik defaults to https');
    assert.equal(r.value.hostname, null);
    assert.equal(typeof r.value.security_value, 'number');
  }
});

test('a non-authentik fingerprint defaults tls to false and uses its own target_port', () => {
  const r = validateManualSourceInput({ ip_address: '10.0.0.9', fingerprint_id: 'adguard-home' });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.target_port, 3000);
    assert.equal(r.value.tls, false);
  }
});

test('an explicit custom port + tls + hostname are honored', () => {
  const r = validateManualSourceInput({
    ip_address: '10.0.0.9',
    fingerprint_id: 'pihole',
    port: 8080,
    tls: true,
    hostname: 'dns1',
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.target_port, 8080);
    assert.equal(r.value.tls, true);
    assert.equal(r.value.hostname, 'dns1');
  }
});

test('a DNS name for ip_address is rejected (would break the INET cast)', () => {
  const r = validateManualSourceInput({ ip_address: 'pihole.local', fingerprint_id: 'pihole' });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.status, 400);
    assert.match(r.message, /ip_address/);
  }
});

test('a missing/blank ip_address is rejected', () => {
  assert.equal(validateManualSourceInput({ fingerprint_id: 'pihole' }).ok, false);
  assert.equal(validateManualSourceInput({ ip_address: '   ', fingerprint_id: 'pihole' }).ok, false);
});

test('an IPv6 literal is accepted', () => {
  const r = validateManualSourceInput({ ip_address: 'fe80::1', fingerprint_id: 'home-assistant' });
  assert.equal(r.ok, true);
});

test('a non-pollable fingerprint id is rejected (real fingerprint without a poll adapter)', () => {
  // proxmox is a real bundled fingerprint but has no api_pull poll adapter.
  const r = validateManualSourceInput({ ip_address: '192.168.1.5', fingerprint_id: 'proxmox' });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.status, 400);
    assert.match(r.message, /pollable device type/);
  }
});

test('an unknown fingerprint id is rejected', () => {
  const r = validateManualSourceInput({ ip_address: '192.168.1.5', fingerprint_id: 'not-a-real-device' });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.status, 400);
});

test('a missing fingerprint id is rejected', () => {
  assert.equal(validateManualSourceInput({ ip_address: '192.168.1.5' }).ok, false);
});

test('an out-of-range or non-integer port is rejected', () => {
  for (const port of [0, 70000, -5, 3.5, 'eighty']) {
    const r = validateManualSourceInput({ ip_address: '192.168.1.5', fingerprint_id: 'authentik', port });
    assert.equal(r.ok, false, `port=${port} should be rejected`);
  }
});

test('a non-boolean tls is rejected', () => {
  const r = validateManualSourceInput({ ip_address: '192.168.1.5', fingerprint_id: 'authentik', tls: 'yes' });
  assert.equal(r.ok, false);
});
