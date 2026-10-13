/**
 * Poll targets: the endpoint-path rules, where a source's overrides are read
 * from (a manual source's evidence, a discovered source's poll_overrides), the
 * view the edit dialog shows, and the hard non-regression requirement that a
 * scan-discovered source without overrides is polled at exactly the URL it was
 * before overrides existed. Uses the real fingerprint library and adapter
 * registry. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DiscoverySource } from '../../../models/DiscoverySource';
import { getFingerprintById } from '../fingerprintLoader';
import { getAdapter } from './registry';
import { resolveEndpoint } from './urls';
import { serializeCursor } from './adapters/homeAssistant';
import {
  MAX_ENDPOINT_LENGTH,
  buildPollTarget,
  describePollTarget,
  effectivePollUrl,
  readTargetOverrides,
  validateEndpointPath,
} from './pollTarget';

test('validateEndpointPath accepts plain paths and treats empty as "use the default"', () => {
  for (const ok of ['/api/error_log', '/api/hassio/core/logs', '/ha/api/hassio/core/logs/latest', '/api/v3/events/events/', "/a-b_c.d~e!$&'()*+,;=:@f"]) {
    assert.deepEqual(validateEndpointPath(ok), { ok: true, value: ok }, ok);
  }
  assert.deepEqual(validateEndpointPath('  /api/error_log  '), { ok: true, value: '/api/error_log' }, 'trimmed');
  for (const empty of ['', '   ', null, undefined]) {
    assert.deepEqual(validateEndpointPath(empty), { ok: true, value: null });
  }
  assert.deepEqual(validateEndpointPath('/' + 'a'.repeat(MAX_ENDPOINT_LENGTH - 1)).ok, true, 'exactly at the cap');
});

test('validateEndpointPath rejects anything that is not a plain path on the same host', () => {
  const bad: Array<[unknown, RegExp]> = [
    ['api/error_log', /starting with a single "\/"/],
    ['http://evil.example/api/error_log', /starting with a single "\/"/],
    ['//evil.example/api/error_log', /starting with a single "\/"/],
    ['https:/x', /starting with a single "\/"/],
    ['/api/../admin', /"\." or "\.\." path segments/],
    ['/api/./error_log', /"\." or "\.\." path segments/],
    ['/..', /"\." or "\.\." path segments/],
    ['/api/error_log?x=1', /without a query string or fragment/],
    ['/api/error_log#frag', /without a query string or fragment/],
    ['/api/error\nlog', /control characters/],
    ['/api/\u0000x', /control characters/],
    ['/api/\u0085x', /control characters/],
    ['/api/error log', /may only contain/],
    ['/api\\error_log', /may only contain/],
    ['/api/%2e%2e/x', /may only contain/],
    ['/api/érror', /may only contain/],
    ['/' + 'a'.repeat(MAX_ENDPOINT_LENGTH), /at most 256 characters/],
    [42, /must be a path string/],
    [{ path: '/x' }, /must be a path string/],
  ];
  for (const [value, message] of bad) {
    const r = validateEndpointPath(value);
    assert.equal(r.ok, false, `${JSON.stringify(value)} must be rejected`);
    if (!r.ok) assert.match(r.message, message, JSON.stringify(value));
  }
});

// A row as the scanner stores it: scan evidence, no poll_overrides.
function discovered(fingerprintId: string, over: Partial<DiscoverySource> = {}): DiscoverySource {
  return {
    id: 94,
    ip_address: '192.168.1.50',
    mac_address: null,
    hostname: null,
    open_ports: fingerprintId === 'authentik' ? [9443] : [],
    matched_fingerprint_id: fingerprintId,
    confidence: 90,
    is_guess: false,
    security_value: 6,
    status: 'onboarded',
    selected_log_access: null,
    evidence: {
      discovery_methods: ['active_probe'],
      matched_signals: ['port 8123'],
      http_responses: [{ port: 8123, path: '/manifest.json', status: 200 }],
      tls_subjects: [],
      mdns_services: [],
      ssdp_services: [],
    },
    poll_overrides: null,
    last_scan_id: 7,
    first_seen: '2026-10-01T00:00:00Z',
    last_seen: '2026-10-01T00:00:00Z',
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    ...over,
  };
}

function manual(fingerprintId: string, evidence: Record<string, unknown>): DiscoverySource {
  return discovered(fingerprintId, { evidence: { manual: true, ...evidence }, last_scan_id: null, open_ports: [Number(evidence.target_port) || 0] });
}

function apiPull(fingerprintId: string) {
  const la = getFingerprintById(fingerprintId)!.log_access.find((l) => l.method === 'api_pull');
  assert.ok(la, `${fingerprintId} declares api_pull`);
  return la!;
}

// The URLs each adapter requested for a scan-discovered source before overrides existed.
const PRE_OVERRIDE_URLS: Record<string, string> = {
  'home-assistant': 'http://192.168.1.50:8123/api/error_log',
  authentik: 'https://192.168.1.50:9443/api/v3/events/events/',
  pihole: 'http://192.168.1.50/admin/api.php',
  'adguard-home': 'http://192.168.1.50:3000/control/querylog',
};

test('a scan-discovered source without overrides gets the same PollTarget and the exact same URL as before', () => {
  for (const [fingerprintId, url] of Object.entries(PRE_OVERRIDE_URLS)) {
    const source = discovered(fingerprintId);
    const logAccess = apiPull(fingerprintId);
    const target = buildPollTarget(source, logAccess);
    // What pollOneSource built before: no port/tls (no evidence.target_port/.tls on a scanned row).
    assert.deepEqual(target, {
      sourceId: 94,
      ip: '192.168.1.50',
      openPorts: source.open_ports,
      evidence: source.evidence,
      port: undefined,
      tls: undefined,
      endpoint: undefined,
      logAccess,
    });
    assert.equal(resolveEndpoint(target, 'unused'), logAccess.endpoint, 'the fingerprint endpoint, as `logAccess.endpoint || default` gave');
    assert.equal(getAdapter(fingerprintId)!.describeUrl(target, null), url, fingerprintId);
    assert.equal(effectivePollUrl(source, fingerprintId, null), url);
  }
});

test('poll_overrides apply to a discovered source; its evidence target keys never do', () => {
  const overridden = discovered('home-assistant', {
    poll_overrides: { port: 8443, tls: true, endpoint: '/api/hassio/core/logs' },
  });
  assert.deepEqual(readTargetOverrides(overridden), { port: 8443, tls: true, endpoint: '/api/hassio/core/logs' });
  assert.equal(effectivePollUrl(overridden, 'home-assistant', null), 'https://192.168.1.50:8443/api/hassio/core/logs');

  // Only a manual row's evidence is a poll target; a scanned row's is the scanner's.
  const stray = discovered('home-assistant', { evidence: { target_port: 9999, tls: true, endpoint: '/x' } });
  assert.deepEqual(readTargetOverrides(stray), {});
});

test("a manual source's target comes from its evidence (poll_overrides is ignored)", () => {
  const source = manual('home-assistant', { target_port: 8124, tls: false, endpoint: '/api/hassio/core/logs' });
  source.poll_overrides = { port: 1, tls: true };
  assert.deepEqual(readTargetOverrides(source), { port: 8124, tls: false, endpoint: '/api/hassio/core/logs' });
  // A manual source created before endpoints existed: port and scheme only.
  assert.deepEqual(readTargetOverrides(manual('pihole', { target_port: 8080, tls: false })), { port: 8080, tls: false });
});

test('malformed stored values are ignored, never handed to an adapter', () => {
  const source = discovered('home-assistant', {
    poll_overrides: { port: 70000, tls: 'yes', endpoint: 'http://evil.example/x' },
  });
  assert.deepEqual(readTargetOverrides(source), {});
  assert.equal(effectivePollUrl(source, 'home-assistant', null), PRE_OVERRIDE_URLS['home-assistant']);
  assert.deepEqual(readTargetOverrides(discovered('home-assistant', { poll_overrides: { endpoint: '/a/../b' } })), {});
});

test('describePollTarget: effective values, stored overrides and defaults; null without an API pull adapter', () => {
  assert.deepEqual(describePollTarget(discovered('home-assistant'), 'home-assistant', null), {
    fingerprint_id: 'home-assistant',
    manual: false,
    ip_address: '192.168.1.50',
    port: 8123,
    tls: false,
    effective_url: 'http://192.168.1.50:8123/api/error_log',
    overrides: { port: null, tls: null, endpoint: null },
    defaults: { port: 8123, tls: false, endpoint: '/api/error_log' },
  });

  // The remembered Supervisor fallback shows as the URL in use, without an override.
  const fallback = serializeCursor({ tail: null, errorLogCheckedAt: Date.now() });
  assert.equal(
    describePollTarget(discovered('home-assistant'), 'home-assistant', fallback)!.effective_url,
    'http://192.168.1.50:8123/api/hassio/core/logs'
  );

  const pihole = describePollTarget(discovered('pihole', { poll_overrides: { tls: true } }), 'pihole', null)!;
  assert.equal(pihole.effective_url, 'https://192.168.1.50/admin/api.php');
  assert.deepEqual([pihole.port, pihole.tls], [443, true]);
  assert.deepEqual(pihole.defaults, { port: 80, tls: false, endpoint: '/admin/api.php' });
  assert.deepEqual(pihole.overrides, { port: null, tls: true, endpoint: null });

  const man = describePollTarget(manual('adguard-home', { target_port: 3001, tls: true }), 'adguard-home', null)!;
  assert.equal(man.manual, true);
  assert.equal(man.effective_url, 'https://192.168.1.50:3001/control/querylog');
  assert.deepEqual(man.overrides, { port: 3001, tls: true, endpoint: null });

  assert.equal(describePollTarget(discovered('proxmox'), 'proxmox', null), null, 'no api_pull adapter');
  assert.equal(describePollTarget(discovered('home-assistant'), null, null), null);
  assert.equal(effectivePollUrl(discovered('home-assistant'), 'not-a-fingerprint', null), null);
});

test('an IPv6 source is bracketed in the URL', () => {
  const v6 = discovered('home-assistant', { ip_address: 'fd00::50' });
  assert.equal(effectivePollUrl(v6, 'home-assistant', null), 'http://[fd00::50]:8123/api/error_log');
  assert.equal(describePollTarget(v6, 'home-assistant', null)!.port, 8123);
});
