import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rankSources, buildReason, ADVANCED_SECURITY_VALUE_THRESHOLD, RankableItem } from './ranker';
import { FingerprintEntry, RuntimeSource } from './types';

function fp(overrides: Partial<FingerprintEntry> = {}): FingerprintEntry {
  return {
    id: 'x',
    name: 'X',
    category: 'test',
    security_value: 8,
    signals: { ports: [], http: [], mdns: [], ssdp: [], tls: [], mac_oui: [] },
    confidence_floor: 50,
    attack_data_sources: ['firewall logs', 'network traffic flow'],
    log_access: [{ method: 'syslog_push' }],
    onboard_template: 'templates/syslog_source.j2',
    credentials: { required: false, optional: [] },
    ...overrides,
  };
}

function source(overrides: Partial<RuntimeSource> = {}): RuntimeSource {
  return {
    id: 1,
    ip: '192.168.1.1',
    mac: null,
    hostname: null,
    open_ports: [],
    matched_fingerprint_id: null,
    confidence: 80,
    is_guess: false,
    security_value: null,
    status: 'candidate',
    selected_log_access: null,
    evidence: {},
    ...overrides,
  };
}

test('buildReason lists the first few attack data sources', () => {
  const reason = buildReason(fp({ name: 'OPNsense', attack_data_sources: ['firewall logs', 'dns queries', 'network traffic flow', 'extra'] }));
  assert.equal(reason, 'OPNsense can provide firewall logs, dns queries, network traffic flow.');
});

test('buildReason falls back to category when there are no attack data sources', () => {
  const reason = buildReason(fp({ name: 'Widget', category: 'iot', attack_data_sources: [] }));
  assert.equal(reason, 'Widget is a iot source worth collecting.');
});

test('rankSources sorts by security_value descending, then confidence', () => {
  const items: RankableItem[] = [
    { source: source({ id: 1, ip: '10.0.0.1', security_value: 8, confidence: 90 }), fingerprint: fp({ security_value: 8 }) },
    { source: source({ id: 2, ip: '10.0.0.2', security_value: 10, confidence: 60 }), fingerprint: fp({ security_value: 10 }) },
    { source: source({ id: 3, ip: '10.0.0.3', security_value: 10, confidence: 95 }), fingerprint: fp({ security_value: 10 }) },
  ];
  const { top } = rankSources(items);
  assert.deepEqual(top.map((r) => r.id), [3, 2, 1]);
});

test('rankSources dedupes repeat detections of the same ip, keeping the first', () => {
  const items: RankableItem[] = [
    { source: source({ id: 1, ip: '10.0.0.1' }), fingerprint: fp() },
    { source: source({ id: 2, ip: '10.0.0.1' }), fingerprint: fp() },
  ];
  const { top } = rankSources(items);
  assert.equal(top.length, 1);
  assert.equal(top[0].id, 1);
});

test('rankSources drops ignored sources from both lists', () => {
  const items: RankableItem[] = [
    { source: source({ id: 1, ip: '10.0.0.1', status: 'ignored', security_value: 10 }), fingerprint: fp() },
  ];
  const { top, advanced } = rankSources(items);
  assert.equal(top.length, 0);
  assert.equal(advanced.length, 0);
});

test('rankSources groups low security_value sources under advanced', () => {
  const items: RankableItem[] = [
    { source: source({ id: 1, ip: '10.0.0.1', security_value: ADVANCED_SECURITY_VALUE_THRESHOLD - 1 }), fingerprint: fp() },
    { source: source({ id: 2, ip: '10.0.0.2', security_value: ADVANCED_SECURITY_VALUE_THRESHOLD }), fingerprint: fp() },
  ];
  const { top, advanced } = rankSources(items);
  assert.deepEqual(top.map((r) => r.id), [2]);
  assert.deepEqual(advanced.map((r) => r.id), [1]);
});

test('rankSources falls back to a generic reason and 0 security_value for unmatched hosts', () => {
  const items: RankableItem[] = [{ source: source({ security_value: null }), fingerprint: null }];
  const { advanced } = rankSources(items);
  assert.equal(advanced[0].security_value, 0);
  assert.match(advanced[0].reason, /Unidentified host/);
});
