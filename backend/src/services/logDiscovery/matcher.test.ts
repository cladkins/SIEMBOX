import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreSource, confidenceFromWeight, matchHost, pickBestMatch } from './matcher';
import { DiscoveredSignals, FingerprintEntry } from './types';

const PIHOLE: FingerprintEntry = {
  id: 'pihole',
  name: 'Pi-hole',
  category: 'dns',
  security_value: 8,
  signals: {
    ports: [{ port: 53, weight: 20 }, { port: 80, weight: 10 }],
    http: [{ path: '/admin/', expect: 'Pi-hole', weight: 60 }],
    mdns: [],
    ssdp: [],
    tls: [],
    mac_oui: [],
  },
  confidence_floor: 50,
  attack_data_sources: ['dns queries', 'network traffic flow'],
  log_access: [{ method: 'file', path: '/var/log/pihole/pihole.log' }],
  onboard_template: 'templates/file_tail.j2',
  credentials: { required: false, optional: [] },
};

const HOME_ASSISTANT: FingerprintEntry = {
  id: 'home-assistant',
  name: 'Home Assistant',
  category: 'home-automation',
  security_value: 6,
  signals: {
    ports: [{ port: 8123, weight: 40 }],
    http: [{ path: '/manifest.json', expect: 'Home Assistant', weight: 50 }],
    mdns: [{ service: '_home-assistant._tcp', weight: 60 }],
    ssdp: [],
    tls: [],
    mac_oui: [],
  },
  confidence_floor: 50,
  attack_data_sources: ['authentication logs', 'application logs'],
  log_access: [{ method: 'api_pull', endpoint: '/api/error_log', auth: 'bearer_token' }],
  onboard_template: 'templates/api_poller.j2',
  credentials: { required: false, optional: [{ type: 'long_lived_token', unlocks: ['api_pull'] }] },
};

const LIBRARY = [PIHOLE, HOME_ASSISTANT];

function fixture(overrides: Partial<DiscoveredSignals> = {}): DiscoveredSignals {
  return {
    ip: '192.168.1.50',
    open_ports: [],
    http_responses: [],
    tls_subjects: [],
    banners: [],
    mdns_services: [],
    ssdp_services: [],
    discovery_methods: ['arp'],
    ...overrides,
  };
}

test('confidenceFromWeight caps at 100 and floors at 0', () => {
  assert.equal(confidenceFromWeight(130), 100);
  assert.equal(confidenceFromWeight(0), 0);
  assert.equal(confidenceFromWeight(-5), 0);
  assert.equal(confidenceFromWeight(45), 45);
});

test('a single open port never reaches the pi-hole confidence floor alone', () => {
  const source = fixture({ open_ports: [53] });
  const { weight } = scoreSource(source, PIHOLE);
  assert.equal(weight, 20);
  assert.ok(confidenceFromWeight(weight) < PIHOLE.confidence_floor, 'one weak signal must stay below the floor');
});

test('multiple weak signals combine into a confirmed match', () => {
  const source = fixture({
    open_ports: [53, 80],
    http_responses: [{ port: 80, path: '/admin/', status: 200, body: 'Pi-hole Admin Console', headers: {} }],
  });
  const { weight, matched } = scoreSource(source, PIHOLE);
  assert.equal(weight, 20 + 10 + 60);
  assert.equal(matched.length, 3);
  assert.ok(confidenceFromWeight(weight) >= PIHOLE.confidence_floor);
});

test('http expect string match is case-insensitive substring, not exact', () => {
  const source = fixture({
    open_ports: [80],
    http_responses: [{ port: 80, path: '/admin/', status: 200, body: '<title>PI-HOLE</title>', headers: {} }],
  });
  const { weight } = scoreSource(source, PIHOLE);
  assert.equal(weight, 10 + 60);
});

test('a wrong http body does not contribute weight even if the path matches', () => {
  const source = fixture({
    open_ports: [80],
    http_responses: [{ port: 80, path: '/admin/', status: 200, body: 'nginx welcome page', headers: {} }],
  });
  const { weight } = scoreSource(source, PIHOLE);
  assert.equal(weight, 10); // only the port-80 signal, not the http signal
});

test('mdns signal contributes even with zero open ports observed', () => {
  const source = fixture({ mdns_services: ['_home-assistant._tcp'] });
  const { weight, matched } = scoreSource(source, HOME_ASSISTANT);
  assert.equal(weight, 60);
  assert.deepEqual(matched, ['mdns _home-assistant._tcp']);
});

test('matchHost returns only fingerprints with nonzero weight, sorted by confidence desc', () => {
  const source = fixture({
    open_ports: [8123, 53],
    http_responses: [{ port: 8123, path: '/manifest.json', status: 200, body: 'Home Assistant', headers: {} }],
  });
  const matches = matchHost(source, LIBRARY);
  assert.equal(matches.length, 2);
  assert.equal(matches[0].fingerprint.id, 'home-assistant'); // 40 + 50 = 90
  assert.equal(matches[1].fingerprint.id, 'pihole'); // 20
  assert.ok(matches[0].confidence >= matches[1].confidence);
});

test('matchHost excludes fingerprints with zero matched signals', () => {
  const source = fixture({ open_ports: [9999] });
  const matches = matchHost(source, LIBRARY);
  assert.equal(matches.length, 0);
});

test('pickBestMatch flags a below-floor match as a guess', () => {
  const source = fixture({ open_ports: [53] }); // weight 20, floor 50
  const best = pickBestMatch(source, LIBRARY);
  assert.ok(best);
  assert.equal(best?.fingerprint.id, 'pihole');
  assert.equal(best?.is_guess, true);
});

test('pickBestMatch does not flag an above-floor match as a guess', () => {
  const source = fixture({
    open_ports: [53, 80],
    http_responses: [{ port: 80, path: '/admin/', status: 200, body: 'Pi-hole', headers: {} }],
  });
  const best = pickBestMatch(source, LIBRARY);
  assert.equal(best?.is_guess, false);
});

test('pickBestMatch returns null when nothing matched', () => {
  const source = fixture();
  assert.equal(pickBestMatch(source, LIBRARY), null);
});
