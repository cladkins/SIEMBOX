import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadFingerprintLibrary, validateFingerprint, getFingerprintById } from './fingerprintLoader';

const SCHEMA = {
  required: [
    'id', 'name', 'category', 'security_value', 'signals', 'confidence_floor',
    'attack_data_sources', 'log_access', 'onboard_template', 'credentials',
  ],
};

const VALID_FINGERPRINT = {
  id: 'test-product',
  name: 'Test Product',
  category: 'test',
  security_value: 5,
  signals: {
    ports: [{ port: 443, weight: 40 }],
    http: [{ path: '/', expect: 'Test', weight: 40 }],
    mdns: [],
    ssdp: [],
    tls: [],
    mac_oui: [],
  },
  confidence_floor: 50,
  attack_data_sources: ['application logs'],
  log_access: [{ method: 'file', path: '/var/log/test.log' }],
  onboard_template: 'templates/file_tail.j2',
  credentials: { required: false, optional: [] },
};

test('validateFingerprint accepts a well-formed fingerprint', () => {
  assert.deepEqual(validateFingerprint(VALID_FINGERPRINT, SCHEMA), []);
});

test('validateFingerprint rejects a missing required field', () => {
  const rest: Record<string, unknown> = { ...VALID_FINGERPRINT };
  delete rest.security_value;
  const errors = validateFingerprint(rest, SCHEMA);
  assert.ok(errors.some((e) => e.includes('security_value')));
});

test('validateFingerprint rejects an out-of-range security_value', () => {
  const errors = validateFingerprint({ ...VALID_FINGERPRINT, security_value: 11 }, SCHEMA);
  assert.ok(errors.some((e) => e.includes('security_value')));
});

test('validateFingerprint rejects an id with invalid characters', () => {
  const errors = validateFingerprint({ ...VALID_FINGERPRINT, id: 'Test Product!' }, SCHEMA);
  assert.ok(errors.some((e) => e.includes('id must match')));
});

test('validateFingerprint rejects a port signal missing weight', () => {
  const errors = validateFingerprint(
    { ...VALID_FINGERPRINT, signals: { ...VALID_FINGERPRINT.signals, ports: [{ port: 443 }] } },
    SCHEMA
  );
  assert.ok(errors.some((e) => e.includes('signals.ports[0]')));
});

test('validateFingerprint rejects an empty log_access array', () => {
  const errors = validateFingerprint({ ...VALID_FINGERPRINT, log_access: [] }, SCHEMA);
  assert.ok(errors.some((e) => e.includes('log_access')));
});

test('loadFingerprintLibrary loads the bundled seed fingerprints', () => {
  const library = loadFingerprintLibrary({ force: true });
  assert.ok(library.length >= 10, `expected at least 10 bundled fingerprints, got ${library.length}`);
  const ids = library.map((f) => f.id);
  assert.ok(ids.includes('pihole'));
  assert.ok(ids.includes('opnsense'));
  assert.ok(new Set(ids).size === ids.length, 'fingerprint ids must be unique');
});

test('getFingerprintById finds a bundled fingerprint', () => {
  const fp = getFingerprintById('unifi-controller');
  assert.ok(fp);
  assert.equal(fp?.name, 'UniFi Network');
});
