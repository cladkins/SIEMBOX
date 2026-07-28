import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderTemplate, loadTemplate, buildTemplateVars, renderOnboardInstructions } from './onboarder';
import { FingerprintEntry, RuntimeSource } from './types';

test('renderTemplate substitutes known vars and blanks unknown ones', () => {
  const out = renderTemplate('Host: {{ ip }} Port: {{ port }} Missing: {{ nope }}', { ip: '10.0.0.1', port: 443 });
  assert.equal(out, 'Host: 10.0.0.1 Port: 443 Missing: ');
});

test('renderTemplate leaves the template untouched when there is nothing to substitute', () => {
  assert.equal(renderTemplate('plain text', {}), 'plain text');
});

test('loadTemplate refuses to escape the service directory', () => {
  assert.throws(() => loadTemplate('../../../etc/passwd'));
});

test('loadTemplate loads a bundled template', () => {
  const content = loadTemplate('templates/syslog_source.j2');
  assert.match(content, /syslog listener/);
});

function fingerprint(overrides: Partial<FingerprintEntry> = {}): FingerprintEntry {
  return {
    id: 'pihole',
    name: 'Pi-hole',
    category: 'dns',
    security_value: 8,
    signals: { ports: [], http: [], mdns: [], ssdp: [], tls: [], mac_oui: [] },
    confidence_floor: 50,
    attack_data_sources: [],
    log_access: [{ method: 'file', path: '/var/log/pihole/pihole.log' }],
    onboard_template: 'templates/file_tail.j2',
    credentials: { required: false, optional: [] },
    ...overrides,
  };
}

function source(overrides: Partial<RuntimeSource> = {}): RuntimeSource {
  return {
    id: 1,
    ip: '192.168.1.50',
    mac: null,
    hostname: null,
    open_ports: [80, 53],
    matched_fingerprint_id: 'pihole',
    confidence: 90,
    is_guess: false,
    security_value: 8,
    status: 'confirmed',
    selected_log_access: null,
    evidence: {},
    ...overrides,
  };
}

test('buildTemplateVars picks a web port by priority, not just the first open port', () => {
  const vars = buildTemplateVars(fingerprint(), source({ open_ports: [22, 8443, 80] }), { method: 'file' }, { host: '10.0.0.5', port: 514 });
  assert.equal(vars.port, 8443); // 8443 outranks 80 in WEB_PORT_PRIORITY
});

test('buildTemplateVars falls back to the first open port when none match the priority list', () => {
  const vars = buildTemplateVars(fingerprint(), source({ open_ports: [9999, 22] }), { method: 'file' }, { host: '10.0.0.5', port: 514 });
  assert.equal(vars.port, 9999);
});

test('renderOnboardInstructions fills the file_tail template end to end', () => {
  const text = renderOnboardInstructions(
    fingerprint(),
    source(),
    { method: 'file', path: '/var/log/pihole/pihole.log' },
    { host: '10.0.0.5', port: 514 }
  );
  assert.match(text, /path: "\/var\/log\/pihole\/pihole\.log"/);
  assert.match(text, /tag: "pihole"/);
  assert.match(text, /10\.0\.0\.5:514/);
});

test('renderOnboardInstructions fills the syslog_source template', () => {
  const unifi = fingerprint({
    id: 'unifi-controller',
    name: 'UniFi Network',
    log_access: [{ method: 'syslog_push', target_port: 514, format: 'rfc3164' }],
    onboard_template: 'templates/syslog_source.j2',
  });
  const text = renderOnboardInstructions(
    unifi,
    source({ matched_fingerprint_id: 'unifi-controller' }),
    { method: 'syslog_push' },
    { host: '10.0.0.5', port: 514 }
  );
  assert.match(text, /UniFi Network at 192\.168\.1\.50/);
  assert.match(text, /Host:\s+10\.0\.0\.5/);
  assert.match(text, /Port:\s+514/);
});

test('renderOnboardInstructions fills the api_poller template', () => {
  const ha = fingerprint({
    id: 'home-assistant',
    name: 'Home Assistant',
    log_access: [{ method: 'api_pull', endpoint: '/api/error_log', auth: 'bearer_token' }],
    onboard_template: 'templates/api_poller.j2',
  });
  const text = renderOnboardInstructions(
    ha,
    source({ matched_fingerprint_id: 'home-assistant', open_ports: [8123] }),
    { method: 'api_pull', endpoint: '/api/error_log' },
    { host: '10.0.0.5', port: 514 }
  );
  assert.match(text, /https:\/\/192\.168\.1\.50:8123\/api\/error_log/);
  assert.match(text, /logger -n 10\.0\.0\.5 -P 514/);
});
