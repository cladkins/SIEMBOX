/**
 * Base-URL construction for all four api_pull adapters, pinning the two
 * behaviours the manual-source feature depends on:
 *   (a) an explicit evidence port + scheme (a manually added source) produces the
 *       custom URL, and
 *   (b) a scan-discovered source (no target.port / target.tls) reproduces each
 *       adapter's EXISTING default URL byte-for-byte — the hard non-regression
 *       requirement, since every source onboarded before this feature has neither.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildBaseUrl as authentikBaseUrl } from './authentik';
import { buildBaseUrl as homeAssistantBaseUrl } from './homeAssistant';
import { buildBaseUrl as piholeBaseUrl } from './pihole';
import { buildBaseUrl as adguardBaseUrl } from './adguardHome';
import { PollTarget } from '../types';

// A minimal target; `openPorts` matters only for authentik's default derivation.
function target(over: Partial<PollTarget> = {}): PollTarget {
  return {
    sourceId: 1,
    ip: '192.168.1.50',
    openPorts: [],
    evidence: {},
    logAccess: { method: 'api_pull' },
    ...over,
  };
}

// ---------------------------------------------------------------------------
// (b) No-evidence fallback — must equal the pre-feature URL exactly.
// ---------------------------------------------------------------------------

test('authentik: no evidence falls back to the discovered 9443/9000 derivation unchanged', () => {
  // openPorts drives the default scheme+port exactly as before the feature.
  assert.equal(authentikBaseUrl(target({ openPorts: [9443] })), 'https://192.168.1.50:9443');
  assert.equal(authentikBaseUrl(target({ openPorts: [] })), 'https://192.168.1.50:9443'); // 9443 primary when neither seen
  assert.equal(authentikBaseUrl(target({ openPorts: [9000] })), 'http://192.168.1.50:9000'); // 9000 only -> http
  assert.equal(authentikBaseUrl(target({ openPorts: [9000, 9443] })), 'https://192.168.1.50:9443');
});

test('home-assistant: no evidence falls back to http://ip:8123', () => {
  assert.equal(homeAssistantBaseUrl(target()), 'http://192.168.1.50:8123');
});

test('pihole: no evidence falls back to the bare http://ip (no :port appended)', () => {
  assert.equal(piholeBaseUrl(target()), 'http://192.168.1.50');
});

test('adguard-home: no evidence falls back to http://ip:3000', () => {
  assert.equal(adguardBaseUrl(target()), 'http://192.168.1.50:3000');
});

// ---------------------------------------------------------------------------
// (a) Explicit port + scheme (a manually added source) overrides the default.
// ---------------------------------------------------------------------------

test('authentik: explicit port + tls override the openPorts derivation', () => {
  // https even though neither 9443 nor 9000 is open, and the custom port.
  assert.equal(authentikBaseUrl(target({ openPorts: [443], port: 443, tls: true })), 'https://192.168.1.50:443');
  // tls:false forces http on whatever port, regardless of openPorts.
  assert.equal(authentikBaseUrl(target({ openPorts: [9443], port: 8080, tls: false })), 'http://192.168.1.50:8080');
});

test('home-assistant: explicit port + tls produce the custom URL', () => {
  assert.equal(homeAssistantBaseUrl(target({ port: 443, tls: true })), 'https://192.168.1.50:443');
  assert.equal(homeAssistantBaseUrl(target({ port: 8124, tls: false })), 'http://192.168.1.50:8124');
});

test('pihole: an explicit port is appended, and tls switches the scheme', () => {
  assert.equal(piholeBaseUrl(target({ port: 8080, tls: false })), 'http://192.168.1.50:8080');
  assert.equal(piholeBaseUrl(target({ port: 443, tls: true })), 'https://192.168.1.50:443');
});

test('adguard-home: explicit port + tls produce the custom URL', () => {
  assert.equal(adguardBaseUrl(target({ port: 8443, tls: true })), 'https://192.168.1.50:8443');
  assert.equal(adguardBaseUrl(target({ port: 3001, tls: false })), 'http://192.168.1.50:3001');
});
