import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  ageLabel,
  categoryLabel,
  compareVersions,
  driftOrder,
  isBehind,
  isNetworkOnly,
  locationsBehind,
  logsLink,
  matchesSearch,
  signatureSourceText,
  sortVersions,
  sourceLabel,
  vulnerabilityLink,
  whereLabel,
  type ApplicationRow,
} from './applications.ts';

const app = (over: Partial<ApplicationRow>): ApplicationRow => ({
  id: 'x', name: 'X', vendor: 'V', category: 'web-server', sources: ['container'], hosts: 1, clients: 0, versions: [], latest_version: null,
  drift: false, unmanaged: false, vulnerabilities: { total: 0, exact: 0, critical: 0, high: 0 }, events: 0, first_seen: null, last_seen: null, ...over,
});

describe('versions', () => {
  it('orders numerically, with suffixes', () => {
    assert.deepEqual(['1.10.0', '1.9.2', '8.9p1', '8.4p1', '16'].sort(compareVersions), ['1.9.2', '1.10.0', '8.4p1', '8.9p1', '16']);
    assert.deepEqual(sortVersions([{ version: '2.0' }, { version: '1.10' }]).map((v) => v.version), ['1.10', '2.0']);
  });
  it('marks versions behind the newest and counts the locations on them', () => {
    assert.equal(isBehind('1.9', '1.10'), true);
    assert.equal(isBehind('1.10', '1.10'), false);
    assert.equal(isBehind('1.9', null), false);
    const a = app({ drift: true, latest_version: '1.10', versions: [{ version: '1.8', locations: 2, last_seen: '' }, { version: '1.9', locations: 1, last_seen: '' }, { version: '1.10', locations: 5, last_seen: '' }] });
    assert.equal(locationsBehind(a), 3);
  });
  it('drift view: only drifting apps, most locations behind first', () => {
    const one = app({ id: 'one', name: 'One', drift: true, latest_version: '2', versions: [{ version: '1', locations: 1, last_seen: '' }, { version: '2', locations: 1, last_seen: '' }] });
    const many = app({ id: 'many', name: 'Many', drift: true, latest_version: '3', versions: [{ version: '1', locations: 4, last_seen: '' }, { version: '3', locations: 1, last_seen: '' }] });
    const none = app({ id: 'none', name: 'None' });
    assert.deepEqual(driftOrder([one, none, many]).map((a) => a.id), ['many', 'one']);
  });
});

describe('labels', () => {
  it('sources, where, categories, signature source', () => {
    assert.equal(sourceLabel('edr_package'), 'Vulnerable package');
    assert.equal(sourceLabel('endpoint_sbom'), 'Installed package');
    assert.equal(sourceLabel('something-new'), 'something-new');
    assert.equal(whereLabel({ hosts: 1, clients: 0 }), '1 host');
    assert.equal(whereLabel({ hosts: 3, clients: 12 }), '3 hosts, 12 clients');
    assert.equal(whereLabel({ hosts: 0, clients: 0 }), '—');
    assert.equal(categoryLabel('reverse-proxy'), 'Reverse proxy');
    assert.equal(categoryLabel('saas'), 'SaaS');
    assert.match(signatureSourceText('bundled', 23), /built-in starter/);
    assert.match(signatureSourceText(null, 0), /not loaded/);
  });
  it('network-only evidence is "unmanaged"', () => {
    assert.equal(isNetworkOnly(['dns']), true);
    assert.equal(isNetworkOnly(['dns', 'user_agent']), true);
    assert.equal(isNetworkOnly(['dns', 'container']), false);
    assert.equal(isNetworkOnly([]), false);
  });
  it('age', () => {
    const now = Date.parse('2026-10-26T12:00:00Z');
    assert.equal(ageLabel('2026-10-26T11:59:30Z', now), 'just now');
    assert.equal(ageLabel('2026-10-26T11:00:00Z', now), '60 min ago');
    assert.equal(ageLabel('2026-10-23T12:00:00Z', now), '3 d ago');
    assert.equal(ageLabel(null, now), '—');
    assert.equal(ageLabel('garbage', now), '—');
  });
});

describe('links', () => {
  it('logs: a program by name, a client by IP; nothing for a non-IP key', () => {
    assert.deepEqual(logsLink({ value: 'sshd' }, 'syslog_program', 'web01'), { path: '/logs', query: { app_name: 'sshd', tab: 'raw', range: '7d' } });
    assert.deepEqual(logsLink({ value: 'x' }, 'dns', '192.168.1.50'), { path: '/logs', query: { source_ip: '192.168.1.50', tab: 'parsed', range: '7d' } });
    assert.equal(logsLink({ value: 'x' }, 'dns', 'not an ip'), null);
    assert.equal(logsLink(null, 'container', '7'), null);
  });
  it('vulnerability management by CVE', () => {
    assert.deepEqual(vulnerabilityLink('CVE-2024-6387'), { path: '/vulnerability-management', query: { search: 'CVE-2024-6387' } });
  });
  it('search', () => {
    assert.equal(matchesSearch(app({ name: 'Home Assistant' }), 'assist'), true);
    assert.equal(matchesSearch(app({ name: 'Home Assistant' }), 'plex'), false);
    assert.equal(matchesSearch(app({}), '  '), true);
  });
});
