/**
 * The Big Display's privacy check (services/display/redact.ts): labels are
 * cleaned and validated, and assertDisplaySafe() passes the declared shapes
 * and withholds a panel holding an email address, a free title, an unknown
 * key, or a label a public-area display may not show.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertDisplaySafe, categoryOf, configLabel, envelopeProblem, safeHost, safeLabel } from './redact';
import { foldOpenAlerts, foldRecentAlerts, foldShippers, foldSources, foldTopSources } from './panels';
import type { PanelEnvelope } from './types';

const AT = Date.UTC(2026, 9, 16, 12, 0, 0);
const asOf = new Date(AT).toISOString();
const ok = (data: unknown) => ({ state: 'ok', as_of: asOf, data }) as PanelEnvelope;
const quiet = () => {
  const errors: unknown[] = [];
  return { errors, log: { error: (_m: string, meta?: unknown) => errors.push(meta) } };
};

test('safeLabel: no control characters, one space at a time, at most 64 characters', () => {
  assert.equal(safeLabel('  SSH\tbrute\n\nforce\u0000  '), 'SSH brute force');
  const long = safeLabel('x'.repeat(100));
  assert.equal(Array.from(long).length, 64);
  assert.ok(long.endsWith('…'));
  assert.equal(configLabel('Mail to admin@example.com'), null, 'an email address is never a label');
  assert.equal(configLabel('   '), null);
  assert.equal(configLabel(42), null);
});

test('host labels: a plain host name, else the address, else nothing', () => {
  assert.equal(safeHost('fw-1.lan', '10.0.0.1'), 'fw-1.lan');
  assert.equal(safeHost('bad host; rm', '10.0.0.1'), '10.0.0.1');
  assert.equal(safeHost('<script>', 'not-an-ip'), null);
  assert.equal(safeHost(null, '2001:db8::5'), '2001:db8::5');
  assert.equal(categoryOf(null), 'rule');
  assert.equal(categoryOf('leaked-creds'), 'leaked_credentials');
  assert.equal(categoryOf('anything'), 'other');
});

test('assertDisplaySafe passes what the folds build, in both privacy modes', () => {
  for (const privacy of ['operations', 'public'] as const) {
    const panels: Record<string, PanelEnvelope> = {
      open_alerts: ok(foldOpenAlerts([{ severity: 'high', open: 1, untouched: 1, oldest_at: new Date(AT) }])),
      'recent_alerts:high': ok(foldRecentAlerts([{ severity: 'high', status: 'new', created_at: new Date(AT), source: null, rule_name: 'Port scan' }], 'high', privacy)),
      shippers: ok(foldShippers([{ id: 1, name: 'web', status: 'online', last_seen: new Date(AT - 3600_000) }], 0, privacy, AT)),
      'sources:15': ok(foldSources({ rollupSince: null, overflowMinutes: [], sources: [] }, 15, privacy, AT)),
      vulnerabilities: { state: 'not_configured', message: 'No scans yet' },
      endpoints: { state: 'forbidden' },
      digital_risk: { state: 'unavailable', reason: 'busy' },
    };
    if (privacy === 'operations') {
      panels.top_sources = ok(foldTopSources([{ ip: '203.0.113.9', cc: 'DE', n: 1, worst: 4, last_at: new Date(AT) }], privacy));
    }
    const { errors, log } = quiet();
    assert.deepEqual(assertDisplaySafe(panels, privacy, log), panels, privacy);
    assert.deepEqual(errors, []);
  }
});

test('assertDisplaySafe withholds an email address, a free title, an unknown key and labels public mode may not show', () => {
  const recent = (label: string) =>
    ok({ min_severity: 'high', more: false, items: [{ severity: 'high', status: 'new', category: 'rule', label, at: asOf }] });
  const shippers = (extra: Record<string, unknown> = {}) =>
    ok({ total: 1, online: 0, offline: 1, pending: 0, error: 0, unknown_shippers_24h: null, offline_list: [{ name: 'web', last_seen_at: null }], ...extra });
  const cases: Array<[string, string, PanelEnvelope, 'operations' | 'public']> = [
    ['an email address', 'recent_alerts:high', recent('canary@example.com'), 'operations'],
    ['a rule name in public', 'recent_alerts:high', recent('Port scan'), 'public'],
    ['an unclean label', 'recent_alerts:high', recent('a\nb'), 'operations'],
    ['a free title where an enum belongs', 'open_alerts', ok({ ...foldOpenAlerts([]), total: 'canary-user found in Adobe breach' }), 'operations'],
    ['an unknown key', 'shippers', shippers({ title: 'x' }), 'operations'],
    ['a shipper name in public', 'shippers', shippers(), 'public'],
    ['an address in public', 'top_sources', ok({ items: [{ ip: '203.0.113.9', country_code: null, alerts: 1, worst_severity: 'low', last_at: asOf }] }), 'public'],
    ['a country name', 'threat_map:1', ok({ window_days: 1, located: 1, total_in_window: 1, countries: [{ code: 'Germany', count: 1 }] }), 'operations'],
    ['a not-configured message of its own', 'shippers', { state: 'not_configured', message: 'canary-user' } as PanelEnvelope, 'operations'],
    ['an extra envelope key', 'open_alerts', { ...ok(foldOpenAlerts([])), title: 'x' } as PanelEnvelope, 'operations'],
    ['a kind no one declared', 'future_graph', ok({}), 'operations'],
  ];
  for (const [what, key, envelope, privacy] of cases) {
    assert.ok(envelopeProblem(key, envelope, privacy), `${what}: found`);
    const { errors, log } = quiet();
    const out = assertDisplaySafe({ [key]: envelope, open_alerts_ok: ok(foldOpenAlerts([])) } as never, privacy, log);
    assert.deepEqual(out[key], { state: 'unavailable', reason: 'error' }, what);
    assert.equal(errors.length, 2, `${what}: logged (the stray key too)`);
    assert.ok(!JSON.stringify(errors).includes('canary'), `${what}: the log names the path, never the value`);
  }
});
