import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_PANELS_PER_VIEW,
  PANEL_CATALOGUE,
  PRESETS,
  defaultConfig,
  moveItem,
  newPanel,
  parseCidrList,
  publicConflicts,
  shortBrowser,
  statusText,
} from './displayLinks.ts';

const NOW = Date.parse('2026-10-16T12:00:00Z');

describe('defaults and presets', () => {
  it('a new link is an operations-room display with the three signed-in views', () => {
    const config = defaultConfig();
    assert.equal(config.privacy, 'operations');
    assert.deepEqual(
      config.views.map((v) => v.title),
      ['SOC overview', 'Threats', 'Health']
    );
    assert.ok(config.views.every((v) => v.panels.length <= MAX_PANELS_PER_VIEW));
  });

  it('the public preset uses only panels a public-area display allows', () => {
    const preset = PRESETS.find((p) => p.key === 'public')!;
    assert.deepEqual(publicConflicts({ ...defaultConfig(), privacy: 'public', views: preset.views }), []);
  });

  it('switching the SOC layout to public names the refused panels', () => {
    const conflicts = publicConflicts({ ...defaultConfig(), privacy: 'public' });
    assert.ok(conflicts.some((c) => c.startsWith('Threats: Top alerting addresses')));
  });

  it('never offers endpoint health and gives each option kind its default', () => {
    assert.ok(!PANEL_CATALOGUE.some((p) => (p.id as string) === 'endpoints'));
    assert.deepEqual(newPanel('threat_map'), { id: 'threat_map', window_days: 1 });
    assert.deepEqual(newPanel('ingest'), { id: 'ingest' });
  });
});

describe('statusText', () => {
  it('reads live, idle, never opened, paused and expired', () => {
    assert.equal(statusText({ status: 'live', last_used_at: '2026-10-16T11:59:48Z', expires_at: null }, NOW).text, 'Live — refreshed 12 s ago');
    assert.deepEqual(statusText({ status: 'idle', last_used_at: '2026-10-16T09:00:00Z', expires_at: null }, NOW), {
      text: 'Not seen for 3 h',
      tone: 'warning',
    });
    assert.equal(statusText({ status: 'never_used', last_used_at: null, expires_at: '2026-11-03T09:00:00Z' }, NOW).text, 'Never opened · expires 3 Nov');
    assert.equal(statusText({ status: 'paused', last_used_at: null, expires_at: null }, NOW).text, 'Paused');
    assert.equal(statusText({ status: 'expired', last_used_at: null, expires_at: '2026-10-01T09:00:00Z' }, NOW).text, 'Expired 1 Oct');
  });
});

describe('helpers', () => {
  it('names browsers', () => {
    assert.equal(shortBrowser('Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36'), 'Chrome on Linux');
    assert.equal(shortBrowser('Mozilla/5.0 (Linux; Android 9; AFTMM) AppleWebKit/537.36 (KHTML, like Gecko) Silk/120.1 Chrome/120.0 Safari/537.36'), 'Silk on Android');
    assert.equal(shortBrowser(null), 'unknown browser');
  });

  it('moves list items and splits CIDR lists', () => {
    assert.deepEqual(moveItem([1, 2, 3], 0, 1), [2, 1, 3]);
    assert.deepEqual(moveItem([1, 2, 3], 0, -1), [1, 2, 3]);
    assert.deepEqual(parseCidrList(' 10.0.0.0/8,\n192.168.1.5  '), ['10.0.0.0/8', '192.168.1.5']);
  });
});
