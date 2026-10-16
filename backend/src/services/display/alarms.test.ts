/**
 * The alarm strip and the attribution list (services/display/alarms.ts).
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ALARM_TEXT, deriveAlarms, deriveAttributions, durationText } from './alarms';
import { foldOpenAlerts } from './panels';
import type { PanelEnvelope } from './types';

const AT = Date.UTC(2026, 9, 16, 12, 0, 0);
const asOf = new Date(AT).toISOString();
const ok = (data: unknown) => ({ state: 'ok', as_of: asOf, data }) as PanelEnvelope;
const ingest = (state: string, lastMinutesAgo: number, drops: number | null = 0) =>
  ok({ state, last_log_at: new Date(AT - lastMinutesAgo * 60_000).toISOString(), udp_dropped_15m: drops });

test('alarms: critical first, at most 4, fixed wording only', () => {
  const panels: Record<string, PanelEnvelope> = {
    shippers: ok({ offline: 2 }),
    'sources:15': ok({ silent: 3 }),
    ingest: ingest('stalled', 18, 4),
    open_alerts: ok(foldOpenAlerts([{ severity: 'critical', open: 3, untouched: 2, oldest_at: null }])),
    endpoints: ok({ offline: 1 }),
    vulnerabilities: { state: 'unavailable', reason: 'busy' },
  };
  const alarms = deriveAlarms(panels, AT);
  assert.deepEqual(alarms.map((a) => [a.key, a.level, a.text, a.panel]), [
    ['new_critical', 'critical', '◆ 2 NEW CRITICAL', 'open_alerts'],
    ['ingest_stalled', 'critical', '✕ NO LOGS FOR 18 MIN', 'ingest'],
    ['udp_drops', 'warning', '▲ DROPPING LOGS (UDP)', 'ingest'],
    ['sources_silent', 'warning', '▲ 3 SOURCES SILENT', 'sources:15'],
  ]);
  for (const alarm of alarms) assert.match(alarm.text, ALARM_TEXT);
});

test('alarms: each condition, singular wording, and none from forbidden or empty panels', () => {
  const one = (panels: Record<string, PanelEnvelope>) => deriveAlarms(panels, AT).map((a) => a.text);
  assert.deepEqual(one({ ingest: ingest('slow', 0) }), ['▲ LOG RATE LOW']);
  assert.deepEqual(one({ shippers: ok({ offline: 1 }) }), ['▲ 1 SHIPPER OFFLINE']);
  assert.deepEqual(one({ endpoints: ok({ offline: 4 }) }), ['▲ 4 ENDPOINTS OFFLINE']);
  assert.deepEqual(one({ 'sources:5': ok({ silent: 1 }), 'sources:60': ok({ silent: 4 }) }), ['▲ 4 SOURCES SILENT'], 'the larger count');
  assert.deepEqual(one({ open_alerts: { state: 'stale', as_of: asOf, reason: 'busy', data: foldOpenAlerts([]) } }), ['▲ SOME DATA DELAYED']);
  assert.deepEqual(one({ endpoints: { state: 'forbidden' }, shippers: { state: 'not_configured', message: 'No shippers registered' } }), []);
  assert.deepEqual(one({ ingest: ingest('flowing', 0, null), open_alerts: ok(foldOpenAlerts([])) }), []);
  assert.equal(durationText(185 * 60_000), '3 H');
  assert.equal(durationText(3 * 24 * 3600_000), '3 D');
});

test('attributions: DB-IP for the map and source addresses, HIBP for Digital Risk', () => {
  assert.deepEqual(deriveAttributions({ open_alerts: ok({}) }), []);
  assert.deepEqual(deriveAttributions({ 'threat_map:7': ok({}), digital_risk: { state: 'not_configured', message: 'Digital Risk is not set up' } }), ['dbip', 'hibp']);
  assert.deepEqual(deriveAttributions({ top_sources: ok({}) }), ['dbip']);
});
