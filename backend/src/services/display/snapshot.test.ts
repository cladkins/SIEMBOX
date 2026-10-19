/**
 * The snapshot builder's caching, concurrency and budget
 * (services/display/snapshot.ts), with fake panel fetches: concurrent screens
 * share one fetch per panel; a panel whose refresh times out comes back stale
 * with its old data while the others are ok; at most 3 panel queries run at
 * once; the soft budget answers on time; a signed-in viewer gets endpoints
 * forbidden and an admin gets data.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDisplayConfig, type DisplayConfig, type PanelSpec } from './config';
import { SIGNED_IN_CONFIG, createSemaphore, createSnapshotBuilder, type BuilderDeps } from './snapshot';

const silentLog = { warn: () => undefined, error: () => undefined };

const RAW: Record<string, unknown> = {
  open_alerts: [{ severity: 'critical', open: 2, untouched: 1, oldest_at: new Date() }],
  alert_pulse: { hourly: [], totals: { total_24h: 5 } },
  threat_map: { rows: [{ code: 'DE', n: 3 }], total: 4 },
  top_sources: [{ ip: '203.0.113.9', cc: 'DE', n: 3, worst: 4, last_at: new Date() }],
  endpoints: { counts: { total: 3, online: 2 }, offline: [{ hostname: 'pc-1', last_seen: null }], detections: 1 },
  vulnerabilities: { row: { total: 0 }, scans: false },
};

function config(panels: PanelSpec[] | object[]): DisplayConfig {
  const parsed = parseDisplayConfig({ views: [{ title: 'T', panels }] });
  assert.ok(parsed.ok);
  return parsed.value;
}

function builder(overrides: Partial<BuilderDeps> = {}) {
  const calls: string[] = [];
  let clock = Date.now();
  const deps: BuilderDeps = {
    runPanel: async (spec) => {
      calls.push(spec.id);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return RAW[spec.id];
    },
    now: () => clock,
    log: silentLog,
    budgetMs: 8000,
    appVersion: '9.9.9',
    ...overrides,
  };
  return { b: createSnapshotBuilder(deps), calls, advance: (ms: number) => (clock += ms) };
}

const input = (c: DisplayConfig) => ({ name: 'Wall', configVersion: 3, config: c });

test('20 concurrent snapshots run each panel fetch once', async () => {
  const { b, calls } = builder();
  const c = config([{ id: 'open_alerts' }, { id: 'alert_pulse' }, { id: 'threat_map', window_days: 1 }]);
  const snapshots = await Promise.all(Array.from({ length: 20 }, () => b.build(input(c))));
  assert.deepEqual(calls.sort(), ['alert_pulse', 'open_alerts', 'threat_map']);
  for (const s of snapshots) {
    assert.deepEqual(Object.values(s.panels).map((p) => p.state), ['ok', 'ok', 'ok']);
    assert.equal(s.app_version, '9.9.9');
    assert.equal(s.display.name, 'Wall');
    assert.deepEqual(s.attributions, ['dbip']);
    assert.deepEqual(s.alarms.map((a) => a.key), ['new_critical']);
  }
  // Warm: no fetch at all.
  await b.build(input(c));
  assert.equal(calls.length, 3);
});

test('a panel whose refresh times out comes back stale with its old data; the others are ok', async () => {
  let failMap = false;
  const { b, advance } = builder({
    runPanel: async (spec) => {
      if (spec.id === 'threat_map' && failMap) throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
      return RAW[spec.id];
    },
  });
  const c = config([{ id: 'open_alerts' }, { id: 'threat_map', window_days: 1 }]);
  const first = await b.build(input(c));
  const firstAsOf = (first.panels['threat_map:1'] as { as_of: string }).as_of;
  failMap = true;
  advance(61_000); // past every TTL
  const second = await b.build(input(c));
  assert.equal(second.panels.open_alerts.state, 'ok');
  const map = second.panels['threat_map:1'];
  assert.equal(map.state, 'stale');
  assert.equal(map.state === 'stale' && map.reason, 'busy');
  assert.equal(map.state === 'stale' && map.as_of, firstAsOf, 'as of the last good fetch');
  assert.deepEqual(map.state === 'stale' && map.data, first.panels['threat_map:1'].state === 'ok' && first.panels['threat_map:1'].data);
  assert.ok(second.alarms.some((a) => a.key === 'data_delayed' && a.panel === 'threat_map:1'));
  // A panel that never had data is unavailable.
  const { b: cold } = builder({ runPanel: async () => Promise.reject(new Error('boom')) });
  const none = await cold.build(input(config([{ id: 'open_alerts' }])));
  assert.deepEqual(none.panels.open_alerts, { state: 'unavailable', reason: 'error' });
});

test('the semaphore never lets more than 3 run at once', async () => {
  const semaphore = createSemaphore(3);
  let running = 0;
  let most = 0;
  const done = await Promise.all(
    Array.from({ length: 12 }, (_, i) =>
      semaphore.run(async () => {
        running++;
        most = Math.max(most, running);
        await new Promise((resolve) => setTimeout(resolve, 5 + (i % 3)));
        running--;
        return i;
      })
    )
  );
  assert.equal(done.length, 12);
  assert.equal(most, 3);
  assert.deepEqual(semaphore.stats(), { active: 0, waiting: 0, peak: 3 });
  // Through the builder: a cold signed-in board has more panels than slots.
  const gate = createSemaphore(3);
  const { b } = builder({ runPanel: (spec) => gate.run(async () => (await new Promise((r) => setTimeout(r, 5)), RAW[spec.id] ?? [])) });
  await b.build({ ...input(SIGNED_IN_CONFIG), role: 'admin' });
  assert.equal(gate.stats().peak, 3);
});

test('the soft budget answers on time: a slow panel is unavailable, or stale once it has data', async () => {
  let hang = false;
  const { b, advance } = builder({
    budgetMs: 150,
    runPanel: async (spec) => {
      if (spec.id === 'top_sources' && hang) return new Promise(() => undefined);
      return RAW[spec.id];
    },
  });
  const c = config([{ id: 'open_alerts' }, { id: 'top_sources' }]);
  assert.equal((await b.build(input(c))).panels.top_sources.state, 'ok');
  hang = true;
  advance(61_000);
  const started = Date.now();
  const late = await b.build(input(c));
  assert.ok(Date.now() - started < 1000, `answered in ${Date.now() - started} ms`);
  assert.equal(late.panels.open_alerts.state, 'ok');
  assert.equal(late.panels.top_sources.state, 'stale');
  const { b: cold } = builder({ budgetMs: 100, runPanel: () => new Promise(() => undefined) });
  assert.deepEqual((await cold.build(input(c))).panels.top_sources, { state: 'unavailable', reason: 'busy' });
});

test('signed in: a viewer gets endpoints forbidden (and no alarm from it), an admin gets its data', async () => {
  const { b, calls } = builder({ runPanel: async (spec) => (spec.id === 'endpoints' ? RAW.endpoints : (RAW[spec.id] ?? [])) });
  const viewer = await b.build({ name: 'Big Display', configVersion: 1, config: SIGNED_IN_CONFIG, role: 'viewer' });
  assert.deepEqual(viewer.panels.endpoints, { state: 'forbidden' });
  assert.ok(!calls.includes('endpoints'), 'never fetched for a viewer');
  assert.ok(!viewer.alarms.some((a) => a.key === 'endpoints_offline'));
  const admin = await b.build({ name: 'Big Display', configVersion: 1, config: SIGNED_IN_CONFIG, role: 'admin' });
  assert.equal(admin.panels.endpoints.state, 'ok');
  assert.ok(admin.alarms.some((a) => a.key === 'endpoints_offline'));
  assert.deepEqual(SIGNED_IN_CONFIG.views.map((v) => v.title), ['SOC overview', 'Threats', 'Health']);
});
