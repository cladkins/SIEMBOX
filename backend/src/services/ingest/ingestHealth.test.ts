/**
 * Stall detection: /health's verdict and the built-in stall alert. The
 * database is mocked (pool.query); no Postgres needed. `npm test`.
 */
import { test, mock, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../../config/database';
import {
  evaluateIngestHealth,
  getIngestHealth,
  readIngestSnapshot,
  resetIngestHealthCache,
  SNAPSHOT_SQL,
} from './ingestHealth';
import { checkStallAlert, stallAlertEventId, STALL_ALERT_SOURCE } from '../../jobs/ingestionHealth';
import { AlertModel } from '../../models/Alert';

const NOW = Date.parse('2026-10-29T20:46:00Z');
const STALL_AT = new Date('2026-10-29T20:36:00Z');

/** Answers the snapshot query with `snapshot`, settings with `settings`. */
function mockDb(snapshot: { newest: Date | null; online: number } | 'hang' | Error, settings: Record<string, string> = {}) {
  return mock.method(pool, 'query', async (sql: string, params?: unknown[]) => {
    if (sql === SNAPSHOT_SQL) {
      if (snapshot === 'hang') return new Promise(() => undefined);
      if (snapshot instanceof Error) throw snapshot;
      return { rows: [snapshot], rowCount: 1 };
    }
    if (sql.includes('FROM system_settings')) {
      const value = settings[String(params?.[0])];
      return { rows: value === undefined ? [] : [{ value }], rowCount: value === undefined ? 0 : 1 };
    }
    throw new Error(`unexpected query: ${sql}`);
  });
}

beforeEach(() => {
  mock.restoreAll();
  resetIngestHealthCache();
});

test('healthy while logs are recent', () => {
  const h = evaluateIngestHealth({ newestRawLogAt: new Date(NOW - 60_000), onlineShippers: 3 }, 300, NOW);
  assert.equal(h.ok, true);
  assert.equal(h.newestRawLogAgeSeconds, 60);
});

test('stalled: newest log older than the threshold while shippers are online', () => {
  const h = evaluateIngestHealth({ newestRawLogAt: STALL_AT, onlineShippers: 3 }, 300, NOW);
  assert.equal(h.ok, false);
  assert.match(h.reason!, /no logs stored for 600s .* 3 shipper/);
});

test('no shippers online: quiet is not a stall (fresh install, all shippers down)', () => {
  assert.equal(evaluateIngestHealth({ newestRawLogAt: STALL_AT, onlineShippers: 0 }, 300, NOW).ok, true);
  assert.equal(evaluateIngestHealth({ newestRawLogAt: null, onlineShippers: 0 }, 300, NOW).ok, true);
});

test('shippers online but nothing ever stored is a stall; threshold 0 disables', () => {
  assert.equal(evaluateIngestHealth({ newestRawLogAt: null, onlineShippers: 1 }, 300, NOW).ok, false);
  assert.equal(evaluateIngestHealth({ newestRawLogAt: STALL_AT, onlineShippers: 3 }, 0, NOW).ok, true);
});

test('getIngestHealth fails when the database errors', async () => {
  mockDb(new Error('connection refused'));
  const h = await getIngestHealth();
  assert.equal(h.ok, false);
  assert.match(h.reason!, /cannot read ingest state: connection refused/);
});

test('a hung database read times out instead of hanging /health', async () => {
  mockDb('hang');
  const t0 = Date.now();
  await assert.rejects(readIngestSnapshot(50), /did not answer within 50ms/);
  assert.ok(Date.now() - t0 < 2000);
});

test('getIngestHealth is cached (one query per burst of probes)', async () => {
  const q = mockDb({ newest: new Date(), online: 1 });
  await Promise.all([getIngestHealth(), getIngestHealth(), getIngestHealth()]);
  await getIngestHealth();
  assert.equal(q.mock.callCount(), 1);
});

test('stall alert: raised once per stall after 10 minutes of zero ingest', async () => {
  mockDb({ newest: STALL_AT, online: 3 });
  const created = mock.method(AlertModel, 'createSourced', async () => 42);
  assert.equal(await checkStallAlert(NOW + 1000), 'stalled');
  assert.equal(created.mock.callCount(), 1);
  const arg = created.mock.calls[0].arguments[0] as { source: string; event_id: string; severity: string };
  assert.equal(arg.source, STALL_ALERT_SOURCE);
  assert.equal(arg.event_id, stallAlertEventId(STALL_AT), 'deduped per stall by the newest log time');
  assert.equal(arg.severity, 'critical');
});

test('stall alert: not raised before 10 minutes, or when turned off', async () => {
  mockDb({ newest: new Date(NOW - 9 * 60_000), online: 3 });
  const created = mock.method(AlertModel, 'createSourced', async () => 1);
  assert.equal(await checkStallAlert(NOW), 'healthy');
  mock.restoreAll();
  mockDb({ newest: STALL_AT, online: 3 }, { ingestion_stall_alert_enabled: 'false' });
  assert.equal(await checkStallAlert(NOW + 60_000), 'disabled');
  assert.equal(created.mock.callCount(), 0);
});
