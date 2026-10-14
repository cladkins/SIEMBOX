/**
 * Sign-in alerts (authAlerts.ts): at most 20 raised an hour, one per event_id
 * (a repeat that the unique index drops is neither counted nor notified), the
 * spike alert after more than 100 checked failures in 10 minutes at most once
 * an hour, and AUTH_ALERTS=off. Hermetic: the pool is a recorded stub (the
 * real INSERT ... ON CONFLICT runs against Postgres in
 * routes/signInProtection.db.test.ts). Run with `npm test` (tsx --test).
 */
import { test, before, after, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';

let authAlerts: typeof import('./authAlerts');
let policy: typeof import('./signInPolicy');
const inserted: string[] = [];
const seen = new Set<string>();
let notified = 0;
const restore: Array<() => void> = [];

before(async () => {
  const db = await import('../../config/database');
  const fakeQuery = async (text: string, params: unknown[] = []) => {
    if (/INSERT INTO alerts/.test(text)) {
      const eventId = String(params[5]);
      if (seen.has(eventId)) return { rowCount: 0, rows: [] };
      seen.add(eventId);
      inserted.push(eventId);
      return { rowCount: 1, rows: [{ id: inserted.length }] };
    }
    return { rowCount: 0, rows: [] }; // settings reads (triage gate, notification preferences)
  };
  const q = mock.method(db.default, 'query', fakeQuery as never);
  restore.push(() => q.mock.restore(), () => void db.closePools());
  const { NotificationService } = await import('../notifications/notificationService');
  const n = mock.method(NotificationService, 'notifyAlert', async () => {
    notified++;
  });
  restore.push(() => n.mock.restore());
  const { logger } = await import('../../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restore.push(() => (transport.silent = was));
  }
  authAlerts = await import('./authAlerts');
  policy = await import('./signInPolicy');
});

after(() => {
  while (restore.length) restore.pop()!();
});

beforeEach(() => {
  inserted.length = 0;
  seen.clear();
  notified = 0;
  delete process.env.AUTH_ALERTS;
  policy.reloadSignInSettings();
  authAlerts.resetAuthAlertState();
});

const alert = (key: string, streakStartedAt = 1_700_000_000) => ({
  trigger: 'network-pause' as const,
  severity: 'medium' as const,
  key,
  streakStartedAt,
  title: `Sign-in paused for network ${key}`,
  description: 'test',
  matched: {},
});

test('one alert per streak: a repeat of the same event_id is not raised again or notified', async () => {
  assert.equal(await authAlerts.raiseAuthAlert(alert('ip:192.0.2.1')), true);
  assert.equal(await authAlerts.raiseAuthAlert(alert('ip:192.0.2.1')), false);
  assert.equal(await authAlerts.raiseAuthAlert(alert('ip:192.0.2.1', 1_700_000_999)), true, 'a new streak is a new alert');
  assert.equal(inserted.length, 2);
  assert.equal(notified, 2);
  assert.match(inserted[0], /^siembox-auth:network-pause:[0-9a-f]{16}:1700000000$/);
  assert.ok(!inserted[0].includes('192.0.2.1'), 'the key is hashed into event_id');
});

test('at most 20 alerts are raised an hour', async () => {
  const results: boolean[] = [];
  for (let i = 0; i < 25; i++) results.push(await authAlerts.raiseAuthAlert(alert(`ip:192.0.2.${i}`)));
  assert.equal(results.filter(Boolean).length, 20);
  assert.equal(inserted.length, 20);
  assert.equal(notified, 20);
});

test('the spike alert: more than 100 checked failures in 10 minutes, once an hour', async () => {
  const start = Date.UTC(2026, 9, 14, 10, 0, 0);
  const raised: boolean[] = [];
  for (let i = 0; i < 150; i++) raised.push(await authAlerts.noteCheckedFailure(start + i * 1000));
  assert.deepEqual(raised.map((r, i) => (r ? i : -1)).filter((i) => i >= 0), [100], 'the 101st failure raises it, once');
  assert.deepEqual(inserted, ['siembox-auth:spike:2026-10-14T10']);
  // Failures spread out (one a minute) never reach it.
  authAlerts.resetAuthAlertState();
  for (let i = 0; i < 150; i++) assert.equal(await authAlerts.noteCheckedFailure(start + 3_600_000 + i * 60_000), false);
});

test('AUTH_ALERTS=off raises nothing', async () => {
  process.env.AUTH_ALERTS = 'off';
  policy.reloadSignInSettings();
  assert.equal(await authAlerts.raiseAuthAlert(alert('ip:192.0.2.9')), false);
  for (let i = 0; i < 120; i++) await authAlerts.noteCheckedFailure(Date.now() + i);
  assert.equal(inserted.length, 0);
  assert.equal(notified, 0);
});
