/**
 * Calendar timing for scheduled scans, end to end: the real app on an
 * ephemeral port and a real Postgres. Covers create and edit with a calendar
 * `schedule` or a fixed `interval_minutes`, the 400s for bad timing, the
 * preview route, and how next_run_at rolls forward after a run (fixed-interval
 * schedules exactly as before; calendar ones to their next occurrence after
 * now, also after runs missed while SIEMBox was down).
 *
 * Every schedule here is created disabled, or marked run by hand, so the
 * dispatcher (and a test file running in parallel against the same database)
 * never starts one of them. Skips itself when Postgres isn't reachable. Rows
 * created here are removed again, with what an interrupted run left behind.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { ScheduledScanModel } from '../models/ScheduledScan';
import { computeNextRun, nextRuns, type CalendarSchedule } from '../utils/scheduleTiming';

const SKIP = 'Postgres with the scheduled-scan timing schema is not reachable';
const TEST_NAME = '^schedtiming-[0-9a-f]{12}';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `schedtiming-${tag}`;
let token = '';
let userId = 0;

before(async () => {
  try {
    await pool.query('SELECT schedule, interval_minutes FROM scheduled_scans LIMIT 1');
    await pool.query('SELECT token FROM sessions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const user = await UserModel.create({
    username: `${name}-operator`,
    email: `${name}-operator@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'operator',
  });
  userId = user.id;
  token = (await SessionModel.create(user.id, 1)).token;
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    await pool.query(`DELETE FROM scheduled_scans WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_NAME]);
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_NAME]
    );
    const doomed = [userId, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]);
  }
  await closePools();
});

async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

/** next_run_at as an instant, read in SQL so the column's session-zone conversion is Postgres's own. */
async function nextRunOf(id: number): Promise<number> {
  const row = (await pool.query(`SELECT next_run_at::timestamptz AS at FROM scheduled_scans WHERE id = $1`, [id])).rows[0];
  return (row.at as Date).getTime();
}

async function dbNow(): Promise<number> {
  return ((await pool.query('SELECT NOW() AS now')).rows[0].now as Date).getTime();
}

const asset = { scan_type: 'asset' as const, scan_options: { targets: ['192.0.2.10'] }, enabled: false };
const weekdays: CalendarSchedule = { frequency: 'weekly', time: '02:30', days: [1, 2, 3, 4, 5], timezone: 'America/Chicago' };

test('create with a calendar schedule: stored normalized, next run is its next occurrence', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = await dbNow();
  const created = await call('POST', '/api/scheduled-scans', {
    ...asset,
    name: `${name}-weekly`,
    schedule: { mode: 'calendar', ...weekdays, days: [5, 4, 3, 2, 1, 1] },
  });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  assert.deepEqual(created.json.schedule, weekdays);
  assert.equal(created.json.interval_minutes, null);
  const at = await nextRunOf(created.json.id);
  const after = await dbNow();
  // The next occurrence after "now" at create time, wherever in [before, after] that was.
  const lo = computeNextRun(weekdays, new Date(before - 1000)).getTime();
  const hi = computeNextRun(weekdays, new Date(after)).getTime();
  assert.ok(at >= lo && at <= hi, `${new Date(at).toISOString()} within [${new Date(lo).toISOString()}, ${new Date(hi).toISOString()}]`);
  assert.ok(at > after - 1000);
});

test('create with interval_minutes still makes a fixed-interval schedule', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = await dbNow();
  const created = await call('POST', '/api/scheduled-scans', { ...asset, name: `${name}-interval`, interval_minutes: 90 });
  assert.equal(created.status, 201);
  assert.equal(created.json.schedule, null);
  assert.equal(created.json.interval_minutes, 90);
  const at = await nextRunOf(created.json.id);
  assert.ok(Math.abs(at - (before + 90 * 60_000)) < 60_000, 'NOW() + 90 minutes');
});

test('bad timing is a 400 that names the problem', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{}, /interval_minutes must be an integer of at least 5/],
    [{ interval_minutes: 4 }, /interval_minutes must be an integer of at least 5/],
    [{ interval_minutes: 60, schedule: weekdays }, /either schedule .* or interval_minutes/],
    [{ schedule: { ...weekdays, timezone: 'Mars/Olympus_Mons' } }, /schedule\.timezone must be an IANA time zone/],
    [{ schedule: { ...weekdays, timezone: '+05:00' } }, /schedule\.timezone/],
    [{ schedule: { ...weekdays, days: [] } }, /schedule\.days must be a non-empty array/],
    [{ schedule: { ...weekdays, time: '2:30' } }, /schedule\.time must be HH:MM/],
    [{ schedule: { ...weekdays, frequency: 'yearly' } }, /schedule\.frequency must be one of/],
    [{ schedule: { frequency: 'hourly', minute: 0, every_hours: 24, timezone: 'UTC' } }, /every_hours/],
    [{ schedule: { frequency: 'monthly', time: '02:00', day_of_month: 32, timezone: 'UTC' } }, /day_of_month/],
    [{ schedule: { mode: 'interval', interval_minutes: 60 } }, /schedule\.mode must be 'calendar'/],
    [{ schedule: 'daily' }, /schedule must be an object/],
  ];
  for (const [timing, message] of cases) {
    const res = await call('POST', '/api/scheduled-scans', { ...asset, name: `${name}-bad`, ...timing });
    assert.equal(res.status, 400, JSON.stringify(timing));
    assert.match(res.json.message, message, JSON.stringify(timing));
  }
  assert.equal((await pool.query('SELECT 1 FROM scheduled_scans WHERE name = $1', [`${name}-bad`])).rowCount, 0, 'nothing was created');
});

test('edit: switch between calendar and interval, recompute only when the timing changes', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const created = await call('POST', '/api/scheduled-scans', { ...asset, name: `${name}-edit`, interval_minutes: 1440 });
  const id = created.json.id;
  // Park next_run_at somewhere recognizable.
  await pool.query(`UPDATE scheduled_scans SET next_run_at = '2030-01-01 00:00' WHERE id = $1`, [id]);
  const parked = await nextRunOf(id);

  // Renaming leaves the timing (and next run) alone.
  assert.equal((await call('PUT', `/api/scheduled-scans/${id}`, { name: `${name}-edit2` })).status, 200);
  assert.equal(await nextRunOf(id), parked);

  // Interval -> calendar.
  const daily: CalendarSchedule = { frequency: 'daily', time: '02:00', timezone: 'Europe/London' };
  const toCal = await call('PUT', `/api/scheduled-scans/${id}`, { schedule: daily });
  assert.equal(toCal.status, 200);
  assert.deepEqual(toCal.json.schedule, daily);
  assert.equal(toCal.json.interval_minutes, null);
  const calAt = await nextRunOf(id);
  assert.equal(calAt, computeNextRun(daily, new Date(calAt - 1)).getTime(), 'lands on an occurrence');
  assert.ok(calAt > (await dbNow()) && calAt <= (await dbNow()) + 25 * 3600_000);

  // Bad edits change nothing.
  for (const body of [
    { schedule: { ...daily, timezone: 'Nowhere' } },
    { schedule: daily, interval_minutes: 60 },
    { schedule: null },
    { interval_minutes: null },
    { interval_minutes: 2 },
  ]) {
    const res = await call('PUT', `/api/scheduled-scans/${id}`, body);
    assert.equal(res.status, 400, JSON.stringify(body));
    assert.ok(res.json.message, 'a message');
  }
  assert.deepEqual((await ScheduledScanModel.findById(id))!.schedule, daily);

  // Calendar -> interval.
  const toInt = await call('PUT', `/api/scheduled-scans/${id}`, { schedule: null, interval_minutes: 120 });
  assert.equal(toInt.status, 200);
  assert.equal(toInt.json.schedule, null);
  assert.equal(toInt.json.interval_minutes, 120);
  assert.ok(Math.abs((await nextRunOf(id)) - ((await dbNow()) + 120 * 60_000)) < 60_000);

  // interval_minutes alone on a calendar schedule also switches it.
  await call('PUT', `/api/scheduled-scans/${id}`, { schedule: daily });
  const back = await call('PUT', `/api/scheduled-scans/${id}`, { interval_minutes: 60 });
  assert.equal(back.json.schedule, null);
  assert.equal(back.json.interval_minutes, 60);

  // Re-enabling recomputes from now.
  await call('PUT', `/api/scheduled-scans/${id}`, { schedule: daily });
  await pool.query(`UPDATE scheduled_scans SET next_run_at = '2020-01-01 00:00' WHERE id = $1`, [id]);
  await call('PUT', `/api/scheduled-scans/${id}`, { enabled: true });
  await call('PUT', `/api/scheduled-scans/${id}`, { enabled: false });
  const reenabled = await nextRunOf(id);
  assert.equal(reenabled, computeNextRun(daily, new Date(reenabled - 1)).getTime());
  assert.ok((await nextRunOf(id)) > (await dbNow()));
});

test('after a run: interval schedules roll forward by their interval, calendar ones to the next occurrence (once, after missed runs)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const legacy = await ScheduledScanModel.create({ ...asset, name: `${name}-legacy`, interval_minutes: 60 });
  const hourly: CalendarSchedule = { frequency: 'hourly', minute: 7, every_hours: 1, timezone: 'UTC' };
  const cal = await ScheduledScanModel.create({ ...asset, name: `${name}-cal`, interval_minutes: null, schedule: hourly });

  // Both were due three days ago (SIEMBox was down since).
  await pool.query(`UPDATE scheduled_scans SET next_run_at = NOW() - INTERVAL '3 days', enabled = false WHERE id = ANY($1)`, [[legacy.id, cal.id]]);
  await ScheduledScanModel.markRun(legacy.id, null);
  await ScheduledScanModel.markRun(cal.id, null);
  const now = await dbNow();

  const legacyAt = await nextRunOf(legacy.id);
  assert.ok(Math.abs(legacyAt - (now + 60 * 60_000)) < 60_000, 'fixed interval: NOW() + 60 minutes, as before');
  const calAt = await nextRunOf(cal.id);
  assert.ok(calAt > now, 'the next run is in the future: no catch-up burst');
  assert.equal(new Date(calAt).getUTCMinutes(), 7);
  assert.ok(calAt - now <= 3600_000);
  const row = (await ScheduledScanModel.findById(cal.id))!;
  assert.ok(row.last_run_at);
  assert.deepEqual(row.schedule, hourly);
});

test('preview: the next runs of a calendar schedule or an interval', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = Date.now();
  const res = await call('POST', '/api/scheduled-scans/preview', { schedule: weekdays });
  assert.equal(res.status, 200);
  assert.deepEqual(res.json.schedule, weekdays);
  assert.equal(res.json.next_runs.length, 3);
  const expected = nextRuns(weekdays, new Date(before - 1000), 4).map((d) => d.toISOString());
  assert.ok(
    JSON.stringify(res.json.next_runs) === JSON.stringify(expected.slice(0, 3)) ||
      JSON.stringify(res.json.next_runs) === JSON.stringify(expected.slice(1, 4))
  );

  const five = await call('POST', '/api/scheduled-scans/preview', { interval_minutes: 60, count: 5 });
  assert.equal(five.status, 200);
  assert.equal(five.json.next_runs.length, 5);
  assert.equal(Date.parse(five.json.next_runs[1]) - Date.parse(five.json.next_runs[0]), 3600_000);

  assert.equal((await call('POST', '/api/scheduled-scans/preview', { schedule: { ...weekdays, days: [9] } })).status, 400);
  assert.equal((await call('POST', '/api/scheduled-scans/preview', { schedule: weekdays, count: 11 })).status, 400);
  assert.equal((await pool.query('SELECT 1 FROM scheduled_scans WHERE name LIKE $1', [`${name}-preview%`])).rowCount, 0);
});
