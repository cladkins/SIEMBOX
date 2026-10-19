/**
 * The log-relationship rollup (migration 044) against a real Postgres.
 *
 * Each test runs in its own schema (cg_rollup_<tag>) holding empty copies of
 * raw_logs, parsed_logs, graph_log_edges and graph_log_edges_state, put first
 * on the rollup's search_path; the key functions and everything else come from
 * public. So the rollup sees only these fixtures, and no other DB test (nor
 * the real cursor) sees or disturbs it. Dropped in `after`.
 *
 * Covers: the edges equal a brute-force aggregation of the fixture logs; no
 * actor edges from sender-fallback or unparsed logs (which still give sent_by
 * and shipped_by); junk, control-character and over-long values dropped; IPv6
 * canonical and ::ffff: folded; the device is the header host, else the
 * sender; a crashed batch replays without double counting, and so do two
 * runners at once; logs inside the lag wait; the daily cap goes update-only
 * and lists the day; the backfill start; pruning to the retention, and none
 * when both retentions are 0; and the SQL key functions agree with
 * entityKey.ts on ENTITY_KEY_FIXTURES. Skips itself without Postgres.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { canonicalKey, ENTITY_KEY_FIXTURES } from './entityKey';
import { logHost } from './resolvers/alerts';
import { countNewRows, DEFAULT_LOG_EDGE_SETTINGS, runLogEdgeRollup, type LogEdgeSettings, type RollupClient } from './logEdgeRollup';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const schema = `cg_rollup_${crypto.randomBytes(4).toString('hex')}`;
let ready = false;

async function connect(): Promise<RollupClient> {
  const client = await pool.connect();
  await client.query(`SET search_path TO ${schema}, public`);
  return {
    query: (sql, params) => client.query(sql, params as unknown[]),
    release: (err) => {
      void client
        .query('RESET search_path')
        .catch(() => undefined)
        .finally(() => client.release(err));
    },
  };
}

const settings = (over: Partial<LogEdgeSettings> = {}): LogEdgeSettings => ({ ...DEFAULT_LOG_EDGE_SETTINGS, ...over });
const run = (over: Partial<Parameters<typeof runLogEdgeRollup>[0]> = {}) =>
  runLogEdgeRollup({ connect, settings: settings(), lag: '0 seconds', ...over });

let nextId = 1;
interface Log {
  parsed?: boolean;
  data: Record<string, unknown>;
  hostname?: string | null;
  sender: string;
  shipper?: string | null;
  ago?: string;
}

async function insertLogs(logs: Log[]): Promise<void> {
  for (const log of logs) {
    const id = nextId++;
    await pool.query(
      `INSERT INTO ${schema}.raw_logs (id, timestamp, raw_message, source_ip, hostname, shipper_id, created_at)
       VALUES ($1, NOW(), 'msg', $2, $3, $4, NOW() - $5::interval)`,
      [id, log.sender, log.hostname ?? null, log.shipper ?? null, log.ago ?? '10 minutes']
    );
    await pool.query(
      `INSERT INTO ${schema}.parsed_logs (id, raw_log_id, parser_id, parsed_data, timestamp, source_ip, created_at)
       VALUES ($1, $1, $2, $3, NOW(), $4, NOW() - $5::interval)`,
      [id, log.parsed === false ? null : 1, JSON.stringify({ observer_ip: log.sender, ...log.data }), log.sender, log.ago ?? '10 minutes']
    );
  }
}

type Edge = { rel: string; a: string; b: string; events: number; failures: number; successes: number };
async function edges(): Promise<Edge[]> {
  const { rows } = await pool.query(
    `SELECT rel, a_type || ':' || a_value AS a, b_type || ':' || b_value AS b,
            sum(events)::int AS events, sum(failures)::int AS failures, sum(successes)::int AS successes
       FROM ${schema}.graph_log_edges GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`
  );
  return rows;
}
const find = (all: Edge[], rel: string, a: string, b: string) => all.find((e) => e.rel === rel && e.a === a && e.b === b);
const state = async () => (await pool.query(`SELECT *, to_char(covered_from, 'YYYY-MM-DD') AS from_day FROM ${schema}.graph_log_edges_state`)).rows[0];

/** The fixture set the first tests share. */
const SENDER = '10.77.0.1';
const FIXTURES: Log[] = [
  // An actor signing in: 3 failures, 1 success, through a shipper, on host Web01.
  ...[1, 2, 3].map(() => ({ data: { source_ip: '203.0.113.5', user: 'alice', auth_outcome: 'failure' }, hostname: 'Web01', sender: SENDER, shipper: 'DEADBEEF' })),
  { data: { source_ip: '203.0.113.5', user: 'alice', auth_outcome: 'success' }, hostname: 'Web01', sender: SENDER, shipper: 'DEADBEEF' },
  // Sender fallback (source_ip = observer): no actor edges, but user_on.
  { data: { source_ip: SENDER, user: 'bob' }, hostname: 'web01', sender: SENDER },
  // Unparsed: only sent_by and shipped_by.
  { parsed: false, data: { source_ip: '198.51.100.9', user: 'carol' }, hostname: 'web01', sender: SENDER, shipper: 'deadbeef' },
  // Junk users.
  { data: { source_ip: '203.0.113.6', user: '-' }, hostname: 'web01', sender: SENDER },
  { data: { source_ip: '203.0.113.6', user: 'eve\u0007' }, hostname: 'web01', sender: SENDER },
  { data: { source_ip: '203.0.113.6', user: 'u'.repeat(129) }, hostname: 'web01', sender: SENDER },
  // IPv6 canonical, ::ffff: folded; no header host: the device is the sender.
  { data: { source_ip: '2001:DB8:0:0:0:0:0:1', user: 'dave' }, hostname: null, sender: '10.77.0.2' },
  { data: { source_ip: '::ffff:192.0.2.7', dest_ip: '10.77.0.9', domain: 'Example.COM.' }, hostname: '-', sender: '10.77.0.2' },
];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM graph_log_edges_state LIMIT 1');
  } catch {
    return;
  }
  await pool.query(`CREATE SCHEMA ${schema}`);
  for (const table of ['raw_logs', 'parsed_logs', 'graph_log_edges', 'graph_log_edges_state']) {
    await pool.query(`CREATE TABLE ${schema}.${table} (LIKE public.${table} INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES)`);
  }
  ready = true;
});

beforeEach(async () => {
  if (!ready) return;
  await pool.query(`TRUNCATE ${schema}.raw_logs, ${schema}.parsed_logs, ${schema}.graph_log_edges, ${schema}.graph_log_edges_state`);
  await pool.query(`INSERT INTO ${schema}.graph_log_edges_state (id) VALUES (1)`);
  nextId = 1;
});

after(async () => {
  if (ready) await pool.query(`DROP SCHEMA ${schema} CASCADE`);
  await closePools();
});

test('the edges equal the fixture logs, with only trusted actors', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs(FIXTURES);
  const result = await run();
  assert.equal(result.consumed, FIXTURES.length);
  const all = await edges();

  assert.deepEqual(find(all, 'signed_in_as', 'ip:203.0.113.5', 'user:alice'), {
    rel: 'signed_in_as', a: 'ip:203.0.113.5', b: 'user:alice', events: 4, failures: 3, successes: 1,
  });
  assert.equal(find(all, 'seen_on', 'ip:203.0.113.5', 'host:web01')?.events, 4);
  assert.equal(find(all, 'shipped_by', 'host:web01', 'shipper_tag:deadbeef')?.events, 5, 'upper- and lower-case tags are one');
  // Every log with a header host was sent from the sender (the '-' host is junk, the null one absent).
  assert.equal(find(all, 'sent_by', 'host:web01', `ip:${SENDER}`)?.events, 9);
  // Sender fallback and unparsed logs: no actor edges.
  assert.equal(all.filter((e) => e.a === `ip:${SENDER}` || e.a === 'ip:198.51.100.9').length, 0);
  assert.equal(find(all, 'user_on', 'user:bob', 'host:web01')?.events, 1);
  assert.equal(all.filter((e) => e.b === 'user:carol' || e.a === 'user:carol').length, 0, 'an unparsed log names no user');
  // Junk users dropped; the actor is still seen on the device.
  assert.equal(all.filter((e) => e.rel === 'signed_in_as' && e.a === 'ip:203.0.113.6').length, 0);
  assert.equal(find(all, 'seen_on', 'ip:203.0.113.6', 'host:web01')?.events, 3);
  // IPv6 canonical, ::ffff: folded, the sender as the device, the domain normalized.
  assert.equal(find(all, 'signed_in_as', 'ip:2001:db8::1', 'user:dave')?.events, 1);
  assert.equal(find(all, 'seen_on', 'ip:2001:db8::1', 'ip:10.77.0.2')?.events, 1);
  assert.equal(find(all, 'connected_to', 'ip:192.0.2.7', 'ip:10.77.0.9')?.events, 1);
  assert.equal(find(all, 'queried', 'ip:192.0.2.7', 'domain:example.com')?.events, 1);
  assert.equal(all.filter((e) => e.a.startsWith('host:-')).length, 0);

  // Brute force: per relation, the events equal the number of logs that qualify.
  const perRel = new Map<string, number>();
  for (const e of all) perRel.set(e.rel, (perRel.get(e.rel) ?? 0) + e.events);
  assert.deepEqual(Object.fromEntries(perRel), {
    signed_in_as: 5, // alice x4, dave
    seen_on: 9, // alice x4, 203.0.113.6 x3, dave, 192.0.2.7
    user_on: 6, // alice x4, bob, dave
    connected_to: 1,
    queried: 1,
    sent_by: 9, // every log with a valid header host
    shipped_by: 5, // the logs that carry a tag
  });

  const s = await state();
  assert.equal(Number(s.last_parsed_log_id), FIXTURES.length);
  assert.equal(s.caught_up, true);
  assert.ok(s.covered_until);
});

test('a crashed batch replays without double counting, and two runners count once', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs(FIXTURES);
  let calls = 0;
  await assert.rejects(
    run({
      batchSize: 3,
      afterBatch: () => {
        if (++calls === 2) throw new Error('simulated crash');
      },
    })
  );
  const s = await state();
  assert.equal(Number(s.last_parsed_log_id), 6, 'two batches committed before the crash');
  await Promise.all([run({ batchSize: 2 }), run({ batchSize: 2 })]);
  const all = await edges();
  assert.equal(find(all, 'signed_in_as', 'ip:203.0.113.5', 'user:alice')?.events, 4);
  assert.equal(find(all, 'sent_by', 'host:web01', `ip:${SENDER}`)?.events, 9);
  assert.equal(Number((await state()).last_parsed_log_id), FIXTURES.length);
});

test('logs inside the lag wait for the next run', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([
    { data: { source_ip: '203.0.113.20', user: 'old' }, hostname: 'h1', sender: SENDER, ago: '10 minutes' },
    { data: { source_ip: '203.0.113.21', user: 'fresh' }, hostname: 'h1', sender: SENDER, ago: '10 seconds' },
  ]);
  const result = await run({ lag: '2 minutes' });
  assert.equal(result.consumed, 1);
  const all = await edges();
  assert.ok(find(all, 'signed_in_as', 'ip:203.0.113.20', 'user:old'));
  assert.equal(find(all, 'signed_in_as', 'ip:203.0.113.21', 'user:fresh'), undefined);
});

test('the daily cap: update-only for the day, which is listed as incomplete', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([{ data: { source_ip: '203.0.113.30', user: 'u0' }, hostname: 'h', sender: SENDER }]);
  const capped = await run({ settings: settings({ dailyNewCap: 3 }) });
  assert.equal(capped.cappedDays.length, 1, 'one log makes 5 new rows: over a cap of 3');
  const day = capped.cappedDays[0];
  // More logs that day: the known pair is updated, new pairs are not inserted.
  await insertLogs([
    { data: { source_ip: '203.0.113.30', user: 'u0' }, hostname: 'h', sender: SENDER },
    { data: { source_ip: '203.0.113.31', user: 'u1' }, hostname: 'h', sender: SENDER },
  ]);
  await run({ settings: settings({ dailyNewCap: 3 }) });
  const all = await edges();
  assert.equal(find(all, 'signed_in_as', 'ip:203.0.113.30', 'user:u0')?.events, 2);
  assert.equal(find(all, 'signed_in_as', 'ip:203.0.113.31', 'user:u1'), undefined);
  const s = await pool.query(`SELECT to_char(unnest(truncated_days), 'YYYY-MM-DD') AS d FROM ${schema}.graph_log_edges_state`);
  assert.deepEqual(s.rows.map((r) => r.d), [day]);
});

test('the backfill starts backfill_days back', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([
    { data: { source_ip: '203.0.113.40', user: 'ancient' }, hostname: 'h', sender: SENDER, ago: '10 days' },
    { data: { source_ip: '203.0.113.41', user: 'recent' }, hostname: 'h', sender: SENDER, ago: '2 days' },
  ]);
  const result = await run({ settings: settings({ backfillDays: 7 }) });
  assert.equal(result.consumed, 1);
  const all = await edges();
  assert.equal(find(all, 'signed_in_as', 'ip:203.0.113.40', 'user:ancient'), undefined);
  assert.ok(find(all, 'signed_in_as', 'ip:203.0.113.41', 'user:recent'));
  const s = await state();
  const expected = new Date(Date.now() - 7 * 86_400_000).toISOString().slice(0, 10);
  // CURRENT_DATE is the database's day: allow its zone to be a day off UTC.
  assert.ok(Math.abs(Date.parse(s.from_day) - Date.parse(expected)) <= 86_400_000, `covered_from ${s.from_day}`);
});

test('pruning keeps the retention, and everything when both retentions are 0', async (t) => {
  if (!ready) return t.skip(SKIP);
  await pool.query(
    `INSERT INTO ${schema}.graph_log_edges (day, rel, a_type, a_value, b_type, b_value, events, first_seen, last_seen)
     VALUES (CURRENT_DATE - 40, 'sent_by', 'host', 'old', 'ip', '10.0.0.1', 1, NOW(), NOW()),
            (CURRENT_DATE - 5, 'sent_by', 'host', 'new', 'ip', '10.0.0.1', 1, NOW(), NOW())`
  );
  await run({ settings: settings({ retentionDays: 0, rawRetentionDays: 0 }), forcePrune: true });
  assert.equal((await edges()).length, 2, 'both 0: nothing pruned');
  const pruned = await run({ settings: settings({ retentionDays: 0, rawRetentionDays: 30 }), forcePrune: true });
  assert.equal(pruned.pruned, 1);
  assert.deepEqual((await edges()).map((e) => e.a), ['host:new']);
  // At most hourly unless forced.
  const again = await run({ settings: settings({ retentionDays: 1 }) });
  assert.equal(again.pruned, 0);
});

test('the SQL key functions agree with entityKey.ts', async (t) => {
  if (!ready) return t.skip(SKIP);
  const fn: Record<string, string> = { ip: 'graph_ip', user: 'graph_user', host: 'graph_log_host', domain: 'graph_domain' };
  for (const [type, input, expected] of ENTITY_KEY_FIXTURES) {
    if (!fn[type]) continue;
    const { rows } = await pool.query(`SELECT ${fn[type]}($1) AS v`, [input]);
    const ts = type === 'host' ? logHost(input) : canonicalKey(type, input);
    assert.equal(ts, expected, `entityKey ${type} ${JSON.stringify(input)}`);
    assert.equal(rows[0].v, expected, `${fn[type]}(${JSON.stringify(input)})`);
  }
  for (const v of ['::1.2.3.4', '::0.0.1.2', '1:0:0:1:0:0:0:1', '::ffff:102:304']) {
    const { rows } = await pool.query(`SELECT graph_ip($1) AS v`, [v]);
    assert.equal(rows[0].v, canonicalKey('ip', v), v);
  }
});

test('countNewRows: per-day counters cross the cap once', () => {
  const out = countNewRows({ day: '2026-10-18', count: 8, truncated: [] }, [
    { day: '2026-10-19', new_rows: 4 },
    { day: '2026-10-18', new_rows: 3 },
  ], 10);
  assert.deepEqual(out, { day: '2026-10-19', count: 4, truncated: ['2026-10-18'], capped: ['2026-10-18'] });
});
