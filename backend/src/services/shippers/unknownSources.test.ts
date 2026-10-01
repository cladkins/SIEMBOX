/**
 * Tests for the unknown-sources service. The motivating incident: the old query
 * scanned all of raw_logs on every Shippers page load, took >10 s, and -- because
 * Postgres keeps running a query after the browser gives up -- stacked heavy scans
 * that starved log ingestion of connections. These tests pin the protections that
 * replace it: a statement timeout, single-flight + TTL caching, a failure
 * cooldown, stale-on-error, and correct invalidation.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createUnknownSourcesService,
  createDbFetcher,
  isStatementTimeout,
  isDatabaseBusy,
  UNKNOWN_SOURCES_SQL,
  UnknownSourceRow,
  UnknownSourcesOptions,
  QueryClient,
} from './unknownSources';

const OPTS: UnknownSourcesOptions = {
  windowHours: 24,
  timeoutMs: 8000,
  ttlMs: 30_000,
  failureCooldownMs: 20_000,
  maxDistinctIds: 5000,
};

function row(over: Partial<UnknownSourceRow> = {}): UnknownSourceRow {
  return {
    shipper_id: 'deadbeef',
    log_count: '42', // COUNT(*) is a bigint -> pg returns a string
    first_seen: '2026-10-01T00:00:00.000Z',
    last_seen: '2026-10-01T12:00:00.000Z',
    source_ips: ['192.168.1.5', null],
    hostnames: ['host-a'],
    app_names: ['nginx', null],
    ids_enumerated: '7',
    ...over,
  };
}

interface Harness {
  svc: ReturnType<typeof createUnknownSourcesService>;
  calls: Array<{ windowHours: number; maxIds: number; timeoutMs: number }>;
  clock: { t: number };
  logs: { warn: string[]; error: string[] };
  setFetch(fn: () => Promise<UnknownSourceRow[]>): void;
}

function harness(initial: () => Promise<UnknownSourceRow[]>, opts: UnknownSourcesOptions = OPTS): Harness {
  const calls: Harness['calls'] = [];
  const clock = { t: 1_000_000 };
  const logs = { warn: [] as string[], error: [] as string[] };
  let fetchImpl = initial;
  const svc = createUnknownSourcesService(
    {
      fetchRows: (windowHours, maxIds, timeoutMs) => {
        calls.push({ windowHours, maxIds, timeoutMs });
        return fetchImpl();
      },
      now: () => clock.t,
      log: { warn: (m) => logs.warn.push(m), error: (m) => logs.error.push(m) },
    },
    opts
  );
  return { svc, calls, clock, logs, setFetch: (fn) => (fetchImpl = fn) };
}

test('maps rows: bigint count -> number, NULL array elements dropped, params forwarded', async () => {
  const h = harness(async () => [row()]);
  const out = await h.svc.get();
  assert.deepEqual(out, [
    {
      shipper_id: 'deadbeef',
      log_count: 42,
      first_seen: '2026-10-01T00:00:00.000Z',
      last_seen: '2026-10-01T12:00:00.000Z',
      source_ips: ['192.168.1.5'],
      hostnames: ['host-a'],
      app_names: ['nginx'],
    },
  ]);
  assert.deepEqual(h.calls, [{ windowHours: 24, maxIds: 5000, timeoutMs: 8000 }]);
});

test('serves from cache inside the TTL, re-queries after it', async () => {
  const h = harness(async () => [row()]);
  await h.svc.get();
  h.clock.t += 29_999;
  await h.svc.get();
  assert.equal(h.calls.length, 1, 'still fresh -> no second query');
  h.clock.t += 2;
  await h.svc.get();
  assert.equal(h.calls.length, 2, 'TTL elapsed -> refreshed');
});

test('single-flight: concurrent callers share ONE query (page loads cannot stack scans)', async () => {
  let release!: (rows: UnknownSourceRow[]) => void;
  const h = harness(() => new Promise<UnknownSourceRow[]>((r) => (release = r)));
  const [a, b, c] = [h.svc.get(), h.svc.get(), h.svc.get()];
  assert.equal(h.calls.length, 1);
  release([row()]);
  const results = await Promise.all([a, b, c]);
  assert.equal(h.calls.length, 1);
  assert.equal(results[0], results[1]);
  assert.equal(results[1], results[2]);
});

test('invalidate() forces the next call to re-query even inside the TTL', async () => {
  const h = harness(async () => [row()]);
  await h.svc.get();
  h.svc.invalidate();
  await h.svc.get();
  assert.equal(h.calls.length, 2);
});

test('a result computed BEFORE an invalidate() is returned to its waiters but never cached', async () => {
  // Registering a shipper while a scan is in flight must not leave the (now
  // out-of-date) scan result cached, or the adopted source would keep showing.
  let release!: (rows: UnknownSourceRow[]) => void;
  const h = harness(() => new Promise<UnknownSourceRow[]>((r) => (release = r)));
  const first = h.svc.get();
  h.svc.invalidate(); // shipper registered mid-scan
  release([row({ shipper_id: 'stale001' })]);
  const out = await first;
  assert.equal(out[0].shipper_id, 'stale001', 'waiter still gets the result it asked for');

  h.setFetch(async () => []);
  const next = await h.svc.get();
  assert.equal(h.calls.length, 2, 'not cached -> the next call re-queried');
  assert.deepEqual(next, []);
});

test('failure with nothing cached: throws, then fails FAST during the cooldown (no hammering)', async () => {
  const boom = Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
  const h = harness(async () => {
    throw boom;
  });
  await assert.rejects(h.svc.get(), (e) => e === boom);
  assert.equal(h.calls.length, 1);
  assert.equal(h.logs.error.length, 1);

  h.clock.t += 5_000;
  await assert.rejects(h.svc.get(), (e) => e === boom);
  assert.equal(h.calls.length, 1, 'cooldown -> no new query');
  assert.equal(h.logs.error.length, 1, 'cooldown replays are not re-logged');

  h.clock.t += 16_000; // past the 20 s cooldown
  h.setFetch(async () => [row()]);
  const out = await h.svc.get();
  assert.equal(h.calls.length, 2, 'cooldown over -> retried');
  assert.equal(out.length, 1, 'and recovered');
});

test('failure with a previous result: serves it stale instead of erroring', async () => {
  const h = harness(async () => [row()]);
  await h.svc.get();
  h.clock.t += 31_000; // expired
  h.setFetch(async () => {
    throw new Error('timeout exceeded when trying to connect');
  });
  const out = await h.svc.get();
  assert.equal(out.length, 1, 'stale result served');
  assert.equal(h.logs.warn.length, 1);
  assert.equal(h.logs.error.length, 0);

  // ...and the cooldown also serves stale instead of re-trying immediately.
  h.clock.t += 1_000;
  const again = await h.svc.get();
  assert.equal(again.length, 1);
  assert.equal(h.calls.length, 2);
});

test('a stale result survives invalidate() when the refresh fails (still better than an error)', async () => {
  const h = harness(async () => [row()]);
  await h.svc.get();
  h.svc.invalidate();
  h.setFetch(async () => {
    throw new Error('db down');
  });
  const out = await h.svc.get();
  assert.equal(out.length, 1);
});

test('a fetcher that throws SYNCHRONOUSLY cannot wedge the in-flight slot', async () => {
  const h = harness(() => {
    throw new Error('sync boom');
  });
  await assert.rejects(h.svc.get(), /sync boom/);
  h.clock.t += 25_000;
  h.setFetch(async () => [row()]);
  const out = await h.svc.get(); // would hang/reject forever if `inflight` stayed pinned
  assert.equal(out.length, 1);
});

test('warns when the distinct-id enumeration hits its cap (sender spraying shipper tags)', async () => {
  const h = harness(async () => [row({ ids_enumerated: '5000' })]);
  await h.svc.get();
  assert.equal(h.logs.warn.length, 1);
  assert.match(h.logs.warn[0], /cap of 5000/);

  const quiet = harness(async () => [row({ ids_enumerated: '4999' })]);
  await quiet.svc.get();
  assert.equal(quiet.logs.warn.length, 0);
});

test('error classification: statement timeout and pool-acquire timeout are "busy" (503), others are not', () => {
  assert.equal(isStatementTimeout(Object.assign(new Error('x'), { code: '57014' })), true);
  assert.equal(isStatementTimeout(new Error('x')), false);
  assert.equal(isStatementTimeout(null), false);
  assert.equal(isDatabaseBusy(Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' })), true);
  assert.equal(isDatabaseBusy(new Error('timeout exceeded when trying to connect')), true);
  assert.equal(isDatabaseBusy(new Error('relation "raw_logs" does not exist')), false);
  assert.equal(isDatabaseBusy('weird'), false);
});

// ---------------------------------------------------------------------------
// createDbFetcher: the transaction protocol that bounds the query.
// ---------------------------------------------------------------------------

function fakeClient(script: { failOn?: string; failRollback?: boolean; rows?: any[] } = {}) {
  const statements: Array<{ text: string; params?: any[] }> = [];
  const released: Array<Error | boolean | undefined> = [];
  const client: QueryClient = {
    async query(text: string, params?: any[]) {
      statements.push({ text, params });
      if (script.failOn && text.includes(script.failOn)) throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
      if (script.failRollback && text === 'ROLLBACK') throw new Error('connection terminated');
      return { rows: text === UNKNOWN_SOURCES_SQL ? script.rows ?? [] : [] };
    },
    release(arg?: Error | boolean) {
      released.push(arg);
    },
  };
  return { client, statements, released };
}

test('DB fetcher: READ ONLY txn, parameterized LOCAL timeout, bound params, COMMIT, clean release', async () => {
  const f = fakeClient({ rows: [row()] });
  const rows = await createDbFetcher(async () => f.client)(24, 5000, 8000);
  assert.equal(rows.length, 1);
  assert.deepEqual(
    f.statements.map((s) => s.text.trim().split('\n')[0].trim()),
    ['BEGIN READ ONLY', "SELECT set_config('statement_timeout', $1, true)", 'WITH RECURSIVE shipper_hashes AS MATERIALIZED (', 'COMMIT']
  );
  assert.deepEqual(f.statements[1].params, ['8000'], 'timeout is passed as a bind parameter, never interpolated');
  assert.deepEqual(f.statements[2].params, [24, 5000]);
  assert.deepEqual(f.released, [undefined], 'healthy connection goes back to the pool');
});

test('DB fetcher: on a statement timeout it ROLLBACKs, releases the client, and rethrows', async () => {
  const f = fakeClient({ failOn: 'WITH RECURSIVE' });
  await assert.rejects(createDbFetcher(async () => f.client)(24, 5000, 8000), (e: any) => e.code === '57014');
  assert.equal(f.statements[f.statements.length - 1].text, 'ROLLBACK');
  assert.deepEqual(f.released, [undefined]);
});

test('DB fetcher: if ROLLBACK itself fails the connection is destroyed, not recycled', async () => {
  const f = fakeClient({ failOn: 'WITH RECURSIVE', failRollback: true });
  await assert.rejects(createDbFetcher(async () => f.client)(24, 5000, 8000), (e: any) => e.code === '57014');
  assert.equal(f.released.length, 1);
  assert.ok(f.released[0] instanceof Error, 'release(err) tells pg-pool to discard the client');
});

test('DB fetcher: a failure to acquire a connection is surfaced and nothing is released', async () => {
  const err = new Error('timeout exceeded when trying to connect');
  await assert.rejects(
    createDbFetcher(async () => {
      throw err;
    })(24, 5000, 8000),
    (e) => e === err
  );
});

test('the SQL keeps its safety properties (guards against a well-meaning "simplification")', () => {
  assert.match(UNKNOWN_SOURCES_SQL, /shipper_hashes AS MATERIALIZED/, 'malformed api_keys must be filtered before decode()');
  assert.match(UNKNOWN_SOURCES_SQL, /WITH RECURSIVE/, 'distinct ids come from the skip scan, not a full-table DISTINCT');
  assert.match(UNKNOWN_SOURCES_SQL, /ids\.n < \$2/, 'the skip scan is bounded');
  assert.match(UNKNOWN_SOURCES_SQL, /created_at >= NOW\(\) - \(\$1 \* INTERVAL '1 hour'\)/, 'aggregation is windowed');
});
