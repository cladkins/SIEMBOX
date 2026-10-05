/**
 * Tests for the direct-syslog-sources list. The shared cache/transaction
 * plumbing (snapshotCache.ts) is covered in depth by unknownSources.test.ts;
 * these cover what is specific here: which rows count as "direct syslog", row
 * mapping and list capping, the sender cap warning, and that the service is
 * wired through the shared cache. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DIRECT_SYSLOG_SQL,
  createDirectSyslogSourcesService,
  createDirectSyslogDbFetcher,
  toDirectSyslogSource,
  DirectSyslogSourceRow,
} from './directSyslogSources';

const OPTS = { windowHours: 24, timeoutMs: 8000, ttlMs: 30_000, failureCooldownMs: 20_000, maxSources: 500, maxListItems: 3 };

function harness(rowsByCall: Array<DirectSyslogSourceRow[] | Error>) {
  let t = 0;
  const calls: Array<[number, number, number]> = [];
  const logs = { warn: [] as string[], error: [] as string[] };
  const service = createDirectSyslogSourcesService(
    {
      fetchRows: async (w, m, to) => {
        calls.push([w, m, to]);
        const next = rowsByCall.shift() ?? [];
        if (next instanceof Error) throw next;
        return next;
      },
      now: () => t,
      log: { warn: (m) => logs.warn.push(m), error: (m) => logs.error.push(m) },
    },
    OPTS
  );
  return { service, calls, logs, advance: (ms: number) => (t += ms) };
}

const row = (over: Partial<DirectSyslogSourceRow> = {}): DirectSyslogSourceRow => ({
  source_ip: '192.168.1.1',
  log_count: '42',
  first_seen: '2026-10-05T10:00:00Z',
  last_seen: '2026-10-05T11:00:00Z',
  hostnames: ['gw'],
  app_names: ['kernel'],
  ...over,
});

test('the SQL selects exactly "no shipper, not API-polled" rows, windowed and bounded', () => {
  assert.match(DIRECT_SYSLOG_SQL, /shipper_id IS NULL/, 'logs from a shipper (registered or not) are not direct syslog');
  assert.match(DIRECT_SYSLOG_SQL, /discovery_source_id IS NULL/, 'API-polled logs have their own section');
  assert.match(DIRECT_SYSLOG_SQL, /created_at >= NOW\(\) - \(\$1 \* INTERVAL '1 hour'\)/, 'aggregation is windowed');
  assert.match(DIRECT_SYSLOG_SQL, /LIMIT \$2/, 'number of senders is bounded');
  assert.match(DIRECT_SYSLOG_SQL, /GROUP BY source_ip, hostname, app_name/, 'two-stage aggregation (avoids the big sort)');
});

test('maps rows: bigint count -> number, NULL list entries dropped, params forwarded', async () => {
  const h = harness([[row({ log_count: '1234', hostnames: ['a', null, 'b'], app_names: [null] })]]);
  const out = await h.service.get();
  assert.deepEqual(h.calls, [[24, 500, 8000]]);
  assert.deepEqual(out, [
    {
      source_ip: '192.168.1.1',
      log_count: 1234,
      first_seen: '2026-10-05T10:00:00Z',
      last_seen: '2026-10-05T11:00:00Z',
      hostnames: ['a', 'b'],
      hostname_count: 2,
      app_names: [],
      app_name_count: 0,
    },
  ]);
});

test('long hostname/app lists are capped, but the true totals are reported', () => {
  const out = toDirectSyslogSource(row({ hostnames: ['h1', 'h2', 'h3', 'h4', 'h5'], app_names: ['a1', 'a2'] }), 3);
  assert.deepEqual(out.hostnames, ['h1', 'h2', 'h3']);
  assert.equal(out.hostname_count, 5);
  assert.deepEqual(out.app_names, ['a1', 'a2']);
  assert.equal(out.app_name_count, 2);
});

test('null arrays from the database are treated as empty', () => {
  const out = toDirectSyslogSource(row({ hostnames: null, app_names: null }));
  assert.deepEqual([out.hostnames, out.hostname_count, out.app_names, out.app_name_count], [[], 0, [], 0]);
});

test('warns when the sender cap is hit', async () => {
  const many = Array.from({ length: 500 }, (_, i) => row({ source_ip: `10.0.${Math.floor(i / 256)}.${i % 256}` }));
  const h = harness([many]);
  await h.service.get();
  assert.equal(h.logs.warn.length, 1);
  assert.match(h.logs.warn[0], /cap of 500 senders/);
});

test('goes through the shared cache: one query inside the TTL, re-query after it', async () => {
  const h = harness([[row()], [row({ source_ip: '10.0.0.9' })]]);
  await h.service.get();
  await h.service.get();
  assert.equal(h.calls.length, 1);
  h.advance(OPTS.ttlMs);
  const out = await h.service.get();
  assert.equal(h.calls.length, 2);
  assert.equal(out[0].source_ip, '10.0.0.9');
});

test('a failed refresh serves the previous result rather than an error', async () => {
  const h = harness([[row()], new Error('canceling statement due to statement timeout')]);
  await h.service.get();
  h.advance(OPTS.ttlMs);
  const out = await h.service.get();
  assert.equal(out[0].source_ip, '192.168.1.1');
  assert.match(h.logs.warn[0], /^direct-syslog-sources: refresh failed/);
});

test('DB fetcher runs the direct-syslog SQL read-only with a LOCAL timeout and bound params', async () => {
  const seen: Array<{ text: string; params?: unknown[] }> = [];
  let released = false;
  const fetchRows = createDirectSyslogDbFetcher(async () => ({
    query: async (text: string, params?: unknown[]) => {
      seen.push({ text, params });
      return { rows: text === DIRECT_SYSLOG_SQL ? [row()] : [] };
    },
    release: () => {
      released = true;
    },
  }));
  const rows = await fetchRows(24, 500, 8000);
  assert.equal(rows.length, 1);
  assert.deepEqual(
    seen.map((s) => s.text.trim().split('\n')[0].trim()),
    ['BEGIN READ ONLY', "SELECT set_config('statement_timeout', $1, true)", 'WITH g AS (', 'COMMIT']
  );
  assert.deepEqual(seen[1].params, ['8000']);
  assert.deepEqual(seen[2].params, [24, 500]);
  assert.equal(released, true);
});
