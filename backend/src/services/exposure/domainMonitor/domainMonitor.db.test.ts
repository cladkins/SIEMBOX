/**
 * The domain monitor against a real Postgres (migration 035): baselines upsert
 * per (domain, collector) and cascade with their domain; due-selection and
 * run bookkeeping follow next_run_at; and a run through the real store records
 * domain-monitor findings with exactly one alert per fingerprint. The
 * collectors are fakes — no network. When Postgres (or the schema) isn't
 * reachable these tests skip themselves; every row created is removed again.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../../config/database';
import {
  DomainBaselineModel,
  WatchedDomainModel,
  type WatchedDomain,
} from '../../../models/Exposure';
import { findingEventId } from '../findingWriter';
import { runDomainNow } from './domainMonitorService';
import { domainFinding, fingerprint, type Collector, type CollectorName } from './types';

let dbReady = false;
let monitorEnabled = false;
const createdDomainIds: number[] = [];
const createdEventIds: string[] = [];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM domain_baselines LIMIT 1');
    await pool.query('SELECT last_summary FROM watched_domains LIMIT 1');
    dbReady = true;
    const r = await pool.query(
      `SELECT value FROM system_settings WHERE key = 'exposure_domain_monitor_enabled'`
    );
    monitorEnabled = (r.rows[0]?.value ?? 'true') === 'true';
  } catch {
    dbReady = false;
  }
});

after(async () => {
  if (dbReady) {
    await pool.query('DELETE FROM alerts WHERE event_id = ANY($1)', [createdEventIds]);
    await pool.query('DELETE FROM watched_domains WHERE id = ANY($1)', [createdDomainIds]);
  }
  await closePools();
});

async function makeDomain(fields: Partial<WatchedDomain> = {}): Promise<WatchedDomain> {
  const domain = await WatchedDomainModel.create({
    domain: `dm-test-${crypto.randomBytes(5).toString('hex')}.siembox-test.net`,
    scope: fields.scope ?? 'own',
    interval_minutes: fields.interval_minutes,
  });
  createdDomainIds.push(domain.id);
  return domain;
}

test('baselines: one row per (domain, collector), updated in place, removed with the domain', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 035 is not reachable');
  const domain = await makeDomain();
  await DomainBaselineModel.upsert(domain.id, 'dns', { v: 1, records: { A: ['192.0.2.1'] } });
  await DomainBaselineModel.upsert(domain.id, 'dns', { v: 1, records: { A: ['192.0.2.2'] } });
  await DomainBaselineModel.upsert(domain.id, 'rdap', { v: 1, nameservers: ['a.ns.example.net'] });
  const rows = await DomainBaselineModel.findByDomain(domain.id);
  assert.deepEqual([...rows.keys()].sort(), ['dns', 'rdap']);
  assert.deepEqual(rows.get('dns')?.snapshot, { v: 1, records: { A: ['192.0.2.2'] } });

  await WatchedDomainModel.delete(domain.id);
  const left = await pool.query(
    'SELECT COUNT(*)::int AS n FROM domain_baselines WHERE domain_id = $1',
    [domain.id]
  );
  assert.equal(left.rows[0].n, 0, 'cascade');
});

test('scheduling: due = enabled and next_run_at passed; markRun reschedules; a new interval counts from the last check', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 035 is not reachable');
  const domain = await makeDomain();
  const dueIds = async () => (await WatchedDomainModel.findDue(10_000)).map((d) => d.id);
  assert.ok((await dueIds()).includes(domain.id), 'never run: due');

  await WatchedDomainModel.markRun(domain.id, {
    status: 'ok',
    error: null,
    nextRunMinutes: 1440,
    summary: { collectors: {} },
  });
  assert.ok(!(await dueIds()).includes(domain.id), 'just ran: not due');
  let row = (await WatchedDomainModel.findById(domain.id)) as WatchedDomain;
  const gap = Date.parse(row.next_run_at as string) - Date.parse(row.last_checked_at as string);
  assert.equal(Math.round(gap / 60_000), 1440);
  assert.deepEqual(
    [row.last_status, row.last_error, row.last_summary],
    ['ok', null, { collectors: {} }]
  );

  row = (await WatchedDomainModel.update(domain.id, { interval_minutes: 60 })) as WatchedDomain;
  const newGap = Date.parse(row.next_run_at as string) - Date.parse(row.last_checked_at as string);
  assert.equal(Math.round(newGap / 60_000), 60);

  await pool.query(
    `UPDATE watched_domains SET next_run_at = NOW() - INTERVAL '1 minute' WHERE id = $1`,
    [domain.id]
  );
  assert.ok((await dueIds()).includes(domain.id), 'overdue: due');
  await WatchedDomainModel.update(domain.id, { enabled: false });
  assert.ok(!(await dueIds()).includes(domain.id), 'disabled: never due');

  await WatchedDomainModel.markRun(domain.id, {
    status: 'error',
    error: 'x'.repeat(2_000),
    nextRunMinutes: 60,
    summary: {},
  });
  row = (await WatchedDomainModel.findById(domain.id)) as WatchedDomain;
  assert.equal(row.last_error?.length, 500, 'errors are capped');
});

test('run now through the real store: findings, one alert per fingerprint, baselines and bookkeeping', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 035 is not reachable');
  if (!monitorEnabled) return t.skip('exposure_domain_monitor_enabled is off in this database');
  const domain = await makeDomain();
  const fp = fingerprint('db-test', domain.domain, 'NS');
  createdEventIds.push(findingEventId('domain-monitor', fp));

  let run = 0;
  const snapshotOnly =
    (name: CollectorName): Collector =>
    async () => ({
      snapshot: { v: 1, name, run },
      findings: [],
      status: run === 1 ? 'baseline' : 'ok',
      note: name,
    });
  const collectors: Record<CollectorName, Collector> = {
    dns: async (ctx) => ({
      snapshot: { v: 1, run },
      findings:
        run === 1
          ? []
          : [
              domainFinding({
                domainId: ctx.domain.id,
                eventType: 'dns_drift',
                fingerprint: fp,
                severity: 'low',
                title: `Nameserver (NS) records changed for ${ctx.domain.domain}`,
                description: 'db test',
                detail: {
                  collector: 'dns',
                  record_type: 'NS',
                  before: ['a'],
                  after: ['b'],
                  token: 'scrubbed',
                },
              }),
            ],
      status: run === 1 ? 'baseline' : 'ok',
      note: 'dns',
    }),
    rdap: snapshotOnly('rdap'),
    lookalike: snapshotOnly('lookalike'),
    ct: snapshotOnly('ct'),
  };

  for (run = 1; run <= 3; run++) {
    const result = await runDomainNow(domain.id, { collectors });
    assert.equal(result.kind, 'ok');
    if (result.kind === 'ok')
      assert.equal(result.summary.new_findings, run === 2 ? 1 : 0, `run ${run}`);
  }

  const baselines = await DomainBaselineModel.findByDomain(domain.id);
  assert.deepEqual([...baselines.keys()].sort(), ['ct', 'dns', 'lookalike', 'rdap']);
  assert.deepEqual(baselines.get('dns')?.snapshot, { v: 1, run: 3 });

  const findings = await pool.query(
    `SELECT source, domain_id, event_type, severity, alert_id, detail FROM exposure_findings WHERE fingerprint = $1`,
    [fp]
  );
  assert.equal(findings.rowCount, 1);
  const finding = findings.rows[0];
  assert.deepEqual(
    [finding.source, finding.domain_id, finding.event_type, finding.severity],
    ['domain-monitor', domain.id, 'dns_drift', 'low']
  );
  assert.ok(finding.alert_id, 'linked to its alert');
  assert.equal(finding.detail.token, undefined, 'the privacy scrub ran');
  const alerts = await pool.query(`SELECT source FROM alerts WHERE event_id = $1`, [
    findingEventId('domain-monitor', fp),
  ]);
  assert.deepEqual(
    alerts.rows,
    [{ source: 'domain-monitor' }],
    'exactly one alert across three runs'
  );

  const row = (await WatchedDomainModel.findById(domain.id)) as WatchedDomain;
  assert.equal(row.last_status, 'ok');
  const summary = row.last_summary as {
    trigger: string;
    collectors: Record<string, { status: string }>;
  };
  assert.equal(summary.trigger, 'manual');
  assert.equal(summary.collectors.dns.status, 'ok');
});
