/**
 * recordFinding against a real Postgres: one finding, one alert — however many
 * times the same exposure is seen. Needs the schema from migration 034; when
 * Postgres (or that schema) isn't reachable these tests skip themselves so
 * `npm test` stays green on a machine without a database. Every row created
 * here is removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { findingEventId, recordFinding, type FindingInput } from './findingWriter';
import { MonitoredIdentityModel, type MonitoredIdentity } from '../../models/Exposure';

let dbReady = false;
const createdIdentityIds: number[] = [];
const createdEventIds: string[] = [];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM exposure_findings LIMIT 1');
    dbReady = true;
  } catch {
    dbReady = false;
  }
});

after(async () => {
  if (dbReady) {
    await pool.query('DELETE FROM alerts WHERE event_id = ANY($1)', [createdEventIds]);
    await pool.query('DELETE FROM monitored_identities WHERE id = ANY($1)', [createdIdentityIds]);
  }
  await closePools();
});

const unique = () => crypto.randomBytes(6).toString('hex');

async function makeIdentity(value: string): Promise<MonitoredIdentity> {
  const identity = await MonitoredIdentityModel.create({ kind: 'email', value });
  createdIdentityIds.push(identity.id);
  return identity;
}

function makeInput(identityId: number, fingerprint: string): FindingInput {
  createdEventIds.push(findingEventId('leaked-creds', fingerprint));
  return {
    source: 'leaked-creds',
    identityId,
    eventType: 'breach',
    fingerprint,
    title: 'db-test@siembox.invalid found in Test breach',
    severity: 'high',
    description: 'test finding',
    detail: {
      account: 'db-test@siembox.invalid',
      password: 'must-not-be-stored',
      nested: { api_key: 'nope' },
    },
  };
}

async function countFindings(fingerprint: string): Promise<number> {
  const r = await pool.query(
    'SELECT COUNT(*)::int AS n FROM exposure_findings WHERE fingerprint = $1',
    [fingerprint]
  );
  return r.rows[0].n;
}

async function countAlerts(fingerprint: string): Promise<number> {
  const r = await pool.query('SELECT COUNT(*)::int AS n FROM alerts WHERE event_id = $1', [
    findingEventId('leaked-creds', fingerprint),
  ]);
  return r.rows[0].n;
}

test('first sighting inserts the finding and exactly one alert; a repeat creates no new alert', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 034 is not reachable');
  const identity = await makeIdentity(`db-test-${unique()}@siembox.invalid`);
  const fingerprint = `db-test-${unique()}`;
  const input = makeInput(identity.id, fingerprint);

  const first = await recordFinding(input, { notify: false });
  assert.equal(first.isNew, true);
  assert.equal(first.alertCreated, true);
  assert.ok(first.alertId);

  const second = await recordFinding(input, { notify: false });
  assert.equal(second.isNew, false);
  assert.equal(second.alertCreated, false);
  assert.equal(second.findingId, first.findingId);
  assert.equal(second.alertId, first.alertId);

  assert.equal(await countFindings(fingerprint), 1);
  assert.equal(await countAlerts(fingerprint), 1);

  const finding = (
    await pool.query(
      'SELECT alert_id, detail, first_seen, last_seen FROM exposure_findings WHERE id = $1',
      [first.findingId]
    )
  ).rows[0];
  assert.equal(finding.alert_id, first.alertId);
  assert.ok(new Date(finding.last_seen) >= new Date(finding.first_seen));

  // The privacy scrub applies to both copies of the detail.
  const alert = (
    await pool.query(
      `SELECT rule_id, source, status, severity, matched_data FROM alerts WHERE id = $1`,
      [first.alertId]
    )
  ).rows[0];
  assert.deepEqual(finding.detail, { account: 'db-test@siembox.invalid', nested: {} });
  assert.deepEqual(alert.matched_data, finding.detail);
  assert.deepEqual(
    {
      rule_id: alert.rule_id,
      source: alert.source,
      status: alert.status,
      severity: alert.severity,
    },
    { rule_id: null, source: 'leaked-creds', status: 'new', severity: 'high' }
  );
});

test('a finding that comes back after its identity was deleted re-links its old alert', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 034 is not reachable');
  const value = `db-test-${unique()}@siembox.invalid`;
  const fingerprint = `db-test-${unique()}`;

  const original = await makeIdentity(value);
  const first = await recordFinding(makeInput(original.id, fingerprint), { notify: false });
  await MonitoredIdentityModel.delete(original.id); // cascades the finding; the alert stays
  assert.equal(await countFindings(fingerprint), 0);

  const again = await makeIdentity(value);
  const result = await recordFinding(makeInput(again.id, fingerprint), { notify: false });
  assert.equal(result.isNew, true, 'it is a new finding row');
  assert.equal(result.alertCreated, false, 'but the operator was already alerted');
  assert.equal(result.alertId, first.alertId);
  assert.equal(await countAlerts(fingerprint), 1);
});
