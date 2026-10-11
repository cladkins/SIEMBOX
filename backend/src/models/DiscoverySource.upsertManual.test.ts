/**
 * Real-DB round-trip for DiscoverySourceModel.upsertManual — the one piece of the
 * manual-source feature whose behaviour is SQL (the INSERT ... ON CONFLICT, the
 * scan-less NULL last_scan_id, the un-ignore CASE). Uses a TEST-NET-2 address that
 * cannot collide with a real discovery row, and cleans up after itself.
 *
 * The rest of the suite is DB-free, so this guards on connectivity: if Postgres
 * isn't reachable or the table hasn't been migrated, every assertion is skipped
 * rather than failing. With a live DB (DB_HOST/DB_NAME/DB_USER/DB_PASSWORD) it
 * runs for real. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { query, closePools } from '../config/database';
import { DiscoverySourceModel } from './DiscoverySource';

const TEST_IP = '198.51.100.77'; // TEST-NET-2 (RFC 5737) — never a real host

let dbReady = false;
let skipReason = 'DB not checked';

async function cleanup(): Promise<void> {
  await query(`DELETE FROM discovery_sources WHERE ip_address = $1`, [TEST_IP]).catch(() => {});
}

before(async () => {
  try {
    const r = await query(`SELECT to_regclass('public.discovery_sources') AS t`);
    if (!r.rows[0]?.t) throw new Error('discovery_sources table missing — run `npm run migrate`');
    await cleanup();
    dbReady = true;
  } catch (err) {
    skipReason = `DB unavailable: ${err instanceof Error ? err.message : String(err)}`;
  }
});

after(async () => {
  if (dbReady) await cleanup();
  await closePools().catch(() => {});
});

async function ready(t: TestContext): Promise<boolean> {
  if (!dbReady) {
    t.skip(skipReason);
    return false;
  }
  await cleanup(); // each test starts from a clean slate for TEST_IP
  return true;
}

test('upsertManual inserts a scan-less, confirmed row with port/scheme in evidence', async (t) => {
  if (!(await ready(t))) return;

  const row = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    hostname: 'authentik-box',
    fingerprint_id: 'authentik',
    target_port: 9443,
    tls: true,
    security_value: 9,
  });

  assert.equal(row.ip_address, TEST_IP);
  assert.equal(row.hostname, 'authentik-box');
  assert.equal(row.matched_fingerprint_id, 'authentik');
  assert.equal(row.confidence, 100);
  assert.equal(row.is_guess, false);
  assert.equal(row.status, 'confirmed');
  assert.equal(row.last_scan_id, null, 'manual rows never came from a scan');
  assert.equal(row.security_value, 9);
  assert.deepEqual(row.open_ports, [9443]);
  assert.deepEqual(row.evidence, { manual: true, target_port: 9443, tls: true });
});

test('upsertManual ON CONFLICT refreshes fingerprint/port/evidence and un-ignores a dismissed host', async (t) => {
  if (!(await ready(t))) return;

  const first = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    hostname: 'box',
    fingerprint_id: 'authentik',
    target_port: 9443,
    tls: true,
    security_value: 9,
  });
  await DiscoverySourceModel.setStatus(first.id, 'ignored');

  // Re-add the same IP as a different device type, custom port, http, and no hostname.
  const second = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    hostname: null,
    fingerprint_id: 'pihole',
    target_port: 8080,
    tls: false,
    security_value: 8,
  });

  assert.equal(second.id, first.id, 'upsert keyed on ip_address — same row, not a duplicate');
  assert.equal(second.status, 'confirmed', 'an ignored host is un-ignored back to confirmed');
  assert.equal(second.matched_fingerprint_id, 'pihole');
  assert.deepEqual(second.open_ports, [8080]);
  assert.deepEqual(second.evidence, { manual: true, target_port: 8080, tls: false });
  assert.equal(second.hostname, 'box', 'COALESCE keeps the existing hostname when null is passed');
});

test('upsertManual ON CONFLICT leaves a non-ignored status untouched (onboarded stays onboarded)', async (t) => {
  if (!(await ready(t))) return;

  const first = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    fingerprint_id: 'authentik',
    target_port: 9443,
    tls: true,
    security_value: 9,
  });
  await DiscoverySourceModel.setStatus(first.id, 'onboarded');

  const second = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    fingerprint_id: 'authentik',
    target_port: 9443,
    tls: true,
    security_value: 9,
  });

  assert.equal(second.status, 'onboarded', 'a user who already onboarded the source keeps that state');
});

test('deleteById removes the row', async (t) => {
  if (!(await ready(t))) return;

  const row = await DiscoverySourceModel.upsertManual({
    ip_address: TEST_IP,
    fingerprint_id: 'pihole',
    target_port: 80,
    tls: false,
    security_value: 8,
  });
  assert.equal(await DiscoverySourceModel.deleteById(row.id), true);
  assert.equal(await DiscoverySourceModel.findById(row.id), null);
  assert.equal(await DiscoverySourceModel.deleteById(row.id), false, 'deleting an absent row returns false');
});
