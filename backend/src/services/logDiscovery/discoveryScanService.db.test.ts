/**
 * Discovery-scan ingestion against a real Postgres: a host the matcher or the
 * database can't handle is recorded on the scan and skipped, and the scan still
 * completes with every other host saved -- on the backend-run path
 * (ingestSignals) and the shipper path (ingestShipperDiscovery). Uses TEST-NET-3
 * addresses that can't collide with real discovery rows, and removes every row
 * it creates. When Postgres (or the discovery schema) isn't reachable the DB
 * tests skip themselves. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { query, closePools } from '../../config/database';
import { DiscoveryScanModel } from '../../models/DiscoveryScan';
import { DiscoverySourceModel } from '../../models/DiscoverySource';
import { ingestShipperDiscovery, ingestSignals, normalizeDiscoveredSignals } from './discoveryScanService';
import { DiscoveredSignals, FingerprintEntry } from './types';

const TWO_CN_IP = '203.0.113.31';
const BAD_SIGNALS_IP = '203.0.113.32';
const SINGLE_CN_IP = '203.0.113.33';
const SHIPPER_IP = '203.0.113.34';
const TEST_IPS = [TWO_CN_IP, BAD_SIGNALS_IP, SINGLE_CN_IP, SHIPPER_IP];

const PROXMOX: FingerprintEntry = {
  id: 'proxmox-ve',
  name: 'Proxmox VE',
  category: 'hypervisor',
  security_value: 8,
  signals: { ports: [{ port: 8006, weight: 60 }], http: [], mdns: [], ssdp: [], tls: [{ subject_cn: 'pve', weight: 20 }], mac_oui: [] },
  confidence_floor: 50,
  attack_data_sources: [],
  log_access: [{ method: 'syslog_push', target_port: 514 }],
  onboard_template: 'templates/syslog_source.j2',
  credentials: { required: false, optional: [] },
};

let dbReady = false;
let skipReason = 'DB not checked';
const scanIds: number[] = [];

async function cleanup(): Promise<void> {
  await query(`DELETE FROM discovery_sources WHERE ip_address = ANY($1::inet[])`, [TEST_IPS]).catch(() => {});
}

before(async () => {
  try {
    const r = await query(`SELECT to_regclass('public.discovery_sources') AS s, to_regclass('public.discovery_scans') AS d`);
    if (!r.rows[0]?.s || !r.rows[0]?.d) throw new Error('discovery tables missing — run `npm run migrate`');
    await cleanup();
    dbReady = true;
  } catch (err) {
    skipReason = `DB unavailable: ${err instanceof Error ? err.message : String(err)}`;
  }
});

after(async () => {
  if (dbReady) {
    await cleanup();
    const ids = scanIds.map(String);
    await query(`DELETE FROM application_errors WHERE context->>'scanId' = ANY($1)`, [ids]).catch(() => {});
    await query(`DELETE FROM discovery_scans WHERE id = ANY($1)`, [scanIds]).catch(() => {});
  }
  await closePools().catch(() => {});
});

async function ready(t: TestContext): Promise<boolean> {
  if (!dbReady) {
    t.skip(skipReason);
    return false;
  }
  await cleanup();
  return true;
}

async function newScan(): Promise<number> {
  const scan = await DiscoveryScanModel.create('active', [], null);
  scanIds.push(scan.id);
  return scan.id;
}

function host(ip: string, overrides: Partial<DiscoveredSignals> = {}): DiscoveredSignals {
  return {
    ip,
    open_ports: [8006],
    http_responses: [],
    tls_subjects: [],
    banners: [],
    mdns_services: [],
    ssdp_services: [],
    discovery_methods: ['active_probe'],
    ...overrides,
  };
}

async function sourceAt(ip: string) {
  const rows = await DiscoverySourceModel.findAll();
  return rows.find((r) => r.ip_address === ip) || null;
}

test('normalizeDiscoveredSignals keeps a posted repeated-CN array and drops TLS entries it cannot use', () => {
  const [signals] = normalizeDiscoveredSignals([
    {
      ip: SHIPPER_IP,
      tls_subjects: [
        { port: 8006, subject_cn: ['proxmox.local', 'pve'], san: ['DNS:pve', 3] },
        { port: 443, subject_cn: 'pve' },
        { port: 8443, subject_cn: 12 },
        { subject_cn: 'no-port' },
        'junk',
        null,
      ],
    },
  ]);
  assert.deepEqual(signals.tls_subjects, [
    { port: 8006, subject_cn: ['proxmox.local', 'pve'], san: ['DNS:pve'] },
    { port: 443, subject_cn: 'pve' },
    { port: 8443 },
  ]);
});

test('a scan with one bad host completes, saves the others, and records the failures', async (t) => {
  if (!(await ready(t))) return;
  const scanId = await newScan();

  // A host whose signals blow up the matcher (the next shape it doesn't expect),
  // a two-CN cert that used to, and a host the database rejects.
  const badSignals = host(BAD_SIGNALS_IP);
  Object.defineProperty(badSignals, 'tls_subjects', {
    get() {
      throw new TypeError('simulated: signals in a shape the matcher does not expect');
    },
  });
  const twoCn = host(TWO_CN_IP, { tls_subjects: [{ port: 8006, subject_cn: ['proxmox.local', 'pve'] }] });
  const rejected = host('not-an-ip');

  await ingestSignals(scanId, [badSignals, twoCn, rejected], [PROXMOX]);

  const scan = await DiscoveryScanModel.findById(scanId);
  assert.equal(scan?.status, 'completed');
  assert.equal(scan?.error_message, null);
  const summary = scan?.results_summary as {
    hosts_seen: number;
    hosts_matched: number;
    hosts_failed: number;
    host_errors: Array<{ ip: string; error: string }>;
  };
  assert.equal(summary.hosts_seen, 3);
  assert.equal(summary.hosts_matched, 1);
  assert.equal(summary.hosts_failed, 2);
  assert.deepEqual(
    summary.host_errors.map((e) => e.ip),
    [BAD_SIGNALS_IP, 'not-an-ip']
  );
  assert.match(summary.host_errors[0].error, /simulated/);
  assert.match(summary.host_errors[1].error, /inet/);

  const saved = await sourceAt(TWO_CN_IP);
  assert.equal(saved?.matched_fingerprint_id, 'proxmox-ve');
  assert.equal(saved?.confidence, 80);
  assert.deepEqual(saved?.evidence.matched_signals, ['port 8006', 'tls cn~"pve"']);
  assert.deepEqual(saved?.evidence.tls_subjects, [{ port: 8006, subject_cn: ['proxmox.local', 'pve'] }]);
  assert.equal(await sourceAt(BAD_SIGNALS_IP), null, 'the bad host is reported, not saved');

  // The failure is on the dashboard error log too (written fire-and-forget).
  let logged = 0;
  for (let i = 0; i < 40 && logged === 0; i++) {
    const r = await query(`SELECT COUNT(*)::int AS n FROM application_errors WHERE context->>'scanId' = $1`, [String(scanId)]);
    logged = r.rows[0].n;
    if (logged === 0) await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(logged, 1);
});

test('a single-CN cert is still stored as a plain string (existing evidence shape)', async (t) => {
  if (!(await ready(t))) return;
  const scanId = await newScan();

  await ingestSignals(scanId, [host(SINGLE_CN_IP, { tls_subjects: [{ port: 8006, subject_cn: 'pve' }] })], [PROXMOX]);

  const scan = await DiscoveryScanModel.findById(scanId);
  assert.equal(scan?.status, 'completed');
  assert.deepEqual(scan?.results_summary, { hosts_seen: 1, hosts_matched: 1, hosts_failed: 0 });
  const saved = await sourceAt(SINGLE_CN_IP);
  assert.deepEqual(saved?.evidence.tls_subjects, [{ port: 8006, subject_cn: 'pve' }]);
  assert.equal(saved?.matched_fingerprint_id, 'proxmox-ve');
});

test('shipper path: a two-CN cert posted as a raw array completes and matches the shipped library', async (t) => {
  if (!(await ready(t))) return;
  const scanId = await newScan();

  // What a shipper's discovery agent built before this fix posts: Node's raw
  // getPeerCertificate() value.
  await ingestShipperDiscovery(scanId, [
    {
      ip: SHIPPER_IP,
      open_ports: [8006],
      tls_subjects: [{ port: 8006, subject_cn: ['proxmox.local', 'pve'], san: ['DNS:proxmox.local', 'DNS:pve'] }],
      discovery_methods: ['active_probe'],
    },
  ]);

  const scan = await DiscoveryScanModel.findById(scanId);
  assert.equal(scan?.status, 'completed');
  assert.equal((scan?.results_summary as Record<string, unknown>).hosts_matched, 1);
  const saved = await sourceAt(SHIPPER_IP);
  assert.equal(saved?.matched_fingerprint_id, 'proxmox-ve');
  assert.ok((saved?.evidence.matched_signals as string[]).includes('tls cn~"pve"'));
});
