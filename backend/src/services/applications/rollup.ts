/**
 * The application inventory rollup (migration 048). jobs/applicationInventory.ts
 * runs it every two minutes on the main pool; ingestion is untouched (no
 * index, trigger or code on the ingest path), so the inventory trails the logs
 * by a few minutes. Modelled on the Context Graph's log-edge rollup
 * (services/graph/logEdgeRollup.ts).
 *
 * Each run:
 *   1. Signatures: the catalog's (appCatalog.ts, with its fallbacks), every
 *      regex through the safety gate, compiled into an AppIndex. When the set
 *      changes it is stored in application_signatures (names for the page, and
 *      the fallback while the catalog is unreachable).
 *   2. Logs: an id cursor over parsed_logs, as the graph rollup's: the bound is
 *      the newest log created more than LAG ago (every id below it has
 *      committed); the first run starts BACKFILL days back; batches of up to
 *      BATCH_SIZE ids, each one transaction that locks the state row (FOR
 *      UPDATE: a second runner waits, then takes the next range), aggregates
 *      the batch in SQL to distinct (program, host), (parser, host),
 *      (user agent, client) and (domain, client) groups, matches those in
 *      JavaScript, upserts the inventory and the unmatched list and moves the
 *      cursor, then commits. The cursor and the counts commit together, so a
 *      crash replays a batch and counts nothing twice. A statement timeout
 *      halves the batch. Between batches it rests PAUSE_RATIO times as long as
 *      the batch took, and it stops after RUN_BUDGET_MS of database time.
 *   3. Snapshots: the small tables are read whole every run (asset_services,
 *      shipper_containers, open EDR package findings, edr_agents' OS) and their
 *      inventory rows replaced: a row that is no longer in its source is
 *      removed at once, so an upgraded container or package does not show two
 *      versions until retention.
 *   4. Vulnerability links: rebuilt from the inventory (exact: an open EDR
 *      finding for a signature's package; best effort: an open finding on an
 *      asset where the application was seen whose title or template names it).
 *   5. At most hourly, prune rows not seen for the retention
 *      (application_inventory_retention_days, 30 by default) and cap the
 *      unmatched list at UNMATCHED_CAP values per source.
 */
import * as crypto from 'crypto';
import { batchedDelete } from '../../utils/batchDelete';
import { isStatementTimeout } from '../shippers/snapshotCache';
import { stableStringify } from '../parser/catalogService';
import { APP_SCHEMA, type AppSignature } from './appFormat';
import { AppIndex, cleanDomain, parseImageRef, userAgentProduct, type AppMatch, MAX_MATCH_INPUT } from './matchers';
import { fetchAppCatalog, gateSignatureRegexes, type AppCatalog, type RegexGateResult } from './appCatalog';

export const BATCH_SIZE = 2_500;
export const MIN_BATCH_SIZE = 1_000;
export const LAG = '2 minutes';
export const RUN_BUDGET_MS = 15_000;
export const BATCH_STATEMENT_TIMEOUT_MS = 15_000;
export const PRUNE_EVERY_MS = 60 * 60_000;
/**
 * Rest between batches, as a multiple of the batch's own time. Measured on a
 * 4-core box with 300,000 logs of backlog: at 3 (the graph rollup's) syslog
 * ingestion ran about 10% slower while a drain ran back to back; at 6, with
 * batches of 2,500, within run-to-run noise (about 28,000 logs a second of
 * database time, 4,000 a second with the rests).
 */
export const PAUSE_RATIO = 6;
export const UNMATCHED_CAP = 500;
/** Rows a snapshot source reads at most (asset_services, shipper_containers, EDR findings). */
export const SNAPSHOT_LIMIT = 200_000;

export const SOURCES = ['syslog_program', 'parser', 'service_scan', 'container', 'edr_package', 'os', 'user_agent', 'dns'] as const;
export type InventorySource = (typeof SOURCES)[number];
export const SNAPSHOT_SOURCES: InventorySource[] = ['service_scan', 'container', 'edr_package', 'os'];
export const NETWORK_SOURCES: InventorySource[] = ['user_agent', 'dns'];

export interface RollupClient {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[]; rowCount?: number | null }>;
  release(err?: Error | boolean): void;
}
type Q = (sql: string, params?: unknown[]) => Promise<{ rows: any[]; rowCount?: number | null }>;

export interface InventorySettings {
  enabled: boolean;
  retentionDays: number;
  backfillDays: number;
}
export const DEFAULT_INVENTORY_SETTINGS: InventorySettings = { enabled: true, retentionDays: 30, backfillDays: 7 };
const SETTING_KEYS = {
  application_inventory_enabled: 'enabled',
  application_inventory_retention_days: 'retentionDays',
  application_inventory_backfill_days: 'backfillDays',
} as const;

export async function readInventorySettings(q: Q): Promise<InventorySettings> {
  const { rows } = await q(`SELECT key, value FROM system_settings WHERE key = ANY($1::text[])`, [Object.keys(SETTING_KEYS)]);
  const out: InventorySettings = { ...DEFAULT_INVENTORY_SETTINGS };
  for (const row of rows as Array<{ key: keyof typeof SETTING_KEYS; value: string | null }>) {
    const field = SETTING_KEYS[row.key];
    if (!field) continue;
    if (field === 'enabled') out.enabled = row.value !== 'false';
    else {
      const n = Number.parseInt(String(row.value ?? ''), 10);
      if (Number.isFinite(n) && n >= 0) out[field] = n;
    }
  }
  if (out.retentionDays < 1) out.retentionDays = 1;
  return out;
}

/** One inventory row as the upserts take it. */
export interface InventoryRow {
  app_id: string;
  loc_type: 'host' | 'asset' | 'shipper' | 'client';
  loc_key: string;
  source: InventorySource;
  version: string;
  events: number;
  first_seen: Date;
  last_seen: Date;
  evidence: Record<string, unknown>;
}

export interface UnmatchedRow {
  source: 'syslog_program' | 'container' | 'user_agent';
  value: string;
  events: number;
  locations: number;
  first_seen: Date;
  last_seen: Date;
  sample_location: string | null;
  sample: string | null;
}

const rowKey = (r: Pick<InventoryRow, 'app_id' | 'loc_type' | 'loc_key' | 'source' | 'version'>) =>
  `${r.app_id}\u0000${r.loc_type}\u0000${r.loc_key}\u0000${r.source}\u0000${r.version}`;

/** Accumulates rows by key: events add, first/last widen, the latest evidence wins. */
export class RowSet {
  readonly rows = new Map<string, InventoryRow>();
  add(r: InventoryRow): void {
    const k = rowKey(r);
    const prev = this.rows.get(k);
    if (!prev) {
      this.rows.set(k, { ...r });
      return;
    }
    prev.events += r.events;
    if (r.first_seen < prev.first_seen) prev.first_seen = r.first_seen;
    if (r.last_seen >= prev.last_seen) {
      prev.last_seen = r.last_seen;
      prev.evidence = r.evidence;
    }
  }
  addMatches(matches: AppMatch[], base: Omit<InventoryRow, 'app_id' | 'version'>): void {
    for (const m of matches) this.add({ ...base, app_id: m.appId, version: m.version ?? '' });
  }
  get size(): number {
    return this.rows.size;
  }
  list(): InventoryRow[] {
    return [...this.rows.values()];
  }
}

export class UnmatchedSet {
  readonly rows = new Map<string, UnmatchedRow & { locs: Set<string> }>();
  add(source: UnmatchedRow['source'], value: string, n: number, first: Date, last: Date, location: string | null, sample: string | null): void {
    const v = value.slice(0, 200);
    if (!v) return;
    const k = `${source}\u0000${v}`;
    const prev = this.rows.get(k);
    if (!prev) {
      this.rows.set(k, { source, value: v, events: n, locations: 1, first_seen: first, last_seen: last, sample_location: location, sample: sample?.slice(0, MAX_MATCH_INPUT) ?? null, locs: new Set(location ? [location] : []) });
      return;
    }
    prev.events += n;
    if (first < prev.first_seen) prev.first_seen = first;
    if (last > prev.last_seen) prev.last_seen = last;
    if (location) prev.locs.add(location);
    prev.locations = Math.max(1, prev.locs.size);
  }
  list(): UnmatchedRow[] {
    return [...this.rows.values()].map(({ locs: _locs, ...r }) => r);
  }
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/**
 * One batch of logs, aggregated: parsed_logs ids ($1, $2], their raw logs
 * bounded by the batch's raw-id range ($3, $4). `seen` is converted to
 * timestamptz in the session time zone, which is how created_at was filled.
 *
 *   program  raw_logs.app_name on the logging host (header hostname, else the sender IP)
 *   parser   the parser that matched, on the logging host
 *   ua       parsed_data.user_agent by client (source_ip when it is not the
 *            sender: fieldNormalizer fills source_ip with the sender when the
 *            parser found no IP)
 *   dns      the queried name of a DNS log (event_type dns*): parsed_data.domain,
 *            else .query / .host (Pi-hole's JSON export maps domain to host)
 */
export const LOG_BATCH_SQL = `
  WITH src AS MATERIALIZED (
    SELECT pl.created_at::timestamptz AS seen, pl.parser_id, pl.raw_log_id,
           graph_ip(pl.parsed_data->>'source_ip')   AS actor,
           graph_ip(pl.parsed_data->>'observer_ip') AS observer,
           left(COALESCE(pl.parsed_data->>'user_agent', pl.parsed_data->>'http_user_agent'), ${MAX_MATCH_INPUT}) AS ua,
           CASE WHEN pl.event_type ILIKE 'dns%'
                THEN graph_domain(left(COALESCE(pl.parsed_data->>'domain', pl.parsed_data->>'query', pl.parsed_data->>'host'), 253)) END AS dom,
           lower(btrim(rl.app_name)) AS prog,
           COALESCE(graph_log_host(rl.hostname), graph_ip(rl.source_ip)) AS host,
           graph_ip(rl.source_ip) AS sender
      FROM parsed_logs pl
      LEFT JOIN raw_logs rl ON rl.id = pl.raw_log_id AND rl.id BETWEEN $3 AND $4
     WHERE pl.id > $1 AND pl.id <= $2
  )
  SELECT 'program' AS kind, prog AS a, host AS b, count(*)::int AS n, min(seen) AS f, max(seen) AS l, max(raw_log_id) AS sample
    FROM src WHERE prog IS NOT NULL AND prog <> '' AND host IS NOT NULL GROUP BY prog, host
  UNION ALL
  SELECT 'parser', parser_id::text, host, count(*)::int, min(seen), max(seen), max(raw_log_id)
    FROM src WHERE parser_id IS NOT NULL AND host IS NOT NULL GROUP BY parser_id, host
  UNION ALL
  SELECT 'ua', ua, actor, count(*)::int, min(seen), max(seen), max(raw_log_id)
    FROM src WHERE parser_id IS NOT NULL AND ua IS NOT NULL AND ua <> '' AND ua <> '-' AND actor IS NOT NULL
               AND actor IS DISTINCT FROM observer AND actor IS DISTINCT FROM sender
   GROUP BY ua, actor
  UNION ALL
  SELECT 'dns', dom, actor, count(*)::int, min(seen), max(seen), max(raw_log_id)
    FROM src WHERE parser_id IS NOT NULL AND dom IS NOT NULL AND actor IS NOT NULL AND actor IS DISTINCT FROM observer
   GROUP BY dom, actor`;

const UPSERT_LOG_ROWS_SQL = `
  INSERT INTO application_inventory AS t (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence)
  SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[], $7::timestamptz[], $8::timestamptz[], $9::jsonb[])
  ON CONFLICT (app_id, loc_type, loc_key, source, version) DO UPDATE
     SET events = t.events + EXCLUDED.events,
         first_seen = LEAST(t.first_seen, EXCLUDED.first_seen),
         last_seen = GREATEST(t.last_seen, EXCLUDED.last_seen),
         evidence = CASE WHEN EXCLUDED.last_seen >= t.last_seen THEN EXCLUDED.evidence ELSE t.evidence END`;

const UPSERT_SNAPSHOT_ROWS_SQL = `
  INSERT INTO application_inventory AS t (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence)
  SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[], $7::timestamptz[], $8::timestamptz[], $9::jsonb[])
  ON CONFLICT (app_id, loc_type, loc_key, source, version) DO UPDATE
     SET events = EXCLUDED.events,
         first_seen = LEAST(t.first_seen, EXCLUDED.first_seen),
         last_seen = GREATEST(t.last_seen, EXCLUDED.last_seen),
         evidence = EXCLUDED.evidence`;

/** Remove snapshot-source rows the current snapshot does not have. */
const DELETE_STALE_SNAPSHOT_SQL = `
  DELETE FROM application_inventory i
   WHERE i.source = ANY($1::text[])
     AND NOT EXISTS (
       SELECT 1 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS k(app_id, loc_type, loc_key, source, version)
        WHERE k.app_id = i.app_id AND k.loc_type = i.loc_type AND k.loc_key = i.loc_key AND k.source = i.source AND k.version = i.version)`;

const UPSERT_UNMATCHED_LOG_SQL = `
  INSERT INTO application_unmatched AS t (source, value, events, locations, first_seen, last_seen, sample_location, sample)
  SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[], $4::int[], $5::timestamptz[], $6::timestamptz[], $7::text[], $8::text[])
  ON CONFLICT (source, value) DO UPDATE
     SET events = t.events + EXCLUDED.events, locations = GREATEST(t.locations, EXCLUDED.locations),
         first_seen = LEAST(t.first_seen, EXCLUDED.first_seen), last_seen = GREATEST(t.last_seen, EXCLUDED.last_seen),
         sample_location = COALESCE(EXCLUDED.sample_location, t.sample_location), sample = COALESCE(EXCLUDED.sample, t.sample)`;

const REPLACE_UNMATCHED_SNAPSHOT_SQL = `
  INSERT INTO application_unmatched AS t (source, value, events, locations, first_seen, last_seen, sample_location, sample)
  SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[], $4::int[], $5::timestamptz[], $6::timestamptz[], $7::text[], $8::text[])
  ON CONFLICT (source, value) DO UPDATE
     SET events = EXCLUDED.events, locations = EXCLUDED.locations,
         first_seen = LEAST(t.first_seen, EXCLUDED.first_seen), last_seen = GREATEST(t.last_seen, EXCLUDED.last_seen),
         sample_location = EXCLUDED.sample_location, sample = EXCLUDED.sample`;

export const UPPER_BOUND_SQL = `SELECT id FROM parsed_logs WHERE created_at < NOW() - $1::interval ORDER BY created_at DESC LIMIT 1`;
export const BACKFILL_START_SQL = `SELECT id FROM parsed_logs WHERE created_at >= NOW() - $1::int * interval '1 day' ORDER BY created_at ASC LIMIT 1`;

function inventoryParams(rows: InventoryRow[]): unknown[] {
  return [
    rows.map((r) => r.app_id),
    rows.map((r) => r.loc_type),
    rows.map((r) => r.loc_key),
    rows.map((r) => r.source),
    rows.map((r) => r.version),
    rows.map((r) => r.events),
    rows.map((r) => r.first_seen.toISOString()),
    rows.map((r) => r.last_seen.toISOString()),
    rows.map((r) => JSON.stringify(r.evidence)),
  ];
}

function unmatchedParams(rows: UnmatchedRow[]): unknown[] {
  return [
    rows.map((r) => r.source),
    rows.map((r) => r.value),
    rows.map((r) => r.events),
    rows.map((r) => r.locations),
    rows.map((r) => r.first_seen.toISOString()),
    rows.map((r) => r.last_seen.toISOString()),
    rows.map((r) => r.sample_location),
    rows.map((r) => r.sample),
  ];
}

const UPSERT_CHUNK = 5_000;
async function upsertRows(client: RollupClient, sql: string, rows: InventoryRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += UPSERT_CHUNK) await client.query(sql, inventoryParams(rows.slice(i, i + UPSERT_CHUNK)));
}
async function upsertUnmatched(client: RollupClient, sql: string, rows: UnmatchedRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += UPSERT_CHUNK) await client.query(sql, unmatchedParams(rows.slice(i, i + UPSERT_CHUNK)));
}

// ---------------------------------------------------------------------------
// Matching a batch (pure: tested without a database)
// ---------------------------------------------------------------------------

export interface LogGroup {
  kind: 'program' | 'parser' | 'ua' | 'dns';
  a: string;
  b: string;
  n: number;
  f: Date;
  l: Date;
  sample: number | string | null;
}

/** Turn one batch's aggregated groups into inventory and unmatched rows. Pure. */
export function matchLogGroups(groups: LogGroup[], index: AppIndex, parserNames: Map<string, string>): { rows: RowSet; unmatched: UnmatchedSet } {
  const rows = new RowSet();
  const unmatched = new UnmatchedSet();
  for (const g of groups) {
    const f = new Date(g.f);
    const l = new Date(g.l);
    const rawLogId = g.sample === null || g.sample === undefined ? null : Number(g.sample);
    switch (g.kind) {
      case 'program': {
        const matches = index.matchProgram(g.a);
        if (matches.length === 0) unmatched.add('syslog_program', g.a, g.n, f, l, g.b, null);
        else rows.addMatches(matches, { loc_type: 'host', loc_key: g.b, source: 'syslog_program', events: g.n, first_seen: f, last_seen: l, evidence: { value: g.a, raw_log_id: rawLogId } });
        break;
      }
      case 'parser': {
        const name = parserNames.get(String(g.a));
        if (!name) break;
        rows.addMatches(index.matchParser(name), { loc_type: 'host', loc_key: g.b, source: 'parser', events: g.n, first_seen: f, last_seen: l, evidence: { value: name, raw_log_id: rawLogId } });
        break;
      }
      case 'ua': {
        const matches = index.matchUserAgent(g.a);
        if (matches.length === 0) {
          const product = userAgentProduct(g.a);
          if (product) unmatched.add('user_agent', product, g.n, f, l, g.b, g.a);
        } else {
          rows.addMatches(matches, { loc_type: 'client', loc_key: g.b, source: 'user_agent', events: g.n, first_seen: f, last_seen: l, evidence: { value: g.a, raw_log_id: rawLogId } });
        }
        break;
      }
      case 'dns': {
        const d = cleanDomain(g.a);
        if (!d) break;
        rows.addMatches(index.matchDomain(d), { loc_type: 'client', loc_key: g.b, source: 'dns', events: g.n, first_seen: f, last_seen: l, evidence: { value: d, raw_log_id: rawLogId } });
        break;
      }
    }
  }
  return { rows, unmatched };
}

export interface SnapshotInput {
  services: Array<{ asset_id: number; port: number; protocol: string; service_name: string | null; service_version: string | null; banner: string | null; seen: Date }>;
  containers: Array<{ shipper_id: number; image: string; containers: number; names: string[]; seen: Date }>;
  packages: Array<{ asset_id: number; package: string; installed: string | null; findings: number; first: Date; seen: Date }>;
  agents: Array<{ asset_id: number; os: string | null; os_version: string | null; seen: Date }>;
}

/** The snapshot sources' rows (and unmatched container images). Pure. */
export function matchSnapshots(input: SnapshotInput, index: AppIndex): { rows: RowSet; unmatched: UnmatchedSet } {
  const rows = new RowSet();
  const unmatched = new UnmatchedSet();
  for (const s of input.services) {
    const matches = index.matchService({ name: s.service_name, version: s.service_version, banner: s.banner });
    for (const m of matches) {
      rows.add({
        app_id: m.appId, loc_type: 'asset', loc_key: String(s.asset_id), source: 'service_scan', version: m.version ?? '', events: 1,
        first_seen: s.seen, last_seen: s.seen,
        evidence: { port: s.port, protocol: s.protocol, service_name: s.service_name, banner: s.banner, service_version: s.service_version },
      });
    }
  }
  for (const c of input.containers) {
    const matches = index.matchImage(c.image);
    if (matches.length === 0) {
      const parsed = parseImageRef(c.image);
      if (parsed) unmatched.add('container', parsed.name, Math.max(1, c.containers), c.seen, c.seen, String(c.shipper_id), c.image);
      continue;
    }
    for (const m of matches) {
      rows.add({
        app_id: m.appId, loc_type: 'shipper', loc_key: String(c.shipper_id), source: 'container', version: m.version ?? '', events: Math.max(1, c.containers),
        first_seen: c.seen, last_seen: c.seen, evidence: { image: c.image, containers: c.names.slice(0, 5) },
      });
    }
  }
  for (const p of input.packages) {
    for (const m of index.matchPackage(p.package, p.installed)) {
      rows.add({
        app_id: m.appId, loc_type: 'asset', loc_key: String(p.asset_id), source: 'edr_package', version: m.version ?? '', events: p.findings,
        first_seen: p.first, last_seen: p.seen, evidence: { package: p.package, installed_version: p.installed },
      });
    }
  }
  for (const a of input.agents) {
    for (const m of index.matchOs(a.os, a.os_version)) {
      rows.add({
        app_id: m.appId, loc_type: 'asset', loc_key: String(a.asset_id), source: 'os', version: m.version ?? '', events: 1,
        first_seen: a.seen, last_seen: a.seen, evidence: { os: a.os, os_version: a.os_version },
      });
    }
  }
  // Snapshot unmatched counts are "now", not cumulative: one row per image name.
  return { rows, unmatched };
}

/**
 * The words a vulnerability title (or Nuclei template id) must contain, as a
 * whole word, to be linked best effort: the application's name and its CPE
 * product, lower case, 4+ characters. Pure.
 */
export function productWords(app: AppSignature): string[] {
  const words = new Set<string>();
  for (const w of [app.name, app.cpe?.product.replace(/_/g, ' ')]) {
    const t = (w ?? '').trim().toLowerCase();
    if (t.length >= 4) words.add(t);
  }
  return [...words];
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The package and installed version of an EDR finding, from its evidence
 * ("package=<name> installed=<version> fixed=... source=grype", edrService):
 * plain string functions (a regex here cost 0.1 ms a row).
 */
const EVIDENCE_PACKAGE_SQL = (col: string) => `left(split_part(substring(${col} FROM 9), ' ', 1), 128)`;
const EVIDENCE_INSTALLED_SQL = (col: string) => `left(split_part(split_part(${col}, ' installed=', 2), ' ', 1), 128)`;

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface InventoryRunOptions {
  connect: () => Promise<RollupClient>;
  settings?: InventorySettings;
  /** The signature set (tests); otherwise fetchAppCatalog(). */
  catalog?: AppCatalog;
  forceCatalog?: boolean;
  /** The regex gate (tests inject one; the default asks services/regex/regexSafety). */
  gate?: (apps: AppSignature[]) => Promise<RegexGateResult>;
  now?: () => number;
  batchSize?: number;
  budgetMs?: number;
  pauseRatio?: number;
  lag?: string;
  forcePrune?: boolean;
  afterBatch?: (batch: { from: number; to: number }) => Promise<void> | void;
}

export interface InventoryRunResult {
  status: 'disabled' | 'ok';
  signatures: number;
  signatureSource: string;
  consumed: number;
  batches: number;
  rowsWritten: number;
  snapshotRows: number;
  vulnLinks: number;
  pruned: number;
  more: boolean;
  backedOff: boolean;
  batchSize: number;
  dbMs: number;
  /** Wall time of each step, ms (signatures includes the regex gate). */
  timings: { signatures: number; logs: number; snapshots: number; vulnLinks: number; prune: number };
}

async function inTransaction<T>(client: RollupClient, work: () => Promise<T>): Promise<T> {
  await client.query('BEGIN');
  try {
    const out = await work();
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  }
}

let indexCache: { hash: string; skipKey: string; index: AppIndex } | null = null;

export function signaturesHash(apps: AppSignature[]): string {
  return crypto.createHash('sha256').update(stableStringify(apps)).digest('hex');
}

async function storeSignatures(client: RollupClient, catalog: AppCatalog, hash: string, gate: RegexGateResult): Promise<void> {
  const { rows } = await client.query(`SELECT signatures_hash, signatures_source FROM application_inventory_state WHERE id = 1`);
  const fromCatalog = catalog.source !== 'bundled';
  const storedSource = fromCatalog ? 'catalog' : 'bundled';
  const changed = rows[0]?.signatures_hash !== hash;
  await inTransaction(client, async () => {
    if (changed) {
      const apps = catalog.apps;
      await client.query(`DELETE FROM application_signatures WHERE id <> ALL($1::text[])`, [apps.map((a) => a.id)]);
      await client.query(
        `INSERT INTO application_signatures AS s (id, name, vendor, category, definition, source, fetched_at, updated_at)
         SELECT id, name, vendor, category, definition, $6, $7::timestamptz, NOW()
           FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::jsonb[]) AS u(id, name, vendor, category, definition)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, vendor = EXCLUDED.vendor, category = EXCLUDED.category,
           definition = EXCLUDED.definition, source = EXCLUDED.source, fetched_at = EXCLUDED.fetched_at, updated_at = NOW()`,
        [apps.map((a) => a.id), apps.map((a) => a.name), apps.map((a) => a.vendor), apps.map((a) => a.category), apps.map((a) => JSON.stringify({ schema: APP_SCHEMA, ...a })), storedSource, catalog.fetched_at]
      );
    }
    await client.query(
      `UPDATE application_inventory_state
          SET signatures_hash = $1, signatures_source = $2, signatures_count = $3, signatures_error = $4, refused_regexes = $5::jsonb
        WHERE id = 1`,
      [hash, catalog.source, catalog.apps.length, catalog.error, JSON.stringify([...gate.refused, ...catalog.invalid.map((i) => ({ appId: i.path, location: 'file', source: '', reason: i.errors.join('; ') }))].slice(0, 100))]
    );
  });
}

/** The stored signature set, for appCatalog's fallback (only a set that came from the catalog). */
export async function loadStoredSignatures(q: Q): Promise<{ docs: unknown[]; fetched_at: string | null } | null> {
  const { rows } = await q(`SELECT definition, fetched_at FROM application_signatures WHERE source = 'catalog' ORDER BY id`);
  if (rows.length === 0) return null;
  const at = rows.find((r) => r.fetched_at)?.fetched_at;
  return { docs: rows.map((r) => r.definition), fetched_at: at ? new Date(at).toISOString() : null };
}

async function startCursor(client: RollupClient, settings: InventorySettings, hi: number | null): Promise<void> {
  await inTransaction(client, async () => {
    const { rows } = await client.query(`SELECT last_parsed_log_id FROM application_inventory_state WHERE id = 1 FOR UPDATE`);
    if (rows[0]?.last_parsed_log_id !== null && rows[0]?.last_parsed_log_id !== undefined) return;
    let last = hi ?? 0;
    if (settings.backfillDays > 0) {
      const { rows: first } = await client.query(BACKFILL_START_SQL, [settings.backfillDays]);
      last = first[0] ? Number(first[0].id) - 1 : (hi ?? 0);
    }
    await client.query(
      `UPDATE application_inventory_state SET last_parsed_log_id = $1, covered_from = NOW() - $2::int * interval '1 day', caught_up = false WHERE id = 1`,
      [last, settings.backfillDays]
    );
  });
}

async function runBatch(
  client: RollupClient,
  index: AppIndex,
  parserNames: Map<string, string>,
  hi: number,
  size: number,
  lag: string
): Promise<{ done: boolean; from: number; to: number; consumed: number; rows: number }> {
  return inTransaction(client, async () => {
    const { rows } = await client.query(`SELECT last_parsed_log_id FROM application_inventory_state WHERE id = 1 FOR UPDATE`);
    const last = Number(rows[0]?.last_parsed_log_id ?? 0);
    if (last >= hi) {
      await client.query(
        `UPDATE application_inventory_state SET caught_up = true, covered_until = GREATEST(covered_until, NOW() - $1::interval), last_run_at = NOW() WHERE id = 1`,
        [lag]
      );
      return { done: true, from: last, to: last, consumed: 0, rows: 0 };
    }
    const upper = Math.min(last + size, hi);
    const { rows: bounds } = await client.query(
      `SELECT min(raw_log_id) AS raw_min, max(raw_log_id) AS raw_max, count(*)::int AS n, max(created_at)::timestamptz AS until
         FROM parsed_logs WHERE id > $1 AND id <= $2`,
      [last, upper]
    );
    const b = bounds[0];
    let written = 0;
    if (b.n > 0) {
      await client.query("SELECT set_config('statement_timeout', $1, true), set_config('jit', 'off', true)", [String(BATCH_STATEMENT_TIMEOUT_MS)]);
      const { rows: groups } = await client.query(LOG_BATCH_SQL, [last, upper, b.raw_min ?? 0, b.raw_max ?? 0]);
      const matched = matchLogGroups(groups as LogGroup[], index, parserNames);
      const list = matched.rows.list();
      await upsertRows(client, UPSERT_LOG_ROWS_SQL, list);
      await upsertUnmatched(client, UPSERT_UNMATCHED_LOG_SQL, matched.unmatched.list());
      written = list.length;
    }
    const caughtUp = upper >= hi;
    await client.query(
      `UPDATE application_inventory_state
          SET last_parsed_log_id = $1,
              covered_until = CASE WHEN $2::boolean THEN GREATEST(covered_until, NOW() - $4::interval) ELSE GREATEST(covered_until, $3::timestamptz) END,
              caught_up = caught_up OR $2::boolean, last_run_at = NOW()
        WHERE id = 1`,
      [upper, caughtUp, b.until, lag]
    );
    return { done: caughtUp, from: last, to: upper, consumed: b.n, rows: written };
  });
}

async function readSnapshots(client: RollupClient): Promise<SnapshotInput> {
  const services = await client.query(
    `SELECT asset_id, port, protocol, service_name, service_version, banner, COALESCE(last_seen, discovered_at, NOW()) AS seen
       FROM asset_services WHERE asset_id IS NOT NULL AND COALESCE(state, 'open') = 'open' ORDER BY id LIMIT $1`,
    [SNAPSHOT_LIMIT]
  );
  const containers = await client.query(
    `SELECT shipper_id, image, jsonb_array_length(container_names) AS containers,
            ARRAY(SELECT jsonb_array_elements_text(container_names) LIMIT 5) AS names, reported_at AS seen
       FROM shipper_containers ORDER BY id LIMIT $1`,
    [SNAPSHOT_LIMIT]
  );
  // EDR (grype) findings: one row per (asset, package, installed version) still open.
  const packages = await client.query(
    `SELECT asset_id, pkg AS package, inst AS installed, count(*)::int AS findings, min(first_detected) AS first, max(last_detected) AS seen
       FROM (SELECT asset_id, first_detected, last_detected,
                    ${EVIDENCE_PACKAGE_SQL('evidence')} AS pkg, ${EVIDENCE_INSTALLED_SQL('evidence')} AS inst
               FROM asset_vulnerabilities
              WHERE status = 'open' AND evidence LIKE 'package=%'
              LIMIT $1) f
      WHERE pkg <> ''
      GROUP BY asset_id, pkg, inst`,
    [SNAPSHOT_LIMIT]
  );
  const agents = await client.query(`SELECT asset_id, os, os_version, COALESCE(last_seen, created_at, NOW()) AS seen FROM edr_agents WHERE asset_id IS NOT NULL`);
  const date = (v: unknown) => (v instanceof Date ? v : new Date(String(v)));
  return {
    services: services.rows.map((r) => ({ ...r, seen: date(r.seen) })),
    containers: containers.rows.map((r) => ({ shipper_id: r.shipper_id, image: r.image, containers: Number(r.containers ?? 0), names: r.names ?? [], seen: date(r.seen) })),
    packages: packages.rows.map((r) => ({ ...r, first: date(r.first ?? r.seen), seen: date(r.seen) })),
    agents: agents.rows.map((r) => ({ ...r, seen: date(r.seen) })),
  };
}

async function refreshSnapshots(client: RollupClient, index: AppIndex): Promise<number> {
  const input = await readSnapshots(client);
  const { rows, unmatched } = matchSnapshots(input, index);
  const list = rows.list();
  await inTransaction(client, async () => {
    await client.query(DELETE_STALE_SNAPSHOT_SQL, [SNAPSHOT_SOURCES, list.map((r) => r.app_id), list.map((r) => r.loc_type), list.map((r) => r.loc_key), list.map((r) => r.source), list.map((r) => r.version)]);
    await upsertRows(client, UPSERT_SNAPSHOT_ROWS_SQL, list);
    const un = unmatched.list();
    await client.query(`DELETE FROM application_unmatched WHERE source = 'container' AND value <> ALL($1::text[])`, [un.map((u) => u.value)]);
    await upsertUnmatched(client, REPLACE_UNMATCHED_SNAPSHOT_SQL, un);
  });
  return list.length;
}

/**
 * Rebuild application_vuln_links. Exact links: an open EDR finding for one of
 * the signature's packages. Best effort: an open finding on an asset where the
 * application was seen (service, container host, logging host), whose title
 * or Nuclei template names the product.
 */
async function rebuildVulnLinks(client: RollupClient, apps: AppSignature[]): Promise<number> {
  const pkgApp: string[] = [];
  const pkgName: string[] = [];
  const patApp: string[] = [];
  const patRe: string[] = [];
  const patWord: string[] = [];
  for (const a of apps) {
    for (const p of a.match.package) {
      pkgApp.push(a.id);
      pkgName.push(p);
    }
    if (a.category === 'saas' || a.category === 'browser' || a.category === 'http-client') continue;
    for (const word of productWords(a)) {
      patApp.push(a.id);
      patRe.push(`\\m${escapeRegex(word)}\\M`);
      patWord.push(`%${word.replace(/[\\%_]/g, '\\$&')}%`);
    }
  }
  return inTransaction(client, async () => {
    await client.query("SELECT set_config('statement_timeout', $1, true)", [String(BATCH_STATEMENT_TIMEOUT_MS)]);
    await client.query(`DELETE FROM application_vuln_links`);
    const exact = await client.query(
      `INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match, version)
       SELECT DISTINCT ON (m.app_id, av.asset_id, av.vulnerability_id)
              m.app_id, av.asset_id, av.vulnerability_id, 'package', ${EVIDENCE_INSTALLED_SQL('av.evidence')}
         FROM asset_vulnerabilities av
         JOIN unnest($1::text[], $2::text[]) AS m(app_id, pkg)
           ON lower(${EVIDENCE_PACKAGE_SQL('av.evidence')}) = m.pkg
        WHERE av.status = 'open' AND av.evidence LIKE 'package=%' AND av.asset_id IS NOT NULL
       ON CONFLICT DO NOTHING`,
      [pkgApp, pkgName]
    );
    const product = await client.query(
      `WITH seen AS (
         SELECT DISTINCT app_id, asset_id FROM application_location_assets WHERE loc_type <> 'client' AND source <> 'edr_package'
       )
       INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match, version)
       SELECT DISTINCT s.app_id, s.asset_id, av.vulnerability_id, 'product', ''
         FROM seen s
         JOIN unnest($1::text[], $2::text[], $3::text[]) AS p(app_id, pattern, word) ON p.app_id = s.app_id
         JOIN asset_vulnerabilities av ON av.asset_id = s.asset_id AND av.status = 'open'
         JOIN vulnerabilities v ON v.id = av.vulnerability_id
         CROSS JOIN LATERAL (SELECT lower(COALESCE(v.title, '') || ' ' || COALESCE(v.metadata->>'nuclei_template', '')) AS text) t
        WHERE t.text LIKE p.word AND t.text ~ p.pattern
       ON CONFLICT DO NOTHING`,
      [patApp, patRe, patWord]
    );
    return (exact.rowCount ?? 0) + (product.rowCount ?? 0);
  });
}

async function prune(client: RollupClient, settings: InventorySettings, nowMs: number, force: boolean): Promise<number> {
  const { rows } = await client.query(`SELECT last_pruned_at FROM application_inventory_state WHERE id = 1`);
  const lastPruned = rows[0]?.last_pruned_at ? new Date(rows[0].last_pruned_at).getTime() : 0;
  if (!force && nowMs - lastPruned < PRUNE_EVERY_MS) return 0;
  const exec = async (sql: string, params: unknown[]) => ({ rowCount: (await client.query(sql, params)).rowCount ?? 0 });
  let deleted = await batchedDelete('application_inventory', `last_seen < NOW() - $1::int * interval '1 day'`, [settings.retentionDays], {
    label: 'Application inventory',
    pauseMs: 20,
    exec,
  });
  deleted += (await client.query(`DELETE FROM application_unmatched WHERE last_seen < NOW() - $1::int * interval '1 day'`, [settings.retentionDays])).rowCount ?? 0;
  deleted +=
    (
      await client.query(
        `DELETE FROM application_unmatched u USING (
           SELECT source, value, row_number() OVER (PARTITION BY source ORDER BY events DESC, last_seen DESC) AS rank FROM application_unmatched
         ) r WHERE r.source = u.source AND r.value = u.value AND r.rank > $1`,
        [UNMATCHED_CAP]
      )
    ).rowCount ?? 0;
  await client.query(`UPDATE application_inventory_state SET last_pruned_at = NOW() WHERE id = 1`);
  return deleted;
}

/** One run of the inventory rollup. */
export async function runInventoryRollup(options: InventoryRunOptions): Promise<InventoryRunResult> {
  const now = options.now ?? (() => Date.now());
  const budget = options.budgetMs ?? RUN_BUDGET_MS;
  let size = options.batchSize ?? BATCH_SIZE;
  const result: InventoryRunResult = {
    status: 'ok', signatures: 0, signatureSource: '', consumed: 0, batches: 0, rowsWritten: 0, snapshotRows: 0, vulnLinks: 0, pruned: 0,
    more: false, backedOff: false, batchSize: size, dbMs: 0,
    timings: { signatures: 0, logs: 0, snapshots: 0, vulnLinks: 0, prune: 0 },
  };
  let mark = now();
  const lap = (step: keyof InventoryRunResult['timings']) => {
    const t = now();
    result.timings[step] += t - mark;
    mark = t;
  };
  const client = await options.connect();
  let releaseArg: Error | undefined;
  try {
    const q: Q = (sql, params) => client.query(sql, params);
    const settings = options.settings ?? (await readInventorySettings(q));
    if (!settings.enabled) {
      result.status = 'disabled';
      return result;
    }
    const catalog = options.catalog ?? (await fetchAppCatalog({ force: options.forceCatalog, loadStored: () => loadStoredSignatures(q) }));
    const gate = await (options.gate ?? ((apps: AppSignature[]) => gateSignatureRegexes(apps)))(catalog.apps);
    const hash = signaturesHash(catalog.apps);
    const skipKey = [...gate.skip].sort().join('\u0000');
    if (!indexCache || indexCache.hash !== hash || indexCache.skipKey !== skipKey) {
      indexCache = { hash, skipKey, index: new AppIndex(catalog.apps, { skipRegex: gate.skip }) };
    }
    const index = indexCache.index;
    result.signatures = catalog.apps.length;
    result.signatureSource = catalog.source;
    await storeSignatures(client, catalog, hash, gate);
    lap('signatures');

    const parserNames = new Map<string, string>(((await client.query(`SELECT id::text AS id, name FROM parsers`)).rows as Array<{ id: string; name: string }>).map((r) => [r.id, r.name]));
    const lag = options.lag ?? LAG;
    const { rows } = await client.query(UPPER_BOUND_SQL, [lag]);
    const hi = rows[0] ? Number(rows[0].id) : null;
    await startCursor(client, settings, hi);

    let spent = 0;
    if (hi !== null) {
      for (;;) {
        if (spent >= budget) {
          result.more = true;
          break;
        }
        const started = now();
        let batch;
        try {
          batch = await runBatch(client, index, parserNames, hi, size, lag);
        } catch (err) {
          if (isStatementTimeout(err) && size > MIN_BATCH_SIZE) {
            size = Math.max(MIN_BATCH_SIZE, Math.floor(size / 2));
            result.backedOff = true;
            continue;
          }
          throw err;
        } finally {
          spent += now() - started;
        }
        if (batch.to > batch.from) {
          result.batches++;
          result.consumed += batch.consumed;
          result.rowsWritten += batch.rows;
          await options.afterBatch?.({ from: batch.from, to: batch.to });
        }
        if (batch.done) break;
        const pause = (now() - started) * (options.pauseRatio ?? PAUSE_RATIO);
        if (pause > 0) await new Promise((resolve) => setTimeout(resolve, Math.min(pause, 5_000)));
      }
    } else {
      await client.query(`UPDATE application_inventory_state SET caught_up = true, covered_until = NOW(), last_run_at = NOW() WHERE id = 1`);
    }
    lap('logs');
    const snapStarted = now();
    result.snapshotRows = await refreshSnapshots(client, index);
    lap('snapshots');
    result.vulnLinks = await rebuildVulnLinks(client, catalog.apps);
    lap('vulnLinks');
    result.pruned = await prune(client, settings, now(), options.forcePrune === true);
    lap('prune');
    spent += now() - snapStarted;
    result.dbMs = spent;
    result.batchSize = size;
    await client.query(`UPDATE application_inventory_state SET last_refresh_at = NOW(), last_run_at = NOW(), last_summary = $1 WHERE id = 1`, [describeInventoryRun(result)]);
    return result;
  } catch (err) {
    if (!isStatementTimeout(err)) releaseArg = err instanceof Error ? err : new Error(String(err));
    throw err;
  } finally {
    client.release(releaseArg);
  }
}

export function describeInventoryRun(r: InventoryRunResult): string {
  if (r.status === 'disabled') return 'switched off in Settings -> Application Monitoring';
  const parts = [
    `${r.signatures} signatures (${r.signatureSource})`,
    `${r.consumed.toLocaleString('en-US')} logs in ${r.batches} batch(es)`,
    `${r.snapshotRows.toLocaleString('en-US')} rows from scans, containers and endpoints`,
    `${r.vulnLinks.toLocaleString('en-US')} vulnerability links`,
  ];
  if (r.more) parts.push('more to do (backlog)');
  if (r.backedOff) parts.push(`batch size cut to ${r.batchSize.toLocaleString('en-US')} after a timeout`);
  if (r.pruned) parts.push(`pruned ${r.pruned.toLocaleString('en-US')} old rows`);
  return parts.join('; ');
}

/** Test seam. */
export function clearInventoryIndexCache(): void {
  indexCache = null;
}
