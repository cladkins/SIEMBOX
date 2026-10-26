/**
 * Application Monitoring reads: the page's inventory, detail, version drift,
 * vulnerabilities, unmanaged and unmatched lists. All of them read the small
 * rollup tables (application_inventory and friends, migration 048), never
 * raw_logs or parsed_logs, so a page view costs the same however many logs
 * there are.
 *
 * Only applications in the stored signature set are listed (rows of a
 * signature the catalog dropped age out with the retention).
 */
import { query } from '../../config/database';
import { catalogNewFileUrl, catalogRepoRef } from '../parser/catalogService';
import { APP_CATEGORIES, APP_FILE_SUFFIX, APP_SCHEMA, type AppSignature } from './appFormat';
import { NETWORK_SOURCES, SOURCES, readInventorySettings } from './rollup';

/** Version order: numeric runs compare as numbers, the rest as text ("1.10" > "1.9", "8.9p1" > "8.4p1"). Pure. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[^0-9A-Za-z]+/).filter(Boolean);
  const pb = b.split(/[^0-9A-Za-z]+/).filter(Boolean);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export interface VersionCount {
  version: string;
  /** Locations whose newest sighting is this version. */
  locations: number;
  last_seen: string;
}

export interface ApplicationSummaryRow {
  id: string;
  name: string;
  vendor: string;
  category: string;
  sources: string[];
  hosts: number;
  clients: number;
  versions: VersionCount[];
  latest_version: string | null;
  drift: boolean;
  unmanaged: boolean;
  vulnerabilities: { total: number; exact: number; critical: number; high: number };
  events: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ListFilters {
  category?: string;
  source?: string;
  host?: string;
  search?: string;
  view?: 'all' | 'drift' | 'vulnerable' | 'unmanaged';
}

const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : String(v));
const isoOrNull = (v: unknown) => (v === null || v === undefined ? null : iso(v));

/** The filter's WHERE on application_inventory i (and signatures s), with its params. */
function filterSql(f: ListFilters, params: unknown[]): string {
  const where: string[] = [];
  if (f.category && (APP_CATEGORIES as readonly string[]).includes(f.category)) {
    params.push(f.category);
    where.push(`s.category = $${params.length}`);
  }
  if (f.source && (SOURCES as readonly string[]).includes(f.source)) {
    params.push(f.source);
    where.push(`i.app_id IN (SELECT app_id FROM application_inventory WHERE source = $${params.length})`);
  }
  if (f.search && f.search.trim()) {
    params.push(`%${f.search.trim().slice(0, 100).replace(/[\\%_]/g, '\\$&')}%`);
    where.push(`(s.name ILIKE $${params.length} OR s.vendor ILIKE $${params.length} OR s.id ILIKE $${params.length})`);
  }
  if (f.host && f.host.trim()) {
    params.push(`%${f.host.trim().slice(0, 255).replace(/[\\%_]/g, '\\$&')}%`);
    const p = `$${params.length}`;
    // A location matches by its own key, or by the asset (host name, IP) or shipper (name, host name) it is.
    where.push(`(i.loc_type, i.loc_key) IN (
      SELECT loc_type, loc_key FROM application_inventory WHERE loc_key ILIKE ${p}
      UNION SELECT la.loc_type, la.loc_key FROM application_location_assets la JOIN assets a ON a.id = la.asset_id
       WHERE a.hostname ILIKE ${p} OR host(a.ip_address) ILIKE ${p}
      UNION SELECT 'shipper', ls.id::text FROM log_shippers ls WHERE ls.name ILIKE ${p} OR ls.hostname ILIKE ${p})`);
  }
  return where.length ? `AND ${where.join(' AND ')}` : '';
}

const LIST_SQL = (filters: string) => `
  WITH inv AS (
    SELECT i.* FROM application_inventory i JOIN application_signatures s ON s.id = i.app_id WHERE TRUE ${filters}
  ), loc AS (
    SELECT app_id, loc_type, loc_key, min(first_seen) AS f, max(last_seen) AS l, sum(events) AS ev,
           (array_agg(version ORDER BY last_seen DESC) FILTER (WHERE version <> ''))[1] AS cur
      FROM inv GROUP BY app_id, loc_type, loc_key
  ), ver AS (
    SELECT app_id, jsonb_agg(jsonb_build_object('version', cur, 'locations', n, 'last_seen', l) ORDER BY l DESC) AS versions
      FROM (SELECT app_id, cur, count(*)::int AS n, max(l) AS l FROM loc WHERE cur IS NOT NULL GROUP BY app_id, cur) v
     GROUP BY app_id
  ), src AS (
    SELECT app_id, array_agg(DISTINCT source ORDER BY source) AS sources FROM inv GROUP BY app_id
  ), agg AS (
    SELECT app_id, count(*) FILTER (WHERE loc_type <> 'client')::int AS hosts, count(*) FILTER (WHERE loc_type = 'client')::int AS clients,
           min(f) AS first_seen, max(l) AS last_seen, sum(ev)::bigint AS events
      FROM loc GROUP BY app_id
  ), vul AS (
    SELECT l.app_id, count(DISTINCT l.vulnerability_id)::int AS total,
           count(DISTINCT l.vulnerability_id) FILTER (WHERE l.match = 'package')::int AS exact,
           count(DISTINCT l.vulnerability_id) FILTER (WHERE lower(v.severity) = 'critical')::int AS critical,
           count(DISTINCT l.vulnerability_id) FILTER (WHERE lower(v.severity) = 'high')::int AS high
      FROM application_vuln_links l JOIN vulnerabilities v ON v.id = l.vulnerability_id
     WHERE l.app_id IN (SELECT app_id FROM agg)
     GROUP BY l.app_id
  )
  SELECT s.id, s.name, s.vendor, s.category, src.sources, agg.hosts, agg.clients, COALESCE(ver.versions, '[]'::jsonb) AS versions,
         agg.first_seen, agg.last_seen, agg.events,
         COALESCE(vul.total, 0) AS v_total, COALESCE(vul.exact, 0) AS v_exact, COALESCE(vul.critical, 0) AS v_critical, COALESCE(vul.high, 0) AS v_high
    FROM agg
    JOIN application_signatures s ON s.id = agg.app_id
    JOIN src ON src.app_id = agg.app_id
    LEFT JOIN ver ON ver.app_id = agg.app_id
    LEFT JOIN vul ON vul.app_id = agg.app_id
   ORDER BY s.name`;

/** Fold one SQL row into the page's shape (versions oldest first, drift, unmanaged). Pure. */
export function summaryFromRow(r: Record<string, any>): ApplicationSummaryRow {
  const versions: VersionCount[] = (r.versions ?? [])
    .map((v: any) => ({ version: String(v.version), locations: Number(v.locations), last_seen: iso(v.last_seen) }))
    .sort((a: VersionCount, b: VersionCount) => compareVersions(a.version, b.version));
  const sources: string[] = r.sources ?? [];
  return {
    id: r.id,
    name: r.name,
    vendor: r.vendor,
    category: r.category,
    sources,
    hosts: Number(r.hosts ?? 0),
    clients: Number(r.clients ?? 0),
    versions,
    latest_version: versions.length ? versions[versions.length - 1].version : null,
    drift: versions.length > 1,
    unmanaged: sources.length > 0 && sources.every((s) => (NETWORK_SOURCES as string[]).includes(s)),
    vulnerabilities: { total: Number(r.v_total ?? 0), exact: Number(r.v_exact ?? 0), critical: Number(r.v_critical ?? 0), high: Number(r.v_high ?? 0) },
    events: Number(r.events ?? 0),
    first_seen: isoOrNull(r.first_seen),
    last_seen: isoOrNull(r.last_seen),
  };
}

export async function listApplications(filters: ListFilters = {}): Promise<ApplicationSummaryRow[]> {
  const params: unknown[] = [];
  const { rows } = await query(LIST_SQL(filterSql(filters, params)), params);
  let apps = rows.map(summaryFromRow);
  if (filters.view === 'drift') apps = apps.filter((a) => a.drift);
  else if (filters.view === 'vulnerable') apps = apps.filter((a) => a.vulnerabilities.total > 0);
  else if (filters.view === 'unmanaged') apps = apps.filter((a) => a.unmanaged);
  return apps;
}

export interface InventoryStatus {
  enabled: boolean;
  retention_days: number;
  caught_up: boolean;
  covered_from: string | null;
  covered_until: string | null;
  last_run_at: string | null;
  last_summary: string | null;
  signatures: { source: string | null; count: number; error: string | null; refused: unknown[] };
  catalog_repo: string;
}

export async function readInventoryStatus(): Promise<InventoryStatus> {
  const settings = await readInventorySettings((sql, params) => query(sql, params as unknown[]));
  const { rows } = await query(`SELECT * FROM application_inventory_state WHERE id = 1`);
  const s = rows[0] ?? {};
  const when = (v: unknown) => (v ? iso(v) : null);
  const { repo } = catalogRepoRef();
  return {
    enabled: settings.enabled,
    retention_days: settings.retentionDays,
    caught_up: s.caught_up === true,
    covered_from: when(s.covered_from),
    covered_until: when(s.covered_until),
    last_run_at: when(s.last_run_at),
    last_summary: s.last_summary ?? null,
    signatures: { source: s.signatures_source ?? null, count: Number(s.signatures_count ?? 0), error: s.signatures_error ?? null, refused: s.refused_regexes ?? [] },
    catalog_repo: repo,
  };
}

export interface LocationDetail {
  loc_type: string;
  loc_key: string;
  label: string;
  asset: { id: number; hostname: string | null; ip_address: string } | null;
  shipper: { id: number; name: string; hostname: string | null } | null;
  current_version: string | null;
  versions: string[];
  sources: string[];
  events: number;
  first_seen: string;
  last_seen: string;
  evidence: Array<{ source: string; version: string; evidence: Record<string, unknown> | null; last_seen: string }>;
}

export interface ApplicationDetail extends ApplicationSummaryRow {
  description: string;
  website: string | null;
  cpe: AppSignature['cpe'];
  matchers: AppSignature['match'];
  locations: LocationDetail[];
  locations_total: number;
  vulnerability_list: Array<{
    vulnerability_id: number;
    cve_id: string;
    title: string | null;
    severity: string | null;
    cvss_score: number | null;
    asset_id: number;
    asset: string;
    match: string;
    version: string;
  }>;
}

export const DETAIL_LOCATION_LIMIT = 500;
export const DETAIL_VULN_LIMIT = 200;

export async function getApplication(id: string): Promise<ApplicationDetail | null> {
  const sig = await query(`SELECT definition FROM application_signatures WHERE id = $1`, [id]);
  if (sig.rows.length === 0) return null;
  const def = sig.rows[0].definition as AppSignature;
  const params: unknown[] = [id];
  const summary =
    (await query(LIST_SQL('AND i.app_id = $1'), params)).rows.map(summaryFromRow)[0] ??
    summaryFromRow({ id: def.id, name: def.name, vendor: def.vendor, category: def.category, sources: [], versions: [], first_seen: null, last_seen: null });
  const { rows: locRows } = await query(
    `WITH loc AS (
       SELECT loc_type, loc_key, min(first_seen) AS f, max(last_seen) AS l, sum(events)::bigint AS ev,
              array_agg(DISTINCT source ORDER BY source) AS sources,
              (array_agg(version ORDER BY last_seen DESC) FILTER (WHERE version <> ''))[1] AS cur,
              array_agg(DISTINCT version) FILTER (WHERE version <> '') AS versions,
              jsonb_agg(jsonb_build_object('source', source, 'version', version, 'evidence', evidence, 'last_seen', last_seen) ORDER BY last_seen DESC) AS evidence,
              count(*) OVER () AS total
         FROM application_inventory WHERE app_id = $1 GROUP BY loc_type, loc_key
        ORDER BY max(last_seen) DESC LIMIT $2
     )
     SELECT loc.*,
            (SELECT jsonb_build_object('id', a.id, 'hostname', a.hostname, 'ip_address', host(a.ip_address))
               FROM application_location_assets la JOIN assets a ON a.id = la.asset_id
              WHERE la.app_id = $1 AND la.loc_type = loc.loc_type AND la.loc_key = loc.loc_key ORDER BY a.id LIMIT 1) AS asset,
            (SELECT jsonb_build_object('id', ls.id, 'name', ls.name, 'hostname', ls.hostname)
               FROM log_shippers ls WHERE loc.loc_type = 'shipper' AND ls.id::text = loc.loc_key) AS shipper
       FROM loc`,
    [id, DETAIL_LOCATION_LIMIT]
  );
  const locations: LocationDetail[] = locRows.map((r) => {
    const asset = r.asset ?? null;
    const shipper = r.shipper ?? null;
    const label =
      r.loc_type === 'shipper'
        ? shipper
          ? `${shipper.hostname || shipper.name} (shipper)`
          : `shipper #${r.loc_key}`
        : r.loc_type === 'asset'
          ? asset
            ? asset.hostname || asset.ip_address
            : `asset #${r.loc_key}`
          : r.loc_key;
    return {
      loc_type: r.loc_type,
      loc_key: r.loc_key,
      label,
      asset,
      shipper,
      current_version: r.cur ?? null,
      versions: ((r.versions ?? []) as string[]).sort(compareVersions),
      sources: r.sources ?? [],
      events: Number(r.ev ?? 0),
      first_seen: iso(r.f),
      last_seen: iso(r.l),
      evidence: ((r.evidence ?? []) as any[]).slice(0, 5).map((e) => ({ ...e, last_seen: iso(e.last_seen) })),
    };
  });
  const { rows: vulnRows } = await query(
    `SELECT l.vulnerability_id, v.cve_id, v.title, v.severity, v.cvss_score::float AS cvss_score, l.asset_id,
            COALESCE(a.hostname, host(a.ip_address)) AS asset, l.match, l.version
       FROM application_vuln_links l
       JOIN vulnerabilities v ON v.id = l.vulnerability_id
       JOIN assets a ON a.id = l.asset_id
      WHERE l.app_id = $1
      ORDER BY v.cvss_score DESC NULLS LAST, v.cve_id
      LIMIT $2`,
    [id, DETAIL_VULN_LIMIT]
  );
  return {
    ...summary,
    description: def.description,
    website: def.website,
    cpe: def.cpe,
    matchers: def.match,
    locations,
    locations_total: Number(locRows[0]?.total ?? 0),
    vulnerability_list: vulnRows,
  };
}

export interface ApplicationVulnerabilityRow {
  app_id: string;
  app_name: string;
  version: string;
  vulnerability_id: number;
  cve_id: string;
  title: string | null;
  severity: string | null;
  cvss_score: number | null;
  asset_id: number;
  asset: string;
  match: string;
}

export const VULN_LIST_LIMIT = 1000;

/** Open vulnerabilities by application (the page's Vulnerabilities tab). */
export async function listApplicationVulnerabilities(filters: { app?: string; severity?: string } = {}): Promise<ApplicationVulnerabilityRow[]> {
  const params: unknown[] = [VULN_LIST_LIMIT];
  const where: string[] = [];
  if (filters.app) {
    params.push(filters.app);
    where.push(`l.app_id = $${params.length}`);
  }
  if (filters.severity) {
    params.push(filters.severity.toLowerCase());
    where.push(`lower(v.severity) = $${params.length}`);
  }
  const { rows } = await query(
    `SELECT l.app_id, s.name AS app_name, l.version, l.vulnerability_id, v.cve_id, v.title, v.severity, v.cvss_score::float AS cvss_score,
            l.asset_id, COALESCE(a.hostname, host(a.ip_address)) AS asset, l.match
       FROM application_vuln_links l
       JOIN application_signatures s ON s.id = l.app_id
       JOIN vulnerabilities v ON v.id = l.vulnerability_id
       JOIN assets a ON a.id = l.asset_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY v.cvss_score DESC NULLS LAST, s.name, v.cve_id
      LIMIT $1`,
    params
  );
  return rows;
}

export interface UnmatchedItem {
  source: string;
  value: string;
  events: number;
  locations: number;
  first_seen: string;
  last_seen: string;
  sample_location: string | null;
  sample: string | null;
  suggest_url: string;
}

/** A starting signature for a value nothing matched, for the catalog's new-file page. Pure. */
export function suggestedSignature(source: string, value: string, sample: string | null): { path: string; yaml: string } {
  const id = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || 'new-application';
  const q = (s: string) => `'${s.replace(/'/g, "''")}'`;
  const esc = value.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  let match: string;
  let test: string;
  if (source === 'syslog_program') {
    match = `  syslog_program: [${q(value)}]`;
    test = `  - source: syslog_program\n    input: ${q(value)}`;
  } else if (source === 'container') {
    match = `  container_image: [${q(value)}]`;
    test = `  - source: container_image\n    input: ${q(sample ?? value)}`;
  } else {
    match = `  user_agent:\n    - ${q(`\\b${esc}/(\\d+(?:\\.\\d+)*)`)}`;
    test = `  - source: user_agent\n    input: ${q(sample ?? `${value}/1.0`)}`;
  }
  const yaml = [
    `schema: ${APP_SCHEMA}`,
    `id: ${id}`,
    `name: ${q(value)}`,
    `vendor: ${q('TODO')}`,
    `category: TODO`,
    `description: ${q('TODO: what it is.')}`,
    `match:`,
    match,
    `tests:`,
    test,
    '',
  ].join('\n');
  return { path: `applications/${id}${APP_FILE_SUFFIX}`, yaml };
}

export const UNMATCHED_LIMIT = 100;

export async function listUnmatched(source?: string, limit = UNMATCHED_LIMIT): Promise<UnmatchedItem[]> {
  const params: unknown[] = [Math.min(Math.max(1, limit), 500)];
  let where = '';
  if (source && ['syslog_program', 'container', 'user_agent'].includes(source)) {
    params.push(source);
    where = `WHERE source = $2`;
  }
  const { rows } = await query(
    `SELECT * FROM (
       SELECT u.*, row_number() OVER (PARTITION BY source ORDER BY events DESC, last_seen DESC) AS rank FROM application_unmatched u ${where}
     ) r WHERE rank <= $1 ORDER BY source, events DESC`,
    params
  );
  return rows.map((r) => {
    const s = suggestedSignature(r.source, r.value, r.sample);
    return {
      source: r.source,
      value: r.value,
      events: Number(r.events),
      locations: Number(r.locations),
      first_seen: iso(r.first_seen),
      last_seen: iso(r.last_seen),
      sample_location: r.sample_location,
      sample: r.sample,
      suggest_url: catalogNewFileUrl(s.path, s.yaml),
    };
  });
}
