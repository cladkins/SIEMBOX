/**
 * The Big Display's panel kinds (docs/architecture/BIG-DISPLAY.md §5.3, §7.7):
 * for each, the routes whose data it mirrors, how long its data is cached,
 * its fixed SQL, and how its rows become the panel's data.
 *
 * - Panel kinds, their one enum parameter and the lowest role that may see
 *   them are declared once, in config.ts; this file adds the rest. A display
 *   link may only use kinds with minRole 'viewer', and each such kind's
 *   viewerRoutes must be routes every signed-in role can read (the route
 *   inventory test checks both), so a link never shows what some role can't.
 * - fetch() runs fixed SQL in a READ ONLY transaction with a 4 s statement
 *   timeout (snapshot.ts). Its result doesn't depend on the display's privacy
 *   level, so one cached fetch serves every screen; shape() applies the
 *   privacy level on every request. The SQL never selects an alert's title,
 *   description or matched_data beyond source_ip and country_code, log text,
 *   usernames, account names, breach names or domains.
 * - The fold functions are pure and exported for the tests.
 *
 * Timestamps: alerts.created_at, raw_logs.created_at and
 * parser_match_hourly.hour are TIMESTAMP (without time zone). Windows compare
 * against NOW() as the rest of the code does; hourly buckets use
 * LOCALTIMESTAMP, the session-local clock DEFAULT NOW() wrote with. Both
 * assume the backend and the database share a time zone, as
 * /api/logs/parse-coverage does (both UTC in the shipped images).
 * ingest_source_minute.minute is TIMESTAMPTZ.
 */
import { OFFLINE_THRESHOLD_MINUTES } from '../../models/EdrAgent';
import { getExposureHeadline } from '../../models/Exposure';
import { RECENT_MINUTES } from '../ingest/ingestCounter';
import { calculateStatus } from '../shippers/status';
import type { ReadOnlyQuery } from '../shippers/snapshotCache';
import { SHIPPER_HASHES_SQL } from '../shippers/unknownSources';
import { getIngestQueueStats } from '../syslog/ingestStats';
import { PANEL_KINDS as CONFIG_KINDS, type PanelId, type PanelSpec, type Privacy } from './config';
import { NOT_CONFIGURED, alertLabel, categoryOf, configLabel, safeCountry, safeHost, safeIp } from './redact';
import {
  SEVERITIES,
  type AlertPulse,
  type DigitalRisk,
  type Endpoints,
  type Ingest,
  type IngestState,
  type OpenAlerts,
  type PanelData,
  type RecentAlerts,
  type Sev,
  type Shippers,
  type SourceState,
  type Sources,
  type ThreatMap,
  type TopRules,
  type TopSources,
  type Vulnerabilities,
} from './types';

/* eslint-disable @typescript-eslint/no-explicit-any -- rows are whatever pg returns for the fixed SQL below */

// --- Helpers ---------------------------------------------------------------------

const MINUTE = 60_000;
const iso = (value: Date | string | number | null | undefined): string | null =>
  value === null || value === undefined ? null : new Date(value).toISOString();
const int = (value: unknown): number => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
};
const round1 = (n: number) => Math.round(n * 10) / 10;
const minuteOf = (value: Date | string | number) => Math.floor(new Date(value).getTime() / MINUTE);
const zeroSevs = (): Record<Sev, number> => ({ critical: 0, high: 0, medium: 0, low: 0 });
const isSev = (value: unknown): value is Sev => SEVERITIES.includes(value as Sev);
const SEV_BY_RANK: Record<number, Sev> = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' };
const sevOfRank = (rank: unknown): Sev => SEV_BY_RANK[int(rank)] ?? 'low';

/** What shape() returns: the panel's data, or that it isn't set up (with the fixed wording). */
export type Shaped = { data: PanelData } | { not_configured: string };

const notConfigured = (id: PanelId): Shaped => ({ not_configured: NOT_CONFIGURED[id]! });

// --- SQL ------------------------------------------------------------------------

export const SQL = {
  /** Index-only on idx_alerts_open_severity (042). */
  open_alerts: `
    SELECT severity, COUNT(*)::int AS open, COUNT(*) FILTER (WHERE status = 'new')::int AS untouched,
           MIN(created_at) AS oldest_at
      FROM alerts WHERE status IN ('new', 'investigating') GROUP BY severity`,
  pulse_hourly: `
    SELECT g.start, COALESCE(a.total, 0)::int AS total, COALESCE(a.critical, 0)::int AS critical
      FROM generate_series(date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '23 hours',
                           date_trunc('hour', LOCALTIMESTAMP), INTERVAL '1 hour') AS g(start)
      LEFT JOIN (SELECT date_trunc('hour', created_at) AS start, COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE severity = 'critical') AS critical
                   FROM alerts WHERE created_at >= date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '23 hours'
                  GROUP BY 1) a ON a.start = g.start
     ORDER BY g.start`,
  pulse_totals: `
    SELECT COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS total_24h,
           COUNT(*) FILTER (WHERE created_at <  NOW() - INTERVAL '24 hours')::int AS prev_24h,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour')::int  AS last_hour,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND severity = 'critical')::int AS critical,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND severity = 'high')::int AS high,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND severity = 'medium')::int AS medium,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND severity = 'low')::int AS low
      FROM alerts WHERE created_at >= NOW() - INTERVAL '48 hours'`,
  /** $1 = the severities at or above the floor. The 7th row only sets `more`. */
  recent_alerts: `
    SELECT a.severity, a.status, a.created_at, a.source, r.name AS rule_name
      FROM alerts a LEFT JOIN detection_rules r ON r.id = a.rule_id
     WHERE a.status IN ('new', 'investigating') AND a.severity = ANY ($1::text[])
       AND a.created_at >= NOW() - INTERVAL '24 hours'
     ORDER BY a.created_at DESC LIMIT 7`,
  /** $1 = window hours. */
  top_rules: `
    SELECT a.rule_id, r.name AS rule_name, a.source, COUNT(*)::int AS n,
           MAX(CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS worst
      FROM alerts a LEFT JOIN detection_rules r ON r.id = a.rule_id
     WHERE a.created_at >= NOW() - make_interval(hours => $1)
     GROUP BY a.rule_id, r.name, a.source ORDER BY n DESC LIMIT 6`,
  /** $1 = window hours. */
  top_rules_total: `SELECT COUNT(*)::int AS n FROM alerts WHERE created_at >= NOW() - make_interval(hours => $1)`,
  last_log: `SELECT MAX(created_at) AS last_log_at FROM raw_logs`,
  /** The oldest minute the rollup holds (the primary key leads with minute). */
  rollup_since: `SELECT MIN(minute) AS since FROM ingest_source_minute`,
  /** Every source and the overflow row: per-minute totals stay exact. */
  rollup_minutes: `
    SELECT minute, SUM(logs)::bigint AS logs FROM ingest_source_minute
     WHERE minute >= NOW() - INTERVAL '24 hours' GROUP BY minute`,
  /** Only while the rollup holds under 2 minutes. */
  raw_last_minute: `SELECT COUNT(*)::int AS n FROM raw_logs WHERE created_at >= NOW() - INTERVAL '1 minute'`,
  parser_hourly: `
    SELECT g.hour, COALESCE(SUM(p.matches), 0)::bigint AS total,
           COALESCE(SUM(p.matches) FILTER (WHERE p.parser_id = 0), 0)::bigint AS unparsed
      FROM generate_series(date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '23 hours',
                           date_trunc('hour', LOCALTIMESTAMP), INTERVAL '1 hour') AS g(hour)
      LEFT JOIN parser_match_hourly p ON p.hour = g.hour
     GROUP BY g.hour ORDER BY g.hour`,
  stall_setting: `SELECT value FROM system_settings WHERE key = 'notify_ingestion_stall_minutes'`,
  /**
   * Per source over 24 h. last_established: the last minute it had a row as one
   * of the counter's established sources (ingestCounter.ts), which it keeps
   * for RECENT_MINUTES: in those minutes it always gets its own row.
   */
  sources: `
    SELECT source_kind, source_key, MAX(minute) AS last_minute, COUNT(*)::int AS active_minutes,
           MAX(minute) FILTER (WHERE established) AS last_established,
           COALESCE(SUM(logs) FILTER (WHERE minute >= date_trunc('minute', NOW()) - INTERVAL '15 minutes'
                                        AND minute <  date_trunc('minute', NOW())), 0)::bigint AS logs_15m,
           SUM(logs)::bigint AS logs_24h
      FROM ingest_source_minute
     WHERE minute >= NOW() - INTERVAL '24 hours' AND source_kind <> 'overflow'
     GROUP BY 1, 2`,
  /** Minutes in which some source's logs were counted only in the overflow row. */
  overflow_minutes: `
    SELECT minute FROM ingest_source_minute
     WHERE minute >= NOW() - INTERVAL '24 hours' AND source_kind = 'overflow' AND logs > 0`,
  /** $1 = shipper keys; name is NULL for an unknown (ghost) shipper. */
  shipper_names: `
    WITH ${SHIPPER_HASHES_SQL}
    SELECT k.key, s.name
      FROM unnest($1::text[]) AS k(key)
      LEFT JOIN LATERAL (SELECT sh.name FROM shipper_hashes sh
                          WHERE k.key IN (sh.md5_id, sh.sha256_id, sh.http_push_id)
                          ORDER BY sh.id LIMIT 1) s ON true`,
  /** $1 = discovery source ids. */
  poller_hosts: `SELECT id, hostname, host(ip_address) AS ip FROM discovery_sources WHERE id = ANY ($1::int[])`,
  /** $1 = sender addresses (valid IPs only). */
  asset_hosts: `
    SELECT DISTINCT ON (ip_address) host(ip_address) AS ip, hostname
      FROM assets WHERE ip_address = ANY ($1::inet[]) ORDER BY ip_address, id`,
  shippers: `SELECT id, name, status, last_seen FROM log_shippers`,
  unknown_shippers: `
    WITH ${SHIPPER_HASHES_SQL}
    SELECT COUNT(DISTINCT m.source_key)::int AS n
      FROM ingest_source_minute m
     WHERE m.minute >= NOW() - INTERVAL '24 hours' AND m.source_kind = 'shipper'
       AND NOT EXISTS (SELECT 1 FROM shipper_hashes sh WHERE m.source_key IN (sh.md5_id, sh.sha256_id, sh.http_push_id))`,
  /** $1 = OFFLINE_THRESHOLD_MINUTES. */
  endpoint_counts: `
    SELECT COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE last_seen > NOW() - make_interval(mins => $1))::int AS online
      FROM edr_agents`,
  endpoint_offline: `
    SELECT hostname, last_seen FROM edr_agents
     WHERE last_seen IS NULL OR last_seen <= NOW() - make_interval(mins => $1)
     ORDER BY last_seen ASC NULLS FIRST LIMIT 7`,
  endpoint_detections: `SELECT COUNT(*)::int AS n FROM alerts WHERE source = 'edr' AND created_at >= NOW() - INTERVAL '24 hours'`,
  /** $1 = window days. Codes are validated here and again in Node. */
  threat_map: `
    SELECT matched_data->>'country_code' AS code, COUNT(*)::int AS n
      FROM alerts WHERE created_at >= NOW() - make_interval(days => $1)
       AND matched_data->>'country_code' ~ '^[A-Z]{2}$'
     GROUP BY 1 ORDER BY n DESC LIMIT 50`,
  threat_map_total: `SELECT COUNT(*)::int AS n FROM alerts WHERE created_at >= NOW() - make_interval(days => $1)`,
  /** Node keeps the first 6 that pass net.isIP(). */
  top_sources: `
    SELECT matched_data->>'source_ip' AS ip, MAX(matched_data->>'country_code') AS cc, COUNT(*)::int AS n,
           MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS worst,
           MAX(created_at) AS last_at
      FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours' AND matched_data ? 'source_ip'
     GROUP BY 1 ORDER BY n DESC LIMIT 10`,
  /** The getVulnerabilityStats() counts, open only. */
  vulnerabilities: `
    SELECT COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'critical')::int AS critical,
           COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'high')::int AS high,
           COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'medium')::int AS medium,
           COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'low')::int AS low,
           COUNT(DISTINCT av.asset_id) FILTER (WHERE av.status = 'open')::int AS affected_assets,
           COUNT(*)::int AS total
      FROM asset_vulnerabilities av JOIN vulnerabilities v ON av.vulnerability_id = v.id`,
  vulnerability_scans: `SELECT EXISTS (SELECT 1 FROM vulnerability_scans) AS any`,
} as const;

/** Example parameters for each statement, for the plan-shape tests. */
export const SQL_PARAMS: Readonly<Partial<Record<keyof typeof SQL, unknown[]>>> = {
  recent_alerts: [['critical', 'high']],
  top_rules: [24],
  top_rules_total: [24],
  shipper_names: [['0123abcd']],
  poller_hosts: [[1]],
  asset_hosts: [['192.0.2.1']],
  endpoint_counts: [OFFLINE_THRESHOLD_MINUTES],
  endpoint_offline: [OFFLINE_THRESHOLD_MINUTES],
  threat_map: [7],
  threat_map_total: [7],
};

// --- Folds: alerts -----------------------------------------------------------------

export function foldOpenAlerts(rows: any[]): OpenAlerts {
  const by_severity = Object.fromEntries(
    SEVERITIES.map((sev) => [sev, { open: 0, untouched: 0, oldest_at: null as string | null }])
  ) as OpenAlerts['by_severity'];
  let total = 0;
  for (const row of rows) {
    const sev: unknown = row.severity;
    if (!isSev(sev)) continue;
    by_severity[sev] = { open: int(row.open), untouched: int(row.untouched), oldest_at: iso(row.oldest_at) };
    total += int(row.open);
  }
  return { total, by_severity };
}

export function foldPulse(hourly: any[], totals: any): AlertPulse {
  const hours = hourly.slice(-24).map((row) => ({ total: int(row.total), critical: int(row.critical) }));
  while (hours.length < 24) hours.unshift({ total: 0, critical: 0 });
  return {
    total_24h: int(totals?.total_24h),
    prev_24h: int(totals?.prev_24h),
    last_hour: int(totals?.last_hour),
    by_severity_24h: { critical: int(totals?.critical), high: int(totals?.high), medium: int(totals?.medium), low: int(totals?.low) },
    hourly: hours,
  };
}

/** The severities at or above a floor. */
export function severitiesFrom(floor: Sev): Sev[] {
  return SEVERITIES.slice(0, SEVERITIES.indexOf(floor) + 1);
}

export function foldRecentAlerts(rows: any[], minSeverity: Sev, privacy: Privacy): RecentAlerts {
  const items: RecentAlerts['items'] = [];
  for (const row of rows.slice(0, 6)) {
    if (!isSev(row.severity) || (row.status !== 'new' && row.status !== 'investigating')) continue;
    const category = categoryOf(row.source ?? null);
    items.push({ severity: row.severity, status: row.status, category, label: alertLabel(category, row.rule_name, privacy), at: iso(row.created_at)! });
  }
  return { min_severity: minSeverity, more: rows.length > 6, items };
}

export function foldTopRules(rows: any[], total: number, windowHours: 1 | 24, privacy: Privacy): TopRules {
  // In public mode several rules share the label "Detection rule": merge them.
  const items: TopRules['items'] = [];
  for (const row of rows) {
    const category = categoryOf(row.source ?? null);
    const label = alertLabel(category, row.rule_name, privacy);
    const worst = sevOfRank(row.worst);
    const same = items.find((item) => item.category === category && item.label === label);
    if (same) {
      same.count += int(row.n);
      if (SEVERITIES.indexOf(worst) < SEVERITIES.indexOf(same.worst_severity)) same.worst_severity = worst;
    } else {
      items.push({ category, label, worst_severity: worst, count: int(row.n) });
    }
  }
  items.sort((a, b) => b.count - a.count);
  return { window_hours: windowHours, total, items: items.slice(0, 6) };
}

// --- Folds: ingest ----------------------------------------------------------------

/** The rollup needs this many minutes before the screen reads from it rather than raw_logs. */
export const ROLLUP_MIN_MINUTES = 2;
/** ...and this many before it has a baseline (and so a "slow" state). */
export const BASELINE_MIN_MINUTES = 60;
/** "Slow" needs a baseline of at least this many logs per minute... */
export const SLOW_MIN_BASELINE = 20;
/** ...and a 15-minute rate below this share of it. */
export const SLOW_RATIO = 0.25;

/** idle: no log in 24 h; stalled: none for stall_minutes; slow (with the rollup only): well under the usual rate. */
export function ingestState(input: {
  lastLogAt: number | null;
  at: number;
  stallMinutes: number;
  rate15: number | null;
  baseline: number | null;
}): IngestState {
  const { lastLogAt, at, stallMinutes, rate15, baseline } = input;
  if (lastLogAt === null || at - lastLogAt >= 24 * 60 * MINUTE) return 'idle';
  if (at - lastLogAt >= stallMinutes * MINUTE) return 'stalled';
  if (rate15 !== null && baseline !== null && baseline >= SLOW_MIN_BASELINE && rate15 < SLOW_RATIO * baseline) return 'slow';
  return 'flowing';
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export interface IngestRaw {
  lastLogAt: string | null;
  rollupSince: string | null;
  /** [minute ISO, logs] over 24 h. */
  minutes: Array<[string, number]>;
  rawLastMinute: number | null;
  hourly: Array<{ total: number; unparsed: number }>;
  stallMinutes: number;
  udpDropped15m: number | null;
}

export function foldIngest(raw: IngestRaw, at: number): Ingest {
  const nowMinute = Math.floor(at / MINUTE);
  const sinceMinute = raw.rollupSince ? minuteOf(raw.rollupSince) : null;
  const covered = sinceMinute === null ? 0 : nowMinute - sinceMinute; // complete minutes the rollup holds
  const hasRollup = covered >= ROLLUP_MIN_MINUTES;
  const byMinute = new Map(raw.minutes.map(([minute, logs]) => [minuteOf(minute), logs]));
  const logsAt = (m: number) => byMinute.get(m) ?? 0;

  let perMinute: number[] | null = null;
  let lastMinute = raw.rawLastMinute;
  let rate15: number | null = null;
  let baseline: number | null = null;
  if (hasRollup) {
    perMinute = Array.from({ length: 60 }, (_, i) => logsAt(nowMinute - 59 + i));
    lastMinute = logsAt(nowMinute - 1);
    const span = Math.min(15, covered);
    let sum = 0;
    for (let m = nowMinute - span; m < nowMinute; m++) sum += logsAt(m);
    rate15 = round1(sum / span);
    const baselineSpan = Math.min(1440, covered);
    if (baselineSpan >= BASELINE_MIN_MINUTES) {
      const values: number[] = [];
      for (let m = nowMinute - baselineSpan; m < nowMinute; m++) values.push(logsAt(m));
      baseline = round1(median(values));
    }
  }

  const hourly = raw.hourly.slice(-24);
  while (hourly.length < 24) hourly.unshift({ total: 0, unparsed: 0 });
  const total = hourly.reduce((n, h) => n + h.total, 0);
  const unparsed = hourly.reduce((n, h) => n + h.unparsed, 0);
  const lastLogAt = raw.lastLogAt ? new Date(raw.lastLogAt).getTime() : null;
  return {
    state: ingestState({ lastLogAt, at, stallMinutes: raw.stallMinutes, rate15, baseline }),
    last_log_at: iso(lastLogAt),
    stall_minutes: raw.stallMinutes,
    logs_last_minute: lastMinute,
    per_minute: perMinute,
    rate_15m_per_minute: rate15,
    baseline_per_minute: baseline,
    hourly,
    parsed_pct_24h: total > 0 ? round1(((total - unparsed) / total) * 100) : null,
    udp_dropped_15m: raw.udpDropped15m,
    rollup_since: raw.rollupSince,
  };
}

/**
 * UDP drops over the last 15 minutes, from the syslog queue's running
 * `dropped` counter: one sample a minute is kept (16 in all), and the answer
 * is the counter now minus the newest sample at least 15 minutes old (the
 * oldest, until there is one). Null with no syslog server running.
 */
export function createDropTracker(read: () => { dropped: number } | null = getIngestQueueStats) {
  const samples: Array<{ at: number; dropped: number }> = [];
  return {
    dropped15m(at: number): number | null {
      const stats = read();
      if (!stats) return null;
      const dropped = int(stats.dropped);
      // A restarted server starts counting again from 0.
      if (samples.length && dropped < samples[samples.length - 1].dropped) samples.length = 0;
      if (!samples.length || at - samples[samples.length - 1].at >= MINUTE) samples.push({ at, dropped });
      // The baseline is the newest sample at least 15 minutes old (or the oldest there is).
      while (samples.length > 16 || (samples.length > 1 && at - samples[1].at >= 15 * MINUTE)) samples.shift();
      return dropped - samples[0].dropped;
    },
  };
}

const drops = createDropTracker();

// --- Folds: sources -------------------------------------------------------------------

export interface SourceRaw {
  kind: 'shipper' | 'poller' | 'direct';
  key: string;
  lastMinute: string;
  lastEstablished: string | null;
  activeMinutes: number;
  logs15m: number;
  logs24h: number;
  /** Operations label, already validated: shipper name, or host name or address. Null = none (or an unknown shipper). */
  label: string | null;
  /** A shipper key that matches no registered shipper. */
  ghost: boolean;
}

export interface SourcesRaw {
  rollupSince: string | null;
  sources: SourceRaw[];
  /** Minutes (ISO) whose overflow row is non-zero. */
  overflowMinutes: string[];
}

/** Classification needs this much rollup; until then every source not logging is quiet. */
export const SOURCES_MIN_MINUTES = 60;

/**
 * One source's state. Silent is a steady source that stopped: it averaged at
 * least a log a minute over the window and logged in at least half of its
 * minutes (a bursty source that writes in batches is exempt: quiet), and has
 * logged nothing for silentAfter minutes. If some source's logs went to the
 * overflow row in a minute since, while this one wasn't sure of a row of its
 * own (no longer an established source), its silence can't be told: unknown.
 */
export function classifySource(
  source: Pick<SourceRaw, 'lastMinute' | 'lastEstablished' | 'activeMinutes' | 'logs24h'>,
  context: { at: number; silentAfter: number; observedMinutes: number; overflowMinutes: number[] }
): { state: SourceState; silentMinutes: number } {
  const nowMinute = Math.floor(context.at / MINUTE);
  const last = minuteOf(source.lastMinute);
  const silentMinutes = Math.max(0, nowMinute - last - 1);
  if (silentMinutes < context.silentAfter) return { state: 'active', silentMinutes };
  const observed = context.observedMinutes;
  const steady = observed >= SOURCES_MIN_MINUTES && source.logs24h >= observed && source.activeMinutes * 2 >= observed;
  if (!steady) return { state: 'quiet', silentMinutes };
  const established = source.lastEstablished ? minuteOf(source.lastEstablished) : null;
  const masked = context.overflowMinutes.some((m) => m > last && !(established !== null && m - established < RECENT_MINUTES));
  return { state: masked ? 'unknown' : 'silent', silentMinutes };
}

export function foldSources(raw: SourcesRaw, silentAfter: 5 | 15 | 30 | 60, privacy: Privacy, at: number): Sources {
  const nowMinute = Math.floor(at / MINUTE);
  const sinceMinute = raw.rollupSince ? minuteOf(raw.rollupSince) : null;
  const observedMinutes = sinceMinute === null ? 0 : Math.min(1440, nowMinute - sinceMinute);
  const overflowMinutes = raw.overflowMinutes.map(minuteOf);
  const classified = raw.sources.map((source) => ({
    source,
    ...classifySource(source, { at, silentAfter, observedMinutes, overflowMinutes }),
  }));
  const count = (state: SourceState) => classified.filter((c) => c.state === state).length;
  const silent = classified.filter((c) => c.state === 'silent').sort((a, b) => b.silentMinutes - a.silentMinutes);
  const unknown = classified.filter((c) => c.state === 'unknown').sort((a, b) => b.silentMinutes - a.silentMinutes);
  const active = classified.filter((c) => c.state === 'active').sort((a, b) => b.source.logs15m - a.source.logs15m);
  const listed = [...silent, ...unknown, ...active].slice(0, 8);
  const rows: Sources['rows'] =
    privacy === 'public'
      ? []
      : listed.map(({ source, state, silentMinutes }) => ({
          kind: source.kind,
          label: source.label,
          state,
          logs_per_minute: round1(source.logs15m / 15),
          last_seen_at: iso(source.lastMinute)!,
          silent_minutes: state === 'silent' || state === 'unknown' ? silentMinutes : null,
        }));
  const activeListed = rows.filter((row) => row.state === 'active').length;
  return {
    silent_after_minutes: silentAfter,
    active: active.length,
    silent: silent.length,
    quiet: count('quiet'),
    unknown: unknown.length,
    unknown_shippers: raw.sources.filter((s) => s.ghost).length,
    since: sinceMinute !== null && nowMinute - sinceMinute < 1440 ? iso(raw.rollupSince) : null,
    more_active: active.length - activeListed,
    rows,
  };
}

// --- Folds: the rest ---------------------------------------------------------------------

export function foldShippers(rows: any[], unknown24h: number | null, privacy: Privacy, at: number): Shippers {
  const out: Shippers = { total: rows.length, online: 0, offline: 0, pending: 0, error: 0, unknown_shippers_24h: unknown24h, offline_list: [] };
  const offline: Array<{ name: string; last: number | null }> = [];
  for (const row of rows) {
    const status = calculateStatus(row.last_seen, row.status, at);
    out[status]++;
    if (status === 'offline') {
      offline.push({ name: configLabel(row.name) ?? `Shipper ${int(row.id)}`, last: row.last_seen ? new Date(row.last_seen).getTime() : null });
    }
  }
  if (privacy === 'operations') {
    offline.sort((a, b) => (a.last ?? 0) - (b.last ?? 0));
    out.offline_list = offline.slice(0, 6).map((s) => ({ name: s.name, last_seen_at: iso(s.last) }));
  }
  return out;
}

export function foldEndpoints(counts: any, offline: any[], detections: number, privacy: Privacy): Endpoints {
  const total = int(counts?.total);
  const online = int(counts?.online);
  return {
    total,
    online,
    offline: Math.max(0, total - online),
    detections_24h: detections,
    offline_list:
      privacy === 'public' ? [] : offline.slice(0, 6).map((row) => ({ hostname: safeHost(row.hostname), last_seen_at: iso(row.last_seen) })),
  };
}

export function foldThreatMap(rows: any[], total: number, windowDays: 1 | 7 | 30): ThreatMap {
  const countries: ThreatMap['countries'] = [];
  for (const row of rows) {
    const code = safeCountry(row.code);
    if (code) countries.push({ code, count: int(row.n) });
  }
  return { window_days: windowDays, located: countries.reduce((n, c) => n + c.count, 0), total_in_window: total, countries: countries.slice(0, 50) };
}

export function foldTopSources(rows: any[], privacy: Privacy): TopSources {
  if (privacy === 'public') return { items: [] };
  const items: TopSources['items'] = [];
  for (const row of rows) {
    const ip = safeIp(row.ip);
    if (!ip) continue;
    items.push({ ip, country_code: safeCountry(row.cc), alerts: int(row.n), worst_severity: sevOfRank(row.worst), last_at: iso(row.last_at)! });
    if (items.length === 6) break;
  }
  return { items };
}

export function foldVulnerabilities(row: any, scansExist: boolean): Vulnerabilities {
  return {
    scanned: scansExist || int(row?.total) > 0,
    open_by_severity: { critical: int(row?.critical), high: int(row?.high), medium: int(row?.medium), low: int(row?.low) },
    affected_assets: int(row?.affected_assets),
  };
}

// --- The registry ---------------------------------------------------------------------

export interface PanelKindDef {
  id: PanelId;
  /** From config.ts: 'viewer', or 'admin' for endpoints. */
  minRole: 'viewer' | 'admin';
  /** The route inventory ids ('GET /api/alerts') whose data the panel mirrors. */
  viewerRoutes: readonly string[];
  ttlMs: number;
  /** Fixed SQL. Its result is cached and shared by every screen, whatever its privacy level. */
  fetch: (spec: PanelSpec, q: ReadOnlyQuery) => Promise<unknown>;
  /** The cached rows as this display's panel data. `at` is when they were fetched. */
  shape: (raw: any, spec: PanelSpec, privacy: Privacy, at: number) => Shaped;
}

const param = <T>(spec: PanelSpec, name: string): T => (spec as unknown as Record<string, T>)[name];

const DEFS: Record<PanelId, Omit<PanelKindDef, 'id' | 'minRole'>> = {
  open_alerts: {
    viewerRoutes: ['GET /api/alerts'],
    ttlMs: 15_000,
    fetch: async (_spec, q) => q(SQL.open_alerts),
    shape: (rows) => ({ data: foldOpenAlerts(rows) }),
  },
  alert_pulse: {
    viewerRoutes: ['GET /api/alerts/statistics'],
    ttlMs: 30_000,
    fetch: async (_spec, q) => ({ hourly: await q(SQL.pulse_hourly), totals: (await q(SQL.pulse_totals))[0] }),
    shape: (raw) => ({ data: foldPulse(raw.hourly, raw.totals) }),
  },
  recent_alerts: {
    viewerRoutes: ['GET /api/alerts', 'GET /api/rules'],
    ttlMs: 15_000,
    fetch: async (spec, q) => q(SQL.recent_alerts, [severitiesFrom(param<Sev>(spec, 'min_severity'))]),
    shape: (rows, spec, privacy) => ({ data: foldRecentAlerts(rows, param<Sev>(spec, 'min_severity'), privacy) }),
  },
  top_rules: {
    viewerRoutes: ['GET /api/alerts', 'GET /api/rules'],
    ttlMs: 30_000,
    fetch: async (spec, q) => {
      const hours = param<1 | 24>(spec, 'window_hours');
      return { rows: await q(SQL.top_rules, [hours]), total: int((await q(SQL.top_rules_total, [hours]))[0]?.n) };
    },
    shape: (raw, spec, privacy) => ({ data: foldTopRules(raw.rows, raw.total, param<1 | 24>(spec, 'window_hours'), privacy) }),
  },
  ingest: {
    viewerRoutes: ['GET /api/logs/parse-coverage', 'GET /api/logs/raw'],
    ttlMs: 15_000,
    fetch: async (_spec, q): Promise<IngestRaw> => {
      const [last] = await q(SQL.last_log);
      const [since] = await q(SQL.rollup_since);
      const rollupSince = iso(since?.since);
      const covered = rollupSince ? Math.floor(Date.now() / MINUTE) - minuteOf(rollupSince) : 0;
      const minutes = covered >= ROLLUP_MIN_MINUTES ? await q(SQL.rollup_minutes) : [];
      const rawLastMinute = covered >= ROLLUP_MIN_MINUTES ? null : int((await q(SQL.raw_last_minute))[0]?.n);
      const hourly = await q(SQL.parser_hourly);
      const [setting] = await q(SQL.stall_setting);
      return {
        lastLogAt: iso(last?.last_log_at),
        rollupSince,
        minutes: minutes.map((row: any) => [iso(row.minute)!, int(row.logs)] as [string, number]),
        rawLastMinute,
        hourly: hourly.map((row: any) => ({ total: int(row.total), unparsed: int(row.unparsed) })),
        stallMinutes: parseInt(setting?.value ?? '15', 10) || 15,
        udpDropped15m: drops.dropped15m(Date.now()),
      };
    },
    shape: (raw, _spec, _privacy, at) => ({ data: foldIngest(raw, at) }),
  },
  sources: {
    viewerRoutes: ['GET /api/shippers/unknown-sources', 'GET /api/shippers/direct-syslog-sources', 'GET /api/shippers'],
    ttlMs: 30_000,
    fetch: async (_spec, q): Promise<SourcesRaw> => {
      const [since] = await q(SQL.rollup_since);
      const rows = await q(SQL.sources);
      const overflow = await q(SQL.overflow_minutes);
      const keysOf = (kind: string) => rows.filter((r: any) => r.source_kind === kind).map((r: any) => String(r.source_key));
      const shipperKeys = keysOf('shipper');
      const pollerIds = keysOf('poller').filter((k: string) => /^\d{1,9}$/.test(k)).map(Number);
      const directIps = keysOf('direct').filter((k: string) => safeIp(k) !== null);
      const names = new Map<string, string | null>();
      if (shipperKeys.length) for (const r of await q(SQL.shipper_names, [shipperKeys])) names.set(r.key, r.name);
      const pollers = new Map<string, string | null>();
      if (pollerIds.length) for (const r of await q(SQL.poller_hosts, [pollerIds])) pollers.set(String(r.id), safeHost(r.hostname, r.ip));
      const assets = new Map<string, string | null>();
      if (directIps.length) for (const r of await q(SQL.asset_hosts, [directIps])) assets.set(r.ip, safeHost(r.hostname));
      return {
        rollupSince: iso(since?.since),
        overflowMinutes: overflow.map((r: any) => iso(r.minute)!),
        sources: rows.map((r: any): SourceRaw => {
          const key = String(r.source_key);
          const kind = r.source_kind as SourceRaw['kind'];
          const name = kind === 'shipper' ? names.get(key) ?? null : null;
          return {
            kind,
            key,
            lastMinute: iso(r.last_minute)!,
            lastEstablished: iso(r.last_established),
            activeMinutes: int(r.active_minutes),
            logs15m: int(r.logs_15m),
            logs24h: int(r.logs_24h),
            label: kind === 'shipper' ? configLabel(name) : kind === 'poller' ? pollers.get(key) ?? null : assets.get(key) ?? safeIp(key),
            ghost: kind === 'shipper' && name === null,
          };
        }),
      };
    },
    shape: (raw, spec, privacy, at) => ({ data: foldSources(raw, param<5 | 15 | 30 | 60>(spec, 'silent_after_minutes'), privacy, at) }),
  },
  shippers: {
    viewerRoutes: ['GET /api/shippers', 'GET /api/shippers/unknown-sources'],
    ttlMs: 30_000,
    fetch: async (_spec, q) => {
      const rows = await q(SQL.shippers);
      const [since] = await q(SQL.rollup_since);
      const unknown = since?.since ? int((await q(SQL.unknown_shippers))[0]?.n) : null;
      return { rows, unknown };
    },
    shape: (raw, _spec, privacy, at) =>
      raw.rows.length === 0 ? notConfigured('shippers') : { data: foldShippers(raw.rows, raw.unknown, privacy, at) },
  },
  endpoints: {
    // Admin-only (minRole 'admin'): signed-in admins only, never a display link.
    viewerRoutes: ['GET /api/edr/agents'],
    ttlMs: 30_000,
    fetch: async (_spec, q) => ({
      counts: (await q(SQL.endpoint_counts, [OFFLINE_THRESHOLD_MINUTES]))[0],
      offline: await q(SQL.endpoint_offline, [OFFLINE_THRESHOLD_MINUTES]),
      detections: int((await q(SQL.endpoint_detections))[0]?.n),
    }),
    shape: (raw, _spec, privacy) =>
      int(raw.counts?.total) === 0 ? notConfigured('endpoints') : { data: foldEndpoints(raw.counts, raw.offline, raw.detections, privacy) },
  },
  threat_map: {
    viewerRoutes: ['GET /api/alerts/by-country'],
    ttlMs: 60_000,
    fetch: async (spec, q) => {
      const days = param<1 | 7 | 30>(spec, 'window_days');
      return { rows: await q(SQL.threat_map, [days]), total: int((await q(SQL.threat_map_total, [days]))[0]?.n) };
    },
    shape: (raw, spec) => ({ data: foldThreatMap(raw.rows, raw.total, param<1 | 7 | 30>(spec, 'window_days')) }),
  },
  top_sources: {
    viewerRoutes: ['GET /api/alerts'],
    ttlMs: 60_000,
    fetch: async (_spec, q) => q(SQL.top_sources),
    shape: (rows, _spec, privacy) => ({ data: foldTopSources(rows, privacy) }),
  },
  digital_risk: {
    viewerRoutes: ['GET /api/exposure/status', 'GET /api/exposure/summary'],
    ttlMs: 300_000,
    fetch: async (_spec, q) => getExposureHeadline((sql, params) => q(sql, params as any[])),
    shape: (raw): Shaped => {
      if (!raw.configured) return notConfigured('digital_risk');
      const data: DigitalRisk = { ...raw, open_by_severity: { ...zeroSevs(), ...raw.open_by_severity } };
      return { data };
    },
  },
  vulnerabilities: {
    viewerRoutes: ['GET /api/vulnerabilities/summary'],
    ttlMs: 300_000,
    fetch: async (_spec, q) => ({ row: (await q(SQL.vulnerabilities))[0], scans: Boolean((await q(SQL.vulnerability_scans))[0]?.any) }),
    shape: (raw): Shaped => {
      const data = foldVulnerabilities(raw.row, raw.scans);
      return data.scanned ? { data } : notConfigured('vulnerabilities');
    },
  },
};

/** Every panel kind: config.ts's declaration plus the above. */
export const PANEL_KINDS: Readonly<Record<PanelId, PanelKindDef>> = Object.fromEntries(
  (Object.keys(CONFIG_KINDS) as PanelId[]).map((id) => [id, { id, minRole: CONFIG_KINDS[id].minRole, ...DEFS[id] }])
) as Record<PanelId, PanelKindDef>;
