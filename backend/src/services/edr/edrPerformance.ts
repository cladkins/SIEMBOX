/**
 * Machine performance from the endpoint agent (migration 055).
 *
 * Ingest (POST /api/edr/metrics, agents with the 'perf_metrics' capability):
 * a batch of per-minute samples and top-process snapshots. Each batch:
 *
 *   1. stores the samples it has not seen (edr_perf_samples, keyed by agent and
 *      timestamp, so an agent re-sending after an outage stores nothing twice);
 *   2. recomputes the hourly rollup (edr_perf_hourly) of every hour that got a
 *      new sample, from that hour's raw rows: idempotent, and late samples land
 *      in the right hour;
 *   3. upserts the newest headline numbers (edr_perf_latest, the Endpoints list);
 *   4. stores the process snapshots;
 *   5. evaluates the endpoint policy's thresholds (evaluatePerformance).
 *
 * Storage: raw samples EDR_PERF_RAW_DAYS (7) — what the 1h/6h/24h charts read;
 * hourly rollups EDR_PERF_HOURLY_DAYS (90) — the 7d/30d/90d charts, so a long
 * range reads at most ~2,200 rows whatever the fleet; process snapshots 7 days.
 * Pruned by the endpoint housekeeping job (jobs/edrAgentRelease.ts).
 *
 * Alerts: one open alert per endpoint, metric and target (a disk's mount
 * point) at a time. edr_perf_alert_state holds a row while it is open: a
 * breach opens it (and the alert, source 'edr-perf', through AlertModel and
 * the notification channels), a recovery (the value back below the threshold,
 * less a hysteresis margin, for a few minutes) deletes the row and notes the
 * recovery on the alert, which an analyst then closes. A value hovering at the
 * threshold therefore cannot raise a storm: it needs a full recovery before a
 * second alert.
 */
import crypto from 'crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { batchedDelete } from '../../utils/batchDelete';
import { ApiError } from '../../middleware/errorHandler';
import { AlertModel } from '../../models/Alert';
import { NotificationService } from '../notifications/notificationService';
import { isUuid } from './agentUpdate';
import { agentPerformance } from './scanPolicies';
import { PERF_METRICS, type PerfMetric, type PerfThreshold, type PolicyPerformance } from './perfConfig';

/** Heartbeat capability of an agent that reports performance. */
export const PERF_CAPABILITY = 'perf_metrics';
/** First agent release with PERF_CAPABILITY (shown to users of older agents). */
export const MIN_PERF_AGENT_VERSION = '0.0.23';
/** alerts.source of performance alerts. */
export const PERF_ALERT_SOURCE = 'edr-perf';

function envDays(name: string, def: number, min: number, max: number): number {
  const v = Number(process.env[name]);
  return Number.isInteger(v) && v >= min && v <= max ? v : def;
}
export const RAW_RETENTION_DAYS = envDays('EDR_PERF_RAW_DAYS', 7, 1, 31);
export const HOURLY_RETENTION_DAYS = envDays('EDR_PERF_HOURLY_DAYS', 90, 7, 730);
export const PROCESS_RETENTION_DAYS = RAW_RETENTION_DAYS;

/** Per-request bounds. A day of samples covers any outage the agent buffers (3 h). */
export const MAX_SAMPLES_PER_BATCH = 1440;
export const MAX_SNAPSHOTS_PER_BATCH = 48;
export const MAX_DISKS = 32;
export const MAX_INTERFACES = 32;
export const MAX_PROCESSES = 25;
/** Samples dated further ahead than this are refused (clock skew allowance). */
const FUTURE_SLACK_MS = 5 * 60_000;

/** Percentage points below the threshold a value must fall to count as recovered. */
export const RECOVERY_MARGIN = 3;
/** Minutes a value must stay below (threshold - margin) to recover (at most; fewer for short thresholds). */
export const RECOVERY_MINUTES = 5;
/** A disk alert whose mount stops being reported for this long closes. */
const MISSING_TARGET_MS = 60 * 60_000;
/** Thresholds are evaluated only on samples at most this old (not on a replay of old data). */
const EVALUATE_MAX_AGE_MS = 10 * 60_000;

// ---- Validation (pure) ----------------------------------------------------------

export interface CleanDisk {
  mount: string;
  fs: string | null;
  total: number;
  used: number;
  free: number;
  pct: number;
}
export interface CleanNet {
  iface: string;
  rx: number;
  tx: number;
}
export interface CleanSample {
  ts: string;
  cpu_pct: number;
  cpu_count: number | null;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  uptime_s: number | null;
  disks: CleanDisk[];
  net: CleanNet[];
}
export interface CleanProcess {
  pid: number;
  name: string;
  user: string | null;
  cpu_pct: number;
  mem_rss: number;
  mem_pct: number;
}
export interface CleanSnapshot {
  ts: string;
  by_cpu: CleanProcess[];
  by_mem: CleanProcess[];
}

const MAX_BYTES = 2 ** 53;

function num(v: unknown, min: number, max: number): number | null {
  return typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max ? v : null;
}
function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}
function round(v: number, places = 2): number {
  const f = 10 ** places;
  return Math.round(v * f) / f;
}
/** Printable text, without control characters, at most `max` characters; null when empty. */
function text(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s ? s.slice(0, max) : null;
}

/** A timestamp inside the raw retention window and not in the future, to the second; else null. */
export function cleanTimestamp(v: unknown, now: Date): string | null {
  if (typeof v !== 'string' || v.length > 40) return null;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) return null;
  if (ms > now.getTime() + FUTURE_SLACK_MS || ms < now.getTime() - RAW_RETENTION_DAYS * 86_400_000) return null;
  return new Date(Math.floor(ms / 1000) * 1000).toISOString();
}

/** The used share of a filesystem as df reports it: used / (used + available). */
export function diskPct(used: number, free: number): number {
  return used + free > 0 ? round((used / (used + free)) * 100, 1) : 0;
}

/** One agent sample, validated and bounded, or null when unusable (no time or memory total). */
export function cleanSample(raw: unknown, now: Date): CleanSample | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const ts = cleanTimestamp(r.ts, now);
  const memTotal = num(r.mem_total, 1, MAX_BYTES);
  if (!ts || memTotal === null) return null;
  const cpu = num(r.cpu_pct, 0, 1e6);
  const swapTotal = num(r.swap_total, 0, MAX_BYTES) ?? 0;
  const load = (v: unknown) => {
    const n = num(v, 0, 1e6);
    return n === null ? null : round(n);
  };
  const disks: CleanDisk[] = [];
  const seenMounts = new Set<string>();
  for (const d of Array.isArray(r.disks) ? r.disks.slice(0, MAX_DISKS * 2) : []) {
    if (!d || typeof d !== 'object') continue;
    const dd = d as Record<string, unknown>;
    const mount = text(dd.mount, 256);
    const total = num(dd.total, 1, MAX_BYTES);
    if (!mount || total === null || seenMounts.has(mount)) continue;
    const used = clamp(num(dd.used, 0, MAX_BYTES) ?? 0, 0, total);
    const free = clamp(num(dd.free, 0, MAX_BYTES) ?? 0, 0, total);
    seenMounts.add(mount);
    disks.push({ mount, fs: text(dd.fs, 32), total: Math.round(total), used: Math.round(used), free: Math.round(free), pct: diskPct(used, free) });
    if (disks.length === MAX_DISKS) break;
  }
  const net: CleanNet[] = [];
  const seenIfaces = new Set<string>();
  for (const n of Array.isArray(r.net) ? r.net.slice(0, MAX_INTERFACES * 2) : []) {
    if (!n || typeof n !== 'object') continue;
    const nn = n as Record<string, unknown>;
    const iface = text(nn.iface, 64);
    if (!iface || seenIfaces.has(iface)) continue;
    seenIfaces.add(iface);
    net.push({ iface, rx: round(num(nn.rx_bps, 0, 1e13) ?? 0), tx: round(num(nn.tx_bps, 0, 1e13) ?? 0) });
    if (net.length === MAX_INTERFACES) break;
  }
  const count = num(r.cpu_count, 1, 32767);
  const uptime = num(r.uptime_seconds, 0, 1e10);
  return {
    ts,
    cpu_pct: round(clamp(cpu ?? 0, 0, 100)),
    cpu_count: count === null ? null : Math.round(count),
    mem_total: Math.round(memTotal),
    mem_used: Math.round(clamp(num(r.mem_used, 0, MAX_BYTES) ?? 0, 0, memTotal)),
    swap_total: Math.round(swapTotal),
    swap_used: Math.round(clamp(num(r.swap_used, 0, MAX_BYTES) ?? 0, 0, swapTotal)),
    load1: load(r.load1),
    load5: load(r.load5),
    load15: load(r.load15),
    uptime_s: uptime === null ? null : Math.round(uptime),
    disks,
    net,
  };
}

function cleanProcess(raw: unknown): CleanProcess | null {
  if (!raw || typeof raw !== 'object') return null;
  const p = raw as Record<string, unknown>;
  const pid = num(p.pid, 0, 2 ** 31);
  const name = text(p.name, 128);
  if (pid === null || !name) return null;
  return {
    pid: Math.round(pid),
    name,
    user: text(p.user, 64),
    cpu_pct: round(num(p.cpu_pct, 0, 1e5) ?? 0),
    mem_rss: Math.round(num(p.mem_rss, 0, MAX_BYTES) ?? 0),
    mem_pct: round(clamp(num(p.mem_pct, 0, 1e3) ?? 0, 0, 100)),
  };
}

export function cleanSnapshot(raw: unknown, now: Date): CleanSnapshot | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const ts = cleanTimestamp(r.ts, now);
  if (!ts) return null;
  const list = (v: unknown) =>
    (Array.isArray(v) ? v.slice(0, MAX_PROCESSES) : []).map(cleanProcess).filter((x): x is CleanProcess => x !== null);
  const snap = { ts, by_cpu: list(r.by_cpu), by_mem: list(r.by_mem) };
  return snap.by_cpu.length + snap.by_mem.length > 0 ? snap : null;
}

/** The UTC hour a timestamp falls in, as ISO. */
export function hourOf(iso: string): string {
  const d = new Date(iso);
  d.setUTCMinutes(0, 0, 0);
  return d.toISOString();
}

// ---- Ingest ----------------------------------------------------------------------

export interface IngestResult {
  accepted: number;
  duplicate: number;
  rejected: number;
  processes: number;
  alerts_opened: number;
  alerts_recovered: number;
}

const ROLLUP_SQL = `
INSERT INTO edr_perf_hourly (agent_id, hour, samples, cpu_avg, cpu_max, mem_used_avg, mem_used_max, mem_total,
                             swap_used_avg, swap_total, load1_avg, load1_max, load5_avg, load15_avg, uptime_max,
                             disks, net, updated_at)
SELECT $1::uuid, h.hour, a.n, a.cpu_avg, a.cpu_max, a.mem_used_avg, a.mem_used_max, a.mem_total,
       a.swap_used_avg, a.swap_total, a.load1_avg, a.load1_max, a.load5_avg, a.load15_avg, a.uptime_max,
       d.disks, nt.net, NOW()
  FROM unnest($2::timestamptz[]) AS h(hour)
  CROSS JOIN LATERAL (
    SELECT COUNT(*)::int AS n, AVG(cpu_pct) AS cpu_avg, MAX(cpu_pct) AS cpu_max,
           ROUND(AVG(mem_used))::bigint AS mem_used_avg, MAX(mem_used) AS mem_used_max, MAX(mem_total) AS mem_total,
           ROUND(AVG(swap_used))::bigint AS swap_used_avg, MAX(swap_total) AS swap_total,
           AVG(load1) AS load1_avg, MAX(load1) AS load1_max, AVG(load5) AS load5_avg, AVG(load15) AS load15_avg,
           MAX(uptime_s) AS uptime_max
      FROM edr_perf_samples s
     WHERE s.agent_id = $1 AND s.ts >= h.hour AND s.ts < h.hour + INTERVAL '1 hour'
  ) a
  CROSS JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(jsonb_build_object('mount', mount, 'pct_avg', ROUND(pct_avg::numeric, 1),
                                                 'pct_max', ROUND(pct_max::numeric, 1), 'used', used, 'total', total)
                              ORDER BY mount), '[]'::jsonb) AS disks
      FROM (SELECT x->>'mount' AS mount, AVG((x->>'pct')::float8) AS pct_avg, MAX((x->>'pct')::float8) AS pct_max,
                   MAX((x->>'used')::bigint) AS used, MAX((x->>'total')::bigint) AS total
              FROM edr_perf_samples s, jsonb_array_elements(s.disks) x
             WHERE s.agent_id = $1 AND s.ts >= h.hour AND s.ts < h.hour + INTERVAL '1 hour'
             GROUP BY 1) dd
  ) d
  CROSS JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(jsonb_build_object('iface', iface, 'rx_avg', ROUND(rx_avg::numeric, 2),
                                                 'tx_avg', ROUND(tx_avg::numeric, 2), 'rx_max', rx_max, 'tx_max', tx_max)
                              ORDER BY iface), '[]'::jsonb) AS net
      FROM (SELECT x->>'iface' AS iface, AVG((x->>'rx')::float8) AS rx_avg, AVG((x->>'tx')::float8) AS tx_avg,
                   MAX((x->>'rx')::float8) AS rx_max, MAX((x->>'tx')::float8) AS tx_max
              FROM edr_perf_samples s, jsonb_array_elements(s.net) x
             WHERE s.agent_id = $1 AND s.ts >= h.hour AND s.ts < h.hour + INTERVAL '1 hour'
             GROUP BY 1) nn
  ) nt
 WHERE a.n > 0
ON CONFLICT (agent_id, hour) DO UPDATE SET
  samples = EXCLUDED.samples, cpu_avg = EXCLUDED.cpu_avg, cpu_max = EXCLUDED.cpu_max,
  mem_used_avg = EXCLUDED.mem_used_avg, mem_used_max = EXCLUDED.mem_used_max, mem_total = EXCLUDED.mem_total,
  swap_used_avg = EXCLUDED.swap_used_avg, swap_total = EXCLUDED.swap_total,
  load1_avg = EXCLUDED.load1_avg, load1_max = EXCLUDED.load1_max, load5_avg = EXCLUDED.load5_avg,
  load15_avg = EXCLUDED.load15_avg, uptime_max = EXCLUDED.uptime_max,
  disks = EXCLUDED.disks, net = EXCLUDED.net, updated_at = NOW()`;

/** Recompute the hourly rollups of these hours (ISO, on the hour) from the raw samples. */
export async function rollupHours(agentId: string, hours: string[]): Promise<number> {
  if (hours.length === 0) return 0;
  const r = await query(ROLLUP_SQL, [agentId, hours]);
  return r.rowCount ?? 0;
}

function headline(s: CleanSample) {
  let disk: CleanDisk | null = null;
  for (const d of s.disks) if (!disk || d.pct > disk.pct) disk = d;
  return {
    mem_pct: s.mem_total > 0 ? round((s.mem_used / s.mem_total) * 100, 1) : null,
    disk_max_pct: disk ? disk.pct : null,
    disk_max_mount: disk ? disk.mount : null,
  };
}

/** Store one agent batch (see the header). Malformed entries are counted in `rejected`, never fail the batch. */
export async function ingestMetrics(agentId: string, body: unknown, now: Date = new Date()): Promise<IngestResult> {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  if (!Array.isArray(b.samples) && !Array.isArray(b.processes)) {
    throw new ApiError(400, 'samples must be an array');
  }
  const rawSamples = Array.isArray(b.samples) ? b.samples : [];
  const rawSnaps = Array.isArray(b.processes) ? b.processes : [];
  if (rawSamples.length > MAX_SAMPLES_PER_BATCH) throw new ApiError(400, `At most ${MAX_SAMPLES_PER_BATCH} samples per request`);
  if (rawSnaps.length > MAX_SNAPSHOTS_PER_BATCH) throw new ApiError(400, `At most ${MAX_SNAPSHOTS_PER_BATCH} process snapshots per request`);

  const byTs = new Map<string, CleanSample>();
  let rejected = 0;
  for (const raw of rawSamples) {
    const s = cleanSample(raw, now);
    if (!s) rejected++;
    else byTs.set(s.ts, s); // the same minute twice in one batch: the later wins
  }
  const samples = [...byTs.values()].sort((x, y) => x.ts.localeCompare(y.ts));

  let accepted = 0;
  if (samples.length > 0) {
    const ins = await query(
      `INSERT INTO edr_perf_samples (agent_id, ts, cpu_pct, cpu_count, mem_total, mem_used, swap_total, swap_used,
                                     load1, load5, load15, uptime_s, disks, net)
       SELECT $1::uuid, r.ts, r.cpu_pct, r.cpu_count, r.mem_total, r.mem_used, r.swap_total, r.swap_used,
              r.load1, r.load5, r.load15, r.uptime_s, r.disks, r.net
         FROM jsonb_to_recordset($2::jsonb) AS r(ts timestamptz, cpu_pct real, cpu_count smallint, mem_total bigint,
              mem_used bigint, swap_total bigint, swap_used bigint, load1 real, load5 real, load15 real,
              uptime_s bigint, disks jsonb, net jsonb)
       ON CONFLICT (agent_id, ts) DO NOTHING
       RETURNING ts`,
      [agentId, JSON.stringify(samples)]
    );
    accepted = ins.rowCount ?? 0;
    const hours = [...new Set(ins.rows.map((r: { ts: Date }) => hourOf(new Date(r.ts).toISOString())))];
    await rollupHours(agentId, hours);

    const newest = samples[samples.length - 1];
    const h = headline(newest);
    await query(
      `INSERT INTO edr_perf_latest (agent_id, ts, cpu_pct, mem_pct, disk_max_pct, disk_max_mount, load1, uptime_s, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       ON CONFLICT (agent_id) DO UPDATE SET
         ts = EXCLUDED.ts, cpu_pct = EXCLUDED.cpu_pct, mem_pct = EXCLUDED.mem_pct, disk_max_pct = EXCLUDED.disk_max_pct,
         disk_max_mount = EXCLUDED.disk_max_mount, load1 = EXCLUDED.load1, uptime_s = EXCLUDED.uptime_s, updated_at = NOW()
       WHERE edr_perf_latest.ts <= EXCLUDED.ts`,
      [agentId, newest.ts, newest.cpu_pct, h.mem_pct, h.disk_max_pct, h.disk_max_mount, newest.load1, newest.uptime_s]
    );
  }

  const snaps: CleanSnapshot[] = [];
  for (const raw of rawSnaps) {
    const s = cleanSnapshot(raw, now);
    if (s) snaps.push(s);
    else rejected++;
  }
  let processes = 0;
  if (snaps.length > 0) {
    const ins = await query(
      `INSERT INTO edr_perf_processes (agent_id, ts, by_cpu, by_mem)
       SELECT $1::uuid, r.ts, r.by_cpu, r.by_mem
         FROM jsonb_to_recordset($2::jsonb) AS r(ts timestamptz, by_cpu jsonb, by_mem jsonb)
       ON CONFLICT (agent_id, ts) DO NOTHING`,
      [agentId, JSON.stringify(snaps)]
    );
    processes = ins.rowCount ?? 0;
  }

  let opened = 0;
  let recovered = 0;
  if (accepted > 0) {
    try {
      ({ opened, recovered } = await evaluatePerformance(agentId, now));
    } catch (err) {
      logger.warn('[EDR] performance threshold evaluation failed', {
        agentId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return { accepted, duplicate: samples.length - accepted, rejected, processes, alerts_opened: opened, alerts_recovered: recovered };
}

// ---- Thresholds (pure) -----------------------------------------------------------

/** A value at a time (ms), newest first. */
export interface SeriesPoint {
  t: number;
  v: number;
}

/**
 * Whether a series (newest first) breaches a threshold: with `minutes` 0 or 1
 * the newest value is above it; otherwise every value in the last `minutes`
 * is above it AND the samples cover that span (at least 80% of the expected
 * one-a-minute samples, reaching back at least minutes - 1 minutes), so an
 * agent that just started or was offline does not alert on two samples.
 */
export function isBreach(series: SeriesPoint[], th: Pick<PerfThreshold, 'percent' | 'minutes'>): boolean {
  if (series.length === 0) return false;
  const newest = series[0].t;
  if (th.minutes <= 1) return series[0].v > th.percent;
  const window = series.filter((p) => p.t > newest - th.minutes * 60_000);
  const oldest = window[window.length - 1].t;
  if (window.length < Math.ceil(th.minutes * 0.8)) return false;
  if (newest - oldest < (th.minutes - 1) * 60_000 - 30_000) return false;
  return window.every((p) => p.v > th.percent);
}

/** The level a value must fall below to count as recovered. */
export function recoveryLevel(percent: number): number {
  return percent - Math.min(RECOVERY_MARGIN, percent / 4);
}

/**
 * Whether an open alert's series (newest first) has recovered: every value in
 * the last min(minutes, RECOVERY_MINUTES) minutes (at least the newest) is
 * below the threshold less the margin.
 */
export function isRecovered(series: SeriesPoint[], th: Pick<PerfThreshold, 'percent' | 'minutes'>): boolean {
  if (series.length === 0) return false;
  const span = Math.max(1, Math.min(th.minutes, RECOVERY_MINUTES));
  const newest = series[0].t;
  const window = span <= 1 ? [series[0]] : series.filter((p) => p.t > newest - span * 60_000);
  const level = recoveryLevel(th.percent);
  return window.every((p) => p.v < level);
}

interface EvalSample {
  ts: Date;
  cpu_pct: number;
  mem_used: string | number;
  mem_total: string | number;
  disks: CleanDisk[] | null;
}

/** Per metric and target, the series (newest first) from samples (newest first). */
export function seriesFrom(samples: EvalSample[]): Map<string, SeriesPoint[]> {
  const out = new Map<string, SeriesPoint[]>();
  const push = (key: string, t: number, v: number) => {
    const list = out.get(key);
    if (list) list.push({ t, v });
    else out.set(key, [{ t, v }]);
  };
  for (const s of samples) {
    const t = new Date(s.ts).getTime();
    push('cpu\u0000', t, Number(s.cpu_pct));
    const total = Number(s.mem_total);
    if (total > 0) push('memory\u0000', t, (Number(s.mem_used) / total) * 100);
    for (const d of Array.isArray(s.disks) ? s.disks : []) {
      if (typeof d?.mount === 'string' && typeof d.pct === 'number') push(`disk\u0000${d.mount}`, t, d.pct);
    }
  }
  return out;
}

const METRIC_LABEL: Record<PerfMetric, string> = { cpu: 'CPU', memory: 'Memory', disk: 'Disk' };

function alertText(metric: PerfMetric, target: string, host: string, value: number, th: PerfThreshold) {
  const v = round(value, 1);
  const sustained = th.minutes > 1 ? ` for ${th.minutes} minutes` : '';
  if (metric === 'disk') {
    return {
      title: `Disk ${target} ${v}% full on ${host}`,
      description: `The ${target} filesystem on ${host} is ${v}% full (threshold ${th.percent}%${sustained}).`,
    };
  }
  return {
    title: `${METRIC_LABEL[metric]} above ${th.percent}%${sustained} on ${host}`,
    description: `${METRIC_LABEL[metric]} use on ${host} has been above ${th.percent}%${sustained || ''}; now ${v}%.`,
  };
}

// ---- Thresholds (DB) -------------------------------------------------------------

interface OpenState {
  metric: PerfMetric;
  target: string;
  alert_id: number | null;
  opened_at: Date;
  last_seen_at: Date;
}

async function recover(agentId: string, s: OpenState, now: Date, value: number | null, reason: string): Promise<boolean> {
  const del = await query(
    `DELETE FROM edr_perf_alert_state WHERE agent_id = $1 AND metric = $2 AND target = $3 RETURNING alert_id`,
    [agentId, s.metric, s.target]
  );
  if (!del.rows[0]) return false; // a concurrent evaluation got there first
  const alertId = del.rows[0].alert_id as number | null;
  if (alertId) {
    const at = now.toISOString();
    const note =
      reason === 'recovered'
        ? `Recovered at ${at}: ${value === null ? '?' : round(value, 1)}%.`
        : reason === 'threshold_off'
          ? `No longer tracked as of ${at}: the endpoint's policy turned this threshold (or performance metrics) off.`
          : `No longer tracked as of ${at}: ${s.target} has not been reported for an hour.`;
    await AlertModel.annotate(
      alertId,
      { performance_state: reason, recovered_at: at, recovered_value: value === null ? null : round(value, 1) },
      note
    );
  }
  return true;
}

/**
 * Evaluate the endpoint policy's thresholds against its newest samples: open
 * an alert per breached metric/target that has none, recover the open ones
 * whose value came back down, drop the ones whose threshold was turned off.
 */
export async function evaluatePerformance(agentId: string, now: Date = new Date()): Promise<{ opened: number; recovered: number }> {
  const agentRow = await query('SELECT hostname, asset_id FROM edr_agents WHERE agent_id = $1', [agentId]);
  if (!agentRow.rows[0]) return { opened: 0, recovered: 0 };
  const host: string = agentRow.rows[0].hostname || agentId;
  const assetId: number | null = agentRow.rows[0].asset_id ?? null;
  const { policy, performance } = await agentPerformance(agentId);

  const statesRes = await query(
    'SELECT metric, target, alert_id, opened_at, last_seen_at FROM edr_perf_alert_state WHERE agent_id = $1',
    [agentId]
  );
  const states = new Map<string, OpenState>(statesRes.rows.map((s: OpenState) => [`${s.metric}\u0000${s.target}`, s]));
  const active = (m: PerfMetric) => performance.metrics && performance.thresholds[m].enabled;

  let opened = 0;
  let recovered = 0;
  for (const s of states.values()) {
    if (!active(s.metric) && (await recover(agentId, s, now, null, 'threshold_off'))) {
      recovered++;
      states.delete(`${s.metric}\u0000${s.target}`);
    }
  }
  if (!PERF_METRICS.some(active)) return { opened, recovered };

  const lookback = Math.max(RECOVERY_MINUTES, ...PERF_METRICS.filter(active).map((m) => performance.thresholds[m].minutes)) + 1;
  const sampleRes = await query(
    `SELECT ts, cpu_pct, mem_used, mem_total, disks FROM edr_perf_samples
      WHERE agent_id = $1
        AND ts > (SELECT MAX(ts) FROM edr_perf_samples WHERE agent_id = $1) - make_interval(mins => $2::int)
      ORDER BY ts DESC
      LIMIT 2000`,
    [agentId, lookback]
  );
  const samples: EvalSample[] = sampleRes.rows;
  if (samples.length === 0 || now.getTime() - new Date(samples[0].ts).getTime() > EVALUATE_MAX_AGE_MS) {
    return { opened, recovered };
  }
  const series = seriesFrom(samples);
  const newestT = new Date(samples[0].ts).getTime();

  for (const [key, points] of series) {
    const [metric, target] = key.split('\u0000') as [PerfMetric, string];
    if (!active(metric) || points[0].t !== newestT) continue; // only targets in the newest sample
    const th = performance.thresholds[metric];
    const state = states.get(key);
    const value = points[0].v;
    if (state) {
      if (isRecovered(points, th)) {
        if (await recover(agentId, state, now, value, 'recovered')) recovered++;
      } else {
        await query(
          `UPDATE edr_perf_alert_state SET last_value = $4, last_seen_at = $5 WHERE agent_id = $1 AND metric = $2 AND target = $3`,
          [agentId, metric, target, round(value, 1), now]
        );
      }
      continue;
    }
    if (!isBreach(points, th)) continue;
    // Claim the (agent, metric, target) slot first: only the claimer raises the alert.
    const claim = await query(
      `INSERT INTO edr_perf_alert_state (agent_id, metric, target, opened_at, opened_value, last_value, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, $5, $4)
       ON CONFLICT (agent_id, metric, target) DO NOTHING RETURNING opened_at`,
      [agentId, metric, target, now, round(value, 1)]
    );
    if (!claim.rows[0]) continue;
    const { title, description } = alertText(metric, target, host, value, th);
    const targetHash = crypto.createHash('sha256').update(target).digest('hex').slice(0, 12);
    // The breaching sample's time: one episode, one id, whatever the server's clock.
    const eventId = `${PERF_ALERT_SOURCE}:${agentId}:${metric}:${targetHash}:${Math.floor(points[0].t / 1000)}`;
    try {
      const alertId = await AlertModel.createSourced({
        source: PERF_ALERT_SOURCE,
        event_id: eventId,
        severity: th.severity,
        title,
        description,
        asset_id: assetId,
        matched_data: {
          agent_id: agentId,
          hostname: host,
          metric,
          ...(metric === 'disk' ? { mount: target } : {}),
          value: round(value, 1),
          threshold_percent: th.percent,
          threshold_minutes: th.minutes,
          policy,
          performance_state: 'open',
          opened_at: now.toISOString(),
        },
      });
      if (alertId === null) {
        // This episode's alert already exists (its slot was lost, or the
        // same sample is evaluated again): link the slot to it, raise nothing.
        await query(
          `UPDATE edr_perf_alert_state st SET alert_id = al.id FROM alerts al
            WHERE st.agent_id = $1 AND st.metric = $2 AND st.target = $3 AND al.event_id = $4`,
          [agentId, metric, target, eventId]
        );
      } else {
        await query(
          'UPDATE edr_perf_alert_state SET alert_id = $4 WHERE agent_id = $1 AND metric = $2 AND target = $3',
          [agentId, metric, target, alertId]
        );
        opened++;
        void NotificationService.notifyAlert({ id: alertId, severity: th.severity, ruleName: 'Endpoint performance', title, description });
      }
    } catch (err) {
      // Give the slot back so the next sample can try again.
      await query('DELETE FROM edr_perf_alert_state WHERE agent_id = $1 AND metric = $2 AND target = $3', [agentId, metric, target]);
      throw err;
    }
  }

  // Disk alerts whose mount has not been reported for an hour.
  for (const s of states.values()) {
    const seen = series.get(`${s.metric}\u0000${s.target}`)?.[0]?.t === newestT;
    if (!seen && now.getTime() - new Date(s.last_seen_at).getTime() > MISSING_TARGET_MS) {
      if (await recover(agentId, s, now, null, 'target_missing')) recovered++;
    }
  }
  return { opened, recovered };
}

// ---- Reads (Endpoints page) -----------------------------------------------------

export const RANGES = {
  '1h': { ms: 3_600_000, bucket: 60, source: 'raw' },
  '6h': { ms: 6 * 3_600_000, bucket: 120, source: 'raw' },
  '24h': { ms: 24 * 3_600_000, bucket: 300, source: 'raw' },
  '7d': { ms: 7 * 86_400_000, bucket: 3600, source: 'hourly' },
  '30d': { ms: 30 * 86_400_000, bucket: 4 * 3600, source: 'hourly' },
  '90d': { ms: 90 * 86_400_000, bucket: 86_400, source: 'hourly' },
} as const;
export type PerfRange = keyof typeof RANGES;

export function parseRange(v: unknown): PerfRange {
  if (v === undefined || v === '') return '24h';
  if (typeof v === 'string' && Object.prototype.hasOwnProperty.call(RANGES, v)) return v as PerfRange;
  throw new ApiError(400, `range must be one of: ${Object.keys(RANGES).join(', ')}`);
}

const ORIGIN = `TIMESTAMPTZ '2000-01-01 00:00:00+00'`;

function n(v: unknown, places = 2): number | null {
  if (v === null || v === undefined) return null;
  const x = Number(v);
  return Number.isFinite(x) ? round(x, places) : null;
}

async function requireAgent(agentId: string) {
  if (!isUuid(agentId)) throw new ApiError(404, 'Agent not found');
  const r = await query('SELECT agent_id, hostname, agent_version, capabilities FROM edr_agents WHERE agent_id = $1', [agentId]);
  if (!r.rows[0]) throw new ApiError(404, 'Agent not found');
  return r.rows[0] as { agent_id: string; hostname: string | null; agent_version: string | null; capabilities: string[] | null };
}

/** The chart data for one endpoint over a range (bucketed; bounded by the range's bucket count). */
export async function getPerformance(agentId: string, range: PerfRange, now: Date = new Date()) {
  const agent = await requireAgent(agentId);
  const cfg = RANGES[range];
  const to = now;
  const from = new Date(now.getTime() - cfg.ms);
  const params = [agentId, from, to, cfg.bucket];
  const bin = (col: string) => `date_bin(make_interval(secs => $4::int), ${col}, ${ORIGIN})`;

  let pointsSql: string;
  let disksSql: string;
  let netSql: string;
  if (cfg.source === 'raw') {
    const where = `agent_id = $1 AND ts > $2 AND ts <= $3`;
    pointsSql = `SELECT ${bin('ts')} AS t, AVG(cpu_pct) AS cpu, MAX(cpu_pct) AS cpu_max, AVG(mem_used) AS mem_used,
                        MAX(mem_total) AS mem_total, AVG(swap_used) AS swap_used, MAX(swap_total) AS swap_total,
                        AVG(load1) AS load1, AVG(load5) AS load5, AVG(load15) AS load15, MAX(uptime_s) AS uptime, COUNT(*) AS samples
                   FROM edr_perf_samples WHERE ${where} GROUP BY 1 ORDER BY 1`;
    disksSql = `SELECT ${bin('s.ts')} AS t, x->>'mount' AS key, AVG((x->>'pct')::float8) AS a, MAX((x->>'pct')::float8) AS b
                  FROM edr_perf_samples s, jsonb_array_elements(s.disks) x WHERE s.${where.replace(/ AND ts/g, ' AND s.ts')}
                 GROUP BY 1, 2 ORDER BY 2, 1`;
    netSql = `SELECT ${bin('s.ts')} AS t, x->>'iface' AS key, AVG((x->>'rx')::float8) AS a, AVG((x->>'tx')::float8) AS b
                FROM edr_perf_samples s, jsonb_array_elements(s.net) x WHERE s.${where.replace(/ AND ts/g, ' AND s.ts')}
               GROUP BY 1, 2 ORDER BY 2, 1`;
  } else {
    // Hours that overlap the range; averages weighted by each hour's sample count.
    const where = `agent_id = $1 AND hour > $2::timestamptz - INTERVAL '1 hour' AND hour <= $3`;
    pointsSql = `SELECT ${bin('hour')} AS t,
                        SUM(cpu_avg * samples) / SUM(samples) AS cpu, MAX(cpu_max) AS cpu_max,
                        SUM(mem_used_avg::float8 * samples) / SUM(samples) AS mem_used, MAX(mem_total) AS mem_total,
                        SUM(swap_used_avg::float8 * samples) / SUM(samples) AS swap_used, MAX(swap_total) AS swap_total,
                        SUM(load1_avg * samples) / NULLIF(SUM(CASE WHEN load1_avg IS NULL THEN 0 ELSE samples END), 0) AS load1,
                        SUM(load5_avg * samples) / NULLIF(SUM(CASE WHEN load5_avg IS NULL THEN 0 ELSE samples END), 0) AS load5,
                        SUM(load15_avg * samples) / NULLIF(SUM(CASE WHEN load15_avg IS NULL THEN 0 ELSE samples END), 0) AS load15,
                        MAX(uptime_max) AS uptime, SUM(samples) AS samples
                   FROM edr_perf_hourly WHERE ${where} GROUP BY 1 ORDER BY 1`;
    const jw = where.replace('agent_id', 'h.agent_id').replace(/hour /g, 'h.hour ');
    disksSql = `SELECT ${bin('h.hour')} AS t, x->>'mount' AS key,
                       SUM((x->>'pct_avg')::float8 * h.samples) / SUM(h.samples) AS a, MAX((x->>'pct_max')::float8) AS b
                  FROM edr_perf_hourly h, jsonb_array_elements(h.disks) x WHERE ${jw}
                 GROUP BY 1, 2 ORDER BY 2, 1`;
    netSql = `SELECT ${bin('h.hour')} AS t, x->>'iface' AS key,
                     SUM((x->>'rx_avg')::float8 * h.samples) / SUM(h.samples) AS a,
                     SUM((x->>'tx_avg')::float8 * h.samples) / SUM(h.samples) AS b
                FROM edr_perf_hourly h, jsonb_array_elements(h.net) x WHERE ${jw}
               GROUP BY 1, 2 ORDER BY 2, 1`;
  }

  const [points, disks, net, latest, alerts, perf] = await Promise.all([
    query(pointsSql, params),
    query(disksSql, params),
    query(netSql, params),
    query(
      `SELECT ts, cpu_pct, cpu_count, mem_total, mem_used, swap_total, swap_used, load1, load5, load15, uptime_s, disks, net
         FROM edr_perf_samples WHERE agent_id = $1 ORDER BY ts DESC LIMIT 1`,
      [agentId]
    ),
    query(
      `SELECT st.metric, st.target, st.opened_at, st.opened_value, st.last_value, st.alert_id,
              al.severity, al.title, al.status
         FROM edr_perf_alert_state st LEFT JOIN alerts al ON al.id = st.alert_id
        WHERE st.agent_id = $1 ORDER BY st.opened_at`,
      [agentId]
    ),
    agentPerformance(agentId),
  ]);

  const series = (rows: any[], a: string, b: string) => {
    const byKey = new Map<string, any[]>();
    for (const r of rows) {
      const list = byKey.get(r.key) ?? [];
      list.push({ t: new Date(r.t).toISOString(), [a]: n(r.a), [b]: n(r.b) });
      byKey.set(r.key, list);
    }
    return [...byKey.entries()].map(([key, pts]) => ({ key, points: pts }));
  };

  const l = latest.rows[0];
  return {
    agent_id: agent.agent_id,
    range,
    from: from.toISOString(),
    to: to.toISOString(),
    bucket_seconds: cfg.bucket,
    source: cfg.source,
    supported: Array.isArray(agent.capabilities) && agent.capabilities.includes(PERF_CAPABILITY),
    min_agent_version: MIN_PERF_AGENT_VERSION,
    agent_version: agent.agent_version,
    policy: perf.policy,
    performance: perf.performance,
    retention: { raw_days: RAW_RETENTION_DAYS, hourly_days: HOURLY_RETENTION_DAYS },
    points: points.rows.map((r: any) => {
      const memTotal = n(r.mem_total, 0);
      const memUsed = n(r.mem_used, 0);
      return {
        t: new Date(r.t).toISOString(),
        cpu: n(r.cpu),
        cpu_max: n(r.cpu_max),
        mem_used: memUsed,
        mem_total: memTotal,
        mem_pct: memTotal && memUsed !== null ? round((memUsed / memTotal) * 100, 1) : null,
        swap_used: n(r.swap_used, 0),
        swap_total: n(r.swap_total, 0),
        load1: n(r.load1),
        load5: n(r.load5),
        load15: n(r.load15),
        uptime: n(r.uptime, 0),
        samples: Number(r.samples),
      };
    }),
    disks: series(disks.rows, 'pct', 'pct_max').map((s) => ({ mount: s.key, points: s.points })),
    net: series(net.rows, 'rx', 'tx').map((s) => ({ iface: s.key, points: s.points })),
    latest: l
      ? {
          ts: new Date(l.ts).toISOString(),
          cpu_pct: n(l.cpu_pct),
          cpu_count: l.cpu_count,
          mem_total: Number(l.mem_total),
          mem_used: Number(l.mem_used),
          swap_total: Number(l.swap_total),
          swap_used: Number(l.swap_used),
          load1: n(l.load1),
          load5: n(l.load5),
          load15: n(l.load15),
          uptime_s: l.uptime_s === null ? null : Number(l.uptime_s),
          disks: l.disks,
          net: l.net,
        }
      : null,
    open_alerts: alerts.rows.map((a: any) => ({
      metric: a.metric,
      target: a.target,
      opened_at: a.opened_at,
      opened_value: n(a.opened_value, 1),
      last_value: n(a.last_value, 1),
      alert_id: a.alert_id,
      severity: a.severity,
      title: a.title,
      status: a.status,
    })),
  };
}

/** Process snapshot times in a range (newest first, at most 300) and the snapshot at `at` (or the newest). */
export async function getProcesses(agentId: string, range: PerfRange, at: unknown, now: Date = new Date()) {
  await requireAgent(agentId);
  const from = new Date(now.getTime() - Math.min(RANGES[range].ms, PROCESS_RETENTION_DAYS * 86_400_000));
  let atDate: Date | null = null;
  if (at !== undefined && at !== '') {
    const ms = typeof at === 'string' ? Date.parse(at) : NaN;
    if (!Number.isFinite(ms)) throw new ApiError(400, 'at must be an ISO timestamp');
    atDate = new Date(ms);
  }
  const [times, snap] = await Promise.all([
    query(
      `SELECT ts FROM edr_perf_processes WHERE agent_id = $1 AND ts > $2 ORDER BY ts DESC LIMIT 300`,
      [agentId, from]
    ),
    query(
      `SELECT ts, by_cpu, by_mem FROM edr_perf_processes
        WHERE agent_id = $1 AND ($2::timestamptz IS NULL OR ts <= $2)
        ORDER BY ts DESC LIMIT 1`,
      [agentId, atDate]
    ),
  ]);
  const s = snap.rows[0];
  return {
    times: times.rows.map((r: { ts: Date }) => new Date(r.ts).toISOString()),
    snapshot: s ? { ts: new Date(s.ts).toISOString(), by_cpu: s.by_cpu, by_mem: s.by_mem } : null,
  };
}

// ---- Retention -------------------------------------------------------------------

/** Delete raw samples and process snapshots past RAW_RETENTION_DAYS and rollups past HOURLY_RETENTION_DAYS. */
export async function prunePerformance(now: Date = new Date()): Promise<{ samples: number; hourly: number; processes: number }> {
  const day = 86_400_000;
  const opts = { pauseMs: 50 };
  const samples = await batchedDelete('edr_perf_samples', 'ts < $1', [new Date(now.getTime() - RAW_RETENTION_DAYS * day)], {
    ...opts,
    label: 'edr_perf_samples',
  });
  const hourly = await batchedDelete('edr_perf_hourly', 'hour < $1', [new Date(now.getTime() - HOURLY_RETENTION_DAYS * day)], {
    ...opts,
    label: 'edr_perf_hourly',
  });
  const processes = await batchedDelete(
    'edr_perf_processes',
    'ts < $1',
    [new Date(now.getTime() - PROCESS_RETENTION_DAYS * day)],
    { ...opts, label: 'edr_perf_processes' }
  );
  return { samples, hourly, processes };
}

export type { PolicyPerformance };
