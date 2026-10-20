/**
 * The DB side of ATT&CK coverage (the model itself is attackCoverage.ts, pure).
 *
 * A snapshot holds everything that does not depend on the platform scope: each
 * rule's level and reason (the dry run over recent per-parser samples), alert
 * counts, exclusions and the inferred platforms. It is cached for 10 minutes;
 * each platform set's coverage is built from it once and memoized with it.
 * invalidateAttackCoverage() (rule writes through DetectionRuleModel,
 * exclusion writes) drops it, and a computation that was already running when
 * that happened does not store its result.
 *
 * The dry run runs in-process: these are the installed rules, whose regexes
 * passed the write-time ReDoS gate and already run on every parsed log; a rule
 * the gate's cache knows to be vulnerable is not dry-run at all.
 */
import { query } from '../../config/database';
import { DetectionRuleModel, type DetectionRule } from '../../models/DetectionRule';
import { collectRuleRegexes, peekRegexSafety } from '../regex/regexSafety';
import { recentParserSamples } from '../rules/ruleSamples';
import {
  PROVEN_WINDOW_DAYS,
  buildCoverage,
  evaluateRule,
  inferPlatforms,
  type CoverageResult,
  type CoverageSampleSource,
  type Exclusion,
  type PlatformEvidence,
  type PlatformInference,
  type RuleEvaluation,
  type TechniqueAlerts,
} from './attackCoverage';
import { coverageGeneration, onCoverageInvalidated } from './coverageCache';

export const COVERAGE_TTL_MS = 10 * 60 * 1000;
/** Samples: per parser and event type, newest first, from the last day. */
export const SAMPLE_WINDOW_HOURS = 24;
export const SAMPLES_PER_PARTITION = 25;
/** Only the window's newest rows are ranked (bounds the query on a busy install). */
export const SAMPLE_SCAN_LIMIT = 200_000;
export const MAX_SAMPLES = 4000;
/** Platform sets memoized per snapshot. */
const MAX_MEMO = 64;

interface Snapshot {
  at: number;
  generation: number;
  computedAt: string;
  rules: RuleEvaluation[];
  exclusions: Exclusion[];
  alertsByTechnique: Map<string, TechniqueAlerts>;
  alertsByParent: Map<string, TechniqueAlerts>;
  inference: PlatformInference;
  sample: { window_hours: number; parsers: number; logs: number };
  timings_ms: { load: number; dry_run: number };
  memo: Map<string, CoverageResult>;
}

let snapshot: Snapshot | null = null;
let inflight: { generation: number; promise: Promise<Snapshot> } | null = null;
let inferenceCache: { at: number; value: PlatformInference } | null = null;

onCoverageInvalidated(() => {
  snapshot = null;
});

/** Test seam: forget every cached value. */
export function resetCoverageCacheForTests(): void {
  snapshot = null;
  inflight = null;
  inferenceCache = null;
}

function iso(value: unknown): string | null {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

async function loadEvidence(): Promise<PlatformEvidence> {
  const [parsers, assets, agents, containers] = await Promise.all([
    query(
      `SELECT p.name, p.event_type, SUM(h.matches)::bigint AS logs_7d
         FROM parser_match_hourly h JOIN parsers p ON p.id = h.parser_id
        WHERE h.parser_id <> 0 AND h.hour >= NOW() - INTERVAL '7 days'
        GROUP BY p.name, p.event_type`
    ),
    query(
      `SELECT os_type AS os, COUNT(*)::int AS count FROM assets
        WHERE os_type IS NOT NULL AND os_type <> ''
          AND COALESCE(status, 'active') = 'active'
          AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL '30 days')
        GROUP BY os_type`
    ),
    query(
      `SELECT os, COUNT(*)::int AS count FROM edr_agents
        WHERE os IS NOT NULL AND os <> ''
          AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL '30 days')
        GROUP BY os`
    ),
    query(`SELECT COUNT(*)::int AS count FROM shipper_containers`),
  ]);
  return {
    parsers: parsers.rows.map((r: any) => ({ name: r.name, event_type: r.event_type, logs_7d: Number(r.logs_7d) })),
    asset_os: assets.rows.map((r: any) => ({ os: String(r.os), count: Number(r.count) })),
    agent_os: agents.rows.map((r: any) => ({ os: String(r.os), count: Number(r.count) })),
    shipper_containers: Number(containers.rows[0]?.count ?? 0),
  };
}

/** The inferred platform scope (cached with the same TTL; it does not depend on rules). */
export async function getPlatformInference(refresh = false): Promise<PlatformInference> {
  if (!refresh && inferenceCache && Date.now() - inferenceCache.at < COVERAGE_TTL_MS) return inferenceCache.value;
  const value = inferPlatforms(await loadEvidence());
  inferenceCache = { at: Date.now(), value };
  return value;
}

function alertMap(rows: any[], key: string): Map<string, TechniqueAlerts> {
  return new Map(rows.map((r) => [String(r[key]), { count: Number(r.count), last: iso(r.last) }]));
}

function ruleInput(rule: DetectionRule, alerts: Map<number, TechniqueAlerts>) {
  const logic = rule.rule_logic || {};
  const a = alerts.get(rule.id);
  return {
    id: rule.id,
    name: rule.name,
    enabled: !!rule.enabled,
    tags: Array.isArray(rule.tags) ? rule.tags : [],
    conditions: Array.isArray(logic.conditions) ? logic.conditions : [],
    aggregation: logic.aggregation ?? null,
    alerts_30d: a?.count ?? 0,
    last_alert: a?.last ?? null,
    unsafe_regex: peekRegexSafety(collectRuleRegexes(rule)).status === 'vulnerable',
  };
}

async function computeSnapshot(generation: number, refreshInference: boolean): Promise<Snapshot> {
  const started = Date.now();
  const window = `${PROVEN_WINDOW_DAYS} days`;
  const [rules, ruleAlerts, techAlerts, parentAlerts, exclusions, samples, inference] = await Promise.all([
    DetectionRuleModel.findAll(),
    query(
      `SELECT rule_id, COUNT(*)::int AS count, MAX(created_at) AS last FROM alerts
        WHERE rule_id IS NOT NULL AND created_at >= NOW() - $1::interval GROUP BY rule_id`,
      [window]
    ),
    query(
      `SELECT t AS technique, COUNT(*)::int AS count, MAX(a.created_at) AS last
         FROM alerts a CROSS JOIN LATERAL unnest(a.attack_techniques) AS t
        WHERE a.created_at >= NOW() - $1::interval AND cardinality(a.attack_techniques) > 0
        GROUP BY t`,
      [window]
    ),
    query(
      `SELECT p AS technique, COUNT(DISTINCT a.id)::int AS count, MAX(a.created_at) AS last
         FROM alerts a CROSS JOIN LATERAL (SELECT DISTINCT split_part(t, '.', 1) AS p FROM unnest(a.attack_techniques) AS t) x
        WHERE a.created_at >= NOW() - $1::interval AND cardinality(a.attack_techniques) > 0
        GROUP BY p`,
      [window]
    ),
    query(
      `SELECT e.technique_id, e.note, u.username AS created_by, e.created_at
         FROM attack_technique_exclusions e LEFT JOIN users u ON u.id = e.created_by
        ORDER BY e.technique_id`
    ),
    recentParserSamples({
      windowHours: SAMPLE_WINDOW_HOURS,
      perPartition: SAMPLES_PER_PARTITION,
      byEventType: true,
      scanLimit: SAMPLE_SCAN_LIMIT,
      maxSamples: MAX_SAMPLES,
    }),
    getPlatformInference(refreshInference),
  ]);
  const loaded = Date.now();

  const byRule = new Map<number, TechniqueAlerts>(
    ruleAlerts.rows.map((r: any) => [Number(r.rule_id), { count: Number(r.count), last: iso(r.last) }])
  );
  const sources: CoverageSampleSource[] = [...samples.values()].map((s) => ({
    parser_name: s.parser_name,
    samples: s.samples,
  }));
  const evaluations = rules.map((rule) => evaluateRule(ruleInput(rule, byRule), sources, { hours: SAMPLE_WINDOW_HOURS }));

  return {
    at: Date.now(),
    generation,
    computedAt: new Date().toISOString(),
    rules: evaluations,
    exclusions: exclusions.rows.map((r: any) => ({
      technique_id: r.technique_id,
      note: r.note ?? null,
      created_by: r.created_by ?? null,
      created_at: iso(r.created_at),
    })),
    alertsByTechnique: alertMap(techAlerts.rows, 'technique'),
    alertsByParent: alertMap(parentAlerts.rows, 'technique'),
    inference,
    sample: {
      window_hours: SAMPLE_WINDOW_HOURS,
      parsers: sources.length,
      logs: sources.reduce((n, s) => n + s.samples.length, 0),
    },
    timings_ms: { load: loaded - started, dry_run: Date.now() - loaded },
    memo: new Map(),
  };
}

/** The current snapshot: cached, or computed once even when several requests ask at the same time. */
async function getSnapshot(refresh: boolean): Promise<{ snap: Snapshot; cached: boolean }> {
  const generation = coverageGeneration();
  if (
    !refresh &&
    snapshot &&
    snapshot.generation === generation &&
    Date.now() - snapshot.at < COVERAGE_TTL_MS
  ) {
    return { snap: snapshot, cached: true };
  }
  if (!refresh && inflight && inflight.generation === generation) {
    return { snap: await inflight.promise, cached: false };
  }
  const promise = computeSnapshot(generation, refresh);
  inflight = { generation, promise };
  try {
    const snap = await promise;
    // Store only if nothing changed while it was computed.
    if (coverageGeneration() === generation) snapshot = snap;
    return { snap, cached: false };
  } finally {
    if (inflight?.promise === promise) inflight = null;
  }
}

export interface CoverageScope {
  platforms: string[];
  /** 'query' when ?platforms= chose them, 'inferred' otherwise. */
  source: 'query' | 'inferred';
  inferred: PlatformInference;
}

export interface CoverageResponse extends CoverageResult {
  scope: CoverageScope;
  sample: Snapshot['sample'];
  computed_at: string;
  cached: boolean;
  timings_ms: Snapshot['timings_ms'];
}

/** Coverage for `platforms` (null: the inferred scope). `refresh` recomputes (the route allows it to analyst+). */
export async function getCoverage(platforms: string[] | null, refresh = false): Promise<CoverageResponse> {
  const { snap, cached } = await getSnapshot(refresh);
  const scopePlatforms = platforms ?? snap.inference.platforms;
  const key = [...scopePlatforms].sort().join('|');
  let result = snap.memo.get(key);
  const memoHit = !!result;
  if (!result) {
    result = buildCoverage({
      rules: snap.rules,
      platforms: scopePlatforms,
      exclusions: snap.exclusions,
      alertsByTechnique: snap.alertsByTechnique,
      alertsByParent: snap.alertsByParent,
    });
    if (snap.memo.size >= MAX_MEMO) snap.memo.clear();
    snap.memo.set(key, result);
  }
  return {
    ...result,
    scope: { platforms: scopePlatforms, source: platforms ? 'query' : 'inferred', inferred: snap.inference },
    sample: snap.sample,
    computed_at: snap.computedAt,
    cached: cached && memoHit,
    timings_ms: snap.timings_ms,
  };
}
