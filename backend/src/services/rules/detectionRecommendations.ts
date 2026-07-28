/**
 * Detection-rule recommendation engine — "which catalog rule should I install?"
 *
 * Same philosophy as parser recommendations: no heuristics. Each not-installed
 * catalog rule's CONDITIONS are dry-run against samples of the user's recent
 * parsed logs using the real condition evaluator, so a recommendation is an
 * empirical statement: "your live data satisfies this rule's conditions" — the
 * rule would actually engage, not just sound relevant.
 *
 * Ranking weighs how much matching traffic the rule would see per day times
 * the rule's severity, so a critical rule matching a modest stream outranks a
 * low-severity rule matching a firehose.
 *
 * DB-backed operators (whitelist / threat-feed checks) can't be evaluated
 * offline; for the dry run they count as satisfied when the field is present,
 * since their outcome is runtime context rather than data shape.
 *
 * Pure and DB-free (same philosophy as runParser / conditionMatch): the route
 * layer supplies samples + candidates.
 */
import { PURE_CONDITION_OPERATORS, evaluatePureCondition } from './conditionMatch';
import { testUserRegex } from './userRegex';

/** Weight per rule severity: matching traffic on a critical rule counts 10×. */
export const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
};

export interface RuleSourceSample {
  /** Name of the parser that produced these logs. */
  parser_name: string;
  /** Recent parsed_data objects from this parser. */
  samples: Array<Record<string, any>>;
  /** Logs this parser matched in the last 24h (from the hourly counters). */
  daily_volume: number;
}

export interface CandidateRule {
  name: string;
  description?: string;
  severity?: string;
  tags?: string[];
  conditions?: Array<{ field: string; operator: string; value?: any }>;
  aggregation?: { field: string; timeframe: string; threshold: number; distinct_count?: string };
}

export interface RuleRecommendationSource {
  parser_name: string;
  matched: number;
  sampled: number;
  daily_volume: number;
}

export interface RuleRecommendation {
  name: string;
  description?: string;
  severity?: string;
  tags: string[];
  /** Parsers whose sampled logs satisfy the rule's conditions. */
  sources: RuleRecommendationSource[];
  matched: number;
  sampled: number;
  /** Σ per-source match_rate × daily_volume — condition-matching logs per day. */
  est_daily_matches: number;
  /** est_daily_matches × severity weight. */
  score: number;
  /** Passed through so the UI can explain when the rule actually fires. */
  aggregation?: CandidateRule['aggregation'];
}

const MAX_FIELD_LENGTH = 4000;

/**
 * Mirror of RulesEngine.evaluateConditions semantics, minus the DB:
 * missing field fails everything except `exists`; pure operators use the
 * shared evaluator; `regex` compiles defensively; I/O-backed operators count
 * as satisfied when the field is present.
 */
export function conditionsMatchSample(
  conditions: Array<{ field: string; operator: string; value?: any }>,
  data: Record<string, any>
): boolean {
  for (const condition of conditions) {
    const fieldValue = data[condition.field];

    if (condition.operator !== 'exists' && (fieldValue === undefined || fieldValue === null)) {
      return false;
    }

    if (PURE_CONDITION_OPERATORS.has(condition.operator)) {
      if (!evaluatePureCondition(condition.operator, fieldValue, condition.value)) return false;
      continue;
    }

    if (condition.operator === 'regex') {
      // Same compile path as the live engine — a preview that used different
      // regex semantics would recommend rules that then never fire.
      const { matched } = testUserRegex(
        String(condition.value),
        String(fieldValue).slice(0, MAX_FIELD_LENGTH),
        (condition as any).flags
      );
      if (!matched) return false;
      continue;
    }

    // not_in_whitelist / on_threat_feed / not_on_threat_feed: runtime context,
    // not data shape — the field being present means the rule can engage.
  }
  return true;
}

export function recommendRules(
  sources: RuleSourceSample[],
  candidates: CandidateRule[]
): { recommendations: RuleRecommendation[] } {
  const recommendations: RuleRecommendation[] = [];

  for (const rule of candidates) {
    const conditions = rule.conditions || [];
    if (conditions.length === 0) continue; // nothing to evaluate — never recommend blind

    const matchedSources: RuleRecommendationSource[] = [];
    let matched = 0;
    let sampled = 0;
    let estDaily = 0;

    for (const src of sources) {
      if (src.samples.length === 0) continue;
      let hit = 0;
      for (const data of src.samples) {
        try {
          if (conditionsMatchSample(conditions, data)) hit++;
        } catch {
          /* a malformed condition never matches */
        }
      }
      sampled += src.samples.length;
      matched += hit;
      if (hit === 0) continue;

      estDaily += (hit / src.samples.length) * src.daily_volume;
      matchedSources.push({
        parser_name: src.parser_name,
        matched: hit,
        sampled: src.samples.length,
        daily_volume: src.daily_volume,
      });
    }

    if (matchedSources.length === 0) continue;

    const weight = SEVERITY_WEIGHTS[rule.severity || ''] ?? 1;
    recommendations.push({
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      tags: rule.tags || [],
      sources: matchedSources,
      matched,
      sampled,
      est_daily_matches: Math.round(estDaily),
      score: Math.round(estDaily * weight),
      aggregation: rule.aggregation,
    });
  }

  recommendations.sort((a, b) => b.score - a.score);
  return { recommendations };
}
