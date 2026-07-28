/**
 * Parser recommendation engine — "which catalog parser should I install?"
 *
 * No heuristics: recent UNPARSED log messages are dry-run through every
 * not-yet-installed catalog parser using the exact production pipeline
 * (runParser), so a recommendation is an empirical statement: "had this parser
 * been installed, it would have matched N% of this source's sample."
 *
 * Sampling and ranking are severity-aware: the syslog PRI severity shipped
 * with each log (raw_logs.severity, 0=emerg..7=debug) marks which unparsed
 * traffic actually matters. Samples are stratified toward warning-or-worse
 * lines, and the ranking score counts a warning+ log 10× a routine one — so a
 * source emitting unparsed errors outranks a chattier source emitting debug
 * noise.
 *
 * This module is the pure, DB-free core (same philosophy as runParser /
 * conditionMatch): the route layer supplies samples + candidates.
 */
import { runParser } from './runParser';
import { PortableParser } from './parserPortable';

/** Syslog severities 0..4 (emerg..warning) count as "high severity". */
export const HIGH_SEVERITY_MAX = 4;
/** Ranking weight: one warning+ log counts as this many routine logs. */
export const HIGH_SEVERITY_WEIGHT = 10;

export interface SourceSample {
  /** Syslog TAG the messages came from (null = untagged). */
  app_name: string | null;
  /** Recent raw_message samples for this source (severity-stratified). */
  messages: string[];
  /** Unparsed logs from this source in the last 24h. */
  unparsed_daily: number;
  /** Of those, how many carried syslog severity <= HIGH_SEVERITY_MAX. */
  unparsed_high_sev_daily: number;
}

export interface RecommendedSource {
  app_name: string | null;
  matched: number;
  sampled: number;
  unparsed_daily: number;
  unparsed_high_sev_daily: number;
}

export interface ParserRecommendation {
  name: string;
  description?: string;
  tags: string[];
  /** Sources where at least one sampled message matched. */
  sources: RecommendedSource[];
  matched: number;
  sampled: number;
  /** Σ per-source match_rate × unparsed_daily — coverage gained per day. */
  est_daily_matches: number;
  /** Σ per-source match_rate × unparsed_high_sev_daily. */
  est_daily_high_severity: number;
  /** est_daily_matches + (HIGH_SEVERITY_WEIGHT-1) × est_daily_high_severity. */
  score: number;
}

export interface UncoveredSource {
  app_name: string | null;
  unparsed_daily: number;
  unparsed_high_sev_daily: number;
  /** One short example message for inline display. */
  example: string;
  /**
   * A few structurally-distinct FULL sample lines to seed the AI builder or a
   * manual parser. Varied formats (not N copies of one line) produce a better
   * generalized parser and more test_samples than a single truncated example.
   */
  samples: string[];
}

/**
 * Pick up to `limit` structurally-distinct lines: dedup by a digit-normalized
 * template (so lines differing only in timestamps/IPs/counts collapse to one),
 * keeping the original full line, each length-capped. Feeds the AI builder,
 * whose own prompt asks for "one sample per distinct event".
 */
export function distinctSamples(messages: string[], limit = 8): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of messages) {
    if (!m) continue;
    const template = m.replace(/\d+/g, '#').slice(0, 200);
    if (seen.has(template)) continue;
    seen.add(template);
    out.push(m.slice(0, 2000));
    if (out.length >= limit) break;
  }
  return out;
}

export interface RecommendationResult {
  recommendations: ParserRecommendation[];
  /** Unparsed sources no catalog candidate matched — parser-authoring targets. */
  uncovered: UncoveredSource[];
}

/** Cap pathological line lengths before regex-matching untrusted samples. */
const MAX_MESSAGE_LENGTH = 4000;

function matchesSample(candidate: PortableParser, message: string): boolean {
  try {
    return runParser(candidate, message.slice(0, MAX_MESSAGE_LENGTH)) !== null;
  } catch {
    // Invalid pattern (or derivation) — treat as non-matching; the candidate is
    // dropped entirely by the caller loop when it matches nothing.
    return false;
  }
}

export function recommendParsers(
  samples: SourceSample[],
  candidates: PortableParser[]
): RecommendationResult {
  const recommendations: ParserRecommendation[] = [];
  const coveredApps = new Set<string | null>();

  for (const candidate of candidates) {
    const sources: RecommendedSource[] = [];
    let matched = 0;
    let sampled = 0;
    let estDaily = 0;
    let estHigh = 0;

    for (const src of samples) {
      if (src.messages.length === 0) continue;
      const hit = src.messages.filter((m) => matchesSample(candidate, m)).length;
      sampled += src.messages.length;
      matched += hit;
      if (hit === 0) continue;

      const rate = hit / src.messages.length;
      estDaily += rate * src.unparsed_daily;
      estHigh += rate * src.unparsed_high_sev_daily;
      sources.push({
        app_name: src.app_name,
        matched: hit,
        sampled: src.messages.length,
        unparsed_daily: src.unparsed_daily,
        unparsed_high_sev_daily: src.unparsed_high_sev_daily,
      });
    }

    if (sources.length === 0) continue;
    for (const s of sources) coveredApps.add(s.app_name);

    recommendations.push({
      name: candidate.name,
      description: candidate.description,
      tags: candidate.metadata?.tags || [],
      sources,
      matched,
      sampled,
      est_daily_matches: Math.round(estDaily),
      est_daily_high_severity: Math.round(estHigh),
      score: Math.round(estDaily + (HIGH_SEVERITY_WEIGHT - 1) * estHigh),
    });
  }

  recommendations.sort((a, b) => b.score - a.score);

  const uncovered: UncoveredSource[] = samples
    .filter((s) => !coveredApps.has(s.app_name) && s.unparsed_daily > 0)
    .map((s) => ({
      app_name: s.app_name,
      unparsed_daily: s.unparsed_daily,
      unparsed_high_sev_daily: s.unparsed_high_sev_daily,
      example: (s.messages[0] || '').slice(0, 160),
      samples: distinctSamples(s.messages),
    }))
    .sort(
      (a, b) =>
        b.unparsed_daily +
        (HIGH_SEVERITY_WEIGHT - 1) * b.unparsed_high_sev_daily -
        (a.unparsed_daily + (HIGH_SEVERITY_WEIGHT - 1) * a.unparsed_high_sev_daily)
    );

  return { recommendations, uncovered };
}
