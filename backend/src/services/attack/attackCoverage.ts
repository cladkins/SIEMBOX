/**
 * ATT&CK coverage: "which techniques can I actually detect today, given my
 * rules AND the logs I really receive?"
 *
 * Per technique, the best level among the rules tagged with it:
 *
 *   none      no rule is tagged with it
 *   disabled  tagged rules exist, all disabled
 *   no_data   an enabled rule, but no recent log sample satisfies its
 *             conditions (dry run with conditionsMatchSample, the
 *             recommendation engine's evaluator)
 *   covered   an enabled rule whose conditions some recent sample satisfies
 *   proven    an enabled rule that raised an alert in the last 30 days
 *             (proven_by 'alert'; 'test' is reserved for rule tests)
 *
 * An alert proves the data arrives even when the current sample window has no
 * matching log, so an enabled rule that alerted is proven either way.
 *
 * A sub-technique rolls up into its parent (the parent's level is the best of
 * its own rules and its in-scope, non-excluded sub-techniques, and it reports
 * "n of m sub-techniques" covered). Tagging the parent alone covers the parent
 * only. Techniques outside the platform scope are left out; excluded ("not
 * applicable") ones keep their level but leave the percentages, and excluding
 * a parent excludes its sub-techniques.
 *
 * Headline numbers count matrix cells (parent techniques): % of in-scope,
 * non-excluded techniques at covered or better, per tactic and overall (a
 * technique under several tactics counts once overall).
 *
 * Pure and DB-free (like detectionRecommendations.ts): services/attack/
 * coverageService.ts supplies rules, samples, alerts and exclusions.
 */
import { attackDataset, attackVersion, type AttackTechnique } from './attackData';
import { analyzeAttackTags } from './attackTags';
import { conditionsMatchSample } from '../rules/detectionRecommendations';

export type CoverageLevel = 'none' | 'disabled' | 'no_data' | 'covered' | 'proven';
export type RuleLevel = Exclude<CoverageLevel, 'none'>;
export type ProvenBy = 'alert' | 'test';

export const COVERAGE_LEVELS: CoverageLevel[] = ['none', 'disabled', 'no_data', 'covered', 'proven'];
const RANK: Record<CoverageLevel, number> = { none: 0, disabled: 1, no_data: 2, covered: 3, proven: 4 };

export function levelRank(level: CoverageLevel): number {
  return RANK[level];
}

/** covered or proven. */
export function isCovered(level: CoverageLevel): boolean {
  return RANK[level] >= RANK.covered;
}

/** How far back the alerts that make a rule `proven` may be. */
export const PROVEN_WINDOW_DAYS = 30;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export interface RuleCondition {
  field: string;
  operator: string;
  value?: any;
}

export interface CoverageRuleInput {
  id: number;
  name: string;
  enabled: boolean;
  tags: string[];
  conditions: RuleCondition[];
  aggregation?: { field: string; timeframe: string; threshold: number } | null;
  /** Alerts the rule raised in the last PROVEN_WINDOW_DAYS. */
  alerts_30d: number;
  last_alert: string | null;
  /** A regex condition is known ReDoS-vulnerable: it is not dry-run. */
  unsafe_regex?: boolean;
}

export interface CoverageSampleSource {
  parser_name: string;
  samples: Array<Record<string, any>>;
}

export interface SampleWindow {
  /** Hours of parsed logs the samples come from (for the reasons). */
  hours: number;
}

export interface RuleEvaluation {
  id: number;
  name: string;
  enabled: boolean;
  /** Live technique IDs the rule is tagged with (canonical). */
  techniques: string[];
  level: RuleLevel;
  proven_by: ProvenBy | null;
  /** Why the rule is at this level, in words. */
  reason: string;
  /** Parsers with a sampled log that satisfies the conditions. */
  matched_parsers: string[];
  alerts_30d: number;
  last_alert: string | null;
}

function describeValue(value: unknown): string {
  let text: string;
  try {
    text = typeof value === 'string' ? `"${value}"` : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === undefined) return '';
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

/** `event contains "Failed password"`. */
export function describeCondition(c: RuleCondition): string {
  const value = c.operator === 'exists' || c.value === undefined ? '' : ` ${describeValue(c.value)}`;
  return `\`${c.field} ${c.operator}${value}\``;
}

function matches(conditions: RuleCondition[], data: Record<string, any>): boolean {
  try {
    return conditionsMatchSample(conditions, data);
  } catch {
    return false; // a malformed condition never matches
  }
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function listNames(names: string[], max = 3): string {
  if (names.length <= max) return names.join(', ');
  return `${names.slice(0, max).join(', ')} and ${names.length - max} more`;
}

/** Why no sample satisfies the conditions: the first condition nothing satisfies, or the closest parser. */
function noMatchReason(conditions: RuleCondition[], sources: CoverageSampleSource[]): string {
  for (const c of conditions) {
    let present = 0;
    let alone = 0;
    const presentIn = new Set<string>();
    for (const src of sources) {
      for (const data of src.samples) {
        const v = data[c.field];
        if (v !== undefined && v !== null) {
          present++;
          presentIn.add(src.parser_name);
        }
        if (matches([c], data)) alone++;
      }
    }
    if (c.operator !== 'exists' && present === 0) {
      return `no recent log from your parsers has the field \`${c.field}\` (needed by ${describeCondition(c)})`;
    }
    if (alone === 0) {
      return (
        `no recent log satisfies ${describeCondition(c)}` +
        (present > 0 ? ` (the field is in ${plural(present, 'sampled log')} from ${listNames([...presentIn].sort())})` : '')
      );
    }
  }
  // Every condition is satisfied by some log, never all by the same one.
  let best = { parser: '', hit: -1 };
  for (const src of sources) {
    for (const data of src.samples) {
      const hit = conditions.filter((c) => matches([c], data)).length;
      if (hit > best.hit) best = { parser: src.parser_name, hit };
    }
  }
  return (
    `no single recent log satisfies all ${conditions.length} conditions together` +
    (best.hit > 0 ? ` (closest: a ${best.parser} log satisfies ${best.hit} of ${conditions.length})` : '')
  );
}

function aggregationNote(rule: CoverageRuleInput): string {
  const a = rule.aggregation;
  if (!a || !a.field) return '';
  return `; it alerts at ${plural(a.threshold, 'matching log')} per \`${a.field}\` within ${a.timeframe}`;
}

/** One rule's level and the reason for it. Pure. */
export function evaluateRule(rule: CoverageRuleInput, sources: CoverageSampleSource[], window: SampleWindow): RuleEvaluation {
  const techniques = analyzeAttackTags(rule.tags || []).techniques;
  const base = {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    techniques,
    alerts_30d: rule.alerts_30d,
    last_alert: rule.last_alert,
  };
  if (!rule.enabled) {
    return { ...base, level: 'disabled', proven_by: null, reason: 'The rule is disabled.', matched_parsers: [] };
  }

  const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
  const sampled = sources.reduce((n, s) => n + s.samples.length, 0);
  const withSamples = sources.filter((s) => s.samples.length > 0);
  const scope = `${plural(sampled, 'log')} sampled from ${plural(withSamples.length, 'parser')} over the last ${window.hours} h`;

  let level: RuleLevel;
  let reason: string;
  const matched: string[] = [];

  if (rule.unsafe_regex) {
    level = 'no_data';
    reason = 'Not dry-run: a regex condition is flagged unsafe (catastrophic backtracking); fix the rule to have it evaluated.';
  } else if (sampled === 0) {
    level = 'no_data';
    reason = `No parsed logs in the last ${window.hours} h to test it against (no parser produced any).`;
  } else {
    let hit = 0;
    for (const src of withSamples) {
      let srcHit = 0;
      for (const data of src.samples) if (matches(conditions, data)) srcHit++;
      if (srcHit > 0) matched.push(src.parser_name);
      hit += srcHit;
    }
    matched.sort();
    if (hit > 0) {
      level = 'covered';
      reason =
        conditions.length === 0
          ? `It has no conditions, so every parsed log satisfies it (${scope})${aggregationNote(rule)}.`
          : `${plural(hit, 'recent log')} from ${listNames(matched)} ${hit === 1 ? 'satisfies' : 'satisfy'} its conditions (${scope})${aggregationNote(rule)}.`;
    } else {
      level = 'no_data';
      reason = `Enabled, but ${noMatchReason(conditions, withSamples)} (${scope}).`;
    }
  }

  if (rule.alerts_30d > 0) {
    const last = rule.last_alert ? `, last ${rule.last_alert}` : '';
    return {
      ...base,
      level: 'proven',
      proven_by: 'alert',
      reason: `Raised ${plural(rule.alerts_30d, 'alert')} in the last ${PROVEN_WINDOW_DAYS} days${last}.`,
      matched_parsers: matched,
    };
  }
  return { ...base, level, proven_by: null, reason, matched_parsers: matched };
}

// ---------------------------------------------------------------------------
// Platforms
// ---------------------------------------------------------------------------

/** Every platform in the bundled dataset, sorted. */
export function allPlatforms(): string[] {
  const set = new Set<string>();
  for (const t of Object.values(attackDataset().techniques)) for (const p of t.platforms) set.add(p);
  return [...set].sort((a, b) => a.localeCompare(b));
}

/** What the scope falls back to when the data implies nothing (spec §6). */
export const DEFAULT_PLATFORMS = ['Containers', 'Linux', 'Network Devices'];

const PLATFORM_ALIASES: Record<string, string> = {
  network: 'Network Devices',
  mac: 'macOS',
  osx: 'macOS',
  idp: 'Identity Provider',
  office: 'Office Suite',
  'office 365': 'Office Suite',
};

/**
 * `?platforms=` → platform names: comma-separated, case-insensitive dataset
 * names (plus a few aliases: network, mac, idp, office) or `all`. Empty or
 * absent → null (use the inferred scope). Unknown names are an error.
 */
export function parsePlatformsParam(raw: unknown): { platforms: string[] | null } | { error: string } {
  if (raw === undefined || raw === null) return { platforms: null };
  if (typeof raw !== 'string') return { error: 'platforms may be given once, as a comma-separated list' };
  const parts = raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return { platforms: null };
  const known = allPlatforms();
  const byLower = new Map(known.map((p) => [p.toLowerCase(), p]));
  const out = new Set<string>();
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (lower === 'all') {
      for (const p of known) out.add(p);
      continue;
    }
    const name = byLower.get(lower) ?? PLATFORM_ALIASES[lower];
    if (!name) return { error: `unknown platform "${part.slice(0, 40)}" (one of ${known.join(', ')}, or all)` };
    out.add(name);
  }
  return { platforms: [...out].sort((a, b) => a.localeCompare(b)) };
}

export interface PlatformEvidence {
  /** Parsers that matched logs in the last 7 days. */
  parsers: Array<{ name: string; event_type?: string | null; logs_7d: number }>;
  /** Distinct assets.os_type values of active assets, with counts. */
  asset_os: Array<{ os: string; count: number }>;
  /** Distinct edr_agents.os values, with counts. */
  agent_os: Array<{ os: string; count: number }>;
  /** Container images log shippers report (shipper_containers rows). */
  shipper_containers: number;
}

export interface InferredFrom {
  platform: string;
  source: 'parsers' | 'assets' | 'endpoint_agents' | 'shipper_containers' | 'default';
  /** What implied it: parser names, OS strings, or a sentence. */
  items: string[];
}

export interface PlatformInference {
  platforms: string[];
  inferred_from: InferredFrom[];
  /** Parsers with logs that imply no platform (they still feed the dry run). */
  unmapped_parsers: string[];
}

/**
 * Parser name / event type → platform. Matched case-insensitively against
 * "<parser name> <event type>"; a parser can imply several platforms. The
 * table is documented in docs/reference/RULES.md ("Platform scope").
 */
export const PARSER_PLATFORM_RULES: Array<{ platform: string; pattern: RegExp }> = [
  { platform: 'Windows', pattern: /windows|winevent|wineventlog|sysmon|evtx|powershell|active[-_ ]?directory/i },
  { platform: 'macOS', pattern: /macos|darwin|\bosx\b/i },
  {
    platform: 'Linux',
    pattern: /syslog|linux|sudo|\bssh|sshd|auditd|journal|systemd|cron|kernel|fail2ban|\bpam\b|nginx|apache|caddy|traefik|haproxy/i,
  },
  {
    platform: 'Network Devices',
    pattern: /firewall|netfilter|iptables|nftables|\bufw\b|pfsense|opnsense|unifi|ubiquiti|\bids\b|\bips\b|ids[-_]?ips|suricata|snort|zeek|\bdns\b|dns[-_]|pihole|dnsmasq|hostapd|wifi|router|fortigate|palo[-_ ]?alto|mikrotik|cisco/i,
  },
  { platform: 'Containers', pattern: /docker|container|kubernetes|\bk8s\b|kube|podman|containerd|portainer|komodo/i },
  { platform: 'Identity Provider', pattern: /authelia|authentik|keycloak|okta|entra|azure[-_ ]?ad|\bldap\b|\bsso\b|\boidc\b|saml/i },
  { platform: 'IaaS', pattern: /\baws\b|cloudtrail|\bgcp\b|google[-_ ]?cloud|azure[-_ ]?activity|\bec2\b/i },
  { platform: 'Office Suite', pattern: /office[-_ ]?365|\bm365\b|exchange|google[-_ ]?workspace|gsuite/i },
];

/** Asset / agent OS string → platform. */
function platformForOs(os: string): string | null {
  if (/windows|\bwin(32|64|10|11)?\b/i.test(os)) return 'Windows';
  if (/mac|darwin|os ?x/i.test(os)) return 'macOS';
  if (/esxi|vmware/i.test(os)) return 'ESXi';
  if (/linux|ubuntu|debian|centos|rhel|red ?hat|fedora|alpine|arch|suse|raspbian|unraid|truenas|proxmox|freebsd|openbsd/i.test(os)) {
    return 'Linux';
  }
  return null;
}

/** The default platform scope from the user's data, and what implied each platform. Pure. */
export function inferPlatforms(evidence: PlatformEvidence): PlatformInference {
  const from = new Map<string, InferredFrom>();
  const add = (platform: string, source: InferredFrom['source'], item: string) => {
    const key = `${platform}\u0000${source}`;
    let entry = from.get(key);
    if (!entry) {
      entry = { platform, source, items: [] };
      from.set(key, entry);
    }
    if (!entry.items.includes(item)) entry.items.push(item);
  };
  const unmapped: string[] = [];

  for (const p of evidence.parsers) {
    if (!(p.logs_7d > 0)) continue;
    const text = `${p.name} ${p.event_type ?? ''}`;
    let any = false;
    for (const rule of PARSER_PLATFORM_RULES) {
      if (rule.pattern.test(text)) {
        add(rule.platform, 'parsers', p.name);
        any = true;
      }
    }
    if (!any) unmapped.push(p.name);
  }
  for (const a of evidence.asset_os) {
    const platform = a.count > 0 ? platformForOs(a.os) : null;
    if (platform) add(platform, 'assets', a.os);
  }
  for (const a of evidence.agent_os) {
    const platform = a.count > 0 ? platformForOs(a.os) : null;
    if (platform) add(platform, 'endpoint_agents', a.os);
  }
  if (evidence.shipper_containers > 0) {
    add('Containers', 'shipper_containers', `${plural(evidence.shipper_containers, 'container image')} reported by log shippers`);
  }

  if (from.size === 0) {
    for (const platform of DEFAULT_PLATFORMS) {
      add(platform, 'default', 'nothing in your data implies a platform yet; this is the default scope');
    }
  }
  const inferred = [...from.values()];
  for (const e of inferred) e.items.sort();
  inferred.sort((a, b) => a.platform.localeCompare(b.platform) || a.source.localeCompare(b.source));
  return {
    platforms: [...new Set(inferred.map((e) => e.platform))].sort((a, b) => a.localeCompare(b)),
    inferred_from: inferred,
    unmapped_parsers: unmapped.sort(),
  };
}

// ---------------------------------------------------------------------------
// Matrix and coverage
// ---------------------------------------------------------------------------

function isLive(t: AttackTechnique): boolean {
  return !t.revoked && !t.deprecated;
}

function inScope(t: AttackTechnique, platforms: Set<string>): boolean {
  return t.platforms.some((p) => platforms.has(p));
}

export interface MatrixTechnique {
  id: string;
  name: string;
  platforms: string[];
  subtechniques: Array<{ id: string; name: string; platforms: string[] }>;
}

export interface MatrixTactic {
  id: string;
  shortname: string;
  name: string;
  order: number;
  techniques: MatrixTechnique[];
}

/** Live parent techniques (and their sub-techniques) in scope, grouped by tactic in matrix order. */
function scopedParents(platforms: string[]): Map<string, { t: AttackTechnique; subs: string[] }> {
  const data = attackDataset();
  const scope = new Set(platforms);
  const out = new Map<string, { t: AttackTechnique; subs: string[] }>();
  const ids = Object.keys(data.techniques).sort();
  const children = new Map<string, string[]>();
  for (const id of ids) {
    const dot = id.indexOf('.');
    if (dot < 0) continue;
    const st = data.techniques[id];
    if (!isLive(st) || !inScope(st, scope)) continue;
    const parent = id.slice(0, dot);
    if (!children.has(parent)) children.set(parent, []);
    children.get(parent)!.push(id);
  }
  for (const id of ids) {
    const t = data.techniques[id];
    if (id.includes('.') || !isLive(t)) continue;
    const subs = children.get(id) ?? [];
    if (inScope(t, scope) || subs.length > 0) out.set(id, { t, subs });
  }
  return out;
}

export function buildMatrix(platforms: string[]): { attack_version: string; platforms: string[]; tactics: MatrixTactic[] } {
  const data = attackDataset();
  const parents = scopedParents(platforms);
  const tactics = [...data.tactics]
    .sort((a, b) => a.order - b.order)
    .map((tac) => ({
      id: tac.id,
      shortname: tac.shortname,
      name: tac.name,
      order: tac.order,
      techniques: [...parents.entries()]
        .filter(([, p]) => p.t.tactics.includes(tac.shortname))
        .map(([id, p]) => ({
          id,
          name: p.t.name,
          platforms: p.t.platforms,
          subtechniques: p.subs.map((s) => ({ id: s, name: data.techniques[s].name, platforms: data.techniques[s].platforms })),
        }))
        .sort((a, b) => a.name.localeCompare(b.name)),
    }));
  return { attack_version: attackVersion(), platforms, tactics };
}

export interface Exclusion {
  technique_id: string;
  note: string | null;
  created_by: string | null;
  created_at: string | null;
}

export interface TechniqueAlerts {
  count: number;
  last: string | null;
}

export interface CoverageRuleRef {
  id: number;
  name: string;
  enabled: boolean;
  level: RuleLevel;
  proven_by: ProvenBy | null;
  reason: string;
  /** The technique the rule is tagged with (a sub-technique's ID on a rolled-up parent). */
  technique_id: string;
}

export interface CoverageTechnique {
  id: string;
  name: string;
  parent_id: string | null;
  tactics: string[];
  platforms: string[];
  level: CoverageLevel;
  proven_by: ProvenBy | null;
  excluded: boolean;
  exclusion: (Exclusion & { inherited_from?: string }) | null;
  rules: CoverageRuleRef[];
  /** Alerts in the last 30 days carrying this technique (a parent counts its sub-techniques' alerts). */
  alerts_30d: number;
  last_alert: string | null;
  /** Parents only: in-scope sub-techniques, excluded ones not counted. */
  subtechniques?: { total: number; covered: number; excluded: number; ids: string[] };
}

export interface CoverageCounts {
  in_scope: number;
  excluded: number;
  /** in_scope - excluded: the denominator. */
  counted: number;
  covered: number;
  proven: number;
  /** covered / counted × 100, one decimal; null when nothing is counted. */
  percent: number | null;
  by_level: Record<CoverageLevel, number>;
}

export interface CoverageResult {
  attack_version: string;
  platforms: string[];
  summary: CoverageCounts;
  tactics: Array<{ id: string; shortname: string; name: string; order: number } & CoverageCounts>;
  /** Parents first in ID order, each followed by its sub-techniques. */
  techniques: CoverageTechnique[];
  rules: { tagged: number; by_level: Record<RuleLevel, number> };
}

export interface CoverageInput {
  rules: RuleEvaluation[];
  platforms: string[];
  exclusions: Exclusion[];
  /** Alerts per exact technique ID (sub-techniques). */
  alertsByTechnique: Map<string, TechniqueAlerts>;
  /** Alerts per parent technique, its sub-techniques' alerts included (each alert once). */
  alertsByParent: Map<string, TechniqueAlerts>;
}

function emptyCounts(): CoverageCounts {
  return {
    in_scope: 0,
    excluded: 0,
    counted: 0,
    covered: 0,
    proven: 0,
    percent: null,
    by_level: { none: 0, disabled: 0, no_data: 0, covered: 0, proven: 0 },
  };
}

function tally(c: CoverageCounts, t: CoverageTechnique): void {
  c.in_scope++;
  if (t.excluded) {
    c.excluded++;
    return;
  }
  c.counted++;
  c.by_level[t.level]++;
  if (isCovered(t.level)) c.covered++;
  if (t.level === 'proven') c.proven++;
}

function finish(c: CoverageCounts): CoverageCounts {
  c.percent = c.counted > 0 ? Math.round((c.covered / c.counted) * 1000) / 10 : null;
  return c;
}

function best(refs: CoverageRuleRef[]): { level: CoverageLevel; proven_by: ProvenBy | null } {
  let out: { level: CoverageLevel; proven_by: ProvenBy | null } = { level: 'none', proven_by: null };
  for (const r of refs) if (RANK[r.level] > RANK[out.level]) out = { level: r.level, proven_by: r.proven_by };
  return out;
}

function refsFor(id: string, byTechnique: Map<string, RuleEvaluation[]>): CoverageRuleRef[] {
  return (byTechnique.get(id) || []).map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    level: r.level,
    proven_by: r.proven_by,
    reason: r.reason,
    technique_id: id,
  }));
}

function byLevelThenName(a: CoverageRuleRef, b: CoverageRuleRef): number {
  return RANK[b.level] - RANK[a.level] || a.name.localeCompare(b.name) || a.id - b.id;
}

/** The coverage of every in-scope technique, and the headline numbers. Pure. */
export function buildCoverage(input: CoverageInput): CoverageResult {
  const data = attackDataset();
  const parents = scopedParents(input.platforms);
  const exclusions = new Map(input.exclusions.map((e) => [e.technique_id, e]));
  const byTechnique = new Map<string, RuleEvaluation[]>();
  for (const r of input.rules) {
    for (const id of r.techniques) {
      if (!byTechnique.has(id)) byTechnique.set(id, []);
      byTechnique.get(id)!.push(r);
    }
  }

  const techniques: CoverageTechnique[] = [];
  const parentEntries = new Map<string, CoverageTechnique>();
  for (const [id, { t, subs }] of parents) {
    const parentExclusion = exclusions.get(id) ?? null;
    const subEntries: CoverageTechnique[] = subs.map((sid) => {
      const st = data.techniques[sid];
      const own = exclusions.get(sid) ?? null;
      const rules = refsFor(sid, byTechnique).sort(byLevelThenName);
      const lvl = best(rules);
      const alerts = input.alertsByTechnique.get(sid);
      return {
        id: sid,
        name: st.name,
        parent_id: id,
        tactics: st.tactics,
        platforms: st.platforms,
        level: lvl.level,
        proven_by: lvl.proven_by,
        excluded: !!(own || parentExclusion),
        exclusion: own ?? (parentExclusion ? { ...parentExclusion, inherited_from: id } : null),
        rules,
        alerts_30d: alerts?.count ?? 0,
        last_alert: alerts?.last ?? null,
      };
    });

    const direct = refsFor(id, byTechnique);
    const counted = subEntries.filter((s) => !s.excluded);
    const rolled = [...direct, ...counted.flatMap((s) => s.rules)].sort(byLevelThenName);
    const lvl = best(rolled);
    const alerts = input.alertsByParent.get(id);
    const entry: CoverageTechnique = {
      id,
      name: t.name,
      parent_id: null,
      tactics: t.tactics,
      platforms: t.platforms,
      level: lvl.level,
      proven_by: lvl.proven_by,
      excluded: !!parentExclusion,
      exclusion: parentExclusion,
      rules: rolled,
      alerts_30d: alerts?.count ?? 0,
      last_alert: alerts?.last ?? null,
      subtechniques: {
        total: counted.length,
        covered: counted.filter((s) => isCovered(s.level)).length,
        excluded: subEntries.length - counted.length,
        ids: subs,
      },
    };
    parentEntries.set(id, entry);
    techniques.push(entry, ...subEntries);
  }

  const summary = emptyCounts();
  for (const entry of parentEntries.values()) tally(summary, entry);
  const tactics = [...data.tactics]
    .sort((a, b) => a.order - b.order)
    .map((tac) => {
      const c = emptyCounts();
      for (const entry of parentEntries.values()) if (entry.tactics.includes(tac.shortname)) tally(c, entry);
      return { id: tac.id, shortname: tac.shortname, name: tac.name, order: tac.order, ...finish(c) };
    });

  const ruleLevels: Record<RuleLevel, number> = { disabled: 0, no_data: 0, covered: 0, proven: 0 };
  let tagged = 0;
  for (const r of input.rules) {
    if (r.techniques.length === 0) continue;
    tagged++;
    ruleLevels[r.level]++;
  }

  return {
    attack_version: attackVersion(),
    platforms: input.platforms,
    summary: finish(summary),
    tactics,
    techniques,
    rules: { tagged, by_level: ruleLevels },
  };
}

// ---------------------------------------------------------------------------
// ATT&CK Navigator layer
// ---------------------------------------------------------------------------

/** Navigator score per level (none is left out of the layer). */
export const NAVIGATOR_SCORES: Record<CoverageLevel, number> = { none: 0, disabled: 1, no_data: 2, covered: 3, proven: 4 };
export const NAVIGATOR_COLORS: Record<CoverageLevel, string> = {
  none: '#ffffff',
  disabled: '#bdbdbd',
  no_data: '#fdae61',
  covered: '#a6d96a',
  proven: '#1a9641',
};

const LEVEL_LABELS: Record<CoverageLevel, string> = {
  none: 'No rule',
  disabled: 'Rules disabled',
  no_data: 'Enabled, no matching data',
  covered: 'Covered (matching data arrives)',
  proven: 'Proven (alerted in 30 days)',
};

/**
 * An ATT&CK Navigator layer (format 4.5, enterprise-attack) for a coverage
 * result: one entry per in-scope technique that has rules or is excluded,
 * scored and coloured by level, the rule names in the comment; excluded
 * techniques are disabled. Pure.
 */
export function buildNavigatorLayer(coverage: CoverageResult, opts: { generatedAt: string }): Record<string, unknown> {
  const major = coverage.attack_version.split('.')[0];
  const entries: Array<Record<string, unknown>> = [];
  for (const t of coverage.techniques) {
    if (t.level === 'none' && !t.excluded) continue;
    const parts: string[] = [];
    if (t.excluded) {
      const why = t.exclusion?.note ? `: ${t.exclusion.note}` : '';
      parts.push(
        t.exclusion?.inherited_from ? `Not applicable (with ${t.exclusion.inherited_from})${why}` : `Not applicable${why}`
      );
    }
    if (t.level !== 'none') parts.push(LEVEL_LABELS[t.level]);
    if (t.subtechniques && t.subtechniques.total > 0) {
      parts.push(`${t.subtechniques.covered} of ${t.subtechniques.total} sub-techniques covered`);
    }
    if (t.rules.length > 0) {
      parts.push(`Rules: ${t.rules.map((r) => `${r.name} (${r.level.replace('_', ' ')})`).join('; ')}`);
    }
    const entry: Record<string, unknown> = {
      techniqueID: t.id,
      enabled: !t.excluded,
      comment: parts.join('. '),
      metadata: [{ name: 'level', value: t.level }],
      showSubtechniques: false,
    };
    if (t.level !== 'none') {
      entry.score = NAVIGATOR_SCORES[t.level];
      entry.color = NAVIGATOR_COLORS[t.level];
    }
    entries.push(entry);
  }
  const s = coverage.summary;
  return {
    name: 'SIEMBox ATT&CK coverage',
    versions: { attack: major, navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description:
      `SIEMBox detection coverage on ${coverage.platforms.join(', ') || 'no platforms'}, generated ${opts.generatedAt}: ` +
      `${s.covered} of ${s.counted} techniques covered or better` +
      (s.percent === null ? '' : ` (${s.percent}%)`) +
      `, ${s.excluded} marked not applicable. ATT&CK ${coverage.attack_version}.`,
    filters: { platforms: coverage.platforms },
    sorting: 0,
    layout: {
      layout: 'side',
      aggregateFunction: 'max',
      showID: true,
      showName: true,
      showAggregateScores: false,
      countUnscored: false,
      expandedSubtechniques: 'none',
    },
    hideDisabled: false,
    techniques: entries,
    gradient: {
      colors: [NAVIGATOR_COLORS.disabled, NAVIGATOR_COLORS.no_data, NAVIGATOR_COLORS.covered, NAVIGATOR_COLORS.proven],
      minValue: NAVIGATOR_SCORES.disabled,
      maxValue: NAVIGATOR_SCORES.proven,
    },
    legendItems: (['proven', 'covered', 'no_data', 'disabled'] as CoverageLevel[]).map((l) => ({
      label: LEVEL_LABELS[l],
      color: NAVIGATOR_COLORS[l],
    })),
    metadata: [
      { name: 'generated_by', value: 'SIEMBox' },
      { name: 'generated_at', value: opts.generatedAt },
      { name: 'attack_dataset', value: coverage.attack_version },
    ],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}
