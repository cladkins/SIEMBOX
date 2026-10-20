/**
 * MITRE ATT&CK in the UI: tag parsing, technique lookup and search, the
 * coverage levels' labels, and the filters the Rules, catalog, Alerts and
 * ATT&CK Coverage pages share. Pure (no Vue, no API), so `npm run test:unit`
 * runs it under node directly.
 *
 * Tags follow the backend (services/attack/attackTags.ts, RULES.md "MITRE
 * ATT&CK Tagging"): `attack.t1110` / `attack.t1110.001` for techniques,
 * `attack.credential_access` for tactics, in the rule's ordinary `tags`.
 */

export type CoverageLevel = 'none' | 'disabled' | 'no_data' | 'covered' | 'proven';

/** GET /api/attack/matrix */
export interface MatrixSubtechnique {
  id: string;
  name: string;
  platforms: string[];
}
export interface MatrixTechnique extends MatrixSubtechnique {
  subtechniques: MatrixSubtechnique[];
}
export interface MatrixTactic {
  id: string;
  shortname: string;
  name: string;
  order: number;
  techniques: MatrixTechnique[];
}
export interface AttackMatrix {
  attack_version: string;
  platforms: string[];
  tactics: MatrixTactic[];
}

/** GET /api/attack/coverage */
export interface CoverageRule {
  id: number;
  name: string;
  enabled: boolean;
  level: Exclude<CoverageLevel, 'none'>;
  proven_by: 'alert' | 'test' | null;
  technique_id: string;
  reason: string;
}
export interface CoverageExclusion {
  technique_id: string;
  note: string | null;
  created_by: string | null;
  created_at: string | null;
  inherited_from?: string;
}
export interface CoverageTechnique {
  id: string;
  name: string;
  parent_id: string | null;
  tactics: string[];
  platforms: string[];
  level: CoverageLevel;
  proven_by: 'alert' | 'test' | null;
  excluded: boolean;
  exclusion: CoverageExclusion | null;
  alerts_30d: number;
  last_alert: string | null;
  rules: CoverageRule[];
  subtechniques?: { total: number; covered: number; excluded: number; ids: string[] };
}
export interface CoverageCounts {
  in_scope: number;
  excluded: number;
  counted: number;
  covered: number;
  proven: number;
  percent: number | null;
  by_level: Record<CoverageLevel, number>;
}
export interface CoverageTactic extends CoverageCounts {
  id: string;
  shortname: string;
  name: string;
  order: number;
}
export interface PlatformEvidence {
  platform: string;
  source: string;
  items: string[];
}
export interface CoverageScope {
  platforms: string[];
  source: 'inferred' | 'query';
  inferred: { platforms: string[]; inferred_from: PlatformEvidence[]; unmapped_parsers: string[] };
}
export interface AttackCoverage {
  attack_version: string;
  platforms: string[];
  summary: CoverageCounts;
  tactics: CoverageTactic[];
  techniques: CoverageTechnique[];
  rules: { tagged: number; by_level: Record<string, number> };
  scope: CoverageScope;
  sample?: { window_hours: number; parsers: number; logs: number };
  computed_at: string;
  cached: boolean;
}

/** The ATT&CK platforms of the bundled dataset (the API's `platforms` names). */
export const ATTACK_PLATFORMS = [
  'Containers',
  'ESXi',
  'IaaS',
  'Identity Provider',
  'Linux',
  'macOS',
  'Network Devices',
  'Office Suite',
  'PRE',
  'SaaS',
  'Windows',
] as const;

export interface LevelInfo {
  label: string;
  /** A short mark shown in every cell next to the colour, so the level never rests on colour alone. */
  mark: string;
  description: string;
}

/** Best last: the order the legend lists them in. */
export const LEVELS: CoverageLevel[] = ['none', 'disabled', 'no_data', 'covered', 'proven'];

export const LEVEL_INFO: Record<CoverageLevel, LevelInfo> = {
  none: { label: 'No rule', mark: '–', description: 'No rule is tagged with this technique.' },
  disabled: { label: 'Disabled', mark: '‖', description: 'Rules are tagged with it, but all of them are disabled.' },
  no_data: {
    label: 'No data',
    mark: '!',
    description: 'An enabled rule, but no recent log satisfies its conditions.',
  },
  covered: { label: 'Covered', mark: '✓', description: 'An enabled rule whose conditions some recent log satisfies.' },
  proven: { label: 'Proven', mark: '★', description: 'An enabled rule raised an alert in the last 30 days.' },
};

export const EXCLUDED_INFO: LevelInfo = {
  label: 'Not applicable',
  mark: '⊘',
  description: 'Marked not applicable: left out of the percentages.',
};

const TECHNIQUE_ID_RE = /^T\d{4}(?:\.\d{3})?$/;
const TECHNIQUE_TAG_RE = /^attack\.(t\d{4}(?:\.\d{3})?)$/i;
const TACTIC_TAG_RE = /^attack\.([a-z][a-z_-]{0,63})$/i;

/** Is this a technique ID (T1110, T1110.001; any case)? */
export function isTechniqueId(value: string): boolean {
  return typeof value === 'string' && TECHNIQUE_ID_RE.test(value.trim().toUpperCase());
}

/** "T1110.001" for "attack.t1110.001" (any case), or null. */
export function techniqueIdFromTag(tag: string): string | null {
  if (typeof tag !== 'string') return null;
  const m = TECHNIQUE_TAG_RE.exec(tag.trim());
  return m ? m[1].toUpperCase() : null;
}

/** The tag form of a technique ID: "attack.t1110.001". */
export function techniqueTag(id: string): string {
  return `attack.${id.trim().toLowerCase()}`;
}

/** The tactic shortname ("credential-access") of a tactic tag ("attack.credential_access"), or null. */
export function tacticFromTag(tag: string): string | null {
  if (typeof tag !== 'string' || techniqueIdFromTag(tag)) return null;
  const m = TACTIC_TAG_RE.exec(tag.trim());
  if (!m) return null;
  const name = m[1].toLowerCase();
  // Sigma group / software tags (attack.g0016, attack.s0002) are not tactics.
  if (/^[gs]\d{4}$/.test(name)) return null;
  return name.replace(/_/g, '-');
}

/** Technique IDs in a tag list, canonical, de-duplicated, sorted. */
export function techniqueIdsFromTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  const out = new Set<string>();
  for (const t of tags) {
    const id = techniqueIdFromTag(t);
    if (id) out.add(id);
  }
  return [...out].sort();
}

/** Is this tag an ATT&CK technique tag (shown as a technique chip rather than a plain tag)? */
export function isTechniqueTag(tag: string): boolean {
  return techniqueIdFromTag(tag) !== null;
}

/** Add a technique's tag to a tag list (no duplicate, any case); returns a new list. */
export function addTechniqueTag(tags: string[], id: string): string[] {
  const canonical = id.trim().toUpperCase();
  if (!isTechniqueId(canonical)) return [...tags];
  if (tags.some((t) => techniqueIdFromTag(t) === canonical)) return [...tags];
  return [...tags, techniqueTag(canonical)];
}

/** Remove a technique's tag (any case) from a tag list; returns a new list. */
export function removeTechniqueTag(tags: string[], id: string): string[] {
  const canonical = id.trim().toUpperCase();
  return tags.filter((t) => techniqueIdFromTag(t) !== canonical);
}

/** The parent of a sub-technique ("T1110" for "T1110.001"), or the ID itself. */
export function parentTechniqueId(id: string): string {
  const dot = id.indexOf('.');
  return dot < 0 ? id : id.slice(0, dot);
}

/** The technique's page on attack.mitre.org (sub-techniques as /T1110/001/). */
export function attackTechniqueUrl(id: string): string {
  const [base, sub] = id.trim().toUpperCase().split('.');
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`;
}

export interface IndexedTechnique {
  id: string;
  name: string;
  /** "Brute Force: Password Guessing" for a sub-technique, the name otherwise. */
  fullName: string;
  parentId: string | null;
  /** Tactic shortnames (hyphenated), in matrix order. */
  tactics: string[];
}

export interface TechniqueIndex {
  byId: Map<string, IndexedTechnique>;
  /** Parents then their sub-techniques, by ID. */
  list: IndexedTechnique[];
  tactics: Array<{ id: string; shortname: string; name: string }>;
}

/** Index a matrix (the full one, `platforms=all`, for names anywhere in the UI). */
export function buildTechniqueIndex(matrix: Pick<AttackMatrix, 'tactics'>): TechniqueIndex {
  const byId = new Map<string, IndexedTechnique>();
  const tactics = [...matrix.tactics].sort((a, b) => a.order - b.order);
  const put = (id: string, name: string, parent: { id: string; name: string } | null, tactic: string) => {
    let entry = byId.get(id);
    if (!entry) {
      entry = { id, name, fullName: parent ? `${parent.name}: ${name}` : name, parentId: parent?.id ?? null, tactics: [] };
      byId.set(id, entry);
    }
    if (!entry.tactics.includes(tactic)) entry.tactics.push(tactic);
  };
  for (const tac of tactics) {
    for (const t of tac.techniques) {
      put(t.id, t.name, null, tac.shortname);
      for (const s of t.subtechniques ?? []) put(s.id, s.name, t, tac.shortname);
    }
  }
  const list = [...byId.values()].sort((a, b) => compareTechniqueIds(a.id, b.id));
  return { byId, list, tactics: tactics.map((t) => ({ id: t.id, shortname: t.shortname, name: t.name })) };
}

/** T1059 < T1059.001 < T1059.004 < T1078. */
export function compareTechniqueIds(a: string, b: string): number {
  return a.localeCompare(b, 'en', { numeric: true });
}

/** "T1110.001 Brute Force: Password Guessing", or the bare ID when the index does not know it. */
export function techniqueLabel(index: TechniqueIndex | null, id: string): string {
  const t = index?.byId.get(id);
  return t ? `${id} ${t.fullName}` : id;
}

/**
 * Techniques matching a search by ID or name, best first: exact ID, ID prefix,
 * name prefix, then name substring. An empty query lists the first `limit`
 * by ID.
 */
export function searchTechniques(index: TechniqueIndex | null, query: string, limit = 50): IndexedTechnique[] {
  if (!index) return [];
  const q = query.trim().toLowerCase();
  if (!q) return index.list.slice(0, limit);
  const scored: Array<{ t: IndexedTechnique; score: number }> = [];
  for (const t of index.list) {
    const id = t.id.toLowerCase();
    const name = t.fullName.toLowerCase();
    let score = -1;
    if (id === q || `attack.${id}` === q) score = 0;
    else if (id.startsWith(q)) score = 1;
    else if (t.name.toLowerCase().startsWith(q) || name.startsWith(q)) score = 2;
    else if (name.includes(q)) score = 3;
    if (score >= 0) scored.push({ t, score });
  }
  scored.sort((a, b) => a.score - b.score || compareTechniqueIds(a.t.id, b.t.id));
  return scored.slice(0, limit).map((s) => s.t);
}

export interface AttackFilter {
  /** A technique ID: matches it and, for a parent, its sub-techniques. */
  technique?: string | null;
  /** A tactic shortname (hyphen or underscore). */
  tactic?: string | null;
}

/** Does a technique ID fall under a filter technique (itself, or a sub-technique of a parent)? */
export function techniqueMatches(id: string, filter: string): boolean {
  const f = filter.trim().toUpperCase();
  return id === f || (!f.includes('.') && parentTechniqueId(id) === f);
}

/**
 * Does a rule (its tags) pass a technique/tactic filter? The technique filter
 * works like GET /api/alerts?technique= (a parent matches its sub-techniques);
 * a tactic matches a rule with any technique under it, or an explicit tactic tag.
 */
export function tagsMatchAttackFilter(tags: unknown, filter: AttackFilter, index: TechniqueIndex | null): boolean {
  const list = Array.isArray(tags) ? (tags as unknown[]).filter((t): t is string => typeof t === 'string') : [];
  const ids = techniqueIdsFromTags(list);
  if (filter.technique && !ids.some((id) => techniqueMatches(id, filter.technique!))) return false;
  if (filter.tactic) {
    const tactic = filter.tactic.toLowerCase().replace(/_/g, '-');
    const viaTechnique = ids.some((id) => index?.byId.get(id)?.tactics.includes(tactic));
    const explicit = list.some((t) => tacticFromTag(t) === tactic);
    if (!viaTechnique && !explicit) return false;
  }
  return true;
}

/**
 * The techniques a catalog rule would fill: its tagged techniques that are in
 * scope, not excluded, and at `none` in the coverage. Empty when it fills no gap.
 */
export function gapsFilled(tags: unknown, coverage: Map<string, Pick<CoverageTechnique, 'level' | 'excluded'>>): string[] {
  return techniqueIdsFromTags(tags).filter((id) => {
    const c = coverage.get(id);
    return !!c && c.level === 'none' && !c.excluded;
  });
}

/** "12.5 %", or "–" when nothing is counted. */
export function formatPercent(p: number | null | undefined): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return '–';
  return `${Number.isInteger(p) ? p : p.toFixed(1)} %`;
}

/**
 * The alerts heatmap's shade (0-4) for a 30-day alert count: 0 none, then
 * 1-9, 10-99, 100-999, 1000+. Fixed steps (not relative to the busiest cell),
 * so a shade means the same thing on every visit; the count is printed too.
 */
export function alertBucket(count: number): 0 | 1 | 2 | 3 | 4 {
  if (!Number.isFinite(count) || count <= 0) return 0;
  if (count < 10) return 1;
  if (count < 100) return 2;
  if (count < 1000) return 3;
  return 4;
}

/** True when nothing in scope has any rule (every counted technique at `none`). */
export function nothingTagged(summary: Pick<CoverageCounts, 'in_scope' | 'by_level'> | null | undefined): boolean {
  if (!summary || summary.in_scope === 0) return false;
  return (summary.by_level?.none ?? 0) >= summary.in_scope;
}

export interface MatrixCell {
  technique: CoverageTechnique;
  /** Sub-techniques to draw under it (only when sub-techniques are shown, or a search matched one). */
  subs: CoverageTechnique[];
}

export interface MatrixColumn {
  tactic: CoverageTactic;
  cells: MatrixCell[];
}

/**
 * The matrix to draw: one column per tactic (in order), the parent techniques
 * under it sorted by name. A search (ID or name) keeps a parent when it or one
 * of its sub-techniques matches, and shows the matching sub-techniques even
 * when sub-techniques are hidden. Sub-techniques are not built at all
 * otherwise, which keeps the ~700 techniques of a full matrix cheap.
 */
export function buildMatrixColumns(
  coverage: Pick<AttackCoverage, 'tactics' | 'techniques'>,
  opts: { search?: string; showSubtechniques?: boolean } = {}
): MatrixColumn[] {
  const q = (opts.search ?? '').trim().toLowerCase();
  const matches = (t: CoverageTechnique) => !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
  const subsByParent = new Map<string, CoverageTechnique[]>();
  if (opts.showSubtechniques || q) {
    for (const t of coverage.techniques) {
      if (!t.parent_id) continue;
      if (!subsByParent.has(t.parent_id)) subsByParent.set(t.parent_id, []);
      subsByParent.get(t.parent_id)!.push(t);
    }
  }
  const parents = coverage.techniques.filter((t) => !t.parent_id).sort((a, b) => a.name.localeCompare(b.name));
  return [...coverage.tactics]
    .sort((a, b) => a.order - b.order)
    .map((tactic) => {
      const cells: MatrixCell[] = [];
      for (const t of parents) {
        if (!t.tactics.includes(tactic.shortname)) continue;
        const subs = subsByParent.get(t.id) ?? [];
        const parentHit = matches(t);
        const subHits = q ? subs.filter(matches) : subs;
        if (!parentHit && subHits.length === 0) continue;
        // Searching: the matching sub-techniques (all of them when the parent itself matched and they are shown).
        const shown = q ? (opts.showSubtechniques && parentHit ? subs : subHits) : opts.showSubtechniques ? subs : [];
        cells.push({ technique: t, subs: shown });
      }
      return { tactic, cells };
    });
}
