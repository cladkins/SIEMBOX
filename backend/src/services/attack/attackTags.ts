/**
 * MITRE ATT&CK tags on detection rules, in the Sigma convention, inside the
 * rule's existing `tags` array:
 *
 *   attack.t1110          technique          (canonical ID T1110)
 *   attack.t1110.001      sub-technique      (T1110.001)
 *   attack.credential_access   tactic (ATT&CK shortname, underscores)
 *   attack.g0016 / attack.s0002   group / software (Sigma; accepted, not checked)
 *
 * Matching is case-insensitive. A rule's tactics are derived from its
 * techniques; an explicit tactic tag is allowed but never needed.
 *
 * analyzeAttackTags is the one check every path shares: validateRule (and so
 * validate-detections, catalog and content-pack installs), the rule
 * create/update routes (422 ATTACK_TAG_INVALID), and the Sigma converter, which
 * drops the bad tags with a warning instead of failing the import.
 */
import {
  attackDataset,
  attackVersion,
  getTactic,
  getTechnique,
  techniqueDisplayName,
} from './attackData';

const PREFIX = 'attack.';
/** attack.tNNNN / attack.tNNNN.NNN after the prefix. Anchored, no nested quantifiers. */
const TECHNIQUE_RE = /^t\d{4}(?:\.\d{3})?$/i;
/** Anything that starts like a technique ID (so attack.t1110.01 is a bad technique, not a tactic). */
const TECHNIQUE_LIKE_RE = /^t\d/i;
/** Sigma group (gNNNN) and software (sNNNN) tags. */
const GROUP_OR_SOFTWARE_RE = /^[gs]\d{4}$/i;
const TACTIC_RE = /^[a-z][a-z_-]{0,63}$/i;

export interface AttackTagReport {
  /** Known, live technique IDs, canonical (T1110.001), sorted. */
  techniques: string[];
  /** Tactics derived from `techniques` (hyphen shortnames), in matrix order. */
  tactics: string[];
  /** Explicit tactic tags that resolved (hyphen shortnames; legacy ones mapped). */
  explicitTactics: string[];
  /** One message per bad tag; any error makes the rule invalid. */
  errors: string[];
  warnings: string[];
  /** The tags behind `errors`, verbatim (what the Sigma import drops). */
  invalidTags: string[];
}

function isAttackTag(tag: string): boolean {
  return tag.length > PREFIX.length && tag.slice(0, PREFIX.length).toLowerCase() === PREFIX;
}

/** "T1110.001" for "attack.t1110.001" (any case), or null when it is not a well-formed technique tag. */
export function techniqueIdFromTag(tag: string): string | null {
  if (typeof tag !== 'string' || !isAttackTag(tag)) return null;
  const rest = tag.slice(PREFIX.length);
  return TECHNIQUE_RE.test(rest) ? rest.toUpperCase() : null;
}

/** The tag form of a technique ID: "attack.t1110.001". */
export function techniqueTag(id: string): string {
  return `${PREFIX}${id.toLowerCase()}`;
}

/**
 * Well-formed technique IDs in a rule's tags, canonical and de-duplicated —
 * what an alert copies into alerts.attack_techniques (migration 045's backfill
 * uses the same pattern in SQL).
 */
export function techniqueIdsFromTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  const out = new Set<string>();
  for (const t of tags) {
    const id = typeof t === 'string' ? techniqueIdFromTag(t) : null;
    if (id) out.add(id);
  }
  return [...out].sort();
}

/** A tactic query/tag value (credential_access, credential-access) as a current shortname, or null. */
export function resolveTacticName(value: string): string | null {
  if (typeof value !== 'string' || !TACTIC_RE.test(value)) return null;
  const shortname = value.toLowerCase().replace(/_/g, '-');
  return getTactic(shortname) ? shortname : null;
}

function tacticOrder(shortname: string): number {
  return getTactic(shortname)?.order ?? Number.MAX_SAFE_INTEGER;
}

/** Check every `attack.*` tag of a rule. Non-attack tags (and non-strings) are ignored. */
export function analyzeAttackTags(tags: unknown): AttackTagReport {
  const report: AttackTagReport = {
    techniques: [],
    tactics: [],
    explicitTactics: [],
    errors: [],
    warnings: [],
    invalidTags: [],
  };
  if (!Array.isArray(tags)) return report;
  const data = attackDataset();
  const version = `ATT&CK ${attackVersion()}`;
  const techniques = new Set<string>();
  const explicit: Array<{ tag: string; tactics: string[] }> = [];
  const bad = (tag: string, message: string) => {
    report.errors.push(message);
    report.invalidTags.push(tag);
  };

  for (const tag of tags) {
    if (typeof tag !== 'string' || !isAttackTag(tag)) continue;
    const rest = tag.slice(PREFIX.length);

    if (TECHNIQUE_LIKE_RE.test(rest)) {
      if (!TECHNIQUE_RE.test(rest)) {
        bad(tag, `${tag}: not an ATT&CK technique ID (use attack.tNNNN or attack.tNNNN.NNN, e.g. attack.t1110.001)`);
        continue;
      }
      const id = rest.toUpperCase();
      const t = getTechnique(id);
      if (!t) {
        bad(tag, `${tag}: ${id} is not a technique in ${version} Enterprise`);
      } else if (t.revoked) {
        const to = t.revokedBy;
        bad(
          tag,
          to
            ? `${tag}: ${id} "${techniqueDisplayName(id)}" was revoked in ${version}; use ${techniqueTag(to)} (${to} "${techniqueDisplayName(to)}")`
            : `${tag}: ${id} "${techniqueDisplayName(id)}" was revoked in ${version} and has no replacement; remove the tag`
        );
      } else if (t.deprecated) {
        bad(tag, `${tag}: ${id} "${techniqueDisplayName(id)}" is deprecated in ${version} and has no replacement; remove the tag`);
      } else {
        techniques.add(id);
      }
      continue;
    }

    if (GROUP_OR_SOFTWARE_RE.test(rest)) continue;

    const shortname = TACTIC_RE.test(rest) ? rest.toLowerCase().replace(/_/g, '-') : null;
    if (shortname && getTactic(shortname)) {
      explicit.push({ tag, tactics: [shortname] });
    } else if (shortname && Object.prototype.hasOwnProperty.call(data.legacyTactics, shortname)) {
      const current = data.legacyTactics[shortname];
      report.warnings.push(
        `${tag}: "${shortname}" is not a tactic in ${version} (it became ${current.map((c) => `attack.${c.replace(/-/g, '_')}`).join(' and ')}); the tag is kept, prefer the current name`
      );
      explicit.push({ tag, tactics: current });
    } else {
      bad(
        tag,
        `${tag}: unknown ATT&CK tactic (one of ${data.tactics.map((t) => t.shortname.replace(/-/g, '_')).join(', ')})`
      );
    }
  }

  report.techniques = [...techniques].sort();
  const derived = new Set<string>();
  for (const id of report.techniques) for (const tac of getTechnique(id)!.tactics) derived.add(tac);
  report.tactics = [...derived].sort((a, b) => tacticOrder(a) - tacticOrder(b));
  const explicitSet = new Set<string>();
  for (const e of explicit) for (const tac of e.tactics) explicitSet.add(tac);
  report.explicitTactics = [...explicitSet].sort((a, b) => tacticOrder(a) - tacticOrder(b));

  // A tactic tag none of the rule's techniques belongs to is probably a
  // mistake, but not necessarily (a technique can serve a tactic the matrix
  // does not list it under), so it only warns.
  if (report.techniques.length > 0) {
    for (const e of explicit) {
      if (!e.tactics.some((tac) => derived.has(tac))) {
        report.warnings.push(
          `${e.tag}: none of the rule's techniques (${report.techniques.join(', ')}) is under this tactic in ${version}; ` +
            `their tactics are ${report.tactics.map((t) => `attack.${t.replace(/-/g, '_')}`).join(', ')}`
        );
      }
    }
  }
  return report;
}

/**
 * The tags with every bad `attack.*` tag removed, and one warning per removal
 * (plus analyzeAttackTags' own warnings) — the Sigma import's policy, so a
 * stale community rule still imports.
 */
export function dropInvalidAttackTags(tags: string[]): { tags: string[]; warnings: string[] } {
  const report = analyzeAttackTags(tags);
  if (report.invalidTags.length === 0) return { tags, warnings: report.warnings };
  const drop = new Set(report.invalidTags);
  return {
    tags: tags.filter((t) => !drop.has(t)),
    warnings: [...report.errors.map((e) => `Dropped ATT&CK tag ${e}`), ...report.warnings],
  };
}
