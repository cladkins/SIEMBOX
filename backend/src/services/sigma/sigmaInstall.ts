/**
 * Add and update detection rules from the SigmaHQ library.
 *
 * The same path as the Sigma import (routes/rules.ts POST /import/sigma):
 * validate -> regex gate (every converted regex; a vulnerable or undecided one
 * refuses the whole Sigma rule, nothing saved) -> upsert. Added rules start
 * DISABLED, as imported ones do, so the user reviews and enables them; a
 * Content Pack install (services/packs) adds its Sigma rules enabled, as it
 * does its catalog detections.
 *
 * Provenance: detection_rules.sigma_id / sigma_release / sigma_hash /
 * sigma_part (migration 046). A name already taken by any other rule is never
 * overwritten: the new rule gets a " (SigmaHQ)" suffix (then "(SigmaHQ 2)", ...).
 *
 * Update keeps each part's row id (its alert history stays attached) and its
 * enabled choice, and replaces conditions, exclude, alert, severity, tags and
 * description. When SigmaHQ changes how many OR alternatives a rule has, parts
 * are added (taking the rule's enabled choice) or removed; a removed part that
 * has alerts is kept, disabled and detached ("retired"), so no history is lost.
 */
import { query } from '../../config/database';
import { DetectionRuleModel, type DetectionRule } from '../../models/DetectionRule';
import { validateRule, ruleLogicOf, portableRuleToYaml, type PortableRule } from '../rules/rulePortable';
import { assessRuleRegexes, isRefused, refusalCode, refusalReason } from '../regex/regexSafety';
import { regexRunErrorResponse } from '../regex/boundedRegex';
import { loadSigmaLibrary } from './sigmaStore';
import type { SigmaLibraryRule } from './sigmaLibrary';

const NAME_MAX = 255;
export const MAX_BULK_INSTALL = 500;

export class SigmaInstallError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public extra: Record<string, unknown> = {}
  ) {
    super(message);
  }
}

/** The SIEMBox name of part `i` (0-based) of `n`, with an optional collision suffix, within 255 chars. */
export function sigmaPartName(title: string, i: number, n: number, suffix = ''): string {
  const tail = `${n > 1 ? ` (part ${i + 1} of ${n})` : ''}${suffix}`;
  return `${title.slice(0, NAME_MAX - tail.length).trimEnd()}${tail}`;
}

/** A free name for a part: the plain one, else " (SigmaHQ)", " (SigmaHQ 2)", ... (never another rule's name). */
async function freeName(title: string, i: number, n: number, own: Set<number>): Promise<string> {
  for (let k = 0; k < 50; k++) {
    const suffix = k === 0 ? '' : k === 1 ? ' (SigmaHQ)' : ` (SigmaHQ ${k})`;
    const name = sigmaPartName(title, i, n, suffix);
    const taken = await DetectionRuleModel.findByName(name);
    if (!taken || own.has(taken.id)) return name;
  }
  throw new SigmaInstallError(409, 'SIGMA_NAME_TAKEN', `No free name for "${title}"`);
}

/** Validate and gate every part; throws SigmaInstallError (422/503) when any is refused. */
async function gateParts(entry: SigmaLibraryRule): Promise<string[]> {
  const warnings: string[] = [];
  for (const [i, part] of entry.parts.entries()) {
    const v = validateRule(part, { strict: false });
    if (!v.ok) throw new SigmaInstallError(422, 'SIGMA_INVALID', `"${entry.title}" failed validation: ${v.errors.join('; ')}`);
    let report;
    try {
      report = await assessRuleRegexes(part);
    } catch (error) {
      const answer = regexRunErrorResponse(error);
      if (!answer) throw error;
      throw new SigmaInstallError(answer.status, answer.body.code, answer.body.message);
    }
    if (isRefused(report)) {
      throw new SigmaInstallError(422, refusalCode(report), `"${entry.title}" was not added: ${refusalReason(report)}`, {
        part: i + 1,
        regex_safety: { vulnerable: report.vulnerable, undecided: report.undecided, unknown: report.unknown },
      });
    }
    warnings.push(...report.warnings);
  }
  return warnings;
}

async function libraryEntry(sigmaId: string): Promise<{ entry: SigmaLibraryRule; tag: string }> {
  const lib = await loadSigmaLibrary();
  const entry = lib.byId.get(sigmaId);
  if (!entry || !lib.tag) throw new SigmaInstallError(404, 'SIGMA_NOT_FOUND', `Sigma rule ${sigmaId} is not in the cached SigmaHQ library`);
  if (!entry.convertible || entry.parts.length === 0) {
    throw new SigmaInstallError(422, 'SIGMA_NOT_CONVERTIBLE', `"${entry.title}" does not convert to a SIEMBox rule: ${entry.errors.join('; ')}`);
  }
  return { entry, tag: lib.tag };
}

function partFields(part: PortableRule) {
  return {
    description: part.description,
    severity: part.severity,
    rule_yaml: portableRuleToYaml(part),
    rule_logic: ruleLogicOf(part),
    tags: part.tags || [],
  };
}

export interface SigmaInstallResult {
  action: 'created' | 'updated';
  rules: DetectionRule[];
  /** Parts removed (no alerts) or retired (kept with their alerts, disabled). */
  removed: number[];
  retired: number[];
  warnings: string[];
}

/**
 * Add a library rule (every part). 409 when it is already added. Disabled
 * unless `enabled` (a Content Pack install: the pack is the reviewed choice,
 * and pack installs create their catalog detections enabled too).
 */
export async function installSigmaRule(sigmaId: string, opts: { enabled?: boolean } = {}): Promise<SigmaInstallResult> {
  const { entry, tag } = await libraryEntry(sigmaId);
  const existing = await DetectionRuleModel.findBySigmaId(sigmaId);
  if (existing.length > 0) {
    throw new SigmaInstallError(409, 'SIGMA_ALREADY_ADDED', `"${entry.title}" is already added`, {
      rule_ids: existing.map((r) => r.id),
    });
  }
  const warnings = await gateParts(entry);
  const created: DetectionRule[] = [];
  try {
    const n = entry.parts.length;
    for (const [i, part] of entry.parts.entries()) {
      created.push(
        await DetectionRuleModel.create({
          name: await freeName(entry.title, i, n, new Set()),
          enabled: opts.enabled === true, // by default added for review, like the Sigma import
          ...partFields(part),
          sigma_id: entry.sigma_id,
          sigma_release: tag,
          sigma_hash: entry.content_hash,
          sigma_part: i + 1,
        })
      );
    }
  } catch (error) {
    for (const r of created) await DetectionRuleModel.delete(r.id).catch(() => undefined);
    throw error;
  }
  return { action: 'created', rules: created, removed: [], retired: [], warnings };
}

/** Update an added library rule to the cached release. 404 when it was never added. */
export async function updateSigmaRule(sigmaId: string): Promise<SigmaInstallResult> {
  const { entry, tag } = await libraryEntry(sigmaId);
  const rows = await DetectionRuleModel.findBySigmaId(sigmaId);
  if (rows.length === 0) throw new SigmaInstallError(404, 'SIGMA_NOT_ADDED', `"${entry.title}" has not been added`);
  const warnings = await gateParts(entry);

  const n = entry.parts.length;
  const byPart = new Map<number, DetectionRule>();
  const unplaced: DetectionRule[] = [];
  for (const r of rows) {
    if (r.sigma_part && r.sigma_part >= 1 && !byPart.has(r.sigma_part)) byPart.set(r.sigma_part, r);
    else unplaced.push(r);
  }
  // The user's choice for the Sigma rule as a whole, for parts SigmaHQ added.
  const enabledChoice = rows.some((r) => r.enabled);

  const saved: DetectionRule[] = [];
  for (const [i, part] of entry.parts.entries()) {
    const row = byPart.get(i + 1) ?? unplaced.shift();
    const name = await freeName(entry.title, i, n, new Set(row ? [row.id] : []));
    const fields = { ...partFields(part), sigma_release: tag, sigma_hash: entry.content_hash, sigma_part: i + 1 };
    if (row) {
      byPart.delete(i + 1);
      const updated = await DetectionRuleModel.update(row.id, { ...fields, name }); // enabled untouched
      if (updated) saved.push(updated);
    } else {
      saved.push(await DetectionRuleModel.create({ name, enabled: enabledChoice, ...fields, sigma_id: entry.sigma_id }));
    }
  }

  // Parts SigmaHQ no longer has.
  const removed: number[] = [];
  const retired: number[] = [];
  for (const row of [...byPart.values(), ...unplaced]) {
    const alerts = await query('SELECT 1 FROM alerts WHERE rule_id = $1 LIMIT 1', [row.id]);
    if ((alerts.rowCount ?? 0) === 0) {
      await DetectionRuleModel.delete(row.id);
      removed.push(row.id);
    } else {
      const retiredName = sigmaPartName(row.name, 0, 1, ` (retired ${row.id})`);
      await DetectionRuleModel.update(row.id, { name: retiredName, enabled: false, sigma_id: null, sigma_part: null });
      retired.push(row.id);
    }
  }
  return { action: 'updated', rules: saved, removed, retired, warnings };
}
