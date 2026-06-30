/**
 * Content Pack install + status. Resolves a bundled pack manifest against the
 * live catalog and installs the referenced parsers + detections through the same
 * validate -> upsert path the per-item catalog install uses. Detection installs
 * reload the rules engine (live); parser installs apply on the next backend
 * restart, exactly like the existing parser catalog install.
 */
import { ParserModel } from '../../models/Parser';
import { DetectionRuleModel } from '../../models/DetectionRule';
import { getCatalogParser } from '../parser/catalogService';
import { validatePortableParser, runSelfTests } from '../parser/parserPortable';
import { fetchDetectionCatalog, getCatalogDetection } from '../rules/detectionCatalog';
import { validateRule, portableRuleToYaml } from '../rules/rulePortable';
import { RulesEngine } from '../rules/rulesEngine';
import { logger } from '../../utils/logger';
import { CONTENT_PACKS, ContentPack, getContentPack, detectionMatchesPack } from './contentPacks';

export interface PackStatus {
  id: string;
  name: string;
  description: string;
  icon: string;
  setup: string[];
  parserTotal: number;
  parserInstalled: number;
  detectionTotal: number;
  detectionInstalled: number;
  /** 'installed' | 'partial' | 'not_installed' — derived from the counts. */
  status: 'installed' | 'partial' | 'not_installed';
  /** True if the detection catalog couldn't be reached (detectionTotal is then unknown). */
  catalogUnavailable: boolean;
}

function deriveStatus(pi: number, pt: number, di: number, dt: number): PackStatus['status'] {
  const total = pt + dt;
  const installed = pi + di;
  if (total > 0 && installed >= total) return 'installed';
  if (installed > 0) return 'partial';
  return 'not_installed';
}

/** List every pack annotated with how many of its items are already installed. */
export async function listPacksWithStatus(): Promise<PackStatus[]> {
  const installedParsers = new Set((await ParserModel.findAll()).map((p) => p.name));
  const installedRules = new Set((await DetectionRuleModel.findAll()).map((r: any) => r.name));

  let entries: Array<{ name: string; tags?: string[]; path?: string }> = [];
  let catalogUnavailable = false;
  try {
    entries = (await fetchDetectionCatalog(false)).entries as any[];
  } catch (e) {
    catalogUnavailable = true;
    logger.warn('[Packs] detection catalog unavailable for status', {
      error: e instanceof Error ? e.message : String(e),
    });
  }

  return CONTENT_PACKS.map((pack) => {
    const matched = entries.filter((e) => detectionMatchesPack(e, pack));
    const parserInstalled = pack.parsers.filter((n) => installedParsers.has(n)).length;
    const detectionInstalled = matched.filter((e) => installedRules.has(e.name)).length;
    const parserTotal = pack.parsers.length;
    const detectionTotal = matched.length;
    return {
      id: pack.id,
      name: pack.name,
      description: pack.description,
      icon: pack.icon,
      setup: pack.setup,
      parserTotal,
      parserInstalled,
      detectionTotal,
      detectionInstalled,
      status: catalogUnavailable
        ? parserInstalled >= parserTotal && parserTotal > 0
          ? 'installed'
          : parserInstalled > 0
            ? 'partial'
            : 'not_installed'
        : deriveStatus(parserInstalled, parserTotal, detectionInstalled, detectionTotal),
      catalogUnavailable,
    };
  });
}

export interface PackInstallResult {
  pack: string;
  parsers: { installed: number; updated: number; failed: Array<{ name: string; reason: string }> };
  detections: { installed: number; updated: number; failed: Array<{ name: string; reason: string }> };
}

/** Install (or update) every parser + detection a pack references. */
export async function installPack(id: string): Promise<PackInstallResult> {
  const pack = getContentPack(id);
  if (!pack) throw new Error(`Unknown content pack "${id}"`);

  const result: PackInstallResult = {
    pack: pack.id,
    parsers: { installed: 0, updated: 0, failed: [] },
    detections: { installed: 0, updated: 0, failed: [] },
  };

  // --- Parsers ---
  for (const name of pack.parsers) {
    try {
      const portable = await getCatalogParser(name);
      if (!portable) {
        result.parsers.failed.push({ name, reason: 'not found in catalog' });
        continue;
      }
      const validation = validatePortableParser(portable, { strict: false });
      if (!validation.ok) {
        result.parsers.failed.push({ name, reason: 'failed validation' });
        continue;
      }
      // Self-test is informational here; the user explicitly chose the pack, so a
      // self-test miss doesn't block install (matches catalog install with force).
      runSelfTests(portable);
      const existing = await ParserModel.findByName(portable.name);
      const params = {
        name: portable.name,
        description: portable.description,
        enabled: portable.enabled,
        priority: portable.priority,
        parser_type: portable.parser_type,
        pattern: portable.pattern,
        field_mappings: portable.field_mappings,
        test_samples: portable.test_samples,
        event_type: portable.event_type ?? undefined,
        derivations: portable.derivations ?? null,
      };
      if (existing) {
        await ParserModel.update(existing.id, params);
        result.parsers.updated++;
      } else {
        await ParserModel.create(params);
        result.parsers.installed++;
      }
    } catch (e) {
      result.parsers.failed.push({ name, reason: e instanceof Error ? e.message : 'install error' });
    }
  }

  // --- Detections (matched against the live catalog by category/tag) ---
  let matchedNames: string[] = [];
  try {
    const { entries } = await fetchDetectionCatalog(false);
    matchedNames = (entries as any[]).filter((e) => detectionMatchesPack(e, pack)).map((e) => e.name);
  } catch (e) {
    result.detections.failed.push({ name: '(catalog)', reason: 'detection catalog unavailable' });
  }

  for (const name of matchedNames) {
    try {
      const found = await getCatalogDetection(name);
      if (!found) {
        result.detections.failed.push({ name, reason: 'not found in catalog' });
        continue;
      }
      const { rule_yaml, parsed } = found;
      const validation = validateRule(parsed, { strict: false });
      if (!validation.ok) {
        result.detections.failed.push({ name, reason: 'failed validation' });
        continue;
      }
      const rule_logic = { conditions: parsed.conditions, aggregation: parsed.aggregation, alert: parsed.alert };
      const existing = await DetectionRuleModel.findByName(parsed.name);
      if (existing) {
        await DetectionRuleModel.update(existing.id, {
          description: parsed.description,
          severity: parsed.severity,
          rule_yaml: rule_yaml || portableRuleToYaml(parsed),
          rule_logic,
          tags: parsed.tags || [],
        });
        result.detections.updated++;
      } else {
        await DetectionRuleModel.create({
          name: parsed.name,
          description: parsed.description,
          enabled: parsed.enabled !== false,
          severity: parsed.severity,
          rule_yaml: rule_yaml || portableRuleToYaml(parsed),
          rule_logic,
          tags: parsed.tags || [],
        });
        result.detections.installed++;
      }
    } catch (e) {
      result.detections.failed.push({ name, reason: e instanceof Error ? e.message : 'install error' });
    }
  }

  if (result.detections.installed > 0 || result.detections.updated > 0) {
    await RulesEngine.getInstance().reload();
  }

  return result;
}

export { CONTENT_PACKS, ContentPack };
