/**
 * Content Pack status and install.
 *
 * Packs come from the catalog (packCatalog.ts; the bundled set is the
 * fallback). A pack references content, it does not carry it: parsers by
 * catalog name, catalog detections by category / tag / name, and SigmaHQ
 * rules by Sigma id. Installing a pack runs the normal install for each item:
 *  - parsers and catalog detections through the same validate -> regex gate
 *    -> upsert path as the per-item catalog install (detections created
 *    enabled unless the rule says otherwise, as before);
 *  - Sigma rules through the SigmaHQ library install (sigmaInstall.ts), created
 *    ENABLED: installing a pack is the explicit "turn this on" choice, made
 *    after reading its guide, the same as for the pack's catalog detections. A
 *    Sigma rule already added (from the library, disabled) is left as it is.
 *    While the SigmaHQ library is not loaded (never refreshed, or SigmaHQ is
 *    unreachable), its Sigma items are reported as pending with the reason and
 *    everything else installs.
 * Detection installs reload the rules engine (live); parser installs reload
 * the parser engine.
 *
 * Every install is recorded (content_pack_installs, migration 047): the pack
 * version and its item list at that moment. Status compares that snapshot with
 * the pack as the catalog has it now, so the page can show "What's new since
 * you installed" and install only those items (installPack onlyNew).
 */
import { query } from '../../config/database';
import { ParserModel } from '../../models/Parser';
import { DetectionRuleModel } from '../../models/DetectionRule';
import { getCatalogParser, fetchCatalog } from '../parser/catalogService';
import { ParserEngine } from '../parser/parserEngine';
import { validatePortableParser } from '../parser/parserPortable';
import { fetchDetectionCatalog, getCatalogDetection } from '../rules/detectionCatalog';
import { validateRule, portableRuleToYaml, ruleLogicOf } from '../rules/rulePortable';
import { RulesEngine } from '../rules/rulesEngine';
import { logger } from '../../utils/logger';
import { assessParserRegexes, assessRuleRegexes, isRefused, refusalReason, type RegexSafetyReport } from '../regex/regexSafety';
import { regexRunErrorResponse } from '../regex/boundedRegex';
import { getSigmaState, loadSigmaLibrary, sigmaCompatibility } from '../sigma/sigmaStore';
import { installSigmaRule, SigmaInstallError } from '../sigma/sigmaInstall';
import { detectionMatchesPack, type ContentPack, type PackSetupStep, type PackSigmaRef } from './packFormat';
import { fetchPackCatalog, type PackCatalog } from './packCatalog';

export class PackError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string
  ) {
    super(message);
  }
}

/**
 * The write-time regex gate for one pack item: a refusal reason (a regex recheck
 * proves vulnerable, or cannot read when nothing bounds it at run time, or the
 * checker is saturated), or null when it may be saved.
 * Indeterminate regexes are installed; their warnings go into `warnings`.
 */
async function packItemRefusal(
  check: () => Promise<RegexSafetyReport>,
  name: string,
  warnings: Array<{ name: string; warnings: string[] }>
): Promise<string | null> {
  try {
    const report = await check();
    if (isRefused(report)) return refusalReason(report);
    if (report.warnings.length > 0) warnings.push({ name, warnings: report.warnings });
    return null;
  } catch (error) {
    const answer = regexRunErrorResponse(error);
    if (!answer) throw error;
    return answer.body.message;
  }
}

// ---------------------------------------------------------------------------
// Install records (migration 047).
// ---------------------------------------------------------------------------

export interface PackPendingItem {
  kind: 'parser' | 'detection' | 'sigma';
  name: string;
  reason: string;
}

export interface PackInstallRecord {
  pack_id: string;
  version: number;
  source: string;
  installed_at: string;
  installed_by: number | null;
  installed_by_username: string | null;
  parsers: string[];
  detections: string[];
  sigma: string[];
  pending: PackPendingItem[];
  updated_at: string;
}

const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : String(v));

function rowToRecord(row: any): PackInstallRecord {
  return {
    pack_id: row.pack_id,
    version: row.version,
    source: row.source,
    installed_at: iso(row.installed_at),
    installed_by: row.installed_by ?? null,
    installed_by_username: row.installed_by_username ?? null,
    parsers: row.parsers ?? [],
    detections: row.detections ?? [],
    sigma: row.sigma ?? [],
    pending: Array.isArray(row.pending) ? row.pending : [],
    updated_at: iso(row.updated_at),
  };
}

export async function getPackInstallRecords(): Promise<Map<string, PackInstallRecord>> {
  const r = await query('SELECT * FROM content_pack_installs');
  return new Map(r.rows.map((row: any) => [row.pack_id, rowToRecord(row)]));
}

async function getPackInstallRecord(packId: string): Promise<PackInstallRecord | null> {
  const r = await query('SELECT * FROM content_pack_installs WHERE pack_id = $1', [packId]);
  return r.rows[0] ? rowToRecord(r.rows[0]) : null;
}

async function saveInstallRecord(rec: Omit<PackInstallRecord, 'installed_at' | 'updated_at'>): Promise<PackInstallRecord> {
  const r = await query(
    `INSERT INTO content_pack_installs (pack_id, version, source, installed_at, installed_by, installed_by_username,
        parsers, detections, sigma, pending, updated_at)
     VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9, NOW())
     ON CONFLICT (pack_id) DO UPDATE SET version = EXCLUDED.version, source = EXCLUDED.source,
        installed_at = NOW(), installed_by = EXCLUDED.installed_by,
        installed_by_username = EXCLUDED.installed_by_username, parsers = EXCLUDED.parsers,
        detections = EXCLUDED.detections, sigma = EXCLUDED.sigma, pending = EXCLUDED.pending, updated_at = NOW()
     RETURNING *`,
    [
      rec.pack_id,
      rec.version,
      rec.source,
      rec.installed_by,
      rec.installed_by_username,
      rec.parsers,
      rec.detections,
      rec.sigma,
      JSON.stringify(rec.pending),
    ]
  );
  return rowToRecord(r.rows[0]);
}

// ---------------------------------------------------------------------------
// What's new.
// ---------------------------------------------------------------------------

export interface PackWhatsNew {
  from_version: number;
  to_version: number;
  /** The catalog bumped the pack's version since the install. */
  version_bumped: boolean;
  parsers: string[];
  detections: string[];
  sigma: PackSigmaRef[];
  count: number;
}

/** Items of the pack as it is now that the install snapshot does not have (pure). */
export function packWhatsNew(
  current: { version: number; parsers: string[]; detections: string[]; sigma: PackSigmaRef[] },
  rec: Pick<PackInstallRecord, 'version' | 'parsers' | 'detections' | 'sigma'>
): PackWhatsNew {
  const had = (list: string[]) => new Set(list);
  const p = had(rec.parsers);
  const d = had(rec.detections);
  const s = had(rec.sigma);
  const parsers = current.parsers.filter((x) => !p.has(x));
  const detections = current.detections.filter((x) => !d.has(x));
  const sigma = current.sigma.filter((x) => !s.has(x.id));
  return {
    from_version: rec.version,
    to_version: current.version,
    version_bumped: current.version > rec.version,
    parsers,
    detections,
    sigma,
    count: parsers.length + detections.length + sigma.length,
  };
}

// ---------------------------------------------------------------------------
// Status.
// ---------------------------------------------------------------------------

/** Per-item status so the UI can show exactly what's installed vs missing, and why. */
export interface PackItemStatus {
  name: string;
  installed: boolean;
  /** False = the pack references this item but it isn't in the catalog (name gap). */
  inCatalog: boolean;
  /** Not in the install snapshot: added to the pack since it was installed. */
  new: boolean;
}

export type SigmaItemState = 'installed' | 'available' | 'pending' | 'not_convertible';

export interface PackSigmaStatus {
  id: string;
  title: string;
  installed: boolean;
  /** Parts of an added rule that are enabled (0 = added but switched off). */
  enabled_parts: number;
  /** installed; available (installs now); pending (library not loaded, or not in its release); not_convertible. */
  state: SigmaItemState;
  reason: string | null;
  /** Whether this install's recent logs carry the rule's fields (null: unknown). */
  compatible: boolean | null;
  missing_field: string | null;
  level: string | null;
  new: boolean;
}

export interface PackStatus {
  id: string;
  name: string;
  description: string;
  icon: string;
  version: number;
  setup: PackSetupStep[];
  parserTotal: number;
  parserInstalled: number;
  detectionTotal: number;
  detectionInstalled: number;
  sigmaTotal: number;
  sigmaInstalled: number;
  /** 'installed' | 'partial' | 'not_installed' — derived from the counts. */
  status: 'installed' | 'partial' | 'not_installed';
  /** True if the detection catalog couldn't be reached (detectionTotal is then unknown). */
  catalogUnavailable: boolean;
  parsers: PackItemStatus[];
  detections: PackItemStatus[];
  sigma: PackSigmaStatus[];
  install: Pick<PackInstallRecord, 'version' | 'installed_at' | 'installed_by_username' | 'pending' | 'source'> | null;
  whats_new: PackWhatsNew | null;
}

export interface PacksOverview {
  source: Omit<PackCatalog, 'packs'>;
  sigma_library: { loaded: boolean; release: string | null; last_error: string | null };
  packs: PackStatus[];
}

/** Why the pack's Sigma items cannot install now, or null when the library is loaded. */
async function sigmaLibraryReason(): Promise<{ reason: string | null; release: string | null; last_error: string | null }> {
  try {
    const [lib, state] = await Promise.all([loadSigmaLibrary(), getSigmaState()]);
    if (lib.tag && lib.rules.length > 0) return { reason: null, release: lib.tag, last_error: state.last_error };
    const why = state.last_error
      ? `the SigmaHQ library could not be fetched (${state.last_error})`
      : 'the SigmaHQ library has not been loaded yet';
    return { reason: `${why}: refresh it on Detection Rules > SigmaHQ, then install this pack again`, release: null, last_error: state.last_error };
  } catch (error) {
    return { reason: `the SigmaHQ library is unavailable (${error instanceof Error ? error.message : String(error)})`, release: null, last_error: null };
  }
}

function deriveStatus(installed: number, total: number): PackStatus['status'] {
  if (total > 0 && installed >= total) return 'installed';
  if (installed > 0) return 'partial';
  return 'not_installed';
}

/** List every pack annotated with which of its items are installed / available, and what's new. */
export async function listPacksWithStatus(opts: { refresh?: boolean } = {}): Promise<PacksOverview> {
  const catalog = await fetchPackCatalog(opts.refresh === true);
  const records = await getPackInstallRecords();
  const installedParsers = new Set((await ParserModel.findAll()).map((p) => p.name));
  const rules = await DetectionRuleModel.findAll();
  const installedRules = new Set(rules.map((r: any) => r.name));
  const sigmaRows = new Map<string, { enabled: number }>();
  for (const r of rules) {
    if (!r.sigma_id) continue;
    const s = sigmaRows.get(r.sigma_id) ?? { enabled: 0 };
    if (r.enabled) s.enabled++;
    sigmaRows.set(r.sigma_id, s);
  }

  let detEntries: Array<{ name: string; tags?: string[]; path?: string }> = [];
  let catalogUnavailable = false;
  try {
    detEntries = (await fetchDetectionCatalog(false)).entries as any[];
  } catch (e) {
    catalogUnavailable = true;
    logger.warn('[Packs] detection catalog unavailable for status', { error: e instanceof Error ? e.message : String(e) });
  }

  // Parser catalog names, so we can flag a pack parser that isn't in the catalog
  // at all (a name gap) vs one that's simply not installed yet.
  let catalogParserNames = new Set<string>();
  try {
    const { entries } = await fetchCatalog(false);
    catalogParserNames = new Set((entries as any[]).map((p) => p.name));
  } catch (e) {
    logger.warn('[Packs] parser catalog unavailable for status', { error: e instanceof Error ? e.message : String(e) });
  }
  const parserCatalogKnown = catalogParserNames.size > 0;

  const wantsSigma = catalog.packs.some((p) => p.sigma.length > 0);
  const libStatus = await sigmaLibraryReason();
  const lib = wantsSigma && !libStatus.reason ? await loadSigmaLibrary() : null;
  let compat: Awaited<ReturnType<typeof sigmaCompatibility>> | null = null;
  if (lib) {
    try {
      compat = await sigmaCompatibility();
    } catch (e) {
      logger.warn('[Packs] SigmaHQ compatibility unavailable', { error: e instanceof Error ? e.message : String(e) });
    }
  }

  const packs = catalog.packs.map((pack): PackStatus => {
    const rec = records.get(pack.id) ?? null;
    const matched = detEntries.filter((e) => detectionMatchesPack(e, pack)).map((e) => e.name);
    // A detection named by the pack that the catalog does not have.
    const namedMissing = catalogUnavailable ? [] : pack.detections.names.filter((n) => !matched.includes(n));
    const detectionNames = catalogUnavailable ? (rec?.detections ?? []) : matched;
    const isNew = (list: string[] | undefined, name: string) => !!rec && !(list ?? []).includes(name);

    const parsers: PackItemStatus[] = pack.parsers.map((name) => ({
      name,
      installed: installedParsers.has(name),
      // If we couldn't load the parser catalog, don't claim a gap — assume present.
      inCatalog: parserCatalogKnown ? catalogParserNames.has(name) : true,
      new: isNew(rec?.parsers, name),
    }));
    const detections: PackItemStatus[] = [
      ...detectionNames.map((name) => ({ name, installed: installedRules.has(name), inCatalog: true, new: isNew(rec?.detections, name) })),
      ...namedMissing.map((name) => ({ name, installed: installedRules.has(name), inCatalog: false, new: isNew(rec?.detections, name) })),
    ];
    const sigma: PackSigmaStatus[] = pack.sigma.map((ref) => {
      const added = sigmaRows.get(ref.id);
      const entry = lib?.byId.get(ref.id);
      const res = compat?.results.get(ref.id);
      let state: SigmaItemState;
      let reason: string | null = null;
      if (added) state = 'installed';
      else if (libStatus.reason) [state, reason] = ['pending', libStatus.reason];
      else if (!entry) [state, reason] = ['pending', `not in the cached SigmaHQ release (${libStatus.release})`];
      else if (!entry.convertible) [state, reason] = ['not_convertible', entry.errors.join('; ') || 'does not convert to a SIEMBox rule'];
      else state = 'available';
      return {
        id: ref.id,
        title: entry?.title ?? ref.title,
        installed: !!added,
        enabled_parts: added?.enabled ?? 0,
        state,
        reason,
        compatible: res ? res.compatible : null,
        missing_field: res?.missing_field ?? null,
        level: entry?.level ?? null,
        new: isNew(rec?.sigma, ref.id),
      };
    });

    const parserInstalled = parsers.filter((p) => p.installed).length;
    const detectionInstalled = detections.filter((d) => d.installed).length;
    const sigmaInstalled = sigma.filter((s) => s.installed).length;
    // Items that cannot install (not in the catalog, not convertible) do not
    // keep a pack from reading "installed".
    const total =
      parsers.filter((p) => p.inCatalog).length +
      detections.filter((d) => d.inCatalog).length +
      sigma.filter((s) => s.state !== 'not_convertible').length;
    const installedCount =
      parsers.filter((p) => p.inCatalog && p.installed).length +
      detections.filter((d) => d.inCatalog && d.installed).length +
      sigmaInstalled;

    const whatsNew = rec
      ? packWhatsNew(
          { version: pack.version, parsers: pack.parsers, detections: detectionNames, sigma: pack.sigma },
          rec
        )
      : null;

    return {
      id: pack.id,
      name: pack.name,
      description: pack.description,
      icon: pack.icon,
      version: pack.version,
      setup: pack.setup,
      parserTotal: parsers.length,
      parserInstalled,
      detectionTotal: detections.length,
      detectionInstalled,
      sigmaTotal: sigma.length,
      sigmaInstalled,
      status: deriveStatus(installedCount, total),
      catalogUnavailable,
      parsers,
      detections,
      sigma,
      install: rec
        ? { version: rec.version, installed_at: rec.installed_at, installed_by_username: rec.installed_by_username, pending: rec.pending, source: rec.source }
        : null,
      // Only when there is something to install: a version bump alone (a guide
      // edit) shows as the version, not as a badge.
      whats_new: whatsNew && whatsNew.count > 0 ? whatsNew : null,
    };
  });

  return {
    source: {
      source: catalog.source,
      repo: catalog.repo,
      ref: catalog.ref,
      invalid: catalog.invalid,
      fetched_at: catalog.fetched_at,
      error: catalog.error,
    },
    sigma_library: { loaded: !libStatus.reason, release: libStatus.release, last_error: libStatus.last_error },
    packs,
  };
}

// ---------------------------------------------------------------------------
// Install.
// ---------------------------------------------------------------------------

type Failed = Array<{ name: string; reason: string }>;

export interface PackInstallResult {
  pack: string;
  version: number;
  /** full: every item of the pack; new: only the items the install snapshot did not have. */
  mode: 'full' | 'new';
  parsers: { installed: number; updated: number; failed: Failed };
  detections: { installed: number; updated: number; failed: Failed };
  sigma: {
    installed: number;
    /** Already added (from the SigmaHQ library or an earlier install): left as they are. */
    already: number;
    /** Could not install now (SigmaHQ library not loaded, or not in its release); install again later. */
    pending: Array<{ id: string; title: string; reason: string }>;
    failed: Array<{ id: string; title: string; reason: string }>;
  };
  /** Installed items with a regex that could not be proven safe (indeterminate). */
  warnings: Array<{ name: string; warnings: string[] }>;
}

async function installParserItem(name: string, result: PackInstallResult): Promise<void> {
  try {
    const portable = await getCatalogParser(name);
    if (!portable) {
      result.parsers.failed.push({ name, reason: 'not found in catalog' });
      return;
    }
    const validation = validatePortableParser(portable, { strict: false });
    if (!validation.ok) {
      result.parsers.failed.push({ name, reason: 'failed validation' });
      return;
    }
    // The same regex gate as a single catalog install: a ReDoS-vulnerable
    // regex is refused even though the user chose the pack.
    const refused = await packItemRefusal(() => assessParserRegexes(portable), name, result.warnings);
    if (refused) {
      result.parsers.failed.push({ name, reason: refused });
      return;
    }
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

async function installDetectionItem(name: string, result: PackInstallResult): Promise<void> {
  try {
    const found = await getCatalogDetection(name);
    if (!found) {
      result.detections.failed.push({ name, reason: 'not found in catalog' });
      return;
    }
    const { rule_yaml, parsed } = found;
    const validation = validateRule(parsed, { strict: false });
    if (!validation.ok) {
      result.detections.failed.push({ name, reason: `failed validation: ${validation.errors.join('; ')}` });
      return;
    }
    const refused = await packItemRefusal(() => assessRuleRegexes(parsed), name, result.warnings);
    if (refused) {
      result.detections.failed.push({ name, reason: refused });
      return;
    }
    const rule_logic = ruleLogicOf(parsed);
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

async function installSigmaItems(refs: PackSigmaRef[], result: PackInstallResult): Promise<void> {
  if (refs.length === 0) return;
  const lib = await sigmaLibraryReason();
  for (const ref of refs) {
    if (lib.reason) {
      result.sigma.pending.push({ id: ref.id, title: ref.title, reason: lib.reason });
      continue;
    }
    try {
      await installSigmaRule(ref.id, { enabled: true });
      result.sigma.installed++;
    } catch (error) {
      if (error instanceof SigmaInstallError && error.code === 'SIGMA_ALREADY_ADDED') result.sigma.already++;
      else if (error instanceof SigmaInstallError && error.code === 'SIGMA_NOT_FOUND') {
        result.sigma.pending.push({ id: ref.id, title: ref.title, reason: `not in the cached SigmaHQ release (${lib.release})` });
      } else {
        result.sigma.failed.push({ id: ref.id, title: ref.title, reason: error instanceof Error ? error.message : 'install error' });
      }
    }
  }
}

const union = (a: string[], b: string[]) => [...new Set([...a, ...b])];

/**
 * Install a pack: every item (`onlyNew` off), or only the items added to the
 * pack since it was installed (`onlyNew`; 409 when it was never installed).
 * Records the install (version + item snapshot).
 */
export async function installPack(
  id: string,
  opts: { onlyNew?: boolean; user?: { id: number; username: string } } = {}
): Promise<PackInstallResult> {
  const catalog = await fetchPackCatalog(false);
  const pack: ContentPack | undefined = catalog.packs.find((p) => p.id === id);
  if (!pack) throw new PackError(404, 'PACK_NOT_FOUND', `Unknown content pack "${id}"`);
  const rec = await getPackInstallRecord(pack.id);
  if (opts.onlyNew && !rec) {
    throw new PackError(409, 'PACK_NOT_INSTALLED', `"${pack.name}" has not been installed yet; install the whole pack first`);
  }

  const result: PackInstallResult = {
    pack: pack.id,
    version: pack.version,
    mode: opts.onlyNew ? 'new' : 'full',
    parsers: { installed: 0, updated: 0, failed: [] },
    detections: { installed: 0, updated: 0, failed: [] },
    sigma: { installed: 0, already: 0, pending: [], failed: [] },
    warnings: [],
  };

  // The pack's detections, matched against the live catalog by category/tag/name.
  let detectionNames: string[] | null = null;
  try {
    const { entries } = await fetchDetectionCatalog(false);
    detectionNames = (entries as any[]).filter((e) => detectionMatchesPack(e, pack)).map((e) => e.name);
    for (const n of pack.detections.names) if (!detectionNames.includes(n)) detectionNames.push(n);
  } catch {
    result.detections.failed.push({ name: '(catalog)', reason: 'detection catalog unavailable' });
  }

  let parsers = pack.parsers;
  let detections = detectionNames ?? [];
  let sigma = pack.sigma;
  if (opts.onlyNew && rec) {
    const diff = packWhatsNew({ version: pack.version, parsers, detections, sigma }, rec);
    parsers = diff.parsers;
    detections = diff.detections;
    sigma = diff.sigma;
  }

  for (const name of parsers) await installParserItem(name, result);
  for (const name of detections) await installDetectionItem(name, result);
  await installSigmaItems(sigma, result);

  if (result.parsers.installed > 0 || result.parsers.updated > 0) {
    await ParserEngine.getInstance().reload();
  }
  if (result.detections.installed > 0 || result.detections.updated > 0 || result.sigma.installed > 0) {
    await RulesEngine.getInstance().reload();
  }

  // The snapshot: the pack's item list as installed now (what's new merges in).
  const retried = new Set([...parsers.map((n) => `parser:${n}`), ...detections.map((n) => `detection:${n}`), ...sigma.map((x) => `sigma:${x.id}`)]);
  const pending: PackPendingItem[] = [
    // Install what's new leaves the earlier pending items it did not retry.
    ...(opts.onlyNew && rec ? rec.pending.filter((p) => !retried.has(`${p.kind}:${p.name}`)) : []),
    ...result.parsers.failed.map((f) => ({ kind: 'parser' as const, name: f.name, reason: f.reason })),
    ...result.detections.failed.map((f) => ({ kind: 'detection' as const, name: f.name, reason: f.reason })),
    ...[...result.sigma.pending, ...result.sigma.failed].map((f) => ({ kind: 'sigma' as const, name: f.id, reason: f.reason })),
  ];
  const fullDetections = detectionNames ?? rec?.detections ?? [];
  await saveInstallRecord({
    pack_id: pack.id,
    version: pack.version,
    source: catalog.source === 'bundled' ? 'bundled' : 'catalog',
    installed_by: opts.user?.id ?? null,
    installed_by_username: opts.user?.username ?? null,
    parsers: opts.onlyNew && rec ? union(rec.parsers, pack.parsers) : pack.parsers,
    detections: opts.onlyNew && rec ? union(rec.detections, detections) : fullDetections,
    sigma: opts.onlyNew && rec ? union(rec.sigma, pack.sigma.map((s) => s.id)) : pack.sigma.map((s) => s.id),
    pending,
  });

  return result;
}
