/**
 * Local application signatures (migration 051): written on the Application
 * Monitoring page in the catalog's own format (siembox.app/v1), checked by the
 * same validator the catalog's CI runs, and used by the rollup next to the
 * catalog's set. A local id that is also a catalog id overrides it.
 *
 * What a save does to the inventory (rollup.ts):
 *   - snapshot evidence (nmap services, containers, installed packages, EDR
 *     findings, endpoint OS) is matched again on every run, so the next run
 *     (started at once by the save) shows it;
 *   - the Not identified list drops the values the new set matches;
 *   - log evidence the cursor has already passed (programs, parsers, user
 *     agents, DNS) is looked back for: the signature's id is queued
 *     (requestRescan), and the rollup walks parsed_logs of the last
 *     application_inventory_backfill_days days, newest first, for just the
 *     queued signatures (see runRescan).
 *
 * Pure helpers (merge, canonical YAML, catalog status, the checks) are
 * DB-free and unit-tested; the store functions take the database pool.
 */
import * as yaml from '../../utils/yaml';
import { query } from '../../config/database';
import { stableStringify } from '../parser/catalogService';
import {
  APP_FILE_SUFFIX,
  APP_SCHEMA,
  collectAppRegexes,
  crossCheckApplications,
  matcherKinds,
  validateApplication,
  type AppSignature,
} from './appFormat';
import { AppIndex, runAppTests } from './matchers';
import type { RegexSafetyReport, RegexRef } from '../regex/regexSafety';

type Q = (sql: string, params?: unknown[]) => Promise<{ rows: any[]; rowCount?: number | null }>;

/** Largest signature text a save or a check takes. */
export const MAX_SIGNATURE_BYTES = 64 * 1024;
export const MAX_LOCAL_SIGNATURES = 1000;

export type SignatureOrigin = 'catalog' | 'local' | 'override';
export type CatalogStatus = 'not_in_catalog' | 'same' | 'differs';

// ---------------------------------------------------------------------------
// Pure
// ---------------------------------------------------------------------------

/**
 * The set the rollup uses: the catalog's signatures, a local one replacing a
 * catalog one with its id, and the other local ones added. Sorted by name.
 */
export function mergeSignatures(catalog: AppSignature[], local: AppSignature[]): { apps: AppSignature[]; origins: Map<string, SignatureOrigin> } {
  const byId = new Map<string, AppSignature>();
  const origins = new Map<string, SignatureOrigin>();
  for (const a of catalog) {
    byId.set(a.id, a);
    origins.set(a.id, 'catalog');
  }
  for (const a of local) {
    origins.set(a.id, byId.has(a.id) ? 'override' : 'local');
    byId.set(a.id, a);
  }
  return { apps: [...byId.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)), origins };
}

/** The signature as a catalog document, keys in the catalog's order, empty matchers left out. */
export function signatureDocument(app: AppSignature): Record<string, unknown> {
  const doc: Record<string, unknown> = { schema: APP_SCHEMA, id: app.id, name: app.name, vendor: app.vendor, category: app.category };
  if (app.description) doc.description = app.description;
  if (app.website) doc.website = app.website;
  if (app.cpe) doc.cpe = { vendor: app.cpe.vendor, product: app.cpe.product };
  if (app.supersedes.length) doc.supersedes = [...app.supersedes];
  const m = app.match;
  const match: Record<string, unknown> = {};
  if (m.syslog_program.length) match.syslog_program = [...m.syslog_program];
  if (m.parser.length) match.parser = [...m.parser];
  if (m.service.names.length || m.service.banner.length) {
    const service: Record<string, unknown> = {};
    if (m.service.names.length) service.names = [...m.service.names];
    if (m.service.banner.length) service.banner = [...m.service.banner];
    match.service = service;
  }
  if (m.container_image.length) match.container_image = [...m.container_image];
  if (m.package.length) match.package = [...m.package];
  if (m.user_agent.length) match.user_agent = [...m.user_agent];
  if (m.dns.length) match.dns = [...m.dns];
  if (m.os) match.os = m.os.pretty_name ? { family: m.os.family, pretty_name: m.os.pretty_name } : { family: m.os.family };
  doc.match = match;
  doc.tests = app.tests.map((t) => {
    const out: Record<string, unknown> = { source: t.source, input: typeof t.input === 'string' ? t.input : { ...t.input } };
    if (t.version !== undefined) out.version = t.version;
    if (!t.match) out.match = false;
    return out;
  });
  return doc;
}

/** Catalog-ready YAML for applications/<id>.app.yaml (round-trips through the validator). */
export function signatureToYaml(app: AppSignature): string {
  return yaml.dump(signatureDocument(app), { lineWidth: -1, noRefs: true, quotingType: "'", flowLevel: -1 });
}

/** The catalog file a signature is contributed as. */
export function catalogPath(id: string, dir = 'applications'): string {
  return `${dir}/${id}${APP_FILE_SUFFIX}`;
}

/** Same content as the catalog's signature (order-insensitive where the format is)? */
export function catalogStatus(local: AppSignature, catalogApp: AppSignature | undefined): CatalogStatus {
  if (!catalogApp) return 'not_in_catalog';
  return stableStringify(local) === stableStringify(catalogApp) ? 'same' : 'differs';
}

/**
 * What the author sent: { yaml: "<text>" } or { signature: {...} }. The
 * document (or why it cannot be read), and the YAML text to store.
 */
export function readSignatureInput(body: unknown): { doc?: unknown; text?: string; error?: string } {
  const b = (body ?? {}) as Record<string, unknown>;
  if (typeof b.yaml === 'string') {
    if (Buffer.byteLength(b.yaml, 'utf8') > MAX_SIGNATURE_BYTES) return { error: `the signature is larger than ${MAX_SIGNATURE_BYTES / 1024} KB` };
    try {
      return { doc: yaml.load(b.yaml), text: b.yaml };
    } catch (e) {
      return { error: `YAML parse error: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}` };
    }
  }
  if (b.signature && typeof b.signature === 'object' && !Array.isArray(b.signature)) {
    const text = JSON.stringify(b.signature);
    if (Buffer.byteLength(text, 'utf8') > MAX_SIGNATURE_BYTES) return { error: `the signature is larger than ${MAX_SIGNATURE_BYTES / 1024} KB` };
    return { doc: b.signature };
  }
  return { error: 'send the signature as { "yaml": "..." } or { "signature": { ... } }' };
}

export interface SignatureCheck {
  /** Can be saved locally: valid, tests pass, no claim conflict, regexes safe. */
  ok: boolean;
  /** Can be contributed as is (the catalog CI's strict checks too). */
  ready: boolean;
  errors: string[];
  warnings: string[];
  /** Strict-only problems: they do not stop a local save, they stop a contribution. */
  contribute_errors: string[];
  signature: AppSignature | null;
  yaml: string | null;
  tests: { total: number; failures: string[] };
}

export interface CheckContext {
  /** The signature set in use (catalog + local), the checked one's own id excluded or not. */
  effective: AppSignature[];
  /** Parser names a match.parser may name (installed ones and the catalog's); null: not checked. */
  parserNames?: Set<string> | null;
  /** The regex gate's report for the signature's regexes (null: not run, e.g. invalid). */
  regex?: RegexSafetyReport | null;
  /** When updating: the id it must keep. */
  expectId?: string;
  /** Other signatures' regexes the gate refused (left out when the tests run, as the rollup leaves them out). */
  skipRegex?: Set<string>;
}

/** Every regex a signature runs, as the write-time gate takes them. */
export function signatureRegexRefs(app: AppSignature): RegexRef[] {
  return collectAppRegexes(app);
}

/**
 * The checks a local save and a contribution run, in one pass (the regex
 * gate's verdicts are passed in: they come from a worker thread).
 *   save: the format (non-strict), its tests against the whole set, no
 *         matcher value another signature claims, no unsafe regex;
 *   contribute: the same strictly (unknown keys, a test per matcher kind), as
 *         validate-applications does in the catalog's CI.
 */
export function checkSignature(doc: unknown, ctx: CheckContext): SignatureCheck {
  const loose = validateApplication(doc, { strict: false, expectId: ctx.expectId });
  const out: SignatureCheck = { ok: false, ready: false, errors: [...loose.errors], warnings: [...loose.warnings], contribute_errors: [], signature: null, yaml: null, tests: { total: 0, failures: [] } };
  if (!loose.ok || !loose.app) return out;
  const app = loose.app;
  out.signature = app;
  out.yaml = signatureToYaml(app);
  const strict = validateApplication(doc, { strict: true, expectId: ctx.expectId });
  for (const e of strict.errors) if (!out.errors.includes(e)) out.contribute_errors.push(e);
  // Unknown keys are warnings for a save, errors for the catalog.
  out.warnings = out.warnings.filter((w) => !out.contribute_errors.includes(w));

  const others = ctx.effective.filter((a) => a.id !== app.id);
  const set = [...others, app];
  // `app` is last in the set, so a value it shares with another signature is reported against it.
  for (const p of crossCheckApplications(set, { checkSupersedes: false })) {
    if (p.id === app.id) out.errors.push(`${p.error} (one value can name only one application)`);
  }
  for (const s of app.supersedes) if (!others.some((a) => a.id === s)) out.warnings.push(`supersedes "${s}", which is not a signature in use`);
  if (ctx.parserNames) for (const p of app.match.parser) if (!ctx.parserNames.has(p)) out.warnings.push(`match.parser "${p}" is not an installed or catalog parser`);
  if (app.tests.length === 0) out.warnings.push('no tests: add one per matcher (the catalog requires them)');

  if (ctx.regex) {
    out.errors.push(...ctx.regex.errors);
    out.warnings.push(...ctx.regex.warnings);
  }
  // The tests run only once every regex is known to be safe.
  const regexSafe = !ctx.regex || (ctx.regex.vulnerable.length === 0 && ctx.regex.undecided.length === 0);
  if (regexSafe && (ctx.regex || signatureRegexRefs(app).length === 0)) {
    const failures = runAppTests(app, new AppIndex(set, { skipRegex: ctx.skipRegex }));
    out.tests = { total: app.tests.length, failures };
    out.errors.push(...failures);
  } else if (!ctx.regex && signatureRegexRefs(app).length > 0) {
    out.warnings.push('the regexes were not checked, so the tests did not run');
  }
  for (const k of matcherKinds(app.match)) if (!app.tests.some((t) => t.source === k && t.match)) {
    const msg = `tests: add at least one matching test for match.${k}`;
    if (!out.contribute_errors.includes(msg)) out.contribute_errors.push(msg);
  }
  out.ok = out.errors.length === 0;
  out.ready = out.ok && out.contribute_errors.length === 0;
  return out;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export interface CustomSignatureRow {
  id: string;
  definition: AppSignature;
  yaml: string;
  enabled: boolean;
  created_by: string | null;
  updated_by: string | null;
  created_at: string;
  updated_at: string;
}

const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : String(v));
const rowOut = (r: any): CustomSignatureRow => ({ ...r, created_at: iso(r.created_at), updated_at: iso(r.updated_at) });

/**
 * The enabled local signatures, each validated again (a stored one written by
 * an older version may no longer pass): the valid ones, and why the others
 * were left out.
 */
export async function loadCustomSignatures(q: Q = (sql, p) => query(sql, p)): Promise<{ apps: AppSignature[]; invalid: Array<{ path: string; errors: string[] }> }> {
  const { rows } = await q(`SELECT id, definition FROM custom_application_signatures WHERE enabled ORDER BY id LIMIT $1`, [MAX_LOCAL_SIGNATURES]);
  const apps: AppSignature[] = [];
  const invalid: Array<{ path: string; errors: string[] }> = [];
  for (const r of rows) {
    const v = validateApplication({ schema: APP_SCHEMA, ...r.definition }, { strict: false, expectId: r.id });
    if (v.ok && v.app) apps.push(v.app);
    else invalid.push({ path: `local/${r.id}`, errors: v.errors });
  }
  return { apps, invalid };
}

export async function listCustomSignatures(): Promise<CustomSignatureRow[]> {
  const { rows } = await query(`SELECT * FROM custom_application_signatures ORDER BY id LIMIT $1`, [MAX_LOCAL_SIGNATURES]);
  return rows.map(rowOut);
}

export async function getCustomSignature(id: string): Promise<CustomSignatureRow | null> {
  const { rows } = await query(`SELECT * FROM custom_application_signatures WHERE id = $1`, [id]);
  return rows[0] ? rowOut(rows[0]) : null;
}

export async function countCustomSignatures(): Promise<number> {
  return Number((await query(`SELECT count(*)::int AS n FROM custom_application_signatures`)).rows[0]?.n ?? 0);
}

export async function insertCustomSignature(app: AppSignature, text: string, user: string | null): Promise<CustomSignatureRow | null> {
  const { rows } = await query(
    `INSERT INTO custom_application_signatures (id, definition, yaml, enabled, created_by, updated_by)
     VALUES ($1, $2, $3, TRUE, $4, $4) ON CONFLICT (id) DO NOTHING RETURNING *`,
    [app.id, JSON.stringify({ schema: APP_SCHEMA, ...app }), text, user]
  );
  return rows[0] ? rowOut(rows[0]) : null;
}

export async function updateCustomSignature(
  id: string,
  change: { app?: AppSignature; text?: string; enabled?: boolean },
  user: string | null
): Promise<CustomSignatureRow | null> {
  const { rows } = await query(
    `UPDATE custom_application_signatures
        SET definition = COALESCE($2::jsonb, definition), yaml = COALESCE($3, yaml), enabled = COALESCE($4, enabled),
            updated_by = $5, updated_at = NOW()
      WHERE id = $1 RETURNING *`,
    [id, change.app ? JSON.stringify({ schema: APP_SCHEMA, ...change.app }) : null, change.text ?? null, change.enabled ?? null, user]
  );
  return rows[0] ? rowOut(rows[0]) : null;
}

/**
 * Delete a local signature. One that only existed locally takes its
 * inventory rows with it; one that overrode a catalog signature hands its id
 * back to the catalog's (whose history is then looked back for).
 */
export async function deleteCustomSignature(id: string, catalogHasId: boolean): Promise<boolean> {
  const { rowCount } = await query(`DELETE FROM custom_application_signatures WHERE id = $1`, [id]);
  if (!rowCount) return false;
  if (catalogHasId) await requestRescan([id]);
  else {
    await query(`DELETE FROM application_inventory WHERE app_id = $1`, [id]);
    await query(`DELETE FROM application_vuln_links WHERE app_id = $1`, [id]);
    await query(`DELETE FROM application_signatures WHERE id = $1`, [id]);
  }
  return true;
}

/**
 * Queue signatures for the look back over logs the cursor already passed
 * (the next rollup run starts it). Ids already queued stay queued once.
 */
export async function requestRescan(ids: string[], q: Q = (sql, p) => query(sql, p)): Promise<void> {
  if (ids.length === 0) return;
  await q(
    `UPDATE application_inventory_state
        SET rescan_pending = ARRAY(SELECT DISTINCT unnest(rescan_pending || $1::text[]) ORDER BY 1)
      WHERE id = 1`,
    [ids]
  );
}

/** Values an analyst hid from the Not identified list. */
export async function ignoreUnmatched(source: string, value: string, user: string | null): Promise<void> {
  await query(`INSERT INTO application_unmatched_ignores (source, value, created_by) VALUES ($1, $2, $3) ON CONFLICT (source, value) DO NOTHING`, [source, value, user]);
}

export async function unignoreUnmatched(source: string, value: string): Promise<boolean> {
  return ((await query(`DELETE FROM application_unmatched_ignores WHERE source = $1 AND value = $2`, [source, value])).rowCount ?? 0) > 0;
}
