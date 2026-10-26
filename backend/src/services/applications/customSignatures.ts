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
 * The pure helpers (merge, YAML, catalog status, the checks) live in
 * signatureCheck.ts and are re-exported here; this module adds the store.
 */
import { query } from '../../config/database';
import { APP_SCHEMA, validateApplication, type AppSignature } from './appFormat';
import { MAX_LOCAL_SIGNATURES } from './signatureCheck';

export * from './signatureCheck';

type Q = (sql: string, params?: unknown[]) => Promise<{ rows: any[]; rowCount?: number | null }>;

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
