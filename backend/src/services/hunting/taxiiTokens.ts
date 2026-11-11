/**
 * TAXII client tokens: read-only credentials for tools that poll SIEMBox's
 * TAXII 2.1 collection (OpenCTI, MISP, a SOAR), so they need no user login.
 *
 * A token is shown once, when an admin creates it; only its SHA-256 hash is
 * stored. It reads the TAXII routes (/api/taxii2/...) and nothing else.
 */
import { createHash, randomBytes } from 'crypto';
import { query } from '../../config/database';

export const TAXII_TOKEN_PREFIX = 'sbx_taxii_';

export interface TaxiiTokenRow {
  id: number;
  name: string;
  token_prefix: string;
  created_by: number | null;
  created_at: Date;
  last_used_at: Date | null;
  revoked_at: Date | null;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function looksLikeTaxiiToken(value: string | undefined | null): value is string {
  return typeof value === 'string' && value.startsWith(TAXII_TOKEN_PREFIX) && value.length < 200;
}

export class TaxiiTokenModel {
  static async list(): Promise<TaxiiTokenRow[]> {
    const r = await query(
      `SELECT id, name, token_prefix, created_by, created_at, last_used_at, revoked_at
         FROM taxii_tokens ORDER BY revoked_at NULLS FIRST, created_at DESC`
    );
    return r.rows;
  }

  static async create(name: string, createdBy: number | null): Promise<{ token: string; row: TaxiiTokenRow }> {
    const token = TAXII_TOKEN_PREFIX + randomBytes(24).toString('base64url');
    const r = await query(
      `INSERT INTO taxii_tokens (name, token_hash, token_prefix, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, token_prefix, created_by, created_at, last_used_at, revoked_at`,
      [name, hashToken(token), token.slice(0, TAXII_TOKEN_PREFIX.length + 6), createdBy]
    );
    return { token, row: r.rows[0] };
  }

  static async revoke(id: number): Promise<boolean> {
    const r = await query(`UPDATE taxii_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, [id]);
    return (r.rowCount ?? 0) > 0;
  }

  /** The live token with this hash, or null. Records the use (at most once a minute). */
  static async findForAuth(hash: string): Promise<TaxiiTokenRow | null> {
    const r = await query(
      `SELECT id, name, token_prefix, created_by, created_at, last_used_at, revoked_at
         FROM taxii_tokens WHERE token_hash = $1 AND revoked_at IS NULL`,
      [hash]
    );
    const row: TaxiiTokenRow | undefined = r.rows[0];
    if (!row) return null;
    if (!row.last_used_at || Date.now() - new Date(row.last_used_at).getTime() > 60_000) {
      await query(`UPDATE taxii_tokens SET last_used_at = NOW() WHERE id = $1`, [row.id]).catch(() => undefined);
    }
    return row;
  }
}
