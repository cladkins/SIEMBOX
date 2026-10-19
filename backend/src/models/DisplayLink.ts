/**
 * Display links (migration 042; docs/architecture/BIG-DISPLAY.md §4, §7.3).
 *
 * A link is a read-only credential for one wall screen. Only the sha256 of
 * its secret is stored; the secret itself is returned once, by create() and
 * rotate(). Nothing here ever selects token_hash: findForAuth() only looks
 * rows up by it. Links belong to the install, not to the admin who made them:
 * nothing about a user (password, sessions, deletion) touches them.
 */
import type { PoolClient } from 'pg';
import { getClient, query } from '../config/database';
import { hashDisplayToken, newDisplayToken, tokenHint } from '../services/display/token';
import { LIMITS, configPanelKeys, parseDisplayConfig, type DisplayConfig, type Privacy } from '../services/display/config';
import { displayLinkStatus, type DisplayLinkStatus } from '../services/display/linkStatus';
import { logger } from '../utils/logger';

/** At most this many addresses are kept per link (the least recently seen go first). */
export const MAX_CLIENTS_PER_LINK = 20;

export type DisplayLinkErrorCode =
  | 'DISPLAY_LINK_NOT_FOUND'
  | 'DISPLAY_LINK_LIMIT'
  | 'DISPLAY_LINK_NAME_TAKEN'
  | 'DISPLAY_LINK_REVOKED';

const ERROR_ANSWERS: Record<DisplayLinkErrorCode, { status: number; message: string }> = {
  DISPLAY_LINK_NOT_FOUND: { status: 404, message: 'Display link not found' },
  DISPLAY_LINK_LIMIT: {
    status: 409,
    message: `There are already ${LIMITS.liveLinks} display links. Revoke one you no longer use first.`,
  },
  DISPLAY_LINK_NAME_TAKEN: { status: 409, message: 'Another display link already has this name' },
  DISPLAY_LINK_REVOKED: { status: 409, message: "This display link was revoked and can't be changed. Create a new one." },
};

/** A refusal the routes answer as is: 404 or 409 with its code. */
export class DisplayLinkError extends Error {
  readonly status: number;
  constructor(readonly code: DisplayLinkErrorCode) {
    super(ERROR_ANSWERS[code].message);
    this.status = ERROR_ANSWERS[code].status;
  }
}

/** A row as the model reads it: everything but token_hash. */
export interface DisplayLinkRow {
  id: number;
  name: string;
  token_hint: string;
  config: unknown;
  config_version: number;
  enabled: boolean;
  allowed_cidrs: string[];
  expires_at: Date | null;
  revoked_at: Date | null;
  created_by: number | null;
  updated_by: number | null;
  created_at: Date;
  updated_at: Date;
  token_rotated_at: Date;
  last_used_at: Date | null;
}

interface ListRow extends DisplayLinkRow {
  creator_username: string | null;
  clients_24h: number;
  last_ip: string | null;
  last_user_agent: string | null;
}

/** What authenticateDisplay needs, and nothing it doesn't. */
export interface DisplayLinkAuth {
  id: number;
  name: string;
  config: unknown;
  config_version: number;
  enabled: boolean;
  expires_at: Date | null;
  revoked_at: Date | null;
  /** The client address is inside allowed_cidrs, or the list is empty. Never null (§4.3). */
  address_allowed: boolean;
}

export interface DisplayLinkClient {
  ip: string;
  user_agent: string | null;
  first_seen: Date;
  last_seen: Date;
}

export interface DisplayLinkSummary {
  id: number;
  name: string;
  token_hint: string;
  status: DisplayLinkStatus;
  privacy: Privacy;
  view_count: number;
  panel_keys: string[];
  enabled: boolean;
  expires_at: Date | null;
  revoked_at: Date | null;
  allowed_cidrs: string[];
  /** null: the account that created it was deleted. */
  created_by: { id: number; username: string } | null;
  created_at: Date;
  updated_at: Date;
  token_rotated_at: Date;
  last_used_at: Date | null;
  last_client: { ip: string; user_agent: string | null } | null;
  /** Distinct addresses seen in the last 24 hours. */
  clients_24h: number;
}

export interface DisplayLinkDetail extends DisplayLinkSummary {
  config: DisplayConfig | null;
  config_version: number;
  clients: DisplayLinkClient[];
}

const COLUMNS = `l.id, l.name, l.token_hint, l.config, l.config_version, l.enabled,
  l.allowed_cidrs::text[] AS allowed_cidrs, l.expires_at, l.revoked_at, l.created_by, l.updated_by,
  l.created_at, l.updated_at, l.token_rotated_at, l.last_used_at`;

const LIST_SQL = `
  SELECT ${COLUMNS}, u.username AS creator_username,
         COALESCE(c.clients_24h, 0)::int AS clients_24h, c.last_ip, c.last_user_agent
    FROM display_links l
    LEFT JOIN users u ON u.id = l.created_by
    LEFT JOIN LATERAL (
      SELECT COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '24 hours') AS clients_24h,
             (array_agg(host(ip) ORDER BY last_seen DESC))[1] AS last_ip,
             (array_agg(user_agent ORDER BY last_seen DESC))[1] AS last_user_agent
        FROM display_link_clients WHERE link_id = l.id
    ) c ON TRUE`;

/** Serializes creates, so two at once can't both pass the live-link limit. */
const CREATE_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext('siembox:display-links:create'))";

/** A stored config, read back through the validator; null (and a log line) when it no longer passes. */
function storedConfig(row: { id: number; config: unknown }): DisplayConfig | null {
  const parsed = parseDisplayConfig(row.config);
  if (parsed.ok) return parsed.value;
  logger.error('Display link has a stored config that does not validate', { linkId: row.id, field: parsed.field });
  return null;
}

function toSummary(row: ListRow, now: Date): { summary: DisplayLinkSummary; config: DisplayConfig | null } {
  const config = storedConfig(row);
  const summary: DisplayLinkSummary = {
    id: row.id,
    name: row.name,
    token_hint: row.token_hint,
    status: displayLinkStatus(row, config?.refresh_seconds ?? 30, now),
    privacy: config?.privacy ?? 'operations',
    view_count: config?.views.length ?? 0,
    panel_keys: config ? configPanelKeys(config) : [],
    enabled: row.enabled,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
    allowed_cidrs: row.allowed_cidrs ?? [],
    created_by: row.created_by !== null && row.creator_username !== null ? { id: row.created_by, username: row.creator_username } : null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    token_rotated_at: row.token_rotated_at,
    last_used_at: row.last_used_at,
    last_client: row.last_ip ? { ip: row.last_ip, user_agent: row.last_user_agent } : null,
    clients_24h: row.clients_24h,
  };
  return { summary, config };
}

function isUniqueViolation(error: unknown, constraint: string): boolean {
  const e = error as { code?: string; constraint?: string } | null;
  return e?.code === '23505' && e.constraint === constraint;
}

async function inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/** Why an UPDATE ... WHERE revoked_at IS NULL matched nothing. */
async function missingOrRevoked(client: PoolClient | null, id: number): Promise<DisplayLinkError> {
  const sql = 'SELECT revoked_at FROM display_links WHERE id = $1';
  const res = client ? await client.query(sql, [id]) : await query(sql, [id]);
  return new DisplayLinkError(res.rows.length === 0 ? 'DISPLAY_LINK_NOT_FOUND' : 'DISPLAY_LINK_REVOKED');
}

export interface DisplayLinkPatch {
  name?: string;
  config?: DisplayConfig;
  enabled?: boolean;
  expiresAt?: Date | null;
  allowedCidrs?: string[];
}

export class DisplayLinkModel {
  /** A new link and its secret (shown once). DISPLAY_LINK_LIMIT past 50 live links, DISPLAY_LINK_NAME_TAKEN for a live name. */
  static async create(input: {
    name: string;
    config: DisplayConfig;
    expiresAt: Date | null;
    allowedCidrs: string[];
    userId: number | null;
  }): Promise<{ link: DisplayLinkDetail; token: string }> {
    const token = newDisplayToken();
    let id: number;
    try {
      id = await inTransaction(async (client) => {
        await client.query(CREATE_LOCK_SQL);
        const live = await client.query('SELECT COUNT(*)::int AS n FROM display_links WHERE revoked_at IS NULL');
        if (live.rows[0].n >= LIMITS.liveLinks) throw new DisplayLinkError('DISPLAY_LINK_LIMIT');
        const res = await client.query(
          `INSERT INTO display_links (name, token_hash, token_hint, config, expires_at, allowed_cidrs, created_by, updated_by)
           VALUES ($1, $2, $3, $4::jsonb, $5, $6::cidr[], $7, $7)
           RETURNING id`,
          [input.name, hashDisplayToken(token), tokenHint(token), JSON.stringify(input.config), input.expiresAt, input.allowedCidrs, input.userId]
        );
        return res.rows[0].id as number;
      });
    } catch (error) {
      if (isUniqueViolation(error, 'idx_display_links_live_name')) throw new DisplayLinkError('DISPLAY_LINK_NAME_TAKEN');
      throw error;
    }
    const link = await DisplayLinkModel.findById(id);
    if (!link) throw new DisplayLinkError('DISPLAY_LINK_NOT_FOUND');
    return { link, token };
  }

  /** Live links, by name; revoked ones after them when asked for. */
  static async list(options: { includeRevoked?: boolean } = {}): Promise<DisplayLinkSummary[]> {
    const res = await query(
      `${LIST_SQL}
        WHERE $1::boolean OR l.revoked_at IS NULL
        ORDER BY l.revoked_at IS NOT NULL, lower(l.name), l.id`,
      [options.includeRevoked === true]
    );
    const now = new Date();
    return (res.rows as ListRow[]).map((row) => toSummary(row, now).summary);
  }

  /** One link with its config and the addresses that used it (most recent first). */
  static async findById(id: number): Promise<DisplayLinkDetail | null> {
    const res = await query(`${LIST_SQL} WHERE l.id = $1`, [id]);
    const row = res.rows[0] as ListRow | undefined;
    if (!row) return null;
    const { summary, config } = toSummary(row, new Date());
    return { ...summary, config, config_version: row.config_version, clients: await DisplayLinkModel.clients(id) };
  }

  /** The row as stored (without token_hash), for comparing before and after a change. */
  static async findRow(id: number): Promise<DisplayLinkRow | null> {
    const res = await query(`SELECT ${COLUMNS} FROM display_links l WHERE l.id = $1`, [id]);
    return (res.rows[0] as DisplayLinkRow | undefined) ?? null;
  }

  static async clients(id: number): Promise<DisplayLinkClient[]> {
    const res = await query(
      `SELECT host(ip) AS ip, user_agent, first_seen, last_seen FROM display_link_clients
        WHERE link_id = $1 ORDER BY last_seen DESC, first_seen DESC LIMIT $2`,
      [id, MAX_CLIENTS_PER_LINK]
    );
    return res.rows;
  }

  /**
   * Change a live link. config_version goes up only when the config changes
   * (JSONB equality, so key order doesn't count). Returns the row before and
   * after. DISPLAY_LINK_NOT_FOUND, DISPLAY_LINK_REVOKED, DISPLAY_LINK_NAME_TAKEN.
   */
  static async update(id: number, patch: DisplayLinkPatch, userId: number | null): Promise<{ before: DisplayLinkRow; after: DisplayLinkRow }> {
    const sets: string[] = [];
    const params: unknown[] = [id, userId];
    const param = (value: unknown, cast = '') => {
      params.push(value);
      return `$${params.length}${cast}`;
    };
    if (patch.name !== undefined) sets.push(`name = ${param(patch.name)}`);
    if (patch.config !== undefined) {
      const config = param(JSON.stringify(patch.config), '::jsonb');
      // Both read the old config: SET expressions see the row as it was.
      sets.push(`config = ${config}`, `config_version = config_version + CASE WHEN config IS DISTINCT FROM ${config} THEN 1 ELSE 0 END`);
    }
    if (patch.enabled !== undefined) sets.push(`enabled = ${param(patch.enabled)}`);
    if (patch.expiresAt !== undefined) sets.push(`expires_at = ${param(patch.expiresAt)}`);
    if (patch.allowedCidrs !== undefined) sets.push(`allowed_cidrs = ${param(patch.allowedCidrs, '::cidr[]')}`);
    try {
      return await inTransaction(async (client) => {
        const old = await client.query(`SELECT ${COLUMNS} FROM display_links l WHERE l.id = $1 FOR UPDATE`, [id]);
        const before = old.rows[0] as DisplayLinkRow | undefined;
        if (!before) throw new DisplayLinkError('DISPLAY_LINK_NOT_FOUND');
        if (before.revoked_at) throw new DisplayLinkError('DISPLAY_LINK_REVOKED');
        await client.query(
          `UPDATE display_links SET ${[...sets, 'updated_by = $2', 'updated_at = NOW()'].join(', ')} WHERE id = $1`,
          params
        );
        const res = await client.query(`SELECT ${COLUMNS} FROM display_links l WHERE l.id = $1`, [id]);
        return { before, after: res.rows[0] as DisplayLinkRow };
      });
    } catch (error) {
      if (isUniqueViolation(error, 'idx_display_links_live_name')) throw new DisplayLinkError('DISPLAY_LINK_NAME_TAKEN');
      throw error;
    }
  }

  /**
   * A new secret for a live link; the old one stops at once (its hash is
   * gone, so it reads as unknown). The devices seen and last use belong to
   * the old secret and are cleared. Returns the new token (shown once).
   */
  static async rotate(id: number, userId: number | null): Promise<string> {
    const token = newDisplayToken();
    await inTransaction(async (client) => {
      const res = await client.query(
        `UPDATE display_links
            SET token_hash = $2, token_hint = $3, token_rotated_at = NOW(), last_used_at = NULL,
                updated_by = $4, updated_at = NOW()
          WHERE id = $1 AND revoked_at IS NULL
          RETURNING id`,
        [id, hashDisplayToken(token), tokenHint(token), userId]
      );
      if (res.rows.length === 0) throw await missingOrRevoked(client, id);
      await client.query('DELETE FROM display_link_clients WHERE link_id = $1', [id]);
    });
    return token;
  }

  /** Revoke a live link: the row stays for the audit trail, nothing accepts it, its name is free. */
  static async revoke(id: number, userId: number | null): Promise<DisplayLinkRow> {
    const res = await query(
      `UPDATE display_links l SET revoked_at = NOW(), updated_by = $2, updated_at = NOW()
        WHERE l.id = $1 AND l.revoked_at IS NULL
        RETURNING ${COLUMNS}`,
      [id, userId]
    );
    if (res.rows.length === 0) throw await missingOrRevoked(null, id);
    return res.rows[0];
  }

  /** Revoke every live link (the recovery CLI). */
  static async revokeAllLive(userId: number | null): Promise<Array<{ id: number; name: string }>> {
    const res = await query(
      `UPDATE display_links SET revoked_at = NOW(), updated_by = $1, updated_at = NOW()
        WHERE revoked_at IS NULL RETURNING id, name`,
      [userId]
    );
    return res.rows;
  }

  /**
   * The link a screen's secret belongs to, by its hash, with whether `ip` is
   * allowed. One statement through the UNIQUE index. COALESCE matters: with
   * no address, `NULL::inet <<= ANY(...)` is NULL, which must read as false.
   */
  static async findForAuth(tokenHash: string, ip: string | null): Promise<DisplayLinkAuth | null> {
    const res = await query(
      `SELECT id, name, config, config_version, enabled, expires_at, revoked_at,
              COALESCE(cardinality(allowed_cidrs) = 0 OR $2::inet <<= ANY (allowed_cidrs), false) AS address_allowed
         FROM display_links
        WHERE token_hash = $1`,
      [tokenHash, ip]
    );
    return res.rows[0] ?? null;
  }

  static async countLive(): Promise<number> {
    const res = await query('SELECT COUNT(*)::int AS n FROM display_links WHERE revoked_at IS NULL');
    return res.rows[0].n;
  }

  /**
   * Record a screen's use from `ip`: last_used_at, and the device's row.
   * True when the address is new for this link (xmax = 0: inserted, not updated).
   * Only while `tokenHash` is still the link's live secret: a use authenticated
   * just before a rotate or revoke, written after it, records nothing (the
   * rotation cleared the old secret's devices and last use).
   */
  static async touch(id: number, tokenHash: string, ip: string, userAgent: string | null): Promise<boolean> {
    const res = await query(
      `WITH t AS (UPDATE display_links SET last_used_at = NOW()
                   WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL RETURNING id)
       INSERT INTO display_link_clients (link_id, ip, user_agent)
       SELECT id, $3::inet, left($4, 256) FROM t
       ON CONFLICT (link_id, ip) DO UPDATE SET last_seen = NOW(), user_agent = EXCLUDED.user_agent
       RETURNING (xmax = 0) AS first_time`,
      [id, tokenHash, ip, userAgent]
    );
    return res.rows[0]?.first_time === true;
  }

  /** A use with no client address: last_used_at only (same live-secret condition as touch). */
  static async touchLastUsed(id: number, tokenHash: string): Promise<void> {
    await query('UPDATE display_links SET last_used_at = NOW() WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL', [id, tokenHash]);
  }

  /** Keep the most recently seen MAX_CLIENTS_PER_LINK addresses of a link. */
  static async trimClients(id: number): Promise<number> {
    const res = await query(
      `DELETE FROM display_link_clients
        WHERE link_id = $1
          AND ip NOT IN (SELECT ip FROM display_link_clients WHERE link_id = $1
                          ORDER BY last_seen DESC, first_seen DESC LIMIT $2)`,
      [id, MAX_CLIENTS_PER_LINK]
    );
    return res.rowCount ?? 0;
  }
}
