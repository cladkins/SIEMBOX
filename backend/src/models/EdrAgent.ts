/**
 * EDR agent + enrollment-token models.
 *
 * Endpoint agents enroll with a one-time token, then authenticate every later
 * call with a per-agent API key. We store only sha256 HASHES of both the token
 * and the api key (the plaintext is shown once, like shipper keys). Inventory,
 * vulns, and detections reuse the existing assets/vulnerabilities/alerts tables —
 * these two tables only hold the agent identity + enrollment tokens.
 */
import crypto from 'crypto';
import { query } from '../config/database';

/** An agent is considered offline if it hasn't been seen within this window. */
export const OFFLINE_THRESHOLD_MINUTES = 5;

/** sha256 hex of a secret — used for both api keys and enrollment tokens. */
export function sha256hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** Generate a 64-char hex secret (matches the shipper api-key format). */
export function generateSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

export interface EdrAgent {
  agent_id: string;
  api_key_hash: string;
  asset_id: number | null;
  hostname: string | null;
  os: string | null;
  os_version: string | null;
  arch: string | null;
  agent_version: string | null;
  ip: string | null;
  status: string;
  config_version: number;
  last_seen: Date | null;
  created_at: Date;
}

export interface CreateEdrAgentParams {
  agent_id: string;
  api_key_hash: string;
  asset_id: number | null;
  hostname?: string | null;
  os?: string | null;
  os_version?: string | null;
  arch?: string | null;
  agent_version?: string | null;
  ip?: string | null;
}

export class EdrAgentModel {
  static async create(p: CreateEdrAgentParams): Promise<EdrAgent> {
    const result = await query(
      `INSERT INTO edr_agents
         (agent_id, api_key_hash, asset_id, hostname, os, os_version, arch, agent_version, ip, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'online')
       RETURNING *`,
      [p.agent_id, p.api_key_hash, p.asset_id, p.hostname ?? null, p.os ?? null,
       p.os_version ?? null, p.arch ?? null, p.agent_version ?? null, p.ip ?? null]
    );
    return result.rows[0];
  }

  static async findById(agentId: string): Promise<EdrAgent | null> {
    const result = await query('SELECT * FROM edr_agents WHERE agent_id = $1', [agentId]);
    return result.rows[0] || null;
  }

  /** Heartbeat: refresh last_seen / status / version; returns current config_version. */
  static async heartbeat(agentId: string, status: string, agentVersion?: string): Promise<number | null> {
    const result = await query(
      `UPDATE edr_agents
         SET last_seen = NOW(),
             status = $2,
             agent_version = COALESCE($3, agent_version)
       WHERE agent_id = $1
       RETURNING config_version`,
      [agentId, status || 'online', agentVersion ?? null]
    );
    return result.rows[0]?.config_version ?? null;
  }

  /** Mark last_seen (used by ingest endpoints so activity counts as liveness). */
  static async touch(agentId: string): Promise<void> {
    await query('UPDATE edr_agents SET last_seen = NOW(), status = $2 WHERE agent_id = $1',
      [agentId, 'online']);
  }

  /** List agents with live status + open-vuln / recent-detection counts for the UI. */
  static async listWithStats(): Promise<any[]> {
    const result = await query(
      `SELECT
         a.*,
         CASE WHEN a.last_seen IS NOT NULL
                   AND a.last_seen > NOW() - INTERVAL '${OFFLINE_THRESHOLD_MINUTES} minutes'
              THEN 'online' ELSE 'offline' END AS live_status,
         COALESCE((SELECT COUNT(*) FROM asset_vulnerabilities av
                    WHERE av.asset_id = a.asset_id AND av.status = 'open'), 0) AS open_vulns,
         COALESCE((SELECT COUNT(*) FROM alerts al
                    WHERE al.asset_id = a.asset_id AND al.source = 'edr'
                      AND al.created_at > NOW() - INTERVAL '7 days'), 0) AS recent_detections,
         (SELECT MAX(av.last_detected) FROM asset_vulnerabilities av
            WHERE av.asset_id = a.asset_id) AS last_scan_at
       FROM edr_agents a
       ORDER BY a.last_seen DESC NULLS LAST, a.created_at DESC`
    );
    return result.rows;
  }

  static async delete(agentId: string): Promise<boolean> {
    const result = await query('DELETE FROM edr_agents WHERE agent_id = $1', [agentId]);
    return (result.rowCount ?? 0) > 0;
  }
}

export interface EdrEnrollmentToken {
  token_hash: string;
  label: string | null;
  created_by: number | null;
  expires_at: Date | null;
  used_at: Date | null;
  created_at: Date;
}

export class EdrEnrollmentTokenModel {
  static async create(p: { token_hash: string; label?: string | null; created_by?: number | null; expires_at?: Date | null }): Promise<EdrEnrollmentToken> {
    const result = await query(
      `INSERT INTO edr_enrollment_tokens (token_hash, label, created_by, expires_at)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [p.token_hash, p.label ?? null, p.created_by ?? null, p.expires_at ?? null]
    );
    return result.rows[0];
  }

  /**
   * Atomically consume a single-use token: succeeds only if it exists, is unused,
   * and not expired. Returns the row (now marked used) or null.
   */
  static async consume(tokenHash: string): Promise<EdrEnrollmentToken | null> {
    const result = await query(
      `UPDATE edr_enrollment_tokens
         SET used_at = NOW()
       WHERE token_hash = $1
         AND used_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
       RETURNING *`,
      [tokenHash]
    );
    return result.rows[0] || null;
  }

  /**
   * List tokens for the admin UI. `token_hash` is a sha256 (NOT the secret) and
   * is safe to show an admin — it's the stable key used to revoke a token.
   */
  static async listAll(): Promise<any[]> {
    const result = await query(
      `SELECT token_hash, label, created_by, expires_at, used_at, created_at,
              (used_at IS NOT NULL) AS used,
              (expires_at IS NOT NULL AND expires_at <= NOW()) AS expired
       FROM edr_enrollment_tokens
       ORDER BY created_at DESC`
    );
    return result.rows;
  }

  /** Revoke/remove a token by its hash. Revoking an active (unused) token means
   *  it can no longer be used to enroll. */
  static async delete(tokenHash: string): Promise<boolean> {
    const result = await query(
      `DELETE FROM edr_enrollment_tokens WHERE token_hash = $1`,
      [tokenHash]
    );
    return (result.rowCount ?? 0) > 0;
  }
}
