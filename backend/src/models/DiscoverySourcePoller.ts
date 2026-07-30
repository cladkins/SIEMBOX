import { query } from '../config/database';
import { CredentialEncryption } from '../services/credentials/credentialEncryption';

export type PollerStatus = 'ok' | 'error';

export interface DiscoverySourcePoller {
  discovery_source_id: number;
  fingerprint_id: string;
  log_access_method: string;
  encrypted_credential: string;
  encryption_iv: string;
  encryption_auth_tag: string;
  credential_username: string | null;
  enabled: boolean;
  poll_interval_minutes: number;
  poll_cursor: string | null;
  last_polled_at: string | null;
  last_status: PollerStatus | null;
  last_error: string | null;
  last_event_count: number | null;
  created_at: string;
  updated_at: string;
}

/** Never includes encrypted_credential/encryption_iv/encryption_auth_tag — the only shape returned over the API. */
export interface DiscoverySourcePollerPublic {
  configured: true;
  fingerprint_id: string;
  credential_username: string | null;
  enabled: boolean;
  poll_interval_minutes: number;
  last_polled_at: string | null;
  last_status: PollerStatus | null;
  last_error: string | null;
  last_event_count: number | null;
}

export interface UpsertCredentialInput {
  fingerprintId: string;
  method: string;
  username?: string | null;
  secret: string;
}

export interface RecordResultInput {
  ok: boolean;
  count: number;
  error?: string;
  /** Only overwritten when explicitly provided — a failed fetch must not lose the last-good cursor. */
  cursor?: string | null;
}

const MIN_INTERVAL_MINUTES = 1;
const MAX_INTERVAL_MINUTES = 1440; // 24h

function clampInterval(minutes: number): number {
  return Math.min(Math.max(Math.round(minutes), MIN_INTERVAL_MINUTES), MAX_INTERVAL_MINUTES);
}

export const DiscoverySourcePollerModel = {
  async findById(sourceId: number): Promise<DiscoverySourcePoller | null> {
    const r = await query(`SELECT * FROM discovery_source_pollers WHERE discovery_source_id = $1`, [sourceId]);
    return r.rows[0] || null;
  },

  /** Same due-query shape as FeedService.refreshAllEnabled, scoped to this table. */
  async findDue(): Promise<DiscoverySourcePoller[]> {
    const r = await query(
      `SELECT * FROM discovery_source_pollers
        WHERE enabled = true
          AND (last_polled_at IS NULL
               OR last_polled_at < NOW() - (poll_interval_minutes || ' minutes')::interval)
        ORDER BY discovery_source_id`
    );
    return r.rows;
  },

  /**
   * Create or replace the credential for a source. Deliberately excludes
   * enabled/poll_interval_minutes/poll_cursor/last_* from the UPDATE SET list
   * (mirrors DiscoverySourceModel.upsert's exclusion of status/selected_log_access)
   * so rotating a token doesn't reset the poll interval or force a re-backfill.
   * The INSERT branch supplies first-ever defaults only.
   */
  async upsertCredential(sourceId: number, input: UpsertCredentialInput): Promise<DiscoverySourcePoller> {
    const enc = CredentialEncryption.encrypt(input.secret); // throws if CREDENTIAL_ENCRYPTION_KEY unset/invalid
    const r = await query(
      `INSERT INTO discovery_source_pollers
         (discovery_source_id, fingerprint_id, log_access_method, encrypted_credential, encryption_iv, encryption_auth_tag, credential_username)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (discovery_source_id) DO UPDATE SET
         fingerprint_id = EXCLUDED.fingerprint_id,
         log_access_method = EXCLUDED.log_access_method,
         encrypted_credential = EXCLUDED.encrypted_credential,
         encryption_iv = EXCLUDED.encryption_iv,
         encryption_auth_tag = EXCLUDED.encryption_auth_tag,
         credential_username = EXCLUDED.credential_username,
         updated_at = NOW()
       RETURNING *`,
      [sourceId, input.fingerprintId, input.method, enc.encrypted, enc.iv, enc.authTag, input.username ?? null]
    );
    return r.rows[0];
  },

  /** Full revoke: stops polling and forgets interval/cursor/history, not just the credential. */
  async clear(sourceId: number): Promise<boolean> {
    const r = await query(`DELETE FROM discovery_source_pollers WHERE discovery_source_id = $1`, [sourceId]);
    return (r.rowCount ?? 0) > 0;
  },

  async setEnabled(sourceId: number, enabled: boolean): Promise<DiscoverySourcePoller | null> {
    const r = await query(
      `UPDATE discovery_source_pollers SET enabled = $2, updated_at = NOW() WHERE discovery_source_id = $1 RETURNING *`,
      [sourceId, enabled]
    );
    return r.rows[0] || null;
  },

  async setInterval(sourceId: number, minutes: number): Promise<DiscoverySourcePoller | null> {
    const r = await query(
      `UPDATE discovery_source_pollers SET poll_interval_minutes = $2, updated_at = NOW() WHERE discovery_source_id = $1 RETURNING *`,
      [sourceId, clampInterval(minutes)]
    );
    return r.rows[0] || null;
  },

  /**
   * Always sets last_polled_at=NOW() (success or failure) so "due" re-evaluates
   * from the most recent attempt, not most recent success — same convention as
   * threat_feeds. poll_cursor is only touched when the caller actually has a
   * new one; a failed fetch keeps the last-good position.
   */
  async recordResult(sourceId: number, result: RecordResultInput): Promise<void> {
    const status: PollerStatus = result.ok ? 'ok' : 'error';
    if (result.cursor !== undefined) {
      await query(
        `UPDATE discovery_source_pollers
            SET last_polled_at = NOW(), last_status = $2, last_error = $3, last_event_count = $4, poll_cursor = $5, updated_at = NOW()
          WHERE discovery_source_id = $1`,
        [sourceId, status, result.error ?? null, result.count, result.cursor]
      );
    } else {
      await query(
        `UPDATE discovery_source_pollers
            SET last_polled_at = NOW(), last_status = $2, last_error = $3, last_event_count = $4, updated_at = NOW()
          WHERE discovery_source_id = $1`,
        [sourceId, status, result.error ?? null, result.count]
      );
    }
  },

  decryptCredential(row: DiscoverySourcePoller): { username: string | null; secret: string } {
    return {
      username: row.credential_username,
      secret: CredentialEncryption.decrypt(row.encrypted_credential, row.encryption_iv, row.encryption_auth_tag),
    };
  },

  toPublic(row: DiscoverySourcePoller): DiscoverySourcePollerPublic {
    return {
      configured: true,
      fingerprint_id: row.fingerprint_id,
      credential_username: row.credential_username,
      enabled: row.enabled,
      poll_interval_minutes: row.poll_interval_minutes,
      last_polled_at: row.last_polled_at,
      last_status: row.last_status,
      last_error: row.last_error,
      last_event_count: row.last_event_count,
    };
  },
};
