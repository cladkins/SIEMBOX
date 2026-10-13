import { query } from '../config/database';
import { CredentialEncryption } from '../services/credentials/credentialEncryption';
import type { DiscoverySource } from './DiscoverySource';

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
  /**
   * Changes (to a new value from a sequence; migration 037) only when the cursor
   * is reset for a new target: a new address or endpoint. BIGINT, read as a
   * string. See RecordResultInput.startedFrom.
   */
  cursor_generation: string;
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
  /**
   * The source's address the token was entered for. When set, the token is only
   * saved while the source still has that address: a token typed while the
   * source was shown at one address never reaches another one.
   */
  expectedIpAddress?: string | null;
}

export interface RecordResultInput {
  ok: boolean;
  count: number;
  error?: string;
  /** Only overwritten when explicitly provided — a failed fetch must not lose the last-good cursor. */
  cursor?: string | null;
  /**
   * The `version` of the PollSnapshot the poll started from. With it, the cursor
   * is only written while the row still has that cursor_generation (the status
   * is always recorded): a cursor reset for a new address or endpoint that
   * commits while the poll runs is not undone by the old target's cursor.
   * Nothing else changes the generation, so a change of the interval, polling
   * on/off, a new token for the same address or another poll's result never
   * makes a running poll drop its cursor (its lines would be stored again).
   */
  startedFrom?: string;
}

/**
 * What one poll needs, read in one statement (findPollSnapshot): the poller row
 * (credential, cursor, schedule) and its source's poll target. An address
 * change commits the new address and its new token together, so a snapshot has
 * both old or both new, never the old token with the new address.
 */
export interface PollSnapshot {
  poller: DiscoverySourcePoller;
  source: Pick<DiscoverySource, 'id' | 'ip_address' | 'hostname' | 'open_ports' | 'evidence' | 'poll_overrides'>;
  /** The poller row's cursor_generation, for RecordResultInput.startedFrom. */
  version: string;
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

  /**
   * The ids of the sources due a poll (same due-query shape as
   * FeedService.refreshAllEnabled). Ids only, on purpose: a cycle polls them one
   * after another, and each poll reads its source's credential and target when
   * its turn comes (findPollSnapshot), never from a row read at cycle start.
   */
  async findDueIds(): Promise<number[]> {
    const r = await query(
      `SELECT discovery_source_id FROM discovery_source_pollers
        WHERE enabled = true
          AND (last_polled_at IS NULL
               OR last_polled_at < NOW() - (poll_interval_minutes || ' minutes')::interval)
        ORDER BY discovery_source_id`
    );
    return r.rows.map((row) => row.discovery_source_id);
  },

  /**
   * The poller row and its source's poll target in one statement, so both come
   * from the same committed state (see PollSnapshot). Null when the source has
   * no poller. The only way a poll reads its credential.
   */
  async findPollSnapshot(sourceId: number): Promise<PollSnapshot | null> {
    const r = await query(
      `SELECT dsp.*, dsp.cursor_generation::text AS poller_version,
              ds.ip_address, ds.hostname, ds.open_ports, ds.evidence, ds.poll_overrides
         FROM discovery_source_pollers dsp
         JOIN discovery_sources ds ON ds.id = dsp.discovery_source_id
        WHERE dsp.discovery_source_id = $1`,
      [sourceId]
    );
    const row = r.rows[0];
    if (!row) return null;
    const { poller_version, ip_address, hostname, open_ports, evidence, poll_overrides, ...poller } = row;
    return {
      poller: poller as DiscoverySourcePoller,
      source: { id: sourceId, ip_address, hostname, open_ports, evidence, poll_overrides },
      version: poller_version,
    };
  },

  /**
   * Create or replace the credential for a source. Deliberately excludes
   * enabled/poll_interval_minutes/poll_cursor/cursor_generation/last_* from the
   * UPDATE SET list (mirrors DiscoverySourceModel.upsert's exclusion of
   * status/selected_log_access) so rotating a token doesn't reset the poll
   * interval or force a re-backfill, nor make a poll running meanwhile drop its
   * cursor. The INSERT branch supplies first-ever defaults only.
   *
   * The statement locks the source row (FOR SHARE) before it writes, and a
   * change of a manual source's address locks it FOR UPDATE
   * (DiscoverySourceModel.updateManualTarget), so a save and a move never
   * overlap: a save that waits behind a move re-checks the moved row. Null when
   * the source doesn't exist, or no longer has input.expectedIpAddress; nothing
   * is saved then.
   */
  async upsertCredential(sourceId: number, input: UpsertCredentialInput): Promise<DiscoverySourcePoller | null> {
    const enc = CredentialEncryption.encrypt(input.secret); // throws if CREDENTIAL_ENCRYPTION_KEY unset/invalid
    const r = await query(
      `WITH source AS (
         SELECT id FROM discovery_sources
          WHERE id = $1 AND ($8::inet IS NULL OR ip_address = $8::inet)
          FOR SHARE
       )
       INSERT INTO discovery_source_pollers
         (discovery_source_id, fingerprint_id, log_access_method, encrypted_credential, encryption_iv, encryption_auth_tag, credential_username)
       SELECT id, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text FROM source
       ON CONFLICT (discovery_source_id) DO UPDATE SET
         fingerprint_id = EXCLUDED.fingerprint_id,
         log_access_method = EXCLUDED.log_access_method,
         encrypted_credential = EXCLUDED.encrypted_credential,
         encryption_iv = EXCLUDED.encryption_iv,
         encryption_auth_tag = EXCLUDED.encryption_auth_tag,
         credential_username = EXCLUDED.credential_username,
         updated_at = NOW()
       RETURNING *`,
      [
        sourceId,
        input.fingerprintId,
        input.method,
        enc.encrypted,
        enc.iv,
        enc.authTag,
        input.username ?? null,
        input.expectedIpAddress ?? null,
      ]
    );
    return r.rows[0] || null;
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
   * new one; a failed fetch keeps the last-good position. With startedFrom, the
   * new cursor is only written while the row still has the cursor_generation
   * the poll started from: after a reset for a new address or endpoint made
   * while the poll ran, the row's own (cleared) cursor is kept.
   */
  async recordResult(sourceId: number, result: RecordResultInput): Promise<void> {
    const status: PollerStatus = result.ok ? 'ok' : 'error';
    if (result.cursor !== undefined) {
      await query(
        `UPDATE discovery_source_pollers
            SET last_polled_at = NOW(), last_status = $2, last_error = $3, last_event_count = $4,
                poll_cursor = CASE
                  WHEN NOT $6::boolean OR cursor_generation = $7::bigint THEN $5
                  ELSE poll_cursor
                END,
                updated_at = NOW()
          WHERE discovery_source_id = $1`,
        [
          sourceId,
          status,
          result.error ?? null,
          result.count,
          result.cursor,
          result.startedFrom !== undefined,
          result.startedFrom ?? null,
        ]
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
