import { query, getClient } from '../config/database';
import { LogAccessMethod } from '../services/logDiscovery/types';

export type DiscoverySourceStatus = 'candidate' | 'confirmed' | 'onboarded' | 'ignored';

export interface DiscoverySource {
  id: number;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  open_ports: number[];
  matched_fingerprint_id: string | null;
  confidence: number;
  is_guess: boolean;
  security_value: number | null;
  status: DiscoverySourceStatus;
  selected_log_access: LogAccessMethod | null;
  evidence: Record<string, unknown>;
  /**
   * An admin's poll-target overrides for a scan-discovered source
   * ({port?, tls?, endpoint?}; migration 036). Scans never write it. A manual
   * source keeps its target in evidence instead, and has NULL here.
   */
  poll_overrides: Record<string, unknown> | null;
  last_scan_id: number | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoverySourceUpsertInput {
  ip_address: string;
  mac_address?: string | null;
  hostname?: string | null;
  open_ports: number[];
  matched_fingerprint_id: string | null;
  confidence: number;
  is_guess: boolean;
  security_value: number | null;
  evidence: Record<string, unknown>;
  last_scan_id: number;
}

/**
 * A manually added api_pull source — an admin who already knows a device
 * (type + IP + port) onboards it without waiting for a scan to find and
 * fingerprint it. See DiscoverySourceModel.upsertManual.
 */
export interface DiscoverySourceManualInput {
  ip_address: string;
  hostname?: string | null;
  /** The chosen device type; also the poll adapter key. */
  fingerprint_id: string;
  /** Base-URL port the adapter should connect to (stored in evidence + open_ports). */
  target_port: number;
  /** https when true, http when false — stored in evidence. */
  tls: boolean;
  /** The fingerprint's security_value, so the ranker places it the same as a discovered match. */
  security_value: number | null;
}

/** discovery_sources joined with its (optional) poller row, for the bulk sources list. */
export interface DiscoverySourceWithPoller extends DiscoverySource {
  poller_configured: boolean;
  poller_enabled: boolean | null;
  poller_last_status: string | null;
  poller_last_polled_at: string | null;
  poller_last_error: string | null;
  /** Internal, for working out the polled URL; never sent to the client as is. */
  poller_fingerprint_id: string | null;
  poller_cursor: string | null;
}

/**
 * A manual source's poll target, as the edit route writes it: the row's own
 * address, plus port/scheme/endpoint in evidence (where upsertManual puts them).
 */
export interface ManualTargetUpdate {
  ip_address: string;
  target_port: number;
  tls: boolean;
  /** null removes the endpoint override (the fingerprint's endpoint applies). */
  endpoint: string | null;
}

/**
 * An already-encrypted replacement poll credential (CredentialEncryption.encrypt
 * output plus the optional Basic-auth username). Applied in the same statement
 * as a manual source's address change, so no poll can ever pair the old token
 * with the new address.
 */
export interface ReplacementCredential {
  encrypted: string;
  iv: string;
  authTag: string;
  username: string | null;
}

/**
 * What the edit route checked a manual source's change against, and merged it
 * with. The update only applies while it still holds, so two edits that overlap
 * can't combine into a state neither checked (e.g. one edit's stale address with
 * the other's new token, or one edit's port with the other's HTTPS switch
 * undone), and a token save never lands on the far side of a move it overlapped.
 */
export interface ManualTargetExpectation {
  /** The address that was checked: the update applies only while the source still has it. */
  ip_address: string;
  /**
   * The source's evidence as the route read it. Only its poll settings
   * (target_port, tls, endpoint) are compared: the update applies only while
   * the source still has those, so it never undoes another edit's change of a
   * setting this one left as it was.
   */
  evidence: Record<string, unknown>;
  /** Set for an address change without a new token, which is only allowed while no token is saved: the update applies only while there is still none. */
  noSavedToken: boolean;
}

/** A manual source's poll settings in its evidence (see upsertManual), as compared by updateManualTarget. */
function manualPollSettings(evidence: Record<string, unknown> | null): string {
  const e = evidence || {};
  return JSON.stringify({ target_port: e.target_port ?? null, tls: e.tls ?? null, endpoint: e.endpoint ?? null });
}

/** Postgres unique_violation, e.g. a manual source moved to an address another source already has. */
export const UNIQUE_VIOLATION = '23505';

export const DiscoverySourceModel = {
  /** LEFT JOINs discovery_source_pollers so the sources list can show polling status without N+1 requests. */
  async findAll(): Promise<DiscoverySourceWithPoller[]> {
    const result = await query(
      `SELECT ds.*,
              (dsp.discovery_source_id IS NOT NULL) AS poller_configured,
              dsp.enabled AS poller_enabled,
              dsp.last_status AS poller_last_status,
              dsp.last_polled_at AS poller_last_polled_at,
              dsp.last_error AS poller_last_error,
              dsp.fingerprint_id AS poller_fingerprint_id,
              dsp.poll_cursor AS poller_cursor
         FROM discovery_sources ds
         LEFT JOIN discovery_source_pollers dsp ON dsp.discovery_source_id = ds.id
        ORDER BY ds.security_value DESC NULLS LAST, ds.confidence DESC`
    );
    return result.rows;
  },

  async findById(id: number): Promise<DiscoverySource | null> {
    const result = await query(`SELECT * FROM discovery_sources WHERE id = $1`, [id]);
    return result.rows[0] || null;
  },

  /**
   * Upsert on ip_address so re-scanning the same host refreshes it in place
   * instead of duplicating. A user's own status decision (confirmed/onboarded/
   * ignored) and selected_log_access are intentionally left untouched here --
   * only re-observed signal/confidence data is refreshed by a scan. So are an
   * admin's poll settings: poll_overrides is never written here, and when the
   * host is a manually added source, the scan's fresh evidence keeps the
   * manual entry's keys (manual, target_port, tls, endpoint) -- without them a
   * re-scan would quietly re-point its poller at the fingerprint defaults.
   */
  async upsert(input: DiscoverySourceUpsertInput): Promise<DiscoverySource> {
    const result = await query(
      `INSERT INTO discovery_sources
         (ip_address, mac_address, hostname, open_ports, matched_fingerprint_id, confidence, is_guess, security_value, evidence, last_scan_id, last_seen)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
       ON CONFLICT (ip_address) DO UPDATE SET
         mac_address = COALESCE(EXCLUDED.mac_address, discovery_sources.mac_address),
         hostname = COALESCE(EXCLUDED.hostname, discovery_sources.hostname),
         open_ports = EXCLUDED.open_ports,
         matched_fingerprint_id = EXCLUDED.matched_fingerprint_id,
         confidence = EXCLUDED.confidence,
         is_guess = EXCLUDED.is_guess,
         security_value = EXCLUDED.security_value,
         evidence = CASE
           WHEN discovery_sources.evidence->'manual' = 'true'::jsonb THEN
             EXCLUDED.evidence || jsonb_strip_nulls(jsonb_build_object(
               'manual', true,
               'target_port', discovery_sources.evidence->'target_port',
               'tls', discovery_sources.evidence->'tls',
               'endpoint', discovery_sources.evidence->'endpoint'))
           ELSE EXCLUDED.evidence
         END,
         last_scan_id = EXCLUDED.last_scan_id,
         last_seen = NOW(),
         updated_at = NOW()
       RETURNING *`,
      [
        input.ip_address,
        input.mac_address ?? null,
        input.hostname ?? null,
        input.open_ports,
        input.matched_fingerprint_id,
        input.confidence,
        input.is_guess,
        input.security_value,
        JSON.stringify(input.evidence),
        input.last_scan_id,
      ]
    );
    return result.rows[0];
  },

  /**
   * Insert (or refresh) a MANUALLY added api_pull source. Separate from upsert():
   * that one is scan-driven and requires a non-null last_scan_id + refreshes
   * re-observed scan signals, whereas this row never came from a scan
   * (last_scan_id stays NULL). A manual row is a known device: confidence=100,
   * is_guess=false, status 'confirmed', open_ports = [target_port], and its chosen
   * base-URL port/scheme live in evidence ({manual:true, target_port, tls}) — no DDL
   * (last_scan_id is nullable, evidence is JSONB). ON CONFLICT refreshes the
   * fingerprint/port/evidence in place and un-ignores a previously dismissed host,
   * but otherwise leaves the user's own status decision untouched. Re-adding a
   * host also drops any poll_overrides it had as a discovered source: from now on
   * its evidence is its poll target.
   */
  async upsertManual(input: DiscoverySourceManualInput): Promise<DiscoverySource> {
    const evidence = { manual: true, target_port: input.target_port, tls: input.tls };
    const result = await query(
      `INSERT INTO discovery_sources
         (ip_address, hostname, open_ports, matched_fingerprint_id, confidence, is_guess, security_value, evidence, status)
       VALUES ($1, $2, $3, $4, 100, false, $5, $6, 'confirmed')
       ON CONFLICT (ip_address) DO UPDATE SET
         matched_fingerprint_id = EXCLUDED.matched_fingerprint_id,
         open_ports = EXCLUDED.open_ports,
         evidence = EXCLUDED.evidence,
         poll_overrides = NULL,
         hostname = COALESCE(EXCLUDED.hostname, discovery_sources.hostname),
         confidence = 100,
         is_guess = false,
         status = CASE WHEN discovery_sources.status = 'ignored' THEN 'confirmed' ELSE discovery_sources.status END,
         updated_at = NOW()
       RETURNING *`,
      [
        input.ip_address,
        input.hostname ?? null,
        [input.target_port],
        input.fingerprint_id,
        input.security_value,
        JSON.stringify(evidence),
      ]
    );
    return result.rows[0];
  },

  /**
   * Change a MANUALLY added source's poll target in place: its address, and the
   * port/scheme/endpoint in evidence, exactly where upsertManual keeps them
   * (open_ports follows the port, as there). Other evidence keys are kept.
   * With resetCursor, the poller's cursor is cleared in the same statement, and
   * its cursor_generation changes so that a poll still running for the old
   * target doesn't write its cursor back (DiscoverySourcePollerModel.recordResult):
   * the next poll starts fresh against the new target. The stored credential
   * (unless replaced), schedule and status are untouched. A new address that
   * another source already has fails with UNIQUE_VIOLATION. Null when the row
   * doesn't exist, or no longer matches `expected` (another edit changed its
   * address or poll settings since the route read it): nothing is changed then.
   *
   * One transaction: the source row is locked FOR UPDATE first (only while it
   * still has expected.ip_address and expected.evidence's poll settings). That
   * waits for a token save or another edit in progress on this source
   * (DiscoverySourcePollerModel.upsertCredential holds the row FOR SHARE), and
   * re-checks the row they leave; any later save or edit waits for this one.
   * For a move without a token, whether a token is saved is then read by a
   * statement of its own: its snapshot, taken after the lock, includes a save
   * that committed while this transaction waited, which a condition inside the
   * UPDATE would not see.
   */
  async updateManualTarget(
    id: number,
    target: ManualTargetUpdate,
    resetCursor: boolean,
    credential: ReplacementCredential | null,
    expected: ManualTargetExpectation
  ): Promise<DiscoverySource | null> {
    const client = await getClient();
    let connectionBroken = false;
    try {
      await client.query('BEGIN');
      const locked = await client.query(
        `SELECT 1 FROM discovery_sources
          WHERE id = $1 AND ip_address = $2::inet
            AND jsonb_build_object('target_port', evidence->'target_port', 'tls', evidence->'tls', 'endpoint', evidence->'endpoint') = $3::jsonb
          FOR UPDATE`,
        [id, expected.ip_address, manualPollSettings(expected.evidence)]
      );
      let unchanged = (locked.rowCount ?? 0) > 0;
      if (unchanged && expected.noSavedToken) {
        const saved = await client.query(`SELECT 1 FROM discovery_source_pollers WHERE discovery_source_id = $1`, [id]);
        unchanged = (saved.rowCount ?? 0) === 0;
      }
      if (!unchanged) {
        await client.query('ROLLBACK');
        return null;
      }
      // One UPDATE of the poller row: Postgres applies only one of two
      // data-modifying CTEs that touch the same row, so the cursor reset and the
      // credential swap must share a statement-level UPDATE. Either one starts a
      // new cursor generation: a poll still running for the old target keeps
      // its cursor to itself.
      const result = await client.query(
        `WITH updated AS (
           UPDATE discovery_sources
              SET ip_address = $2,
                  open_ports = ARRAY[$3::int],
                  evidence = (evidence - 'endpoint') || jsonb_strip_nulls(jsonb_build_object(
                    'manual', true, 'target_port', $3::int, 'tls', $4::boolean, 'endpoint', $5::text)),
                  poll_overrides = NULL,
                  updated_at = NOW()
            WHERE id = $1
            RETURNING *
         ), poller_update AS (
           UPDATE discovery_source_pollers
              SET poll_cursor = CASE WHEN $6::boolean THEN NULL ELSE poll_cursor END,
                  encrypted_credential = CASE WHEN $7::boolean THEN $8::text ELSE encrypted_credential END,
                  encryption_iv = CASE WHEN $7::boolean THEN $9::text ELSE encryption_iv END,
                  encryption_auth_tag = CASE WHEN $7::boolean THEN $10::text ELSE encryption_auth_tag END,
                  credential_username = CASE WHEN $7::boolean THEN $11::text ELSE credential_username END,
                  cursor_generation = nextval('discovery_poll_cursor_generation_seq'),
                  updated_at = NOW()
            WHERE discovery_source_id = $1 AND ($6::boolean OR $7::boolean) AND EXISTS (SELECT 1 FROM updated)
         )
         SELECT * FROM updated`,
        [
          id,
          target.ip_address,
          target.target_port,
          target.tls,
          target.endpoint,
          resetCursor,
          credential !== null,
          credential?.encrypted ?? null,
          credential?.iv ?? null,
          credential?.authTag ?? null,
          credential?.username ?? null,
        ]
      );
      await client.query('COMMIT');
      return result.rows[0] || null;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        connectionBroken = true; // don't hand a dead connection back to the pool
      }
      throw err;
    } finally {
      client.release(connectionBroken || undefined);
    }
  },

  /**
   * Set a scan-discovered source's poll overrides ({port?, tls?, endpoint?}), or
   * clear them all with null. Never touches the address or the scan-owned
   * evidence. resetCursor as in updateManualTarget. `expected` is the source's
   * poll_overrides as the edit route read them (and merged the change with):
   * the update applies only while the source still has them and is still a
   * scan-discovered source, so it never undoes another edit's change that
   * committed in between. Null when the row doesn't exist or no longer matches;
   * nothing is changed then.
   */
  async setPollOverrides(
    id: number,
    overrides: Record<string, unknown> | null,
    resetCursor: boolean,
    expected: Record<string, unknown> | null
  ): Promise<DiscoverySource | null> {
    const result = await query(
      `WITH updated AS (
         UPDATE discovery_sources
            SET poll_overrides = $2::jsonb, updated_at = NOW()
          WHERE id = $1
            AND poll_overrides IS NOT DISTINCT FROM $4::jsonb
            AND evidence->'manual' IS DISTINCT FROM 'true'::jsonb
          RETURNING *
       ), cursor_reset AS (
         UPDATE discovery_source_pollers
            SET poll_cursor = NULL, cursor_generation = nextval('discovery_poll_cursor_generation_seq'), updated_at = NOW()
          WHERE discovery_source_id = $1 AND $3::boolean AND EXISTS (SELECT 1 FROM updated)
       )
       SELECT * FROM updated`,
      [
        id,
        overrides === null ? null : JSON.stringify(overrides),
        resetCursor,
        expected === null ? null : JSON.stringify(expected),
      ]
    );
    return result.rows[0] || null;
  },

  /**
   * Hard-delete a source row. The poller row (discovery_source_pollers) cascades
   * via its ON DELETE CASCADE FK, and raw_logs.discovery_source_id is set NULL.
   * Only reachable from the admin-gated manual-source delete route, which first
   * checks evidence.manual === true.
   */
  async deleteById(id: number): Promise<boolean> {
    const r = await query(`DELETE FROM discovery_sources WHERE id = $1`, [id]);
    return (r.rowCount ?? 0) > 0;
  },

  async setStatus(id: number, status: DiscoverySourceStatus): Promise<DiscoverySource | null> {
    const result = await query(`UPDATE discovery_sources SET status = $2, updated_at = NOW() WHERE id = $1 RETURNING *`, [
      id,
      status,
    ]);
    return result.rows[0] || null;
  },

  async setSelectedLogAccess(id: number, logAccess: LogAccessMethod): Promise<DiscoverySource | null> {
    const result = await query(
      `UPDATE discovery_sources SET selected_log_access = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id, JSON.stringify(logAccess)]
    );
    return result.rows[0] || null;
  },
};
