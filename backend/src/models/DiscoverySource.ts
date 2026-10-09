import { query } from '../config/database';
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
}

export const DiscoverySourceModel = {
  /** LEFT JOINs discovery_source_pollers so the sources list can show polling status without N+1 requests. */
  async findAll(): Promise<DiscoverySourceWithPoller[]> {
    const result = await query(
      `SELECT ds.*,
              (dsp.discovery_source_id IS NOT NULL) AS poller_configured,
              dsp.enabled AS poller_enabled,
              dsp.last_status AS poller_last_status,
              dsp.last_polled_at AS poller_last_polled_at,
              dsp.last_error AS poller_last_error
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
   * only re-observed signal/confidence data is refreshed by a scan.
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
         evidence = EXCLUDED.evidence,
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
   * but otherwise leaves the user's own status decision untouched.
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
