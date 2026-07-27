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

export const DiscoverySourceModel = {
  async findAll(): Promise<DiscoverySource[]> {
    const result = await query(
      `SELECT * FROM discovery_sources ORDER BY security_value DESC NULLS LAST, confidence DESC`
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
