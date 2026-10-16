/**
 * Asset-360: everything correlated to one asset in a single call —
 *   - agent          the EDR endpoint agent reporting on this asset (if any)
 *   - shipper        the log shipper matched by hostname/IP (if any)
 *   - geo            GeoIP country for the asset's IP (null for private IPs)
 *   - vulnerabilities the asset's open/closed findings (nested vuln shape)
 *   - alerts         alerts linked by asset_id OR whose source_ip matches the IP
 *
 * Extracted from routes/assets.ts (GET /:id/related) so it's a plain service
 * function callable both from that route and from the AI analyst/triage tool
 * registry (analystTools.ts's get_asset_context) — tools call services
 * directly, never over HTTP.
 */
import { query } from '../../config/database';
import { AssetRepository } from './assetRepository';
import { VulnerabilityRepository } from '../vulnerabilities/vulnerabilityRepository';
import { geoipService } from '../geoip/geoipService';
import { OFFLINE_THRESHOLD_MINUTES } from '../../models/EdrAgent';
import { alertColumnArm, alertKeyArm, latestAlerts } from '../graph/alertKeys';

/** The source_ip arm, skipped for an asset with no IP ($2 NULL). */
const sourceIpArm = alertKeyArm('source_ip', '$2');

/**
 * The asset's latest 100 alerts: linked by asset_id, or naming its IP as
 * source_ip. One ordered scan per arm (alertKeys.ts latestAlerts()): the
 * asset_id arm on idx_graph_alerts_asset_created, the IP arm on the source_ip
 * index, each stopping at 100 rows. Neither an IP no alert names nor an EDR
 * host whose many alerts are older than its latest 100 sends Postgres back
 * through every alert by created_at.
 */
export const ASSET_ALERTS_SQL = `SELECT a.id, a.rule_id, a.severity, a.title, a.description, a.status, a.source, a.event_id,
              a.matched_data, a.created_at
         FROM alerts a
        WHERE a.id IN (${latestAlerts(
          [alertColumnArm('asset_id', '$1'), { ...sourceIpArm, where: `($2::text IS NOT NULL AND ${sourceIpArm.where})` }],
          'a.id',
          100
        )})
        ORDER BY a.created_at DESC
        LIMIT 100`;

export interface AssetContext {
  agent: Record<string, any> | null;
  shipper: Record<string, any> | null;
  geo: Record<string, any> | null;
  vulnerabilities: any[];
  alerts: any[];
}

export async function getAssetContext(assetId: number): Promise<AssetContext | null> {
  const asset = await AssetRepository.getById(assetId);
  if (!asset) return null;

  const ip = asset.ip_address ? String(asset.ip_address) : null;
  const hostname = asset.hostname || null;

  const [agentResult, shipperResult, alertsResult, vulnerabilities] = await Promise.all([
    // EDR agent reporting on this asset (never expose the api key hash).
    query(
      `SELECT agent_id, asset_id, hostname, os, os_version, arch, agent_version, ip,
              status, config_version, last_seen, created_at,
              (last_seen IS NOT NULL
                 AND last_seen > NOW() - ($2::int * INTERVAL '1 minute'))
                AS online
         FROM edr_agents
        WHERE asset_id = $1
        ORDER BY last_seen DESC NULLS LAST
        LIMIT 1`,
      [assetId, OFFLINE_THRESHOLD_MINUTES]
    ),
    // Log shipper matched by hostname or IP.
    query(
      `SELECT id, name, status, version, last_seen, ip_address, hostname
         FROM log_shippers
        WHERE ($1::text IS NOT NULL AND hostname = $1)
           OR ($2::text IS NOT NULL AND ip_address = $2)
        ORDER BY last_seen DESC NULLS LAST
        LIMIT 1`,
      [hostname, ip]
    ),
    // Alerts linked to the asset, or whose extracted source_ip matches the IP
    // (on migration 043's indexes, one ordered scan per arm).
    query(ASSET_ALERTS_SQL, [assetId, ip]),
    // Reuse the existing nested asset-vuln shape (vulnerability.* fields).
    VulnerabilityRepository.getAssetVulnerabilities(assetId),
  ]);

  return {
    agent: agentResult.rows[0] || null,
    shipper: shipperResult.rows[0] || null,
    geo: ip ? geoipService.lookup(ip) : null,
    vulnerabilities,
    alerts: alertsResult.rows,
  };
}
