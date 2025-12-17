/**
 * Auto-Discovery Service
 *
 * Automatically discovers assets from log correlation and manages
 * asset lifecycle (marking stale assets as offline).
 */

import { AssetRepository } from './assetRepository';
import pool from '../../config/database';
import { AssetType, AssetCriticality, AssetStatus, DiscoveryMethod } from '../../models/Asset';

export class AutoDiscoveryService {
  /**
   * Discover assets from raw_logs table
   * Correlates source IPs and hostnames to identify active assets
   *
   * @returns Number of assets discovered
   */
  static async discoverFromLogs(): Promise<number> {
    try {
      console.log('[Auto-Discovery] Starting log correlation...');

      const query = `
        SELECT DISTINCT
          source_ip as ip_address,
          hostname,
          COUNT(*) as log_count,
          MAX(created_at) as last_seen,
          MIN(created_at) as first_seen
        FROM raw_logs
        WHERE source_ip IS NOT NULL
          AND source_ip != '127.0.0.1'
          AND source_ip NOT LIKE '169.254.%'
          AND created_at >= NOW() - INTERVAL '7 days'
        GROUP BY source_ip, hostname
        HAVING COUNT(*) >= 5
      `;

      const result = await pool.query(query);
      let discovered = 0;

      console.log(`[Auto-Discovery] Found ${result.rows.length} potential assets in logs`);

      for (const row of result.rows) {
        try {
          // Check if asset already exists
          const existingAsset = await AssetRepository.getByIp(row.ip_address);

          if (existingAsset) {
            // Update last_seen for existing asset
            await AssetRepository.update(existingAsset.id, {
              last_seen: row.last_seen,
              status: AssetStatus.ACTIVE,
            });
          } else {
            // Create new asset from log correlation
            const asset = {
              ip_address: row.ip_address,
              hostname: row.hostname,
              asset_type: AssetType.SERVER,
              criticality: AssetCriticality.MEDIUM,
              status: AssetStatus.ACTIVE,
              discovery_method: DiscoveryMethod.LOG_CORRELATION,
              metadata: {
                log_count: parseInt(row.log_count, 10),
                discovery_source: 'raw_logs',
                first_log: row.first_seen,
                last_log: row.last_seen,
              },
            };

            await AssetRepository.create(asset);
            discovered++;
          }
        } catch (error) {
          console.error(`[Auto-Discovery] Failed to process asset ${row.ip_address}:`, error);
        }
      }

      console.log(`[Auto-Discovery] Discovered ${discovered} new assets from logs`);
      return discovered;
    } catch (error) {
      console.error('[Auto-Discovery] Log correlation failed:', error);
      throw error;
    }
  }

  /**
   * Mark assets as offline if not seen recently
   *
   * @param hoursThreshold - Hours of inactivity before marking offline (default: 168 = 7 days)
   * @returns Number of assets marked offline
   */
  static async markStaleAssets(hoursThreshold: number = 168): Promise<number> {
    try {
      console.log(`[Auto-Discovery] Checking for stale assets (threshold: ${hoursThreshold} hours)...`);

      const query = `
        UPDATE assets
        SET status = 'offline', updated_at = NOW()
        WHERE last_seen < NOW() - INTERVAL '${hoursThreshold} hours'
          AND status = 'active'
        RETURNING id, ip_address, hostname
      `;

      const result = await pool.query(query);

      if (result.rows.length > 0) {
        console.log(`[Auto-Discovery] Marked ${result.rows.length} assets as offline:`);
        result.rows.forEach((asset: any) => {
          console.log(`  - ${asset.ip_address} (${asset.hostname || 'no hostname'})`);
        });
      } else {
        console.log('[Auto-Discovery] No stale assets found');
      }

      return result.rowCount || 0;
    } catch (error) {
      console.error('[Auto-Discovery] Failed to mark stale assets:', error);
      throw error;
    }
  }

  /**
   * Get auto-discovery statistics
   *
   * @returns Statistics about discovered assets
   */
  static async getStatistics(): Promise<any> {
    try {
      const query = `
        SELECT
          COUNT(*) FILTER (WHERE discovery_method = 'log_correlation') as log_discovered,
          COUNT(*) FILTER (WHERE discovery_method = 'nmap') as nmap_discovered,
          COUNT(*) FILTER (WHERE discovery_method = 'manual') as manual_discovered,
          COUNT(*) FILTER (WHERE status = 'active') as active_assets,
          COUNT(*) FILTER (WHERE status = 'offline') as offline_assets,
          COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '24 hours') as seen_24h,
          COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '7 days') as seen_7d
        FROM assets
      `;

      const result = await pool.query(query);
      return result.rows[0];
    } catch (error) {
      console.error('[Auto-Discovery] Failed to get statistics:', error);
      throw error;
    }
  }

  /**
   * Enrich asset data from parsed logs
   * Updates assets with additional context from log events
   *
   * @returns Number of assets enriched
   */
  static async enrichFromParsedLogs(): Promise<number> {
    try {
      console.log('[Auto-Discovery] Starting asset enrichment from parsed logs...');

      // Query parsed logs for user agents, authentication events, etc.
      const query = `
        SELECT
          pl.source_ip as ip_address,
          jsonb_object_agg(
            COALESCE(pl.event_type, 'unknown'),
            COUNT(*)
          ) as event_types,
          MAX(pl.timestamp) as last_activity
        FROM parsed_logs pl
        WHERE pl.timestamp >= NOW() - INTERVAL '7 days'
          AND pl.source_ip IS NOT NULL
        GROUP BY pl.source_ip
      `;

      const result = await pool.query(query);
      let enriched = 0;

      for (const row of result.rows) {
        try {
          const existingAsset = await AssetRepository.getByIp(row.ip_address);

          if (existingAsset) {
            // Merge enrichment data into existing metadata
            const enrichmentData = {
              event_types: row.event_types,
              last_activity: row.last_activity,
              enriched_at: new Date().toISOString(),
            };

            const updatedMetadata = {
              ...(existingAsset.metadata || {}),
              enrichment: enrichmentData,
            };

            await AssetRepository.update(existingAsset.id, {
              metadata: updatedMetadata,
            });

            enriched++;
          }
        } catch (error) {
          console.error(`[Auto-Discovery] Failed to enrich asset ${row.ip_address}:`, error);
        }
      }

      console.log(`[Auto-Discovery] Enriched ${enriched} assets from parsed logs`);
      return enriched;
    } catch (error) {
      console.error('[Auto-Discovery] Asset enrichment failed:', error);
      throw error;
    }
  }

  /**
   * Run full auto-discovery cycle
   * Combines all discovery methods
   */
  static async runFullDiscovery(): Promise<{
    discovered: number;
    staleMarked: number;
    enriched: number;
  }> {
    console.log('[Auto-Discovery] Starting full discovery cycle...');

    const discovered = await this.discoverFromLogs();
    const staleMarked = await this.markStaleAssets(168); // 7 days
    const enriched = await this.enrichFromParsedLogs();

    console.log('[Auto-Discovery] Full discovery cycle complete:', {
      discovered,
      staleMarked,
      enriched,
    });

    return {
      discovered,
      staleMarked,
      enriched,
    };
  }
}
