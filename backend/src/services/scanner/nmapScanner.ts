/**
 * NMAP Scanner Service
 *
 * Integrates with node-nmap to perform network asset discovery scans.
 * Stores discovered assets and services in the database.
 */

// @ts-ignore - node-nmap doesn't have TypeScript definitions
import nmap from 'node-nmap';
import { AssetRepository } from '../assets/assetRepository';
import { AuditService } from '../audit/auditService';
import pool from '../../config/database';
import { AssetType, AssetCriticality, AssetStatus, DiscoveryMethod, ServiceState } from '../../models/Asset';

/**
 * Scan options interface
 */
export interface ScanOptions {
  targets: string[]; // IPs or CIDRs
  scanType: 'ping' | 'port' | 'service' | 'os';
  userId: number;
  description?: string;
}

/**
 * NMAP Scanner class
 */
export class NmapScanner {
  /**
   * Initiate a new scan
   * Returns scan ID for tracking progress
   */
  static async scan(options: ScanOptions): Promise<number> {
    // Create scan record in database
    const scanId = await this.createScanRecord(options);

    // Log audit event
    await AuditService.log({
      userId: options.userId,
      action: 'scan.asset.create',
      resourceType: 'scan',
      resourceId: scanId,
      ipAddress: 'system',
      userAgent: 'nmap-scanner',
      responseStatus: 202,
      details: {
        targets: options.targets,
        scanType: options.scanType,
        description: options.description,
      },
    });

    // Execute scan asynchronously (don't await)
    this.executeScan(scanId, options).catch((error) => {
      console.error(`[NMAP] Scan ${scanId} failed:`, error);
    });

    return scanId;
  }

  /**
   * Execute the actual NMAP scan
   * Runs asynchronously in background
   */
  private static async executeScan(scanId: number, options: ScanOptions): Promise<void> {
    try {
      console.log(`[NMAP] Starting scan ${scanId} for targets: ${options.targets.join(', ')}`);

      // Update scan status to 'running'
      await this.updateScanStatus(scanId, 'running', new Date());

      // Build NMAP options based on scan type
      const nmapOptions = this.buildNmapOptions(options.scanType);

      // Join targets into space-separated string
      const targetString = options.targets.join(' ');

      console.log(`[NMAP] Scan ${scanId} command: nmap ${nmapOptions} ${targetString}`);

      // Create NMAP scan instance
      const scan = new nmap.NmapScan(targetString, nmapOptions);

      // Handle scan completion
      scan.on('complete', async (data: any) => {
        console.log(`[NMAP] Scan ${scanId} completed. Processing results...`);
        try {
          await this.processScanResults(scanId, data, options.userId);
          await this.updateScanStatus(scanId, 'completed', undefined, new Date());
          console.log(`[NMAP] Scan ${scanId} results processed successfully`);
        } catch (error: any) {
          console.error(`[NMAP] Scan ${scanId} result processing failed:`, error);
          await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message);
        }
      });

      // Handle scan errors
      scan.on('error', async (error: any) => {
        console.error(`[NMAP] Scan ${scanId} error:`, error);
        await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message || 'Unknown error');
      });

      // Start the scan
      scan.startScan();
    } catch (error: any) {
      console.error(`[NMAP] Scan ${scanId} execution error:`, error);
      await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message);
    }
  }

  /**
   * Build NMAP command options based on scan type
   */
  private static buildNmapOptions(scanType: string): string {
    switch (scanType) {
      case 'ping':
        return '-sn'; // Ping scan only (no port scan)

      case 'port':
        return '-sT -p 1-1000'; // TCP connect scan, top 1000 ports

      case 'service':
        return '-sV -p 1-1000'; // Version detection, top 1000 ports

      case 'os':
        return '-O -sV'; // OS detection + version detection

      default:
        return '-sT -p 22,80,443'; // Default: common ports
    }
  }

  /**
   * Process scan results and store in database
   */
  private static async processScanResults(scanId: number, results: any, userId: number): Promise<void> {
    let assetsDiscovered = 0;
    let servicesDiscovered = 0;

    // Handle both array and single host result
    const hosts = Array.isArray(results) ? results : [results];

    console.log(`[NMAP] Processing ${hosts.length} hosts from scan ${scanId}`);

    for (const host of hosts) {
      try {
        // Skip if host is down
        if (!host || host.status !== 'up') {
          continue;
        }

        // Extract asset information
        const asset = {
          ip_address: host.ip,
          hostname: host.hostname?.[0]?.hostname || null,
          mac_address: host.mac || null,
          os_type: host.osNmap?.osClass?.[0]?.type || null,
          os_version: host.osNmap?.osMatch?.[0]?.name || null,
          asset_type: AssetType.SERVER,
          criticality: AssetCriticality.MEDIUM,
          status: AssetStatus.ACTIVE,
          discovery_method: DiscoveryMethod.NMAP,
          metadata: {
            nmap_scan_id: scanId,
            scan_timestamp: new Date().toISOString(),
            raw_data: host,
          },
        };

        console.log(`[NMAP] Discovered asset: ${asset.ip_address} (${asset.hostname || 'no hostname'})`);

        // Upsert asset
        const createdAsset = await AssetRepository.create(asset);
        assetsDiscovered++;

        // Process ports/services
        if (host.openPorts && Array.isArray(host.openPorts)) {
          for (const portInfo of host.openPorts) {
            try {
              const service = {
                asset_id: createdAsset.id,
                port: portInfo.port,
                protocol: portInfo.protocol || 'tcp',
                service_name: portInfo.service || null,
                service_version: portInfo.version || null,
                state: ServiceState.OPEN,
                banner: portInfo.product ? `${portInfo.product} ${portInfo.version || ''}`.trim() : null,
              };

              await AssetRepository.upsertService(service);
              servicesDiscovered++;
            } catch (error) {
              console.error(`[NMAP] Failed to store service ${portInfo.port}/${portInfo.protocol}:`, error);
            }
          }
        }

        // Update last_scanned timestamp
        await AssetRepository.updateLastScanned(createdAsset.id);
      } catch (error) {
        console.error(`[NMAP] Failed to process host ${host.ip}:`, error);
      }
    }

    console.log(`[NMAP] Scan ${scanId} discovered ${assetsDiscovered} assets and ${servicesDiscovered} services`);

    // Update scan summary
    await this.updateScanSummary(scanId, assetsDiscovered);

    // Log completion audit event
    await AuditService.log({
      userId,
      action: 'scan.asset.complete',
      resourceType: 'scan',
      resourceId: scanId,
      ipAddress: 'system',
      userAgent: 'nmap-scanner',
      responseStatus: 200,
      details: {
        assetsDiscovered,
        servicesDiscovered,
      },
    });
  }

  /**
   * Create scan record in database
   */
  private static async createScanRecord(options: ScanOptions): Promise<number> {
    try {
      const query = `
        INSERT INTO vulnerability_scans (
          scan_type,
          target,
          status,
          initiated_by,
          scan_options,
          created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        RETURNING id
      `;

      const scanOptions = {
        targets: options.targets,
        scanType: options.scanType,
        description: options.description,
      };

      const result = await pool.query(query, [
        'asset_discovery',
        options.targets.join(', '),
        'queued',
        options.userId,
        JSON.stringify(scanOptions),
      ]);

      return result.rows[0].id;
    } catch (error) {
      console.error('[NMAP] Failed to create scan record:', error);
      throw error;
    }
  }

  /**
   * Update scan status
   */
  private static async updateScanStatus(
    scanId: number,
    status: string,
    startedAt?: Date,
    completedAt?: Date,
    errorMessage?: string
  ): Promise<void> {
    try {
      const fields: string[] = ['status = $2', 'updated_at = NOW()'];
      const params: any[] = [scanId, status];
      let paramIndex = 3;

      if (startedAt) {
        fields.push(`started_at = $${paramIndex++}`);
        params.push(startedAt);
      }

      if (completedAt) {
        fields.push(`completed_at = $${paramIndex++}`);
        params.push(completedAt);
      }

      if (errorMessage) {
        fields.push(`error_message = $${paramIndex++}`);
        params.push(errorMessage);
      }

      const query = `
        UPDATE vulnerability_scans
        SET ${fields.join(', ')}
        WHERE id = $1
      `;

      await pool.query(query, params);
    } catch (error) {
      console.error('[NMAP] Failed to update scan status:', error);
      throw error;
    }
  }

  /**
   * Update scan summary with results
   */
  private static async updateScanSummary(scanId: number, assetsDiscovered: number): Promise<void> {
    try {
      const query = `
        UPDATE vulnerability_scans
        SET
          assets_discovered = $2,
          results_summary = $3,
          updated_at = NOW()
        WHERE id = $1
      `;

      const summary = {
        assetsDiscovered,
        completedAt: new Date().toISOString(),
      };

      await pool.query(query, [scanId, assetsDiscovered, JSON.stringify(summary)]);
    } catch (error) {
      console.error('[NMAP] Failed to update scan summary:', error);
      throw error;
    }
  }

  /**
   * Get scan status
   */
  static async getScanStatus(scanId: number): Promise<any> {
    try {
      const query = `
        SELECT
          id,
          scan_type,
          target,
          status,
          started_at,
          completed_at,
          duration_seconds,
          assets_discovered,
          error_message,
          results_summary,
          created_at
        FROM vulnerability_scans
        WHERE id = $1
      `;

      const result = await pool.query(query, [scanId]);
      return result.rows[0] || null;
    } catch (error) {
      console.error('[NMAP] Failed to get scan status:', error);
      throw error;
    }
  }

  /**
   * Get recent scans
   */
  static async getRecentScans(limit: number = 20): Promise<any[]> {
    try {
      const query = `
        SELECT
          vs.id,
          vs.scan_type,
          vs.target,
          vs.status,
          vs.started_at,
          vs.completed_at,
          vs.duration_seconds,
          vs.assets_discovered,
          vs.error_message,
          vs.created_at,
          u.username as initiated_by_username
        FROM vulnerability_scans vs
        LEFT JOIN users u ON vs.initiated_by = u.id
        WHERE vs.scan_type = 'asset_discovery'
        ORDER BY vs.created_at DESC
        LIMIT $1
      `;

      const result = await pool.query(query, [limit]);
      return result.rows;
    } catch (error) {
      console.error('[NMAP] Failed to get recent scans:', error);
      throw error;
    }
  }
}
