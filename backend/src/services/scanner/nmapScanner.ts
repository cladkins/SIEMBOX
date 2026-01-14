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
      ipAddress: '127.0.0.1',
      userAgent: 'nmap-scanner',
      responseStatus: 202,
      details: {
        targets: options.targets,
        scanType: options.scanType,
        description: options.description,
      },
    });

    // Execute scan asynchronously (don't await)
    this.executeScan(scanId, options).catch(async (error) => {
      console.error(`[NMAP] Scan ${scanId} failed:`, error);
      console.error(`[NMAP] Error stack:`, error?.stack);
      const errorMsg = error?.message || error?.toString() || 'Scan execution failed';
      await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
    });

    return scanId;
  }

  /**
   * Execute the actual NMAP scan
   * Runs asynchronously in background
   */
  private static async executeScan(scanId: number, options: ScanOptions): Promise<void> {
    try {
      console.log(`[NMAP] Starting scan ${scanId}`);
      console.log(`[NMAP] Targets received (array):`, JSON.stringify(options.targets));
      console.log(`[NMAP] Targets type:`, typeof options.targets, Array.isArray(options.targets));

      // Update scan status to 'running'
      await this.updateScanStatus(scanId, 'running', new Date());

      // Build NMAP options based on scan type
      const nmapOptions = this.buildNmapOptions(options.scanType);

      // Join targets into space-separated string
      const targetString = options.targets.join(' ');

      console.log(`[NMAP] Target string for nmap:`, JSON.stringify(targetString));
      console.log(`[NMAP] Scan ${scanId} command: nmap ${nmapOptions} ${targetString}`);

      // Check if nmap is available
      console.log(`[NMAP] Checking nmap availability...`);
      const { execSync } = require('child_process');
      try {
        const nmapVersion = execSync('which nmap && nmap --version', { encoding: 'utf-8' });
        console.log(`[NMAP] Found nmap:`, nmapVersion);
      } catch (nmapCheckError: any) {
        console.error(`[NMAP] NMAP not found or not executable:`, nmapCheckError.message);
        throw new Error(`NMAP is not installed or not accessible: ${nmapCheckError.message}`);
      }

      // Create NMAP scan instance
      const scan = new nmap.NmapScan(targetString, nmapOptions);

      // Set timeout for scan (15 minutes max)
      const scanTimeout = setTimeout(async () => {
        console.error(`[NMAP] Scan ${scanId} timed out after 15 minutes`);
        await this.updateScanStatus(scanId, 'failed', undefined, new Date(), 'Scan timed out after 15 minutes');
      }, 15 * 60 * 1000);

      // Handle scan completion
      scan.on('complete', async (data: any) => {
        clearTimeout(scanTimeout);
        console.log(`[NMAP] Scan ${scanId} completed. Processing results...`);
        console.log(`[NMAP] Raw data received:`, JSON.stringify(data).substring(0, 500));
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
        const errorStr = String(error);
        console.error(`[NMAP] Scan ${scanId} stderr output:`, errorStr);

        // Fatal error patterns that should always fail the scan
        const fatalPatterns = [
          /Failed to resolve/i,
          /No targets were specified/i,
          /Could not resolve/i,
          /QUITTING/i,
          /Segmentation fault/i,
        ];

        // Non-fatal warning patterns that can be ignored
        const nonFatalPatterns = [
          /RTTVAR has grown/i,
          /decreasing to/i,
          /packet_trace/i,
          /^Warning:.*timeout/i,  // Only timeout warnings, not all warnings
        ];

        // Check for fatal errors first
        const hasFatalError = fatalPatterns.some(pattern => pattern.test(errorStr));
        const isNonFatal = !hasFatalError && nonFatalPatterns.some(pattern => pattern.test(errorStr));

        if (hasFatalError || !isNonFatal) {
          console.error(`[NMAP] FATAL error detected, marking scan as failed`);
          const errorMsg = error?.message || error?.toString() || JSON.stringify(error) || 'Unknown error';
          await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
        } else {
          console.log(`[NMAP] Non-fatal warning ignored, scan will continue`);
        }
      });

      // Start the scan
      console.log(`[NMAP] Starting scan execution for scan ${scanId}...`);
      scan.startScan();
      console.log(`[NMAP] Scan ${scanId} startScan() called, waiting for events...`);
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

    // Debug: Log the structure of results
    console.log('[NMAP] Raw results structure:', JSON.stringify(results, null, 2));

    // node-nmap returns results with different structure depending on scan type
    // Extract hosts from the results object
    let hosts: any[] = [];

    if (Array.isArray(results)) {
      hosts = results;
    } else if (results && Array.isArray(results.host)) {
      // XML parser returns { host: [...] }
      hosts = results.host;
    } else if (results && results.host) {
      // Single host result
      hosts = [results.host];
    } else if (results) {
      // Try treating the results object itself as a single host
      hosts = [results];
    }

    console.log(`[NMAP] Processing ${hosts.length} hosts from scan ${scanId}`);

    for (const host of hosts) {
      try {
        // node-nmap uses 'up' status in host.status or host.state
        const hostStatus = host.status || host.state || (host.address ? 'up' : 'down');
        const isUp = hostStatus === 'up' || hostStatus.state === 'up';

        // Skip if host is down
        if (!host || !isUp) {
          console.log(`[NMAP] Skipping host - status: ${hostStatus}`);
          continue;
        }

        // Extract IP address - node-nmap can use different field names
        const ipAddress = host.ip ||
                         (host.address && typeof host.address === 'string' ? host.address : null) ||
                         (host.address && host.address.addr ? host.address.addr : null) ||
                         (Array.isArray(host.address) && host.address[0] ? host.address[0].addr : null);

        if (!ipAddress) {
          console.log('[NMAP] Skipping host - no IP address found');
          continue;
        }

        // Extract hostname
        const hostname = host.hostname?.[0]?.hostname ||
                        host.hostname?.name ||
                        (Array.isArray(host.hostnames) && host.hostnames[0]?.name) ||
                        null;

        // Extract MAC address
        const macAddress = host.mac ||
                          (host.address && Array.isArray(host.address) && host.address.find((a: any) => a.addrtype === 'mac')?.addr) ||
                          null;

        // Extract asset information
        const asset = {
          ip_address: ipAddress,
          hostname: hostname,
          mac_address: macAddress,
          os_type: host.osNmap?.osClass?.[0]?.type || host.os?.osmatch?.[0]?.osclass?.[0]?.type || null,
          os_version: host.osNmap?.osMatch?.[0]?.name || host.os?.osmatch?.[0]?.name || null,
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

        // Process ports/services - handle different port field structures
        const ports = host.openPorts || host.ports?.port || [];
        const portArray = Array.isArray(ports) ? ports : [ports];

        if (portArray.length > 0) {
          for (const portInfo of portArray) {
            try {
              // Handle different port object structures
              const portId = portInfo.port || portInfo.portid;
              const protocol = portInfo.protocol || 'tcp';
              const serviceName = portInfo.service || portInfo.service?.name || null;
              const serviceVersion = portInfo.version || portInfo.service?.version || null;
              const product = portInfo.product || portInfo.service?.product || null;

              const service = {
                asset_id: createdAsset.id,
                port: parseInt(portId, 10),
                protocol: protocol,
                service_name: serviceName,
                service_version: serviceVersion,
                state: ServiceState.OPEN,
                banner: product ? `${product} ${serviceVersion || ''}`.trim() : null,
              };

              await AssetRepository.upsertService(service);
              servicesDiscovered++;
            } catch (error) {
              console.error(`[NMAP] Failed to store service:`, error);
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
      ipAddress: '127.0.0.1',
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
