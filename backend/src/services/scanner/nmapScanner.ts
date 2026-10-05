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
import { ErrorLogService } from '../errors/errorLogService';
import { AssetType, AssetCriticality, AssetStatus, DiscoveryMethod, ServiceState } from '../../models/Asset';
import { isValidScanTarget } from '../../utils/typeGuards';
import { parseNmapXml } from './nmapXml';

/**
 * Scan options interface
 */
export interface ScanOptions {
  targets: string[]; // IPs or CIDRs
  scanType: 'ping' | 'port' | 'service' | 'os';
  userId: number;
  description?: string;
  /**
   * Dispatch to a log shipper instead of running on the backend. When set, the
   * scan is created 'queued' and left for that shipper to claim and run (it's
   * out on the LAN where the backend's own nmap can't reach -- see migration
   * 032). null/undefined runs it in-process, exactly as before.
   */
  assignedShipperId?: number | null;
}

/**
 * A scan job handed to a log shipper by the job-pull
 * (GET /api/shippers/:api_key/scan-jobs). Everything the shipper needs to run
 * one nmap invocation and nothing it gets to choose: the args and targets are
 * both server-built and server-validated.
 */
export interface ShipperScanJob {
  scanId: number;
  kind: 'nmap'; // the shipper dispatches on this (nuclei jobs carry kind: 'nuclei')
  nmapArgs: string[]; // e.g. ['-sV', '-p', '1-1000']
  targets: string[]; // validated IPs / CIDRs / hostnames
}

/**
 * Validates a scan's target list. This is the authoritative gate against
 * node-nmap's own argument handling: it builds its argv by splitting the
 * *joined* target string on whitespace before spawning the real `nmap`
 * binary (see node_modules/node-nmap/index.js), so a target containing a
 * space can smuggle in extra nmap flags unless every entry is confirmed to be
 * a bare IP, CIDR, or hostname first -- there is no shell involved, but
 * node-nmap re-splits for us regardless. Called both here (so `scan()` is
 * safe no matter what a caller already checked) and in routes/assets.ts
 * (so a bad request gets a clean 400 instead of a 500 from deeper inside).
 * Returns an error message, or null if `targets` is safe to use.
 */
export function validateScanTargets(targets: unknown): string | null {
  if (!Array.isArray(targets) || targets.length === 0) {
    return 'targets must be a non-empty array of IP addresses, CIDR ranges, or hostnames';
  }
  for (const target of targets) {
    if (typeof target !== 'string' || !isValidScanTarget(target)) {
      return `Invalid target: ${JSON.stringify(target)} is not a valid IP address, CIDR range, or hostname`;
    }
  }
  return null;
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
    const targetError = validateScanTargets(options.targets);
    if (targetError) {
      throw new Error(targetError);
    }

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
        assignedShipperId: options.assignedShipperId ?? null,
      },
    });

    // When the scan is assigned to a log shipper it stays 'queued' for that
    // shipper to claim (GET /api/shippers/:api_key/scan-jobs) and run out on
    // the LAN; the backend does NOT run nmap itself, because its own nmap can't
    // see the real network from inside the Docker bridge (see migration 032).
    // The shipper posts results back to POST /api/shippers/scan-results, which
    // calls ingestShipperResults(). An unassigned scan runs in-process exactly
    // as before.
    if (options.assignedShipperId == null) {
      // Execute scan asynchronously (don't await)
      this.executeScan(scanId, options).catch(async (error) => {
        console.error(`[NMAP] Scan ${scanId} failed:`, error);
        console.error(`[NMAP] Error stack:`, error?.stack);
        const errorMsg = error?.message || error?.toString() || 'Scan execution failed';
        await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
      });
    } else {
      console.log(`[NMAP] Scan ${scanId} queued for shipper ${options.assignedShipperId}`);
    }

    return scanId;
  }

  /**
   * Hand out and claim every queued scan assigned to a shipper.
   *
   * Flips each matching row queued -> running and stamps claimed_at/started_at
   * in a single UPDATE ... RETURNING guarded by FOR UPDATE SKIP LOCKED, so two
   * concurrent polls can't both claim the same job. Returns one job descriptor
   * per claimed scan carrying the server-built nmap argument tokens and the
   * validated target list the shipper must run -- the shipper never picks its
   * own flags or targets. Stored targets are re-validated here at hand-out
   * time; a scan whose stored targets no longer validate is failed and skipped
   * rather than handed out.
   */
  static async claimScanJobsForShipper(shipperId: number): Promise<ShipperScanJob[]> {
    const result = await pool.query(
      `UPDATE vulnerability_scans
          SET status = 'running',
              claimed_at = NOW(),
              started_at = COALESCE(started_at, NOW()),
              updated_at = NOW()
        WHERE id IN (
          SELECT id FROM vulnerability_scans
           WHERE assigned_shipper_id = $1 AND status = 'queued' AND scan_type = 'asset_discovery'
           ORDER BY created_at
           FOR UPDATE SKIP LOCKED
        )
        RETURNING id, scan_options`,
      [shipperId]
    );

    const jobs: ShipperScanJob[] = [];
    for (const row of result.rows) {
      const opts = typeof row.scan_options === 'string' ? JSON.parse(row.scan_options) : row.scan_options;
      const targets: string[] = Array.isArray(opts?.targets) ? opts.targets : [];
      const scanType: string = opts?.scanType || 'port';

      // Defence in depth: only ever hand a shipper a target list that still
      // passes the same validation routes/assets.ts applied on the way in.
      if (validateScanTargets(targets) !== null) {
        await this.updateScanStatus(
          row.id,
          'failed',
          undefined,
          new Date(),
          'Stored scan targets failed validation at hand-out'
        );
        continue;
      }

      jobs.push({ scanId: row.id, kind: 'nmap', nmapArgs: this.nmapArgsFor(scanType), targets });
    }

    return jobs;
  }

  /**
   * Ingest results posted back by a shipper that ran a dispatched scan.
   *
   * The shipper runs `nmap -oX -` out on the LAN and POSTs the raw XML. We
   * parse it into the exact host shape node-nmap would have emitted (nmapXml.ts)
   * and feed it through the same processScanResults path as an in-process scan,
   * so a shipper-run scan and a backend-run scan produce identical assets and
   * services. Marks the scan 'completed' on success; on a parse or processing
   * failure it marks the scan 'failed' and rethrows so the caller can respond.
   */
  static async ingestShipperResults(scanId: number, xml: string, userId: number): Promise<void> {
    try {
      const hosts = await parseNmapXml(xml);
      console.log(`[NMAP] Scan ${scanId} ingesting ${hosts.length} host(s) from shipper`);
      await this.processScanResults(scanId, hosts, userId);
      await this.updateScanStatus(scanId, 'completed', undefined, new Date());
    } catch (error: any) {
      const errorMsg = error?.message || error?.toString() || 'Failed to ingest shipper scan results';
      console.error(`[NMAP] Scan ${scanId} shipper-result ingestion failed:`, error);
      await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
      throw error;
    }
  }

  /**
   * Mark a shipper-dispatched scan as failed. Used when the shipper reports it
   * could not run the scan at all (nmap missing, host unreachable, etc.).
   */
  static async failShipperScan(scanId: number, message: string): Promise<void> {
    await this.updateScanStatus(scanId, 'failed', undefined, new Date(), message || 'Shipper reported scan failure');
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
   * The nmap argument tokens for a scan type, as an array. Single source of
   * truth for what flags each scan type runs: buildNmapOptions() joins it for
   * node-nmap's in-process scanner, and the shipper job-pull
   * (claimScanJobsForShipper) hands the array straight to the shipper. Keeping
   * one definition means a shipper-run scan and a backend-run scan of the same
   * target always use identical flags. Server-dictated: a shipper only ever
   * runs flags chosen here, never anything client-supplied.
   */
  static nmapArgsFor(scanType: string): string[] {
    switch (scanType) {
      case 'ping':
        return ['-sn']; // Ping scan only (no port scan)

      case 'port':
        return ['-sT', '-p', '1-1000']; // TCP connect scan, top 1000 ports

      case 'service':
        return ['-sV', '-p', '1-1000']; // Version detection, top 1000 ports

      case 'os':
        return ['-O', '-sV']; // OS detection + version detection

      default:
        return ['-sT', '-p', '22,80,443']; // Default: common ports
    }
  }

  /**
   * Build NMAP command options based on scan type (space-joined form that
   * node-nmap's in-process NmapScan expects).
   */
  private static buildNmapOptions(scanType: string): string {
    return this.nmapArgsFor(scanType).join(' ');
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
        // Also check for host.ip since some result formats use that instead of host.address
        const hostStatus = host.status || host.state || (host.address || host.ip ? 'up' : 'down');
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

        // Extract hostname - handle various formats from node-nmap
        const hostname = (typeof host.hostname === 'string' ? host.hostname : null) ||
                        host.hostname?.[0]?.hostname ||
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
          assigned_shipper_id,
          created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
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
        options.assignedShipperId ?? null,
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
    if (status === 'failed') {
      ErrorLogService.logBackgroundError('asset-scan', errorMessage || 'Asset discovery scan failed', {
        dedupeKey: String(scanId),
        scanId,
      });
    }

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
        // duration_seconds is computed by the update_scan_duration() trigger
        // (001_initial_schema.sql) whenever completed_at is set -- no need to
        // compute it here too.
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
