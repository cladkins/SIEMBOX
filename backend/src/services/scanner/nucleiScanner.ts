/**
 * Nuclei Scanner Service
 *
 * Integrates with Nuclei to perform vulnerability scanning.
 * Stores discovered vulnerabilities in the database.
 */

import { spawn, ChildProcess } from 'child_process';
import { AuditService } from '../audit/auditService';
import pool from '../../config/database';
import {
  NucleiResult,
  NucleiError,
  NucleiErrorCode,
  ProcessedNucleiVulnerability,
  NucleiSeverity,
} from '../../types/nucleiTypes';

// Template directory (must match templateService.ts)
const TEMPLATES_DIR = process.env.NUCLEI_TEMPLATES_DIR || '/root/nuclei-templates';

/**
 * Scan options interface
 */
export interface ScanOptions {
  target: string;
  templateSelection: {
    all?: boolean;
    templates?: string[];
    tags?: string[];
    cves?: boolean;
    severities?: NucleiSeverity[];
    exclude?: string[];
    excludeTags?: string[];
  };
  userId: number;
  description?: string;
  timeout?: number;
  rateLimit?: number;
}

/**
 * Nuclei Scanner class
 */
export class NucleiScanner {
  private static activeScans: Map<number, ChildProcess> = new Map();

  /**
   * Initiate a new vulnerability scan
   * Returns scan ID for tracking progress
   */
  static async scan(options: ScanOptions): Promise<number> {
    // Create scan record in database
    const scanId = await this.createScanRecord(options);

    // Log audit event
    await AuditService.log({
      userId: options.userId,
      action: 'scan.vulnerability.create',
      resourceType: 'scan',
      resourceId: scanId,
      ipAddress: '127.0.0.1',
      userAgent: 'nuclei-scanner',
      responseStatus: 202,
      details: {
        target: options.target,
        templateSelection: options.templateSelection,
        description: options.description,
      },
    });

    // Execute scan asynchronously (don't await)
    this.executeScan(scanId, options).catch(async (error) => {
      console.error(`[Nuclei] Scan ${scanId} failed:`, error);
      console.error(`[Nuclei] Error stack:`, error?.stack);
      const errorMsg = error?.message || error?.toString() || 'Scan execution failed';
      await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
    });

    return scanId;
  }

  /**
   * Execute the actual Nuclei scan
   * Runs asynchronously in background
   */
  private static async executeScan(scanId: number, options: ScanOptions): Promise<void> {
    try {
      console.log(`[Nuclei] Starting scan ${scanId}`);
      console.log(`[Nuclei] Target: ${options.target}`);

      // Update scan status to 'running'
      await this.updateScanStatus(scanId, 'running', new Date());

      // Check if Nuclei is available
      console.log(`[Nuclei] Checking Nuclei availability...`);
      const { execSync } = require('child_process');
      try {
        const nucleiVersion = execSync('which nuclei && nuclei -version', { encoding: 'utf-8' });
        console.log(`[Nuclei] Found Nuclei:`, nucleiVersion.trim());
      } catch (nucleiCheckError: any) {
        console.error(`[Nuclei] Nuclei not found or not executable:`, nucleiCheckError.message);
        throw new NucleiError(
          `Nuclei is not installed or not accessible: ${nucleiCheckError.message}`,
          NucleiErrorCode.NUCLEI_NOT_FOUND
        );
      }

      // Build Nuclei command arguments
      const args = this.buildNucleiArgs(options);
      console.log(`[Nuclei] Command: nuclei ${args.join(' ')}`);

      // Set timeout (default: 30 minutes for vuln scans)
      const timeout = options.timeout || 30 * 60 * 1000;
      const scanTimeout = setTimeout(async () => {
        console.error(`[Nuclei] Scan ${scanId} timed out after ${timeout / 1000} seconds`);
        if (this.activeScans.has(scanId)) {
          const process = this.activeScans.get(scanId);
          process?.kill('SIGTERM');
          this.activeScans.delete(scanId);
        }
        await this.updateScanStatus(
          scanId,
          'failed',
          undefined,
          new Date(),
          `Scan timed out after ${timeout / 1000} seconds`
        );
      }, timeout);

      // Spawn Nuclei process
      const nucleiProcess = spawn('nuclei', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      // Store process for potential cancellation
      this.activeScans.set(scanId, nucleiProcess);

      const results: NucleiResult[] = [];
      let stderrData = '';
      let templatesTotal = 0;
      let lastProgressUpdate = 0;

      // Handle stdout (JSON results)
      nucleiProcess.stdout?.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n').filter(line => line.trim());

        for (const line of lines) {
          try {
            // Parse JSON result
            const result: NucleiResult = JSON.parse(line);
            results.push(result);
            console.log(
              `[Nuclei] Found vulnerability: ${result.info.name} (${result.info.severity}) at ${result['matched-at']}`
            );
          } catch (parseError) {
            // Non-JSON output (progress/info messages)
            console.log(`[Nuclei] ${line}`);
          }
        }
      });

      // Handle stderr (errors, warnings, and stats)
      nucleiProcess.stderr?.on('data', async (data: Buffer) => {
        const errorOutput = data.toString();
        stderrData += errorOutput;

        // Parse stats output for progress tracking
        // Format: "[0:01:23] | Templates: 1500/6489 (23.1%) | Hosts: 1/1 (100%) | RPS: 150 | Requests: 12500"
        const statsMatch = errorOutput.match(/Templates:\s*(\d+)\/(\d+)\s*\(([0-9.]+)%\).*?Hosts:\s*(\d+)\/(\d+).*?Requests:\s*(\d+)/);
        if (statsMatch) {
          const [, templatesCompleted, templatesTotalParsed, percentComplete, hostsCompleted, hostsTotal, requests] = statsMatch;
          templatesTotal = parseInt(templatesTotalParsed, 10);

          // Throttle database updates to every 3 seconds
          const now = Date.now();
          if (now - lastProgressUpdate >= 3000) {
            lastProgressUpdate = now;
            await this.updateScanProgress(scanId, {
              templatesCompleted: parseInt(templatesCompleted, 10),
              templatesTotal: parseInt(templatesTotalParsed, 10),
              percentComplete: parseFloat(percentComplete),
              hostsCompleted: parseInt(hostsCompleted, 10),
              hostsTotal: parseInt(hostsTotal, 10),
              requests: parseInt(requests, 10),
              vulnerabilitiesFound: results.length,
            }).catch(err => console.error('[Nuclei] Failed to update progress:', err));
          }
        }

        // Also capture "Templates loaded" message for initial count
        const loadedMatch = errorOutput.match(/Templates loaded[^:]*:\s*(\d+)/i);
        if (loadedMatch) {
          templatesTotal = parseInt(loadedMatch[1], 10);
          console.log(`[Nuclei] Templates loaded: ${templatesTotal}`);
          await this.updateScanProgress(scanId, {
            templatesCompleted: 0,
            templatesTotal,
            percentComplete: 0,
            hostsCompleted: 0,
            hostsTotal: 1,
            requests: 0,
            vulnerabilitiesFound: 0,
          }).catch(err => console.error('[Nuclei] Failed to update initial progress:', err));
        }

        // Log non-stats output for debugging
        if (!statsMatch && errorOutput.trim()) {
          console.log(`[Nuclei] stderr:`, errorOutput.trim());
        }
      });

      // Handle process completion
      nucleiProcess.on('close', async (code: number | null) => {
        clearTimeout(scanTimeout);
        this.activeScans.delete(scanId);

        console.log(`[Nuclei] Scan ${scanId} process exited with code ${code}`);
        console.log(`[Nuclei] Found ${results.length} vulnerabilities`);

        if (code === 0 || code === null) {
          // Process results
          try {
            await this.processScanResults(scanId, results, options.userId, options.target);
            await this.updateScanStatus(scanId, 'completed', undefined, new Date());
            console.log(`[Nuclei] Scan ${scanId} completed successfully`);
          } catch (error: any) {
            console.error(`[Nuclei] Scan ${scanId} result processing failed:`, error);
            await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message);
          }
        } else {
          // Scan failed
          const errorMsg = stderrData || `Nuclei exited with code ${code}`;
          await this.updateScanStatus(scanId, 'failed', undefined, new Date(), errorMsg);
        }
      });

      // Handle process errors
      nucleiProcess.on('error', async (error: Error) => {
        clearTimeout(scanTimeout);
        this.activeScans.delete(scanId);
        console.error(`[Nuclei] Scan ${scanId} process error:`, error);
        await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message);
      });

    } catch (error: any) {
      console.error(`[Nuclei] Scan ${scanId} execution error:`, error);
      await this.updateScanStatus(scanId, 'failed', undefined, new Date(), error.message);
    }
  }

  /**
   * Build Nuclei command arguments
   */
  private static buildNucleiArgs(options: ScanOptions): string[] {
    const args: string[] = [];

    // Target
    args.push('-target', options.target);

    // JSON Lines output (Nuclei v3.x uses -jsonl instead of -json)
    args.push('-jsonl');

    // Enable stats output for progress tracking (outputs to stderr)
    args.push('-stats');
    args.push('-stats-interval', '5');

    // Template selection
    const ts = options.templateSelection;

    if (ts.all) {
      // Use all templates
      args.push('-tags', 'all');
    } else {
      // Specific templates
      if (ts.templates && ts.templates.length > 0) {
        for (const template of ts.templates) {
          args.push('-t', template);
        }
      }

      // Tags
      if (ts.tags && ts.tags.length > 0) {
        args.push('-tags', ts.tags.join(','));
      }

      // CVE templates
      if (ts.cves) {
        args.push('-t', 'cves/');
      }

      // Severity filter
      if (ts.severities && ts.severities.length > 0) {
        args.push('-severity', ts.severities.join(','));
      }
    }

    // Exclusions
    if (ts.exclude && ts.exclude.length > 0) {
      for (const exclude of ts.exclude) {
        args.push('-exclude', exclude);
      }
    }

    if (ts.excludeTags && ts.excludeTags.length > 0) {
      args.push('-exclude-tags', ts.excludeTags.join(','));
    }

    // Rate limiting
    if (options.rateLimit) {
      args.push('-rate-limit', options.rateLimit.toString());
    }

    // Specify template directory (critical - tells Nuclei where to find templates)
    args.push('-ud', TEMPLATES_DIR);

    return args;
  }

  /**
   * Process scan results and store in database
   */
  private static async processScanResults(
    scanId: number,
    results: NucleiResult[],
    userId: number,
    target: string
  ): Promise<void> {
    console.log(`[Nuclei] Processing ${results.length} results for scan ${scanId}`);

    const vulnerabilitiesFound = results.length;
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    // Process each result
    for (const result of results) {
      try {
        // Convert to processed vulnerability
        const processedVuln = this.processNucleiResult(result, target);

        // Count by severity
        severityCounts[processedVuln.severity]++;

        // Store in database via vulnerability processor
        await this.storeVulnerability(scanId, processedVuln);

      } catch (error) {
        console.error(`[Nuclei] Failed to process result:`, error);
      }
    }

    console.log(`[Nuclei] Scan ${scanId} processed ${vulnerabilitiesFound} vulnerabilities`);
    console.log(`[Nuclei] Severity breakdown:`, severityCounts);

    // Update scan summary
    await this.updateScanSummary(scanId, vulnerabilitiesFound, severityCounts);

    // Log completion audit event
    await AuditService.log({
      userId,
      action: 'scan.vulnerability.complete',
      resourceType: 'scan',
      resourceId: scanId,
      ipAddress: '127.0.0.1',
      userAgent: 'nuclei-scanner',
      responseStatus: 200,
      details: {
        vulnerabilitiesFound,
        severityCounts,
      },
    });
  }

  /**
   * Process a single Nuclei result into normalized format
   */
  private static processNucleiResult(
    result: NucleiResult,
    target: string
  ): ProcessedNucleiVulnerability {
    const info = result.info;

    // Extract CVE ID from multiple possible locations
    const cveId =
      info['cve-id'] ||
      info.classification?.['cve-id']?.[0] ||
      (result['template-id'].startsWith('CVE-') ? result['template-id'] : undefined);

    // Extract CVSS score
    const cvssScore =
      info['cvss-score'] ||
      info.classification?.['cvss-score'] ||
      undefined;

    // Extract CVSS metrics
    const cvssVector =
      info['cvss-metrics'] ||
      info.classification?.['cvss-metrics'] ||
      undefined;

    // Extract CWE ID
    const cweId =
      typeof info['cwe-id'] === 'string'
        ? info['cwe-id']
        : Array.isArray(info['cwe-id'])
        ? info['cwe-id'][0]
        : info.classification?.['cwe-id']?.[0] ||
          undefined;

    // Build references array
    const references: string[] = [];
    if (info.reference) {
      if (Array.isArray(info.reference)) {
        references.push(...info.reference);
      } else {
        references.push(info.reference);
      }
    }

    // Build evidence from extracted results or matched content
    const evidence = result['extracted-results']?.join(', ') || result['matcher-name'] || '';

    return {
      cveId,
      title: info.name,
      description: info.description,
      severity: info.severity,
      cvssScore,
      cvssVector,
      target,
      matchedAt: result['matched-at'],
      templateId: result['template-id'],
      evidence,
      remediation: info.remediation,
      references,
      cweId,
      rawResult: result,
      detectedAt: new Date(result.timestamp),
    };
  }

  /**
   * Store vulnerability in database
   */
  private static async storeVulnerability(
    _scanId: number,
    vuln: ProcessedNucleiVulnerability
  ): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Upsert vulnerability (if CVE exists)
      let vulnerabilityId: number | null = null;

      if (vuln.cveId) {
        const vulnQuery = `
          INSERT INTO vulnerabilities (
            cve_id, cvss_score, cvss_vector, severity, title, description,
            remediation, "references", cwe_id, metadata, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
          ON CONFLICT (cve_id) DO UPDATE SET
            cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
            cvss_vector = COALESCE(EXCLUDED.cvss_vector, vulnerabilities.cvss_vector),
            severity = COALESCE(EXCLUDED.severity, vulnerabilities.severity),
            title = COALESCE(EXCLUDED.title, vulnerabilities.title),
            description = COALESCE(EXCLUDED.description, vulnerabilities.description),
            remediation = COALESCE(EXCLUDED.remediation, vulnerabilities.remediation),
            "references" = COALESCE(EXCLUDED."references", vulnerabilities."references"),
            cwe_id = COALESCE(EXCLUDED.cwe_id, vulnerabilities.cwe_id),
            metadata = COALESCE(EXCLUDED.metadata, vulnerabilities.metadata),
            updated_at = NOW()
          RETURNING id
        `;

        const vulnResult = await client.query(vulnQuery, [
          vuln.cveId,
          vuln.cvssScore,
          vuln.cvssVector,
          vuln.severity,
          vuln.title,
          vuln.description,
          vuln.remediation,
          vuln.references && vuln.references.length > 0 ? vuln.references : null,
          vuln.cweId,
          JSON.stringify({
            nuclei_template: vuln.templateId,
            matched_at: vuln.matchedAt,
            raw_result: vuln.rawResult,
          }),
        ]);

        vulnerabilityId = vulnResult.rows[0].id;
      }

      // Find or create asset for this target
      const assetQuery = `
        INSERT INTO assets (ip_address, last_seen, updated_at)
        VALUES ($1, NOW(), NOW())
        ON CONFLICT (ip_address) DO UPDATE SET
          last_seen = NOW(),
          updated_at = NOW()
        RETURNING id
      `;

      const assetResult = await client.query(assetQuery, [vuln.target]);
      const assetId = assetResult.rows[0].id;

      // Link asset to vulnerability (if we have a vulnerability record)
      if (vulnerabilityId) {
        const linkQuery = `
          INSERT INTO asset_vulnerabilities (
            asset_id, vulnerability_id, status, evidence,
            first_detected, last_detected, updated_at
          ) VALUES ($1, $2, 'open', $3, NOW(), NOW(), NOW())
          ON CONFLICT (asset_id, vulnerability_id) DO UPDATE SET
            last_detected = NOW(),
            evidence = COALESCE(EXCLUDED.evidence, asset_vulnerabilities.evidence),
            updated_at = NOW()
        `;

        await client.query(linkQuery, [
          assetId,
          vulnerabilityId,
          `Template: ${vuln.templateId}\nMatched at: ${vuln.matchedAt}\nEvidence: ${vuln.evidence}`,
        ]);
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('[Nuclei] Failed to store vulnerability:', error);
      throw error;
    } finally {
      client.release();
    }
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
        target: options.target,
        templateSelection: options.templateSelection,
        description: options.description,
        timeout: options.timeout,
        rateLimit: options.rateLimit,
      };

      const result = await pool.query(query, [
        'vulnerability',
        options.target,
        'queued',
        options.userId,
        JSON.stringify(scanOptions),
      ]);

      return result.rows[0].id;
    } catch (error) {
      console.error('[Nuclei] Failed to create scan record:', error);
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

        // Calculate duration_seconds from started_at
        fields.push(`duration_seconds = EXTRACT(EPOCH FROM ($${paramIndex - 1}::timestamp - started_at))::integer`);
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
      console.error('[Nuclei] Failed to update scan status:', error);
      throw error;
    }
  }

  /**
   * Update scan progress during execution
   */
  private static async updateScanProgress(
    scanId: number,
    progress: {
      templatesCompleted: number;
      templatesTotal: number;
      percentComplete: number;
      hostsCompleted: number;
      hostsTotal: number;
      requests: number;
      vulnerabilitiesFound: number;
    }
  ): Promise<void> {
    try {
      const query = `
        UPDATE vulnerability_scans
        SET
          results_summary = COALESCE(results_summary, '{}'::jsonb) || $2::jsonb,
          vulnerabilities_found = $3,
          updated_at = NOW()
        WHERE id = $1
      `;

      const progressSummary = {
        progress: {
          templatesCompleted: progress.templatesCompleted,
          templatesTotal: progress.templatesTotal,
          percentComplete: progress.percentComplete,
          hostsCompleted: progress.hostsCompleted,
          hostsTotal: progress.hostsTotal,
          requests: progress.requests,
          lastUpdate: new Date().toISOString(),
        }
      };

      await pool.query(query, [scanId, JSON.stringify(progressSummary), progress.vulnerabilitiesFound]);
    } catch (error) {
      console.error('[Nuclei] Failed to update scan progress:', error);
      // Don't throw - progress update failures shouldn't stop the scan
    }
  }

  /**
   * Update scan summary with results
   */
  private static async updateScanSummary(
    scanId: number,
    vulnerabilitiesFound: number,
    severityCounts: Record<string, number>
  ): Promise<void> {
    try {
      const query = `
        UPDATE vulnerability_scans
        SET
          vulnerabilities_found = $2,
          results_summary = $3,
          updated_at = NOW()
        WHERE id = $1
      `;

      const summary = {
        vulnerabilitiesFound,
        severityCounts,
        completedAt: new Date().toISOString(),
      };

      await pool.query(query, [scanId, vulnerabilitiesFound, JSON.stringify(summary)]);
    } catch (error) {
      console.error('[Nuclei] Failed to update scan summary:', error);
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
          vulnerabilities_found,
          error_message,
          results_summary,
          created_at
        FROM vulnerability_scans
        WHERE id = $1
      `;

      const result = await pool.query(query, [scanId]);
      return result.rows[0] || null;
    } catch (error) {
      console.error('[Nuclei] Failed to get scan status:', error);
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
          vs.vulnerabilities_found,
          vs.error_message,
          vs.created_at,
          u.username as initiated_by_username
        FROM vulnerability_scans vs
        LEFT JOIN users u ON vs.initiated_by = u.id
        WHERE vs.scan_type = 'vulnerability'
        ORDER BY vs.created_at DESC
        LIMIT $1
      `;

      const result = await pool.query(query, [limit]);
      return result.rows;
    } catch (error) {
      console.error('[Nuclei] Failed to get recent scans:', error);
      throw error;
    }
  }

  /**
   * Cancel a running scan
   */
  static async cancelScan(scanId: number): Promise<boolean> {
    try {
      if (this.activeScans.has(scanId)) {
        const process = this.activeScans.get(scanId);
        process?.kill('SIGTERM');
        this.activeScans.delete(scanId);

        await this.updateScanStatus(scanId, 'cancelled', undefined, new Date(), 'Scan cancelled by user');

        console.log(`[Nuclei] Scan ${scanId} cancelled`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('[Nuclei] Failed to cancel scan:', error);
      return false;
    }
  }
}
