/**
 * Trivy Container Scanner Service
 *
 * Scans a container image by reference (Trivy pulls the layers itself — no Docker
 * daemon required) and stores the OS/library package vulnerabilities it reports.
 * Runs asynchronously like the Nuclei scanner; results land in the
 * container_scans / container_vulnerabilities tables (migration 013).
 */

import { spawn, ChildProcess } from 'child_process';
import pool from '../../config/database';
import { AuditService } from '../audit/auditService';
import { ErrorLogService } from '../errors/errorLogService';

// A conservative image-reference whitelist: registry/repo[:tag][@digest]. Trivy
// is spawned with an args array (no shell), but we still reject anything outside
// the normal image-ref character set as defence in depth and to fail fast.
const IMAGE_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,510}$/;

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}
interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVuln[] | null;
}
interface TrivyReport {
  Results?: TrivyResult[] | null;
}

export class TrivyScanner {
  private static activeScans = new Map<number, ChildProcess>();

  // Serialize scans. Trivy's local fs cache (a BoltDB) is single-writer, so two
  // concurrent `trivy image` runs contend for the cache lock and all-but-one
  // fail with "unable to initialize fs cache: cache may be in use by another
  // process: timeout". So instead of firing every scan at once (e.g. "Scan all"),
  // we chain them: a scan stays 'queued' until the single worker reaches it, then
  // runs to completion before the next starts.
  private static queue: Promise<void> = Promise.resolve();

  /** Validate an image reference without starting a scan. */
  static isValidImageRef(ref: string): boolean {
    return typeof ref === 'string' && IMAGE_REF_RE.test(ref.trim());
  }

  /** Queue a scan; returns the scan id for tracking. Runs one-at-a-time. */
  static async scan(imageRef: string, userId: number): Promise<number> {
    const ref = imageRef.trim();
    if (!this.isValidImageRef(ref)) {
      throw new Error('Invalid image reference');
    }

    const scanId = await this.createScanRecord(ref, userId);

    await AuditService.log({
      userId,
      action: 'scan.container.create',
      resourceType: 'container_scan',
      resourceId: scanId,
      ipAddress: '127.0.0.1',
      userAgent: 'trivy-scanner',
      responseStatus: 202,
      details: { image_ref: ref },
    });

    // Append to the serial queue. Each scan waits for the previous Trivy process
    // to exit before starting, so the cache is never accessed concurrently.
    // Failures are recorded on the scan row and never break the chain.
    this.queue = this.queue.then(() =>
      this.executeScan(scanId, ref).catch(async (error: any) => {
        console.error(`[Trivy] Scan ${scanId} failed:`, error);
        await this.updateStatus(scanId, 'failed', error?.message || 'Scan failed');
      })
    );

    return scanId;
  }

  /**
   * Run one Trivy scan to completion. The returned promise resolves only when the
   * process has exited (success, failure, or timeout) — that's what lets the
   * queue run scans strictly one at a time.
   */
  private static async executeScan(scanId: number, ref: string): Promise<void> {
    await this.markRunning(scanId);

    const args = [
      'image',
      '--quiet',
      '--scanners', 'vuln',
      '--format', 'json',
      '--timeout', '10m',
      ref,
    ];
    console.log(`[Trivy] Scan ${scanId}: trivy ${args.join(' ')}`);

    await new Promise<void>((resolve) => {
      const proc = spawn('trivy', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      this.activeScans.set(scanId, proc);

      let stdout = '';
      let stderr = '';
      proc.stdout?.on('data', (d: Buffer) => (stdout += d.toString()));
      proc.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));

      // Hard timeout (12m) in case Trivy hangs pulling a huge image.
      const timeout = setTimeout(() => {
        if (this.activeScans.has(scanId)) {
          proc.kill('SIGTERM');
          this.activeScans.delete(scanId);
          void this.updateStatus(scanId, 'failed', 'Scan timed out after 12 minutes');
          resolve();
        }
      }, 12 * 60 * 1000);

      proc.on('error', (err: Error) => {
        clearTimeout(timeout);
        this.activeScans.delete(scanId);
        const msg = /ENOENT/.test(err.message)
          ? 'Trivy is not installed or not on PATH'
          : err.message;
        console.error(`[Trivy] Scan ${scanId} process error:`, err);
        void this.updateStatus(scanId, 'failed', msg);
        resolve();
      });

      proc.on('close', async (code: number | null) => {
        clearTimeout(timeout);
        this.activeScans.delete(scanId);
        try {
          if (code !== 0) {
            const msg = (stderr.trim() || `Trivy exited with code ${code}`).slice(0, 1000);
            console.error(`[Trivy] Scan ${scanId} failed (code ${code}): ${msg}`);
            ErrorLogService.logBackgroundError('container-scan', msg, { dedupeKey: String(scanId), scanId });
            await this.updateStatus(scanId, 'failed', msg);
          } else {
            await this.processResults(scanId, stdout);
          }
        } catch (e: any) {
          console.error(`[Trivy] Scan ${scanId} result processing failed:`, e);
          await this.updateStatus(scanId, 'failed', e?.message || 'Result processing failed');
        } finally {
          resolve();
        }
      });
    });
  }

  private static async processResults(scanId: number, stdout: string): Promise<void> {
    let report: TrivyReport;
    try {
      report = JSON.parse(stdout || '{}');
    } catch {
      throw new Error('Could not parse Trivy JSON output');
    }

    const severityCounts: Record<Severity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, unknown: 0,
    };
    const rows: any[][] = [];
    for (const result of report.Results || []) {
      for (const v of result.Vulnerabilities || []) {
        const sev = this.normalizeSeverity(v.Severity);
        severityCounts[sev]++;
        rows.push([
          scanId,
          (result.Target || '').slice(0, 512),
          (v.VulnerabilityID || 'UNKNOWN').slice(0, 255),
          (v.PkgName || '').slice(0, 255),
          (v.InstalledVersion || '').slice(0, 255),
          (v.FixedVersion || '').slice(0, 255),
          sev,
          v.Title || null,
          v.Description || null,
          v.PrimaryURL || null,
        ]);
      }
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Replace any prior findings for this scan (so a re-run is clean).
      await client.query('DELETE FROM container_vulnerabilities WHERE scan_id = $1', [scanId]);
      for (const r of rows) {
        await client.query(
          `INSERT INTO container_vulnerabilities
             (scan_id, target, vuln_id, pkg_name, installed_version, fixed_version,
              severity, title, description, primary_url)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          r
        );
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    await pool.query(
      `UPDATE container_scans
         SET status = 'completed', completed_at = NOW(),
             duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::integer,
             vulnerabilities_found = $2, severity_counts = $3, updated_at = NOW()
       WHERE id = $1`,
      [scanId, rows.length, JSON.stringify(severityCounts)]
    );
    console.log(`[Trivy] Scan ${scanId} stored ${rows.length} vulnerabilities`, severityCounts);
  }

  private static normalizeSeverity(s?: string): Severity {
    const v = (s || '').toLowerCase() as Severity;
    return SEVERITIES.includes(v) ? v : 'unknown';
  }

  private static async createScanRecord(ref: string, userId: number): Promise<number> {
    const result = await pool.query(
      `INSERT INTO container_scans (image_ref, status, initiated_by, created_at)
       VALUES ($1, 'queued', $2, NOW()) RETURNING id`,
      [ref, userId]
    );
    return result.rows[0].id;
  }

  private static async markRunning(scanId: number): Promise<void> {
    await pool.query(
      `UPDATE container_scans SET status = 'running', started_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [scanId]
    );
  }

  private static async updateStatus(scanId: number, status: string, errorMessage?: string): Promise<void> {
    await pool.query(
      `UPDATE container_scans
         SET status = $2, error_message = $3, completed_at = NOW(),
             duration_seconds = COALESCE(EXTRACT(EPOCH FROM (NOW() - started_at))::integer, duration_seconds),
             updated_at = NOW()
       WHERE id = $1`,
      [scanId, status, errorMessage || null]
    );
  }

  static async getRecentScans(limit = 20): Promise<any[]> {
    const result = await pool.query(
      `SELECT cs.*, u.username AS initiated_by_username
         FROM container_scans cs
         LEFT JOIN users u ON cs.initiated_by = u.id
        ORDER BY cs.created_at DESC LIMIT $1`,
      [limit]
    );
    return result.rows;
  }

  static async getScan(scanId: number): Promise<any | null> {
    const scan = await pool.query('SELECT * FROM container_scans WHERE id = $1', [scanId]);
    if (!scan.rows[0]) return null;
    const vulns = await pool.query(
      `SELECT * FROM container_vulnerabilities WHERE scan_id = $1
        ORDER BY CASE severity
          WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
          WHEN 'low' THEN 3 ELSE 4 END, pkg_name`,
      [scanId]
    );
    return { ...scan.rows[0], vulnerabilities: vulns.rows };
  }
}
