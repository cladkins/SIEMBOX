/**
 * The server side of the public-target guard (classifier: targetSafety.ts).
 *
 * Every route that creates a scan or a schedule (POST /api/assets/scan,
 * POST /api/vulnerabilities/scans, POST /api/log-discovery/scans,
 * POST/PUT /api/scheduled-scans) passes its targets through
 * checkPublicTargets(). A target in public address space is refused with a 400
 * naming it (and a "did you mean" hint for a likely typo) unless the request
 * carries allow_public_targets: true. A confirmed request is let through, and
 * the confirmation (who, when, which targets) is stored with the scan's
 * scan_options and written to audit_logs as scan.public_targets.confirmed.
 */
import type { Request, Response } from 'express';
import { AuditService } from '../audit/auditService';
import { auditSource } from '../../middleware/scanPermissions';
import { describePublicTarget, findPublicTargets, type PublicTargetReport } from './targetSafety';

/** `code` of the 400 a refused request gets. */
export const PUBLIC_TARGETS_REFUSED = 'PUBLIC_TARGETS_UNCONFIRMED';

/** Stored as scan_options.publicTargetsConfirmation on a confirmed scan or schedule. */
export interface PublicTargetConfirmation {
  confirmedBy: number | null;
  confirmedByUsername: string | null;
  confirmedAt: string;
  publicTargets: string[];
}

export type PublicTargetCheck =
  | { ok: true; report: PublicTargetReport; confirmation: PublicTargetConfirmation | null }
  | { ok: false; report: PublicTargetReport; body: Record<string, unknown> };

/** Whether the request confirms public targets. Only a literal `true` counts. */
export function publicTargetsConfirmed(body: unknown): boolean {
  const b = body as { allow_public_targets?: unknown; allowPublicTargets?: unknown } | null | undefined;
  return b?.allow_public_targets === true || b?.allowPublicTargets === true;
}

export function publicTargetsMessage(report: PublicTargetReport): string {
  const listed = report.publicTargets.map(describePublicTarget).join(', ');
  return (
    `Refusing to scan public address space: ${listed}. ` +
    'These targets are outside private and reserved ranges (RFC 1918, 100.64.0.0/10, loopback, link-local, fc00::/7), ' +
    'so they are someone else\'s network unless you own them. ' +
    'If you are authorized to scan them, resend the request with allow_public_targets: true.'
  );
}

/**
 * Check `targets` against the public-target policy for this request. With no
 * public targets: ok, no confirmation. With public targets and
 * allow_public_targets: true: ok, with the confirmation to store. Otherwise:
 * not ok, with the 400 body to send.
 */
export function checkPublicTargets(targets: readonly string[], req: Request): PublicTargetCheck {
  const report = findPublicTargets(targets);
  if (report.publicTargets.length === 0) return { ok: true, report, confirmation: null };
  if (publicTargetsConfirmed(req.body)) {
    return {
      ok: true,
      report,
      confirmation: {
        confirmedBy: req.user?.id ?? null,
        confirmedByUsername: req.user?.username ?? null,
        confirmedAt: new Date().toISOString(),
        publicTargets: report.publicTargets.map((t) => t.target),
      },
    };
  }
  const message = publicTargetsMessage(report);
  return {
    ok: false,
    report,
    body: {
      error: message,
      message,
      code: PUBLIC_TARGETS_REFUSED,
      public_targets: report.publicTargets.map((t) => ({
        target: t.target,
        ...(t.suggestion ? { suggestion: t.suggestion } : {}),
        ...(t.partlyPrivate ? { partly_private: true } : {}),
      })),
      hostnames: report.hostnames,
    },
  };
}

/**
 * Run the check and, when it refuses, send the 400. Returns the check when the
 * route may go on, or null when the response has been sent.
 */
export function enforcePublicTargets(
  targets: readonly string[],
  req: Request,
  res: Response
): Extract<PublicTargetCheck, { ok: true }> | null {
  const check = checkPublicTargets(targets, req);
  if (!check.ok) {
    res.status(400).json(check.body);
    return null;
  }
  return check;
}

/** Write the scan.public_targets.confirmed audit row for a confirmed scan or schedule. Never throws. */
export async function auditPublicTargetConfirmation(
  req: Request,
  confirmation: PublicTargetConfirmation | null,
  resource: { type: 'scan' | 'discovery_scan' | 'scheduled_scan'; id?: number; targets: readonly string[] }
): Promise<void> {
  if (!confirmation) return;
  try {
    const source = auditSource(req);
    await AuditService.log({
      userId: confirmation.confirmedBy,
      action: 'scan.public_targets.confirmed',
      resourceType: resource.type,
      ...(resource.id !== undefined ? { resourceId: resource.id } : {}),
      ipAddress: source.ipAddress,
      userAgent: req.headers['user-agent'] || 'unknown',
      responseStatus: 202,
      details: {
        publicTargets: confirmation.publicTargets,
        targets: resource.targets,
        path: req.originalUrl || req.path,
        ...(source.peerAddress ? { peerAddress: source.peerAddress } : {}),
      },
    });
  } catch {
    // AuditService.log reports its own failures; the scan itself must not fail over it.
  }
}
