/**
 * Agentic SOC triage persistence — one LLM-produced verdict per alert
 * (alert_triage.alert_id is the PK; a re-run overwrites the previous verdict).
 *
 * `claim()` is the concurrency-safety boundary: its conditional UPSERT only
 * succeeds when no run is currently in flight, so the hot-path trigger, the
 * reconciler, and a manual re-run can never double-triage the same alert.
 */
import { query } from '../config/database';

export type TriageStatus = 'pending' | 'analyzing' | 'complete' | 'failed' | 'skipped';
export type TriageVerdictLabel = 'true_positive' | 'false_positive' | 'suspicious' | 'inconclusive';
export type TriageConfidence = 'low' | 'medium' | 'high';
export type TriageTriggeredBy = 'auto' | 'manual' | 'reconciler';

export interface AlertTriageRow {
  alert_id: number;
  status: TriageStatus;
  verdict: TriageVerdictLabel | null;
  risk_score: number | null;
  confidence: TriageConfidence | null;
  summary: string | null;
  reasoning: string | null;
  evidence: any[] | null;
  suggested_queries: any[] | null;
  remediation: Record<string, any> | null;
  trace: any[] | null;
  provider: string | null;
  model: string | null;
  iterations: number | null;
  tool_calls: number | null;
  duration_ms: number | null;
  truncated: boolean;
  degraded: boolean;
  error: string | null;
  attempts: number;
  triggered_by: TriageTriggeredBy;
  requested_by: number | null;
  started_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TriageResultInput {
  verdict: TriageVerdictLabel;
  risk_score: number;
  confidence: TriageConfidence;
  summary: string;
  reasoning: string;
  evidence: any[];
  suggested_queries: any[];
  remediation: Record<string, any>;
}

export interface TriageResultMeta {
  provider?: string;
  model?: string;
  iterations?: number;
  toolCalls?: number;
  durationMs?: number;
  truncated?: boolean;
  degraded?: boolean;
  trace?: any[];
}

/** Counts of completed triage verdicts bucketed by risk_score band (see getRiskRatingSummary). */
export interface TriageRiskRatingSummary {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

function clipError(msg: unknown): string {
  return String(msg ?? 'unknown error').slice(0, 500);
}

export class AlertTriageModel {
  /**
   * Start (or restart) a triage run for an alert. Returns the claimed row, or
   * null if a run is already in flight (pending/analyzing) and `force` wasn't
   * set — that's the single-flight guarantee.
   */
  static async claim(
    alertId: number,
    triggeredBy: TriageTriggeredBy,
    requestedBy?: number | null,
    force = false
  ): Promise<AlertTriageRow | null> {
    const guard = force ? '' : `WHERE alert_triage.status NOT IN ('pending','analyzing')`;
    const r = await query(
      `INSERT INTO alert_triage (alert_id, status, triggered_by, requested_by, error, degraded, updated_at)
       VALUES ($1, 'pending', $2, $3, NULL, FALSE, NOW())
       ON CONFLICT (alert_id) DO UPDATE
         SET status = 'pending', triggered_by = EXCLUDED.triggered_by,
             requested_by = EXCLUDED.requested_by, error = NULL, degraded = FALSE,
             updated_at = NOW()
       ${guard}
       RETURNING *`,
      [alertId, triggeredBy, requestedBy ?? null]
    );
    return r.rows[0] || null;
  }

  static async markAnalyzing(alertId: number): Promise<AlertTriageRow | null> {
    const r = await query(
      `UPDATE alert_triage
          SET status = 'analyzing', attempts = attempts + 1, started_at = NOW(), updated_at = NOW()
        WHERE alert_id = $1 AND status = 'pending'
        RETURNING *`,
      [alertId]
    );
    return r.rows[0] || null;
  }

  static async saveResult(
    alertId: number,
    verdict: TriageResultInput,
    meta: TriageResultMeta = {}
  ): Promise<AlertTriageRow | null> {
    const r = await query(
      `UPDATE alert_triage
          SET status = 'complete',
              verdict = $2, risk_score = $3, confidence = $4, summary = $5, reasoning = $6,
              evidence = $7, suggested_queries = $8, remediation = $9, trace = $10,
              provider = $11, model = $12, iterations = $13, tool_calls = $14, duration_ms = $15,
              truncated = $16, degraded = $17, error = NULL, updated_at = NOW()
        WHERE alert_id = $1
        RETURNING *`,
      [
        alertId,
        verdict.verdict,
        verdict.risk_score,
        verdict.confidence,
        verdict.summary,
        verdict.reasoning,
        JSON.stringify(verdict.evidence ?? []),
        JSON.stringify(verdict.suggested_queries ?? []),
        JSON.stringify(verdict.remediation ?? {}),
        JSON.stringify(meta.trace ?? []),
        meta.provider ?? null,
        meta.model ?? null,
        meta.iterations ?? null,
        meta.toolCalls ?? null,
        meta.durationMs ?? null,
        meta.truncated ?? false,
        meta.degraded ?? false,
      ]
    );
    return r.rows[0] || null;
  }

  static async markFailed(alertId: number, error: unknown): Promise<void> {
    await query(
      `UPDATE alert_triage SET status = 'failed', error = $2, updated_at = NOW() WHERE alert_id = $1`,
      [alertId, clipError(error)]
    );
  }

  static async markSkipped(alertId: number, reason: string): Promise<void> {
    // Upsert so "skipped before any row existed" (e.g. daily cap) also works.
    await query(
      `INSERT INTO alert_triage (alert_id, status, error, updated_at)
       VALUES ($1, 'skipped', $2, NOW())
       ON CONFLICT (alert_id) DO UPDATE SET status = 'skipped', error = $2, updated_at = NOW()
       WHERE alert_triage.status NOT IN ('pending','analyzing')`,
      [alertId, clipError(reason)]
    );
  }

  static async findByAlertId(alertId: number): Promise<AlertTriageRow | null> {
    const r = await query(`SELECT * FROM alert_triage WHERE alert_id = $1`, [alertId]);
    return r.rows[0] || null;
  }

  /**
   * Rows stuck mid-run. `includeAllAnalyzing` treats every pending/analyzing
   * row as orphaned regardless of age — used only on the reconciler's first
   * tick after boot, when the in-memory queue is empty and any such row is
   * therefore definitionally dead (left over from before the restart).
   */
  static async findStuck(
    staleMinutes: number,
    limit: number,
    includeAllAnalyzing = false
  ): Promise<Array<{ alert_id: number; attempts: number; status: TriageStatus }>> {
    const r = await query(
      `SELECT alert_id, attempts, status FROM alert_triage
        WHERE status IN ('pending','analyzing')
          AND ($1 OR updated_at < NOW() - ($2 || ' minutes')::interval)
        ORDER BY updated_at
        LIMIT $3`,
      [includeAllAnalyzing, staleMinutes, limit]
    );
    return r.rows;
  }

  /** Count non-skipped triage runs started in the last N hours (daily cap). */
  static async countSince(hours: number): Promise<number> {
    const r = await query(
      `SELECT COUNT(*)::int AS n FROM alert_triage
        WHERE created_at >= NOW() - ($1 || ' hours')::interval AND status <> 'skipped'`,
      [hours]
    );
    return r.rows[0]?.n ?? 0;
  }

  /**
   * A completed triage of an equivalent alert (same rule_id + title) within
   * the dedupe window, if any — used to skip re-analyzing routine repeats.
   */
  static async findRecentDuplicate(
    alertId: number,
    hours: number
  ): Promise<{ alert_id: number; verdict: TriageVerdictLabel; risk_score: number; created_at: string } | null> {
    const r = await query(
      `SELECT t.alert_id, t.verdict, t.risk_score, t.created_at
         FROM alert_triage t
         JOIN alerts a ON a.id = t.alert_id
         JOIN alerts b ON b.id = $1
        WHERE t.status = 'complete'
          AND a.id <> b.id
          AND a.rule_id IS NOT DISTINCT FROM b.rule_id
          AND a.title = b.title
          AND t.created_at >= NOW() - ($2 || ' hours')::interval
        ORDER BY t.created_at DESC
        LIMIT 1`,
      [alertId, hours]
    );
    return r.rows[0] || null;
  }

  /**
   * Distribution of completed triage verdicts across risk bands, for the
   * dashboard's risk-rating chart. Bands mirror this module's own
   * severity -> default risk_score convention (deterministicFallback in
   * triageAgent.ts: low=20, medium=45, high=70, critical=85), so a completed
   * verdict lands in the band matching its severity's default in the common
   * case. Only 'complete' rows are counted — risk_score is null otherwise.
   */
  static async getRiskRatingSummary(): Promise<TriageRiskRatingSummary> {
    const r = await query(
      `SELECT
         COUNT(*) FILTER (WHERE risk_score < 40)                     AS low,
         COUNT(*) FILTER (WHERE risk_score >= 40 AND risk_score < 60) AS medium,
         COUNT(*) FILTER (WHERE risk_score >= 60 AND risk_score < 80) AS high,
         COUNT(*) FILTER (WHERE risk_score >= 80)                     AS critical
       FROM alert_triage
       WHERE status = 'complete'`
    );
    const row = r.rows[0] || {};
    return {
      low: Number(row.low) || 0,
      medium: Number(row.medium) || 0,
      high: Number(row.high) || 0,
      critical: Number(row.critical) || 0,
    };
  }
}
