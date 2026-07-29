/**
 * Orchestration for agentic SOC triage — the hot-path gate + bounded,
 * concurrency-limited queue that the two alert-creation call sites
 * (rulesEngine.ts, edrService.ts) fire into, plus the actual claim -> analyze
 * -> persist run. This is the only module those call sites talk to, and it
 * never throws (both call it with `void`).
 *
 * Proposes, never acts: the agent's output (triageAgent.ts) is always inert
 * data persisted to alert_triage — applying it (e.g. a status change) still
 * requires an explicit human action through the existing alert-update route.
 */
import { AlertModel } from '../../models/Alert';
import { AlertTriageModel, TriageTriggeredBy } from '../../models/AlertTriage';
import { runAlertTriage, TriageAlertInput } from './triageAgent';
import { getTriageAiConfig, getTriageOperationalConfig, TriageOperationalConfig } from './aiService';
import { ErrorLogService } from '../errors/errorLogService';
import { logger } from '../../utils/logger';

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const MAX_QUEUE = 200;
const CONFIG_CACHE_TTL_MS = 30_000;

interface TriageOpts {
  triggeredBy: TriageTriggeredBy;
  requestedBy?: number;
  force?: boolean;
}
interface QueueItem {
  alertId: number;
  severity: string;
  opts: TriageOpts;
}

const hiQueue: QueueItem[] = [];
const loQueue: QueueItem[] = [];
let active = 0;
const inflight = new Set<number>();

let cachedConfig: TriageOperationalConfig | null = null;
let cachedAt = 0;

async function getCachedOperationalConfig(): Promise<TriageOperationalConfig> {
  const now = Date.now();
  if (!cachedConfig || now - cachedAt > CONFIG_CACHE_TTL_MS) {
    cachedConfig = await getTriageOperationalConfig();
    cachedAt = now;
  }
  return cachedConfig;
}

function toTriageInput(alert: any): TriageAlertInput {
  return {
    id: alert.id,
    severity: alert.severity,
    title: alert.title,
    description: alert.description,
    status: alert.status,
    source: alert.source ?? 'rule',
    asset_id: alert.asset_id ?? null,
    created_at: alert.created_at,
    matched_data: alert.matched_data,
  };
}

function schedule(alertId: number, severity: string, opts: TriageOpts): void {
  if (inflight.has(alertId)) return; // already queued/running in this process
  if (hiQueue.length + loQueue.length >= MAX_QUEUE) {
    void AlertTriageModel.markSkipped(alertId, 'triage queue full');
    return;
  }
  const item: QueueItem = { alertId, severity, opts };
  (SEVERITY_RANK[severity] >= SEVERITY_RANK.high ? hiQueue : loQueue).push(item);
  inflight.add(alertId);
  pump();
}

function pump(): void {
  void getCachedOperationalConfig().then((cfg) => {
    while (active < Math.max(1, cfg.maxConcurrent) && (hiQueue.length > 0 || loQueue.length > 0)) {
      const item = hiQueue.shift() ?? loQueue.shift();
      if (!item) break;
      active++;
      void runOne(item.alertId, item.opts).finally(() => {
        active--;
        inflight.delete(item.alertId);
        pump();
      });
    }
  });
}

/** Queue depth (both priority bands) — exposed for the admin jobs panel / tests. */
export function getTriageQueueDepth(): number {
  return hiQueue.length + loQueue.length;
}

async function runOne(alertId: number, opts: TriageOpts): Promise<void> {
  try {
    const cfg = await getTriageOperationalConfig();

    // Cost cap applies to every trigger, including manual re-run.
    const runToday = await AlertTriageModel.countSince(24);
    if (runToday >= cfg.dailyCap) {
      await AlertTriageModel.markSkipped(alertId, `daily triage cap reached (${cfg.dailyCap})`);
      return;
    }

    // Dedupe window only gates automatic triggers — a human or the reconciler
    // asking explicitly always gets a fresh analysis.
    if (opts.triggeredBy === 'auto' && cfg.dedupeHours > 0) {
      const dup = await AlertTriageModel.findRecentDuplicate(alertId, cfg.dedupeHours);
      if (dup) {
        await AlertTriageModel.markSkipped(
          alertId,
          `duplicate of alert #${dup.alert_id} (verdict: ${dup.verdict}, triaged ${dup.created_at})`
        );
        return;
      }
    }

    const claimed = await AlertTriageModel.claim(alertId, opts.triggeredBy, opts.requestedBy, opts.force);
    if (!claimed) return; // another run already in flight — single-flight guard

    const alert: any = await AlertModel.findById(alertId);
    if (!alert) return; // alert gone (deleted) between claim and read

    const analyzing = await AlertTriageModel.markAnalyzing(alertId);
    if (!analyzing) return;

    const t0 = Date.now();
    const providerCfg = await getTriageAiConfig();
    const res = await runAlertTriage(
      { alert: toTriageInput(alert) },
      { maxToolCalls: cfg.maxToolCalls, wallBudgetMs: cfg.wallBudgetSeconds * 1000 }
    );

    await AlertTriageModel.saveResult(alertId, res.verdict, {
      provider: providerCfg.provider,
      model: providerCfg.model,
      iterations: res.iterations,
      toolCalls: res.toolCalls,
      durationMs: Date.now() - t0,
      truncated: res.truncated,
      degraded: res.degraded,
      trace: res.trace,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn('[Triage] run failed', { alertId, error: msg });
    await AlertTriageModel.markFailed(alertId, msg).catch(() => {});
    // Deduped on the error message, so a persistent misconfiguration (e.g. no
    // API key) produces one dashboard entry, not one per alert.
    ErrorLogService.logBackgroundError('ai-triage', err, { dedupeKey: msg, alertId });
  }
}

/**
 * Hot-path entry point. Fire-and-forget, mirrors the existing
 * `void NotificationService.notifyAlert(...)` pattern at both alert-creation
 * call sites — never awaited, never throws, adds ~zero cost when disabled.
 */
export function maybeTriageAlert(alert: { id: number; severity: string; source?: string }): void {
  void (async () => {
    try {
      const cfg = await getCachedOperationalConfig();
      if (!cfg.enabled) return;
      const rank = SEVERITY_RANK[alert.severity] ?? 0;
      const minRank = SEVERITY_RANK[cfg.minSeverity] ?? 1;
      if (rank < minRank) return;
      schedule(alert.id, alert.severity, { triggeredBy: 'auto' });
    } catch (err) {
      // A gating failure must never affect alert creation.
      logger.debug('[Triage] gate check failed', { error: err instanceof Error ? err.message : String(err) });
    }
  })();
}

/**
 * Explicit re-run (manual, from the rerun route, or reconciler requeueing an
 * orphaned run). Still goes through the concurrency-limited queue and the
 * daily cap; bypasses only the severity gate and the dedupe-window skip.
 */
export async function triageAlert(alertId: number, opts: TriageOpts): Promise<void> {
  const alert: any = await AlertModel.findById(alertId);
  schedule(alertId, alert?.severity ?? 'medium', opts);
}
