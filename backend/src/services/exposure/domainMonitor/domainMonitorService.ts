/**
 * Domain monitoring (Digital Risk, part 2): for each watched domain that is
 * due, run the collectors its scope and settings call for, record what changed
 * since each collector's baseline as exposure findings, and store the new
 * baselines.
 *
 * Collectors per scope
 *  - own:   dns, rdap, lookalike, ct (the domain's own certificates, plus
 *           certificates for its registered lookalikes)
 *  - brand: lookalike, ct (registered lookalikes only). A brand name is a
 *           name to protect, not necessarily one the organization operates: its
 *           DNS, registration and certificates are not ours to police, but
 *           lookalikes of it — and certificates for those — are the threat.
 * Each is also switched by the domain's `collectors` JSON.
 *
 * Guarantees
 *  - Isolation: a collector that throws is recorded as an error for that
 *    collector only; the others still run, and one domain's failure never stops
 *    the cycle. A failed collector's baseline is untouched.
 *  - No alert floods: a collector's first run records its baseline silently
 *    (except expiry warnings and unexpected-CA certificates, which are
 *    actionable whatever the history — see rdap.ts / ct.ts), and every
 *    finding has a stable fingerprint, so re-runs never re-alert.
 *  - Findings are recorded BEFORE the baseline is saved: if a run dies in
 *    between, the next run re-detects the same changes and the fingerprints
 *    dedupe them — nothing is lost, nothing doubles.
 *  - Scheduling follows scheduledScans: a domain is due when next_run_at has
 *    passed; afterwards next_run_at = now + interval_minutes. Transient
 *    collector failures (crt.sh 502s, timeouts — and unexpected errors such as
 *    a database blip) bring the domain back sooner — 60 min, doubling per
 *    consecutive failure, never later than its interval — and that early run
 *    only repeats the collectors that failed. Permanent ones (an unsupported
 *    response, too many certificates) wait for the next regular run.
 *  - One notification per domain run (grouped), through notifyExposure's
 *    opt-in and minimum-severity gates.
 */
import { logger } from '../../../utils/logger';
import { ErrorLogService } from '../../errors/errorLogService';
import {
  DEFAULT_COLLECTORS,
  DomainBaselineModel,
  WatchedDomainModel,
  type DomainBaseline,
  type DomainCollectors,
  type DomainRunRecord,
  type DomainScope,
  type WatchedDomain,
} from '../../../models/Exposure';
import {
  recordFinding,
  toExposureNotice,
  type FindingInput,
  type RecordFindingResult,
} from '../findingWriter';
import { NotificationService, type ExposureNotice } from '../../notifications/notificationService';
import { getExposureSetting, getExposureSettings } from '../settings';
import { createCtCollector } from './ct';
import { createDnsCollector } from './dns';
import { createLookalikeCollector } from './lookalike';
import { createRdapCollector } from './rdap';
import {
  COLLECTOR_ORDER,
  CollectorError,
  capList,
  errorMessage,
  isPlainObject,
  type Collector,
  type CollectorContext,
  type CollectorName,
  type CollectorOutput,
  type DomainMonitorConfig,
} from './types';

/** Job-registry key of the scheduled run (jobs/domainMonitor.ts). */
export const DOMAIN_MONITOR_JOB_KEY = 'domain-monitor';
export const DOMAIN_MONITOR_ALREADY_RUNNING = 'a domain-monitor cycle is already running';
export const DOMAIN_MONITOR_DISABLED = 'domain monitoring is disabled in settings';

export const SCOPE_COLLECTORS: Record<DomainScope, readonly CollectorName[]> = {
  own: ['dns', 'rdap', 'lookalike', 'ct'],
  brand: ['lookalike', 'ct'],
};

const SCHEDULED_BUDGET_MS = 10 * 60 * 1000;
const MAX_DOMAINS_PER_CYCLE = 25;
const RETRY_BASE_MINUTES = 60;
/** Registered lookalikes whose certificates are fetched per run (each costs two crt.sh queries). */
const LOOKALIKE_CT_CHECKS: Record<'schedule' | 'manual', number> = { schedule: 3, manual: 2 };
const RETRY_SLACK_MS = 60_000;

// ---- Summaries ---------------------------------------------------------------------------------

export type CollectorRunStatus =
  | 'ok'
  | 'baseline'
  | 'unsupported'
  | 'error'
  | 'disabled'
  | 'not_applicable';

export interface CollectorRunSummary {
  status: CollectorRunStatus;
  note?: string;
  error?: string;
  /** For errors: retried before the domain's next regular run. */
  transient?: boolean;
  new_findings?: number;
  warnings?: string[];
  details?: Record<string, unknown>;
  /** When this collector last ran (an entry carried over from an earlier run keeps its time). */
  at?: string;
}

export interface DomainRunSummary {
  domain_id: number;
  domain: string;
  scope: DomainScope;
  trigger: 'schedule' | 'manual';
  started_at: string;
  duration_ms: number;
  status: 'ok' | 'error';
  new_findings: number;
  /** Collectors that failed transiently and will be retried early. */
  retry: CollectorName[];
  retry_attempt: number;
  next_run_in_minutes: number;
  collectors: Partial<Record<CollectorName, CollectorRunSummary>>;
}

export interface DomainMonitorRunSummary {
  /** Domains whose run completed (possibly with collector errors). */
  checked: number;
  newFindings: number;
  /** Domains with at least one failed collector, or whose run could not complete. */
  failed: number;
  /** Domains still due after this cycle. */
  remaining: number;
  skipped: boolean;
  reason?: string;
}

// ---- Persistence (swappable for tests) ----------------------------------------------------------

export interface DomainMonitorStore {
  isEnabled(): Promise<boolean>;
  getConfig(trigger: 'schedule' | 'manual'): Promise<DomainMonitorConfig>;
  findDue(limit: number): Promise<WatchedDomain[]>;
  countDue(): Promise<number>;
  findById(id: number): Promise<WatchedDomain | null>;
  /** Every watched domain name (the organization's own names). */
  listDomainNames(): Promise<string[]>;
  getBaselines(domainId: number): Promise<Map<string, DomainBaseline>>;
  saveBaseline(domainId: number, collector: CollectorName, snapshot: unknown): Promise<void>;
  recordFinding(input: FindingInput): Promise<RecordFindingResult>;
  notify(notices: ExposureNotice[]): Promise<void>;
  markRun(domainId: number, run: DomainRunRecord): Promise<void>;
}

const dbStore: DomainMonitorStore = {
  isEnabled: async () => (await getExposureSetting('exposure_domain_monitor_enabled')) === 'true',
  getConfig: async (trigger) => {
    const settings = await getExposureSettings();
    return {
      expiryWarningDays: settings.exposure_domain_expiry_warning_days,
      lookalikeMaxCandidates: settings.exposure_lookalike_max_candidates,
      secondaryResolver: settings.exposure_dns_secondary_resolver || null,
      lookalikeCtChecksPerRun: LOOKALIKE_CT_CHECKS[trigger],
    };
  },
  findDue: (limit) => WatchedDomainModel.findDue(limit),
  countDue: () => WatchedDomainModel.countDue(),
  findById: (id) => WatchedDomainModel.findById(id),
  listDomainNames: () => WatchedDomainModel.listNames(),
  getBaselines: (domainId) => DomainBaselineModel.findByDomain(domainId),
  saveBaseline: (domainId, collector, snapshot) =>
    DomainBaselineModel.upsert(domainId, collector, snapshot),
  // One grouped notification per domain run instead of one per finding.
  recordFinding: (input) => recordFinding(input, { notify: false }),
  notify: (notices) => NotificationService.notifyExposure(notices),
  markRun: (domainId, run) => WatchedDomainModel.markRun(domainId, run),
};

let defaultCollectors: Record<CollectorName, Collector> | null = null;
function collectorsFor(overrides?: Partial<Record<CollectorName, Collector>>) {
  defaultCollectors ??= {
    dns: createDnsCollector(),
    rdap: createRdapCollector(),
    lookalike: createLookalikeCollector(),
    ct: createCtCollector(),
  };
  return { ...defaultCollectors, ...overrides };
}

export interface DomainRunOptions {
  store?: DomainMonitorStore;
  collectors?: Partial<Record<CollectorName, Collector>>;
  now?: () => number;
}

export interface CycleOptions extends DomainRunOptions {
  budgetMs?: number;
  maxDomains?: number;
}

// ---- One domain ----------------------------------------------------------------------------------

function enabledCollectors(value: unknown): DomainCollectors {
  const out: DomainCollectors = { ...DEFAULT_COLLECTORS };
  if (isPlainObject(value)) {
    for (const name of COLLECTOR_ORDER) {
      if (typeof value[name] === 'boolean') out[name] = value[name] as boolean;
    }
  }
  return out;
}

function previousSummary(domain: WatchedDomain): DomainRunSummary | null {
  const s = domain.last_summary;
  return isPlainObject(s) && isPlainObject(s.collectors)
    ? (s as unknown as DomainRunSummary)
    : null;
}

/** Due before its regular time = an early retry of the collectors that failed transiently. */
function isRetryRun(domain: WatchedDomain, nowMs: number): boolean {
  if (!domain.last_checked_at) return false;
  // node-postgres hands TIMESTAMPTZ back as a Date; the API types it as a string.
  const lastChecked = new Date(domain.last_checked_at).getTime();
  const regular = lastChecked + domain.interval_minutes * 60_000;
  return Number.isFinite(regular) && nowMs < regular - RETRY_SLACK_MS;
}

export function retryDelayMinutes(intervalMinutes: number, attempt: number): number {
  return Math.min(intervalMinutes, RETRY_BASE_MINUTES * 2 ** Math.min(Math.max(attempt - 1, 0), 6));
}

interface CheckDeps {
  store: DomainMonitorStore;
  collectors: Record<CollectorName, Collector>;
  config: DomainMonitorConfig;
  trigger: 'schedule' | 'manual';
  now: () => number;
  watchedDomains: readonly string[];
}

async function checkDomain(domain: WatchedDomain, deps: CheckDeps): Promise<DomainRunSummary> {
  const startedMs = deps.now();
  const now = new Date(startedMs);
  const stored = await deps.store.getBaselines(domain.id);
  const baselines: Partial<Record<CollectorName, unknown>> = {};
  for (const name of COLLECTOR_ORDER) {
    const row = stored.get(name);
    if (row) baselines[name] = row.snapshot;
  }
  const before = previousSummary(domain);
  const retryOnly =
    deps.trigger === 'schedule' && isRetryRun(domain, startedMs)
      ? new Set(before?.retry ?? [])
      : null;
  const switches = enabledCollectors(domain.collectors);
  const applicable = SCOPE_COLLECTORS[domain.scope] ?? [];

  const summary: DomainRunSummary = {
    domain_id: domain.id,
    domain: domain.domain,
    scope: domain.scope,
    trigger: deps.trigger,
    started_at: now.toISOString(),
    duration_ms: 0,
    status: 'ok',
    new_findings: 0,
    retry: [],
    retry_attempt: 0,
    next_run_in_minutes: domain.interval_minutes,
    collectors: {},
  };
  const earlier: Partial<Record<CollectorName, CollectorOutput>> = {};
  const notices: ExposureNotice[] = [];

  for (const name of COLLECTOR_ORDER) {
    if (!switches[name]) {
      summary.collectors[name] = { status: 'disabled' };
      continue;
    }
    if (!applicable.includes(name)) {
      summary.collectors[name] = {
        status: 'not_applicable',
        note: `not run for ${domain.scope} domains`,
      };
      continue;
    }
    if (retryOnly && !retryOnly.has(name) && baselines[name] !== undefined) {
      // Succeeded within its interval: carry the last outcome forward.
      summary.collectors[name] = before?.collectors[name] ?? { status: 'ok', note: 'not due' };
      continue;
    }
    const ctx: CollectorContext = {
      domain,
      previous: baselines[name] ?? null,
      config: deps.config,
      now,
      trigger: deps.trigger,
      earlier,
      baselines,
      watchedDomains: deps.watchedDomains,
    };
    try {
      const output = await deps.collectors[name](ctx);
      let fresh = 0;
      for (const finding of output.findings) {
        const result = await deps.store.recordFinding(finding);
        if (result.isNew) fresh++;
        if (result.alertCreated) notices.push(toExposureNotice(finding));
      }
      if (output.snapshot !== undefined) {
        await deps.store.saveBaseline(domain.id, name, output.snapshot);
      }
      earlier[name] = output;
      summary.new_findings += fresh;
      summary.collectors[name] = {
        status: output.status,
        note: output.note,
        new_findings: fresh,
        at: now.toISOString(),
        ...(output.warnings?.length ? { warnings: capList(output.warnings, 10) } : {}),
        ...(output.details ? { details: output.details } : {}),
      };
    } catch (err) {
      // Anything but a collector's own verdict (a database blip, a bug) is retried
      // early too, with the same backoff, so a hiccup doesn't cost a whole interval.
      const transient = err instanceof CollectorError ? err.transient : true;
      const message = errorMessage(err).slice(0, 300);
      summary.collectors[name] = {
        status: 'error',
        error: message,
        transient,
        at: now.toISOString(),
      };
      if (transient) summary.retry.push(name);
      logger.warn(
        `[DomainMonitor] ${name} failed for ${domain.domain} (#${domain.id}): ${message}`
      );
      if (!(err instanceof CollectorError)) {
        // Not an upstream hiccup but a bug or a database failure: surface it on the dashboard.
        ErrorLogService.logBackgroundError('domain-monitor', err, {
          dedupeKey: `collector-${name}`,
          domainId: domain.id,
          collector: name,
        });
      }
    }
  }

  if (notices.length > 0) await deps.store.notify(notices);

  const errors = COLLECTOR_ORDER.flatMap((name) => {
    const entry = summary.collectors[name];
    return entry?.status === 'error' ? [`${name}: ${entry.error ?? 'failed'}`] : [];
  });
  summary.status = errors.length ? 'error' : 'ok';
  summary.retry_attempt = summary.retry.length ? (before?.retry_attempt ?? 0) + 1 : 0;
  summary.next_run_in_minutes = summary.retry.length
    ? retryDelayMinutes(domain.interval_minutes, summary.retry_attempt)
    : domain.interval_minutes;
  summary.duration_ms = deps.now() - startedMs;

  await deps.store.markRun(domain.id, {
    status: summary.status,
    error: errors.length ? errors.join('; ') : null,
    nextRunMinutes: summary.next_run_in_minutes,
    summary: summary as unknown as Record<string, unknown>,
  });
  return summary;
}

// ---- Runs --------------------------------------------------------------------------------------------

// In-process state, like the job registry: it describes this process's runs.
let cycleInFlight: Promise<DomainMonitorRunSummary> | null = null;
const domainsInFlight = new Set<number>();
let lastRun: { at: string; trigger: string; summary: DomainMonitorRunSummary } | null = null;

export function getDomainMonitorRunState(): {
  running: boolean;
  domains_in_progress: number;
  last_run: { at: string; trigger: string; summary: DomainMonitorRunSummary } | null;
} {
  return {
    running: cycleInFlight !== null || domainsInFlight.size > 0,
    domains_in_progress: domainsInFlight.size,
    last_run: lastRun,
  };
}

const skippedCycle = (reason: string): DomainMonitorRunSummary => ({
  checked: 0,
  newFindings: 0,
  failed: 0,
  remaining: 0,
  skipped: true,
  reason,
});

/** Why a scheduled cycle would do nothing right now, or null when there is work. */
export async function getDomainMonitorSkipReason(
  options: Pick<DomainRunOptions, 'store'> = {}
): Promise<string | null> {
  const store = options.store ?? dbStore;
  if (!(await store.isEnabled())) return DOMAIN_MONITOR_DISABLED;
  if ((await store.countDue()) === 0) return 'no watched domains are due';
  return null;
}

/** One-line outcome for the job registry and logs. */
export function describeDomainMonitorRun(s: DomainMonitorRunSummary): string {
  if (s.skipped) return `skipped: ${s.reason}`;
  const parts = [
    `checked ${s.checked} domain${s.checked === 1 ? '' : 's'}`,
    `${s.newFindings} new finding${s.newFindings === 1 ? '' : 's'}`,
  ];
  if (s.failed) parts.push(`${s.failed} with errors`);
  if (s.remaining) parts.push(`${s.remaining} still due`);
  return parts.join(', ');
}

/**
 * Check every due domain once (sequentially, within a time budget; the rest
 * stay due). Overlapping calls return a skipped summary straight away.
 */
export function runDomainChecks(options: CycleOptions = {}): Promise<DomainMonitorRunSummary> {
  if (cycleInFlight) return Promise.resolve(skippedCycle(DOMAIN_MONITOR_ALREADY_RUNNING));
  const run = executeCycle(options).finally(() => {
    cycleInFlight = null;
  });
  cycleInFlight = run;
  return run;
}

async function executeCycle(options: CycleOptions): Promise<DomainMonitorRunSummary> {
  const store = options.store ?? dbStore;
  const now = options.now ?? Date.now;
  const reason = await getDomainMonitorSkipReason({ store });
  if (reason) return skippedCycle(reason);

  const config = await store.getConfig('schedule');
  const watchedDomains = await store.listDomainNames();
  const collectors = collectorsFor(options.collectors);
  const due = await store.findDue(options.maxDomains ?? MAX_DOMAINS_PER_CYCLE);
  const budgetMs = options.budgetMs ?? SCHEDULED_BUDGET_MS;
  const startedAt = now();
  const summary: DomainMonitorRunSummary = {
    checked: 0,
    newFindings: 0,
    failed: 0,
    remaining: 0,
    skipped: false,
  };

  for (const domain of due) {
    if (now() - startedAt >= budgetMs) break; // the rest stay due
    if (domainsInFlight.has(domain.id)) continue; // an admin's run-now is on it
    domainsInFlight.add(domain.id);
    try {
      const result = await checkDomain(domain, {
        store,
        collectors,
        config,
        trigger: 'schedule',
        now,
        watchedDomains,
      });
      summary.checked++;
      summary.newFindings += result.new_findings;
      if (result.status === 'error') summary.failed++;
    } catch (err) {
      // The bookkeeping itself failed (e.g. the database): the domain stays due.
      summary.failed++;
      logger.error(`[DomainMonitor] run for ${domain.domain} (#${domain.id}) failed:`, err);
      ErrorLogService.logBackgroundError('domain-monitor', err, {
        dedupeKey: `domain-${domain.id}`,
        domainId: domain.id,
      });
    } finally {
      domainsInFlight.delete(domain.id);
    }
  }

  summary.remaining = await store.countDue();
  lastRun = { at: new Date(now()).toISOString(), trigger: 'schedule', summary };
  return summary;
}

export type DomainRunNowResult =
  | { kind: 'ok'; summary: DomainRunSummary }
  | { kind: 'not_found' }
  | { kind: 'disabled'; reason: string }
  | { kind: 'busy' };

/**
 * Run every applicable collector for one domain now (an admin's "run now"),
 * whatever its schedule — also for a domain that is switched off.
 */
export async function runDomainNow(
  domainId: number,
  options: DomainRunOptions = {}
): Promise<DomainRunNowResult> {
  const store = options.store ?? dbStore;
  const now = options.now ?? Date.now;
  const domain = await store.findById(domainId);
  if (!domain) return { kind: 'not_found' };
  if (!(await store.isEnabled())) return { kind: 'disabled', reason: DOMAIN_MONITOR_DISABLED };
  if (domainsInFlight.has(domainId)) return { kind: 'busy' };
  domainsInFlight.add(domainId);
  try {
    const config = await store.getConfig('manual');
    const summary = await checkDomain(domain, {
      store,
      collectors: collectorsFor(options.collectors),
      config,
      trigger: 'manual',
      now,
      watchedDomains: await store.listDomainNames(),
    });
    return { kind: 'ok', summary };
  } finally {
    domainsInFlight.delete(domainId);
  }
}
