/**
 * Exposure monitoring ("Digital Risk") persistence: watched domains, monitored
 * identities and the findings raised against them (migration 034), and the
 * domain collectors' baselines (migration 035).
 *
 * Values are validated and lowercased before they get here (see
 * services/exposure/validation.ts); the tables' CHECK constraints are the
 * backstop. Findings are written only through services/exposure/findingWriter.ts,
 * which owns dedupe, alerting and the privacy scrub of `detail`.
 */
import type { PoolClient } from 'pg';
import { getClient, query } from '../config/database';
import type { DomainEventType } from '../services/exposure/domainMonitor/types';
import {
  BUCKET_FOR_DAYS,
  WINDOW_BACK,
  buildAccounts,
  buildLookalikeInventory,
  foldBreakdown,
  foldTrend,
  type AccountRow,
  type BreakdownRow,
  type ExposureSummary,
  type LookalikeDomainInput,
  type LookalikeFindingRow,
  type RiskCategory,
  type SummaryDays,
  type TrendRow,
} from '../services/exposure/summary';

export type DomainScope = 'own' | 'brand';
export type IdentityKind = 'email' | 'email_domain';
export type ExposureSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ExposureFindingSource = 'leaked-creds' | 'domain-monitor';

export const DEFAULT_COLLECTORS = { ct: true, lookalike: true, rdap: true, dns: true } as const;

/**
 * Every event type a finding is written with: 'breach' (leaked credentials)
 * and the domain collectors' DomainEventType. Checked both ways at compile
 * time, so a new collector event type can't be missing from the filters.
 */
export const EXPOSURE_EVENT_TYPES = [
  'breach',
  'new_cert',
  'unexpected_ca',
  'lookalike_registered',
  'rdap_change',
  'dns_drift',
  'expiry_warning',
] as const satisfies readonly ('breach' | DomainEventType)[];
export type ExposureEventType = (typeof EXPOSURE_EVENT_TYPES)[number];
const EVENT_TYPES_LISTED: [Exclude<'breach' | DomainEventType, ExposureEventType>] extends [never]
  ? true
  : never = true;
void EVENT_TYPES_LISTED;

/**
 * Data classes that hand an attacker a way into the account. Hashed passwords
 * count too: leaked hashes get cracked offline. Compared trimmed and
 * lowercased. One list for breach severity (leakedCredentialService) and the
 * "accounts to reset" count (credExposedSql).
 */
export const CREDENTIAL_DATA_CLASSES: ReadonlySet<string> = new Set([
  'passwords',
  'historical passwords',
  'auth tokens',
]);

/**
 * A finding's risk category (alias f; RISK_CATEGORIES in summary.ts): a leaked
 * account, a lookalike of a watched domain (its registration, or a certificate
 * issued for it, which names it in detail.lookalike), or a change to the
 * watched domain itself. Derived from stored data, never stored.
 */
export const CATEGORY_SQL = `(CASE
    WHEN f.event_type = 'breach' THEN 'credentials'
    WHEN f.event_type = 'lookalike_registered' THEN 'impersonation'
    WHEN f.event_type IN ('new_cert', 'unexpected_ca') AND jsonb_typeof(f.detail->'lookalike') = 'string'
      THEN 'impersonation'
    ELSE 'domain_changes' END)`;

/** Severity as a number, most severe highest (alias f). */
export const SEV_RANK_SQL = `(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END)`;

/**
 * A breach finding that exposed credential material or came from a stealer
 * log (alias f). `param` is a text[] parameter holding CREDENTIAL_DATA_CLASSES,
 * matched trimmed and lowercased as exposesCredentials does.
 */
export function credExposedSql(param: string): string {
  return `(COALESCE(f.detail->'is_stealer_log' = 'true'::jsonb, false)
    OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
                 CASE WHEN jsonb_typeof(f.detail->'data_classes') = 'array'
                      THEN f.detail->'data_classes' ELSE '[]'::jsonb END) AS dc
               WHERE lower(btrim(dc)) = ANY(${param}::text[])))`;
}
export type DomainCollectors = Record<keyof typeof DEFAULT_COLLECTORS, boolean>;

export interface WatchedDomain {
  id: number;
  domain: string;
  scope: DomainScope;
  enabled: boolean;
  interval_minutes: number;
  collectors: DomainCollectors;
  expected_cas: string[];
  last_checked_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  /** Per-collector outcome of the last run (migration 035); null before the first. */
  last_summary: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

/** Bookkeeping written after each domain-monitor run. */
export interface DomainRunRecord {
  status: 'ok' | 'error';
  error: string | null;
  /** Minutes until the domain is due again (its interval, or a shorter retry delay). */
  nextRunMinutes: number;
  summary: Record<string, unknown>;
}

export interface DomainBaseline {
  snapshot: unknown;
  updated_at: string;
}

export interface WatchedDomainInput {
  domain: string;
  scope: DomainScope;
  enabled?: boolean;
  interval_minutes?: number;
  collectors?: DomainCollectors;
  expected_cas?: string[];
}

export interface MonitoredIdentity {
  id: number;
  kind: IdentityKind;
  value: string;
  enabled: boolean;
  interval_minutes: number;
  last_checked_at: string | null;
  /**
   * 'ok', 'error', or 'unverified' (an email domain skipped because it isn't
   * verified on the HIBP account, or refused with a 403 while that was
   * unknown: not a failure); null before the first check.
   */
  last_status: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface MonitoredIdentityInput {
  kind: IdentityKind;
  value: string;
  enabled?: boolean;
  interval_minutes?: number;
}

export interface ExposureFinding {
  id: number;
  source: ExposureFindingSource;
  identity_id: number | null;
  domain_id: number | null;
  event_type: string;
  title: string | null;
  severity: ExposureSeverity;
  detail: Record<string, unknown>;
  alert_id: number | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  /** Derived from event_type and detail (CATEGORY_SQL). */
  category: RiskCategory;
  // Joined for display: what the finding was raised against.
  identity_kind: IdentityKind | null;
  identity_value: string | null;
  domain: string | null;
  /** The linked alert's status; null when there is no alert (deleted, or removed by retention). */
  alert_status: string | null;
}

export type FindingSort = 'newest' | 'severity';

export interface FindingFilters {
  source?: ExposureFindingSource;
  unresolved?: boolean;
  severity?: ExposureSeverity;
  identityId?: number;
  domainId?: number;
  eventType?: ExposureEventType;
  category?: RiskCategory;
  /** First seen in the last N days (NOW() - N days). */
  sinceDays?: number;
  /** First seen at or after this time. */
  since?: Date;
  alertId?: number;
  /** Case-insensitive substring of the title, identity, domain, account, lookalike or breach. */
  search?: string;
  /** The breached account (detail.account), whole and case-insensitive. */
  account?: string;
  /** The lookalike domain a finding is about (detail.lookalike), whole and case-insensitive. */
  lookalike?: string;
  /** 'newest' (default): first_seen DESC. 'severity': most severe first, then newest. */
  sort?: FindingSort;
  limit: number;
  offset: number;
}

// Status/error bookkeeping is capped so a verbose upstream error can't bloat a row.
const MAX_ERROR_LENGTH = 500;

/** Build "SET a = $1, b = $2" from the defined fields only. */
function buildSet(fields: Record<string, unknown>, params: unknown[]): string[] {
  const sets: string[] = [];
  for (const [column, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    params.push(value);
    sets.push(`${column} = $${params.length}`);
  }
  return sets;
}

export const WatchedDomainModel = {
  async findAll(): Promise<WatchedDomain[]> {
    const r = await query(`SELECT * FROM watched_domains ORDER BY domain`);
    return r.rows;
  },

  async findById(id: number): Promise<WatchedDomain | null> {
    const r = await query(`SELECT * FROM watched_domains WHERE id = $1`, [id]);
    return r.rows[0] ?? null;
  },

  async create(input: WatchedDomainInput): Promise<WatchedDomain> {
    const r = await query(
      `INSERT INTO watched_domains (domain, scope, enabled, interval_minutes, collectors, expected_cas)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        input.domain,
        input.scope,
        input.enabled ?? true,
        input.interval_minutes ?? 1440,
        JSON.stringify(input.collectors ?? DEFAULT_COLLECTORS),
        input.expected_cas ?? [],
      ]
    );
    return r.rows[0];
  },

  /** The domain itself is immutable: delete and re-add to watch a different one. */
  async update(
    id: number,
    fields: Partial<Omit<WatchedDomainInput, 'domain'>>
  ): Promise<WatchedDomain | null> {
    const params: unknown[] = [];
    const sets = buildSet(
      {
        scope: fields.scope,
        enabled: fields.enabled,
        interval_minutes: fields.interval_minutes,
        collectors: fields.collectors === undefined ? undefined : JSON.stringify(fields.collectors),
        expected_cas: fields.expected_cas,
      },
      params
    );
    if (sets.length === 0) return WatchedDomainModel.findById(id);
    if (fields.interval_minutes !== undefined) {
      // A new interval takes effect from the last full run (the schedule's anchor:
      // early retry runs don't move it), not after the old interval runs out. A
      // pending early retry keeps its time when that is sooner.
      params.push(fields.interval_minutes);
      sets.push(
        `next_run_at = CASE WHEN last_checked_at IS NULL THEN next_run_at
           ELSE LEAST(
             COALESCE(
               CASE WHEN last_summary->>'full_run_at' ~ '^\\d{4}-\\d{2}-\\d{2}T'
                    THEN (last_summary->>'full_run_at')::timestamptz END,
               last_checked_at
             ) + $${params.length} * INTERVAL '1 minute',
             CASE WHEN jsonb_typeof(last_summary->'retry') = 'array'
                       AND last_summary->'retry' <> '[]'::jsonb
                  THEN next_run_at END
           ) END`
      );
    }
    params.push(id);
    const r = await query(
      `UPDATE watched_domains SET ${sets.join(', ')}, updated_at = NOW()
        WHERE id = $${params.length} RETURNING *`,
      params
    );
    return r.rows[0] ?? null;
  },

  async delete(id: number): Promise<boolean> {
    const r = await query(`DELETE FROM watched_domains WHERE id = $1`, [id]);
    return (r.rowCount ?? 0) > 0;
  },

  /**
   * Domains due for the domain monitor: enabled, and never scheduled or
   * scheduled for now or earlier (the scheduledScans pattern, on next_run_at).
   */
  async findDue(limit: number): Promise<WatchedDomain[]> {
    const r = await query(
      `SELECT * FROM watched_domains
        WHERE enabled AND (next_run_at IS NULL OR next_run_at <= NOW())
        ORDER BY next_run_at NULLS FIRST, id
        LIMIT $1`,
      [limit]
    );
    return r.rows;
  },

  async countDue(): Promise<number> {
    const r = await query(
      `SELECT COUNT(*)::int AS n FROM watched_domains
        WHERE enabled AND (next_run_at IS NULL OR next_run_at <= NOW())`
    );
    return r.rows[0]?.n ?? 0;
  },

  /** Every watched domain name (enabled or not): the organization's own names. */
  async listNames(): Promise<string[]> {
    const r = await query(`SELECT domain FROM watched_domains ORDER BY domain`);
    return r.rows.map((row) => row.domain);
  },

  /** Record a run's outcome and when the domain is due next. */
  async markRun(id: number, run: DomainRunRecord): Promise<void> {
    await query(
      `UPDATE watched_domains
          SET last_checked_at = NOW(),
              next_run_at = NOW() + $2 * INTERVAL '1 minute',
              last_status = $3,
              last_error = $4,
              last_summary = $5
        WHERE id = $1`,
      [
        id,
        Math.max(1, Math.round(run.nextRunMinutes)),
        run.status,
        run.error === null ? null : run.error.slice(0, MAX_ERROR_LENGTH),
        JSON.stringify(run.summary),
      ]
    );
  },
};

/** One stored snapshot per (domain, collector); deleting the domain cascades. */
export const DomainBaselineModel = {
  async findByDomain(domainId: number): Promise<Map<string, DomainBaseline>> {
    const r = await query(
      `SELECT collector, snapshot, updated_at FROM domain_baselines WHERE domain_id = $1`,
      [domainId]
    );
    return new Map(
      r.rows.map((row) => [row.collector, { snapshot: row.snapshot, updated_at: row.updated_at }])
    );
  },

  async upsert(domainId: number, collector: string, snapshot: unknown): Promise<void> {
    await query(
      `INSERT INTO domain_baselines (domain_id, collector, snapshot, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (domain_id, collector)
       DO UPDATE SET snapshot = EXCLUDED.snapshot, updated_at = NOW()`,
      [domainId, collector, JSON.stringify(snapshot)]
    );
  },
};

// "Due" = enabled, and never checked or last checked longer ago than its own
// interval. The `force` parameter ignores the interval (an admin's explicit
// "run now" for every identity).
const dueCondition = (forceParam: string) => `enabled AND (
    ${forceParam}::boolean
    OR last_checked_at IS NULL
    OR last_checked_at <= NOW() - interval_minutes * INTERVAL '1 minute'
  )`;

export const MonitoredIdentityModel = {
  async findAll(): Promise<MonitoredIdentity[]> {
    const r = await query(`SELECT * FROM monitored_identities ORDER BY kind, value`);
    return r.rows;
  },

  async findById(id: number): Promise<MonitoredIdentity | null> {
    const r = await query(`SELECT * FROM monitored_identities WHERE id = $1`, [id]);
    return r.rows[0] ?? null;
  },

  async create(input: MonitoredIdentityInput): Promise<MonitoredIdentity> {
    const r = await query(
      `INSERT INTO monitored_identities (kind, value, enabled, interval_minutes)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [input.kind, input.value, input.enabled ?? true, input.interval_minutes ?? 1440]
    );
    return r.rows[0];
  },

  /** kind/value are immutable: findings are fingerprinted on them. */
  async update(
    id: number,
    fields: Partial<Pick<MonitoredIdentityInput, 'enabled' | 'interval_minutes'>>
  ): Promise<MonitoredIdentity | null> {
    const params: unknown[] = [];
    const sets = buildSet(
      { enabled: fields.enabled, interval_minutes: fields.interval_minutes },
      params
    );
    if (sets.length === 0) return MonitoredIdentityModel.findById(id);
    params.push(id);
    const r = await query(
      `UPDATE monitored_identities SET ${sets.join(', ')}, updated_at = NOW()
        WHERE id = $${params.length} RETURNING *`,
      params
    );
    return r.rows[0] ?? null;
  },

  async delete(id: number): Promise<boolean> {
    const r = await query(`DELETE FROM monitored_identities WHERE id = $1`, [id]);
    return (r.rowCount ?? 0) > 0;
  },

  /** Due identities, never-checked and longest-waiting first. */
  async findDue(limit: number, force = false): Promise<MonitoredIdentity[]> {
    const r = await query(
      `SELECT * FROM monitored_identities
        WHERE ${dueCondition('$2')}
        ORDER BY last_checked_at NULLS FIRST, id
        LIMIT $1`,
      [limit, force]
    );
    return r.rows;
  },

  async countDue(force = false): Promise<number> {
    const r = await query(
      `SELECT COUNT(*)::int AS n FROM monitored_identities WHERE ${dueCondition('$1')}`,
      [force]
    );
    return r.rows[0]?.n ?? 0;
  },

  async markChecked(id: number): Promise<void> {
    await query(
      `UPDATE monitored_identities
          SET last_checked_at = NOW(), last_status = 'ok', last_error = NULL
        WHERE id = $1`,
      [id]
    );
  },

  /**
   * Record a failed check. `advance` stamps last_checked_at so the identity
   * waits a full interval before the next try (for failures that retrying soon
   * won't fix, e.g. a domain HIBP refused although it is listed as verified);
   * otherwise it stays due.
   */
  async markFailed(id: number, error: string, advance: boolean): Promise<void> {
    await query(
      `UPDATE monitored_identities
          SET last_status = 'error',
              last_error = $2,
              last_checked_at = CASE WHEN $3::boolean THEN NOW() ELSE last_checked_at END
        WHERE id = $1`,
      [id, error.slice(0, MAX_ERROR_LENGTH), advance]
    );
  },

  /**
   * An email domain HIBP won't search for this key (not verified on the
   * account, or no domain search on the plan): skipped, not failed. It waits a
   * full interval, unless a re-check lists it as verified (requeueVerified).
   */
  async markUnverified(id: number, note: string): Promise<void> {
    await query(
      `UPDATE monitored_identities
          SET last_status = 'unverified', last_error = $2, last_checked_at = NOW()
        WHERE id = $1`,
      [id, note.slice(0, MAX_ERROR_LENGTH)]
    );
  },

  /**
   * Email domains among `values` that were skipped as unverified and are now
   * listed as verified: due again straight away, and back to "not checked yet"
   * rather than reading "Not verified" next to "Verified on HIBP". Disabled ones
   * are reset too, so re-enabling one doesn't show a stale status.
   */
  async requeueVerified(values: readonly string[]): Promise<Array<{ id: number; enabled: boolean }>> {
    if (values.length === 0) return [];
    const r = await query(
      `UPDATE monitored_identities
          SET last_checked_at = NULL, last_status = NULL, last_error = NULL
        WHERE kind = 'email_domain' AND last_status = 'unverified' AND value = ANY($1::text[])
        RETURNING id, enabled`,
      [values]
    );
    return r.rows.map((row) => ({ id: Number(row.id), enabled: row.enabled === true }));
  },

  /** Every monitored email domain (enabled or not). */
  async listEmailDomains(): Promise<Array<{ id: number; value: string; enabled: boolean }>> {
    const r = await query(
      `SELECT id, value, enabled FROM monitored_identities WHERE kind = 'email_domain' ORDER BY value`
    );
    return r.rows.map((row) => ({ id: Number(row.id), value: row.value, enabled: row.enabled === true }));
  },
};

const FINDING_COLUMNS = `
  f.id, f.source, f.identity_id, f.domain_id, f.event_type, f.title, f.severity,
  f.detail, f.alert_id, f.first_seen, f.last_seen, f.resolved_at, ${CATEGORY_SQL} AS category,
  i.kind AS identity_kind, i.value AS identity_value, d.domain, a.status AS alert_status`;

// Every join is on a primary key, so none multiplies rows (the COUNT is unaffected).
const FINDING_FROM = `
  FROM exposure_findings f
  LEFT JOIN monitored_identities i ON i.id = f.identity_id
  LEFT JOIN watched_domains d ON d.id = f.domain_id
  LEFT JOIN alerts a ON a.id = f.alert_id`;

// What the findings search looks in. strpos, not LIKE or a regex: %, _ and
// regex characters in the search are literal, and nothing can backtrack.
const FINDING_SEARCH_TEXT = `lower(concat_ws(' ', f.title, i.value, d.domain, f.detail->>'account',
  f.detail->>'lookalike', f.detail->>'breach_title', f.detail->>'breach_name'))`;

// node-postgres returns BIGSERIAL (int8) as a string; findings will never get
// near 2^53, so hand the API a plain number.
function toFinding(row: Record<string, unknown>): ExposureFinding {
  return { ...row, id: Number(row.id) } as ExposureFinding;
}

export const ExposureFindingModel = {
  async list(filters: FindingFilters): Promise<{ findings: ExposureFinding[]; total: number }> {
    const where: string[] = [];
    const params: unknown[] = [];
    const add = (sql: string, value: unknown) => {
      params.push(value);
      where.push(sql.replace('?', `$${params.length}`));
    };
    if (filters.source) add('f.source = ?', filters.source);
    if (filters.severity) add('f.severity = ?', filters.severity);
    if (filters.identityId !== undefined) add('f.identity_id = ?', filters.identityId);
    if (filters.domainId !== undefined) add('f.domain_id = ?', filters.domainId);
    if (filters.eventType) add('f.event_type = ?', filters.eventType);
    if (filters.category) add(`${CATEGORY_SQL} = ?`, filters.category);
    if (filters.sinceDays !== undefined) add('f.first_seen >= NOW() - make_interval(days => ?::int)', filters.sinceDays);
    if (filters.since !== undefined) add('f.first_seen >= ?::timestamptz', filters.since);
    if (filters.alertId !== undefined) add('f.alert_id = ?', filters.alertId);
    if (filters.search) add(`strpos(${FINDING_SEARCH_TEXT}, lower(?::text)) > 0`, filters.search);
    if (filters.account) add(`lower(f.detail->>'account') = lower(?::text)`, filters.account);
    if (filters.lookalike) add(`lower(f.detail->>'lookalike') = lower(?::text)`, filters.lookalike);
    if (filters.unresolved) where.push('f.resolved_at IS NULL');
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const orderSql =
      filters.sort === 'severity'
        ? `${SEV_RANK_SQL} DESC, f.first_seen DESC, f.id DESC`
        : 'f.first_seen DESC, f.id DESC';

    const total = await query(`SELECT COUNT(*)::int AS n ${FINDING_FROM} ${whereSql}`, params);
    const rows = await query(
      `SELECT ${FINDING_COLUMNS} ${FINDING_FROM} ${whereSql}
        ORDER BY ${orderSql}
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, filters.limit, filters.offset]
    );
    return { findings: rows.rows.map(toFinding), total: total.rows[0]?.n ?? 0 };
  },

  async findById(id: number): Promise<ExposureFinding | null> {
    const r = await query(`SELECT ${FINDING_COLUMNS} ${FINDING_FROM} WHERE f.id = $1`, [id]);
    return r.rows[0] ? toFinding(r.rows[0]) : null;
  },

  /** Idempotent: resolving twice keeps the first resolution time. */
  async resolve(id: number): Promise<ExposureFinding | null> {
    const r = await query(
      `UPDATE exposure_findings SET resolved_at = COALESCE(resolved_at, NOW()) WHERE id = $1 RETURNING id`,
      [id]
    );
    if ((r.rowCount ?? 0) === 0) return null;
    return ExposureFindingModel.findById(id);
  },
};

export interface ExposureCounts {
  identities: number;
  identities_enabled: number;
  identities_due: number;
  domains: number;
  domains_enabled: number;
  domains_due: number;
  findings_total: number;
  findings_open: number;
  findings_open_by_severity: Record<string, number>;
}

export async function getExposureCounts(): Promise<ExposureCounts> {
  const [totals, bySeverity, due, domainsDue] = await Promise.all([
    query(
      `SELECT
         (SELECT COUNT(*) FROM monitored_identities)::int AS identities,
         (SELECT COUNT(*) FROM monitored_identities WHERE enabled)::int AS identities_enabled,
         (SELECT COUNT(*) FROM watched_domains)::int AS domains,
         (SELECT COUNT(*) FROM watched_domains WHERE enabled)::int AS domains_enabled,
         (SELECT COUNT(*) FROM exposure_findings)::int AS findings_total,
         (SELECT COUNT(*) FROM exposure_findings WHERE resolved_at IS NULL)::int AS findings_open`
    ),
    query(
      `SELECT severity, COUNT(*)::int AS n FROM exposure_findings
        WHERE resolved_at IS NULL GROUP BY severity`
    ),
    MonitoredIdentityModel.countDue(),
    WatchedDomainModel.countDue(),
  ]);
  const findings_open_by_severity: Record<string, number> = {};
  for (const row of bySeverity.rows) findings_open_by_severity[row.severity] = row.n;
  return {
    ...totals.rows[0],
    identities_due: due,
    domains_due: domainsDue,
    findings_open_by_severity,
  };
}

// ---- Digital Risk summary ------------------------------------------------------------

/**
 * Everything the Digital Risk page aggregates, read in one REPEATABLE READ
 * snapshot so the tiles, the trend and the lists agree while the jobs write
 * (NOW() is fixed for the transaction too). Pass `client` to run inside the
 * caller's transaction instead (the tests shadow the tables with temp tables,
 * which is why no table name here is schema-qualified). Never calls HIBP,
 * crt.sh or DNS: it reads findings, identities, domains and baselines only.
 *
 * Buckets are UTC (weeks start on Monday) and the window starts on a bucket
 * boundary, so the trend sums exactly to the window's counts.
 */
export async function getExposureSummary(days: SummaryDays, client?: PoolClient): Promise<ExposureSummary> {
  if (client) return readExposureSummary(client, days);
  const own = await getClient();
  let broken = false;
  try {
    await own.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const summary = await readExposureSummary(own, days);
    await own.query('COMMIT');
    return summary;
  } catch (err) {
    try {
      await own.query('ROLLBACK');
    } catch {
      broken = true; // don't hand a dead connection back to the pool
    }
    throw err;
  } finally {
    own.release(broken || undefined);
  }
}

// What tells two breaches apart (alias f): HIBP's breach name, else its title.
const BREACH_KEY_SQL = `COALESCE(f.detail->>'breach_name', f.detail->>'breach_title')`;

// Open breach findings with an account (alias f).
const OPEN_BREACH_SQL = `f.source = 'leaked-creds' AND f.event_type = 'breach' AND f.resolved_at IS NULL
   AND jsonb_typeof(f.detail->'account') = 'string'`;

/**
 * The summary window at `at` (default: the transaction's NOW()): `since` is
 * the start of the UTC bucket holding `at` minus WINDOW_BACK, so the window
 * holds whole buckets (31 days, 13-14 or 26-27 weeks, 13 months). The unit and
 * the interval come from the whitelists and are bound as text, never
 * interpolated. Exported for the tests, which pin `at` to awkward dates.
 */
export async function summaryWindow(
  db: Pick<PoolClient, 'query'>,
  days: SummaryDays,
  at?: Date | string
): Promise<{ now: Date; since: Date }> {
  // timestamptz only: node-pg reads a timestamp without time zone as local time.
  // The interval is taken off the UTC wall-clock time, so months are calendar
  // months in UTC whatever the session's TimeZone.
  const win = await db.query(
    `SELECT n.now,
            date_trunc($2::text, (n.now AT TIME ZONE 'UTC') - $3::text::interval) AT TIME ZONE 'UTC' AS since
       FROM (SELECT COALESCE($1::timestamptz, NOW()) AS now) n`,
    [at ?? null, BUCKET_FOR_DAYS[days], WINDOW_BACK[days]]
  );
  return { now: win.rows[0].now, since: win.rows[0].since };
}

// The queries run one after another on the snapshot's connection.
async function readExposureSummary(db: PoolClient, days: SummaryDays): Promise<ExposureSummary> {
  // The unit comes from the whitelist and is bound as text, never interpolated.
  const unit = BUCKET_FOR_DAYS[days];
  const { now, since } = await summaryWindow(db, days);

  // At most 2 sources x 7 types x 2 categories x 4 severities rows.
  const breakdown = await db.query(
    `SELECT f.source, f.event_type, ${CATEGORY_SQL} AS category, f.severity,
            COUNT(*) FILTER (WHERE f.resolved_at IS NULL)::int AS open_n,
            COUNT(*) FILTER (WHERE f.first_seen >= $1)::int AS new_n,
            COUNT(*) FILTER (WHERE f.resolved_at >= $1)::int AS resolved_n,
            COUNT(*) FILTER (WHERE f.first_seen >= $1::timestamptz - (NOW() - $1::timestamptz)
                               AND f.first_seen < $1)::int AS prev_new_n,
            MIN(f.first_seen) FILTER (WHERE f.resolved_at IS NULL) AS oldest_open
       FROM exposure_findings f
      GROUP BY 1, 2, 3, 4`,
    [since]
  );

  const buckets = await db.query(
    `SELECT gs AT TIME ZONE 'UTC' AS start
       FROM generate_series($1::timestamptz AT TIME ZONE 'UTC',
                            date_trunc($2::text, NOW() AT TIME ZONE 'UTC'),
                            ('1 ' || $2::text)::interval) AS gs
      ORDER BY gs`,
    [since, unit]
  );
  const trendRows = await db.query(
    `SELECT 'new' AS kind,
            date_trunc($2::text, f.first_seen AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS start,
            ${CATEGORY_SQL} AS category, COUNT(*)::int AS n
       FROM exposure_findings f WHERE f.first_seen >= $1 GROUP BY 2, 3
     UNION ALL
     SELECT 'resolved', date_trunc($2::text, f.resolved_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', NULL, COUNT(*)::int
       FROM exposure_findings f WHERE f.resolved_at >= $1 GROUP BY 2
     UNION ALL
     SELECT 'identities', date_trunc($2::text, created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', NULL, COUNT(*)::int
       FROM monitored_identities WHERE created_at >= $1 GROUP BY 2
     UNION ALL
     SELECT 'domains', date_trunc($2::text, created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', NULL, COUNT(*)::int
       FROM watched_domains WHERE created_at >= $1 GROUP BY 2`,
    [since, unit]
  );
  const openBefore = await db.query(
    `SELECT (COUNT(*) FILTER (WHERE first_seen < $1) - COUNT(*) FILTER (WHERE resolved_at < $1))::int AS n
       FROM exposure_findings`,
    [since]
  );

  const credentialClasses = [...CREDENTIAL_DATA_CLASSES];
  const accountTotals = await db.query(
    `SELECT COUNT(DISTINCT lower(f.detail->>'account'))::int AS total,
            (COUNT(DISTINCT lower(f.detail->>'account')) FILTER (WHERE ${credExposedSql('$1')}))::int AS to_reset
       FROM exposure_findings f
      WHERE ${OPEN_BREACH_SQL}`,
    [credentialClasses]
  );
  // breach_date is 'YYYY-MM-DD' text, so text order is date order. Up to ten
  // breaches per account come back; buildAccounts keeps three distinct ones.
  // One breach can be two findings (the account is monitored as an address and
  // through its email domain), so breaches are told apart, and counted, by
  // their name: breach_count, not open_n, is how many breaches there are.
  const accounts = await db.query(
    `SELECT lower(f.detail->>'account') AS account,
            MIN(f.identity_id) AS identity_id,
            COUNT(*)::int AS open_n,
            (COUNT(*) FILTER (WHERE ${credExposedSql('$1')}))::int AS credential_exposures,
            bool_or(COALESCE(f.detail->'is_stealer_log' = 'true'::jsonb, false)) AS stealer_log,
            MAX(${SEV_RANK_SQL}) AS worst_rank,
            COUNT(DISTINCT ${BREACH_KEY_SQL})::int AS breach_count,
            to_jsonb((array_agg(jsonb_build_object(
                'key', ${BREACH_KEY_SQL},
                'title', COALESCE(f.detail->>'breach_title', f.detail->>'breach_name'),
                'date', f.detail->>'breach_date')
              ORDER BY f.detail->>'breach_date' DESC NULLS LAST, f.id DESC))[1:10]) AS breaches,
            MAX(f.first_seen) AS last_detected
       FROM exposure_findings f
      WHERE ${OPEN_BREACH_SQL}
      GROUP BY 1
      ORDER BY (COUNT(*) FILTER (WHERE ${credExposedSql('$1')}) > 0) DESC,
               bool_or(COALESCE(f.detail->'is_stealer_log' = 'true'::jsonb, false)) DESC,
               worst_rank DESC, open_n DESC, account
      LIMIT 10`,
    [credentialClasses]
  );

  // Two baseline rows per enabled domain at most; parsed with the collectors' own parsers.
  const domainRows = await db.query(
    `SELECT d.id AS domain_id, d.domain, d.scope, d.collectors, d.last_summary, b.collector, b.snapshot
       FROM watched_domains d
       LEFT JOIN domain_baselines b ON b.domain_id = d.id AND b.collector IN ('lookalike', 'ct')
      WHERE d.enabled
      ORDER BY d.id`
  );
  const lookalikeFindings = await db.query(
    `SELECT f.domain_id, f.detail->>'lookalike' AS lookalike, COUNT(*)::int AS n,
            MAX(${SEV_RANK_SQL}) AS worst_rank
       FROM exposure_findings f
      WHERE f.source = 'domain-monitor' AND f.resolved_at IS NULL
        AND f.domain_id IS NOT NULL AND jsonb_typeof(f.detail->'lookalike') = 'string'
      GROUP BY 1, 2`
  );

  const domains = new Map<number, LookalikeDomainInput>();
  for (const row of domainRows.rows) {
    const id = Number(row.domain_id);
    let entry = domains.get(id);
    if (!entry) {
      entry = {
        id,
        domain: row.domain,
        scope: row.scope,
        collectors: row.collectors,
        last_summary: row.last_summary,
        lookalike: null,
        ct: null,
      };
      domains.set(id, entry);
    }
    if (row.collector === 'lookalike') entry.lookalike = row.snapshot;
    if (row.collector === 'ct') entry.ct = row.snapshot;
  }

  const totals = accountTotals.rows[0] ?? { total: 0, to_reset: 0 };
  return {
    generated_at: now.toISOString(),
    window: { days, bucket: unit, since: since.toISOString() },
    ...foldBreakdown(breakdown.rows as BreakdownRow[]),
    trend: foldTrend(
      buckets.rows.map((r) => r.start as Date),
      trendRows.rows as TrendRow[],
      Number(openBefore.rows[0]?.n ?? 0)
    ),
    accounts: {
      total: Number(totals.total),
      to_reset: Number(totals.to_reset),
      top: buildAccounts(accounts.rows as AccountRow[]),
    },
    lookalikes: buildLookalikeInventory(
      [...domains.values()],
      lookalikeFindings.rows.map(
        (r): LookalikeFindingRow => ({
          domain_id: Number(r.domain_id),
          lookalike: r.lookalike,
          n: Number(r.n),
          worst_rank: Number(r.worst_rank),
        })
      ),
      Math.floor(now.getTime() / 1000)
    ),
  };
}
