/**
 * Exposure monitoring ("Digital Risk") persistence: watched domains, monitored
 * identities and the findings raised against them (migration 034).
 *
 * Values are validated and lowercased before they get here (see
 * services/exposure/validation.ts); the tables' CHECK constraints are the
 * backstop. Findings are written only through services/exposure/findingWriter.ts,
 * which owns dedupe, alerting and the privacy scrub of `detail`.
 */
import { query } from '../config/database';

export type DomainScope = 'own' | 'brand';
export type IdentityKind = 'email' | 'email_domain';
export type ExposureSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ExposureFindingSource = 'leaked-creds' | 'domain-monitor';

export const DEFAULT_COLLECTORS = { ct: true, lookalike: true, rdap: true, dns: true } as const;
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
  created_at: string;
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
  // Joined for display: what the finding was raised against.
  identity_kind: IdentityKind | null;
  identity_value: string | null;
  domain: string | null;
}

export interface FindingFilters {
  source?: ExposureFindingSource;
  unresolved?: boolean;
  severity?: ExposureSeverity;
  identityId?: number;
  domainId?: number;
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
   * won't fix, e.g. an unverified domain); otherwise it stays due.
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
};

const FINDING_COLUMNS = `
  f.id, f.source, f.identity_id, f.domain_id, f.event_type, f.title, f.severity,
  f.detail, f.alert_id, f.first_seen, f.last_seen, f.resolved_at,
  i.kind AS identity_kind, i.value AS identity_value, d.domain`;

const FINDING_FROM = `
  FROM exposure_findings f
  LEFT JOIN monitored_identities i ON i.id = f.identity_id
  LEFT JOIN watched_domains d ON d.id = f.domain_id`;

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
    if (filters.unresolved) where.push('f.resolved_at IS NULL');
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = await query(`SELECT COUNT(*)::int AS n ${FINDING_FROM} ${whereSql}`, params);
    const rows = await query(
      `SELECT ${FINDING_COLUMNS} ${FINDING_FROM} ${whereSql}
        ORDER BY f.first_seen DESC, f.id DESC
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
  findings_total: number;
  findings_open: number;
  findings_open_by_severity: Record<string, number>;
}

export async function getExposureCounts(): Promise<ExposureCounts> {
  const [totals, bySeverity, due] = await Promise.all([
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
  ]);
  const findings_open_by_severity: Record<string, number> = {};
  for (const row of bySeverity.rows) findings_open_by_severity[row.severity] = row.n;
  return { ...totals.rows[0], identities_due: due, findings_open_by_severity };
}
