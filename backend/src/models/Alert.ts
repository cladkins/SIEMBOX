import { query } from '../config/database';

export interface Alert {
  id: number;
  rule_id: number;
  parsed_log_id: number | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string | null;
  matched_data: Record<string, any>;
  status: 'new' | 'investigating' | 'closed' | 'false_positive';
  assigned_to: number | null;
  created_at: Date;
  updated_at: Date;
  // Joined from alert_triage by findAll()/findAllGrouped() — undefined when not requested/joined.
  triage_status?: 'pending' | 'analyzing' | 'complete' | 'failed' | 'skipped' | null;
  triage_verdict?: 'true_positive' | 'false_positive' | 'suspicious' | 'inconclusive' | null;
  triage_risk_score?: number | null;
}

export interface AlertFilterOptions {
  severity?: string;
  status?: string;
  ruleId?: number;
  startTime?: Date;
  endTime?: Date;
  search?: string;
  triageStatus?: string;
  triageVerdict?: string;
  minRiskScore?: number;
}

/** One alert's summary as it appears inside a correlated group. */
export interface CorrelatedAlert {
  id: number;
  rule_id: number;
  severity: Alert['severity'];
  title: string;
  status: Alert['status'];
  created_at: Date;
}

/**
 * The representative alert for one triggering event, plus everything else that
 * fired on it. `correlated` always includes the representative itself, so
 * `correlated_count` is the true size of the group.
 */
export interface AlertGroup extends Alert {
  correlated_count: number;
  correlated: CorrelatedAlert[];
}

export interface CreateAlertParams {
  rule_id: number;
  parsed_log_id?: number | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description?: string;
  matched_data: Record<string, any>;
  status?: 'new' | 'investigating' | 'closed' | 'false_positive';
  assigned_to?: number | null;
}

export class AlertModel {
  // Both findAll and findAllGrouped join alert_triage — alert_id is its PRIMARY
  // KEY (migration 028), so the join is always 1:1 and never multiplies rows.
  private static readonly FROM_CLAUSE = `FROM alerts a LEFT JOIN alert_triage t ON t.alert_id = a.id`;

  static async create(params: CreateAlertParams): Promise<Alert> {
    const result = await query(
      `INSERT INTO alerts (rule_id, parsed_log_id, severity, title, description, matched_data, status, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        params.rule_id,
        params.parsed_log_id ?? null,
        params.severity,
        params.title,
        params.description ?? null,
        JSON.stringify(params.matched_data),
        params.status ?? 'new',
        params.assigned_to ?? null,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<Alert | null> {
    const result = await query('SELECT * FROM alerts WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  /**
   * Shared WHERE clause for the flat and grouped list views, so a filter added
   * to one cannot silently go missing from the other. Every condition is
   * qualified `a.`/`t.` because both views join alert_triage as `t` —
   * unqualified `status` (alerts.status vs. alert_triage.status) would be
   * ambiguous and fail at query time.
   */
  private static buildFilters(options?: AlertFilterOptions): { whereClause: string; params: any[]; nextIndex: number } {
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (options?.severity) {
      conditions.push(`a.severity = $${paramIndex++}`);
      params.push(options.severity);
    }

    if (options?.status) {
      conditions.push(`a.status = $${paramIndex++}`);
      params.push(options.status);
    }

    if (options?.search) {
      // Keyword / IP search across the alert title, description, and matched_data
      // (where the source IP and other matched fields live). ILIKE = case-insensitive.
      const p = paramIndex++;
      conditions.push(`(a.title ILIKE $${p} OR a.description ILIKE $${p} OR a.matched_data::text ILIKE $${p})`);
      params.push(`%${options.search}%`);
    }

    if (options?.ruleId) {
      conditions.push(`a.rule_id = $${paramIndex++}`);
      params.push(options.ruleId);
    }

    if (options?.startTime) {
      conditions.push(`a.created_at >= $${paramIndex++}`);
      params.push(options.startTime);
    }

    if (options?.endTime) {
      conditions.push(`a.created_at <= $${paramIndex++}`);
      params.push(options.endTime);
    }

    if (options?.triageStatus) {
      conditions.push(`t.status = $${paramIndex++}`);
      params.push(options.triageStatus);
    }

    if (options?.triageVerdict) {
      conditions.push(`t.verdict = $${paramIndex++}`);
      params.push(options.triageVerdict);
    }

    if (options?.minRiskScore !== undefined) {
      conditions.push(`t.risk_score >= $${paramIndex++}`);
      params.push(options.minRiskScore);
    }

    return {
      whereClause: conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '',
      params,
      nextIndex: paramIndex,
    };
  }

  static async findAll(
    options?: AlertFilterOptions & { limit?: number; offset?: number; sortBy?: 'created_at' | 'risk_score' }
  ): Promise<{ alerts: Alert[]; total: number }> {
    const built = this.buildFilters(options);
    const whereClause = built.whereClause;
    const params = built.params;
    let paramIndex = built.nextIndex;

    // Get total count
    const countResult = await query(`SELECT COUNT(*) ${this.FROM_CLAUSE} ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count, 10);

    // Get alerts
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const orderClause =
      options?.sortBy === 'risk_score'
        ? 'ORDER BY t.risk_score DESC NULLS LAST, a.created_at DESC'
        : 'ORDER BY a.created_at DESC';

    params.push(limit, offset);
    const alertsResult = await query(
      `SELECT a.*, t.status AS triage_status, t.verdict AS triage_verdict, t.risk_score AS triage_risk_score
       ${this.FROM_CLAUSE} ${whereClause}
       ${orderClause}
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      params
    );

    return {
      alerts: alertsResult.rows,
      total,
    };
  }

  /**
   * The same list, collapsed to one row per TRIGGERING EVENT.
   *
   * The rules engine evaluates every rule against every log with no early exit,
   * so one request routinely raises several alerts — `;cat /etc/passwd` trips
   * both the SQL-injection and command-injection rules. Flat, that reads as
   * three problems; grouped, it reads as one event three rules agree on.
   *
   * Grouping is by `parsed_log_id` (indexed as idx_alerts_parsed_log_id).
   * Alerts with no parsed log — EDR findings, and anything whose source log was
   * pruned, since the FK is ON DELETE SET NULL — must each stand alone rather
   * than collapsing into one giant NULL bucket, so those key off the alert id.
   *
   * The representative is the most severe member, newest first to break ties,
   * because that is what decides how urgently the event needs attention. It
   * carries its own triage verdict (not an aggregate across the group) so the
   * grouped view shows the same per-alert triage badge as the flat view.
   */
  static async findAllGrouped(
    options?: AlertFilterOptions & { limit?: number; offset?: number }
  ): Promise<{ alerts: AlertGroup[]; total: number }> {
    const { whereClause, params, nextIndex } = this.buildFilters(options);
    let paramIndex = nextIndex;

    // 'p'/'a' prefixes keep a parsed_log_id and an alert id from ever colliding.
    const GROUP_KEY = `COALESCE('p' || a.parsed_log_id::text, 'a' || a.id::text)`;
    const SEV_RANK = `CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`;

    const countResult = await query(
      `SELECT COUNT(*) FROM (SELECT DISTINCT ${GROUP_KEY} AS group_key ${this.FROM_CLAUSE} ${whereClause}) g`,
      params
    );
    const total = parseInt(countResult.rows[0].count, 10);

    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const listParams = [...params, limit, offset];

    const result = await query(
      `WITH filtered AS (
         SELECT a.*, t.status AS triage_status, t.verdict AS triage_verdict, t.risk_score AS triage_risk_score,
                ${GROUP_KEY} AS group_key, ${SEV_RANK} AS sev_rank
         ${this.FROM_CLAUSE} ${whereClause}
       ),
       grouped AS (
         SELECT
           group_key,
           COUNT(*)::int AS correlated_count,
           MAX(created_at) AS group_created_at,
           jsonb_agg(
             jsonb_build_object(
               'id', id, 'rule_id', rule_id, 'severity', severity,
               'title', title, 'status', status, 'created_at', created_at
             ) ORDER BY sev_rank DESC, created_at DESC, id DESC
           ) AS correlated
         FROM filtered
         GROUP BY group_key
       ),
       representative AS (
         SELECT DISTINCT ON (group_key)
           id, rule_id, parsed_log_id, severity, title, description,
           matched_data, status, assigned_to, created_at, updated_at, group_key,
           triage_status, triage_verdict, triage_risk_score
         FROM filtered
         ORDER BY group_key, sev_rank DESC, created_at DESC, id DESC
       )
       SELECT r.id, r.rule_id, r.parsed_log_id, r.severity, r.title, r.description,
              r.matched_data, r.status, r.assigned_to, r.created_at, r.updated_at,
              r.triage_status, r.triage_verdict, r.triage_risk_score,
              g.correlated_count, g.correlated
       FROM representative r
       JOIN grouped g ON g.group_key = r.group_key
       ORDER BY g.group_created_at DESC, r.id DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      listParams
    );

    return { alerts: result.rows, total };
  }

  /**
   * Sibling alerts that share the rule, the asset, or the extracted source IP
   * with the given alert — used by the triage agent's get_related_alerts tool
   * to spot bursts/patterns without a free-text log search.
   */
  static async findRelated(options: {
    alertId: number;
    sinceHours?: number;
    limit?: number;
  }): Promise<Array<Alert & { shares: 'rule' | 'asset' | 'source_ip' }>> {
    const sinceHours = options.sinceHours ?? 24;
    const limit = options.limit ?? 10;
    const r = await query(
      `SELECT b.*,
              CASE
                WHEN b.rule_id IS NOT NULL AND b.rule_id = a.rule_id THEN 'rule'
                WHEN b.asset_id IS NOT NULL AND b.asset_id = a.asset_id THEN 'asset'
                ELSE 'source_ip'
              END AS shares
         FROM alerts a
         JOIN alerts b
           ON b.id <> a.id
          AND b.created_at >= NOW() - ($2 || ' hours')::interval
          AND (
                (b.rule_id IS NOT NULL AND b.rule_id = a.rule_id)
             OR (b.asset_id IS NOT NULL AND b.asset_id = a.asset_id)
             OR (
                  a.matched_data->>'source_ip' IS NOT NULL
                  AND b.matched_data->>'source_ip' = a.matched_data->>'source_ip'
                )
              )
        WHERE a.id = $1
        ORDER BY b.created_at DESC
        LIMIT $3`,
      [options.alertId, sinceHours, limit]
    );
    return r.rows;
  }

  /**
   * How this rule/title has historically been dispositioned — the strongest
   * available false-positive signal ("12 of the last 14 were closed as FP").
   */
  static async getDispositionHistory(options: {
    title: string;
    ruleId?: number | null;
    days?: number;
  }): Promise<{
    same_rule_count: number;
    first_seen: string | null;
    dispositions: Record<'new' | 'investigating' | 'closed' | 'false_positive', number>;
  }> {
    const days = options.days ?? 30;
    const r = await query(
      `SELECT
         COUNT(*)::int AS total,
         MIN(created_at) AS first_seen,
         COUNT(*) FILTER (WHERE status = 'new')::int AS new_count,
         COUNT(*) FILTER (WHERE status = 'investigating')::int AS investigating_count,
         COUNT(*) FILTER (WHERE status = 'closed')::int AS closed_count,
         COUNT(*) FILTER (WHERE status = 'false_positive')::int AS false_positive_count
       FROM alerts
       WHERE title = $1
         AND ($2::int IS NULL OR rule_id = $2)
         AND created_at >= NOW() - ($3 || ' days')::interval`,
      [options.title, options.ruleId ?? null, days]
    );
    const row = r.rows[0] || {};
    return {
      same_rule_count: row.total ?? 0,
      first_seen: row.first_seen ?? null,
      dispositions: {
        new: row.new_count ?? 0,
        investigating: row.investigating_count ?? 0,
        closed: row.closed_count ?? 0,
        false_positive: row.false_positive_count ?? 0,
      },
    };
  }

  static async update(
    id: number,
    params: Partial<CreateAlertParams>
  ): Promise<Alert | null> {
    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (params.status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(params.status);
    }

    if (params.assigned_to !== undefined) {
      updates.push(`assigned_to = $${paramIndex++}`);
      values.push(params.assigned_to);
    }

    if (params.description !== undefined) {
      updates.push(`description = $${paramIndex++}`);
      values.push(params.description);
    }

    if (updates.length === 0) {
      return this.findById(id);
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query(
      `UPDATE alerts SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    return result.rows[0] || null;
  }

  static async delete(id: number): Promise<boolean> {
    const result = await query('DELETE FROM alerts WHERE id = $1', [id]);
    return (result.rowCount || 0) > 0;
  }

  static async getStatistics(): Promise<any> {
    const result = await query(`
      SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'new' THEN 1 END) as new_count,
        COUNT(CASE WHEN status = 'investigating' THEN 1 END) as investigating_count,
        COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_count,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
        COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_count,
        COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_count
      FROM alerts
      WHERE created_at >= NOW() - INTERVAL '24 hours'
    `);

    return result.rows[0];
  }

  /**
   * Aggregate alerts by the GeoIP country of the IP that triggered them.
   * country_code / country_name / geo_foreign are enriched onto the parsed log
   * before rule matching and copied into alerts.matched_data, so no join or
   * extra lookup is needed. Alerts whose IP was private/unresolved (no
   * country_code) are excluded. `days` bounds the window; `limit` caps rows.
   */
  static async getCountByCountry(days = 30, limit = 50): Promise<any[]> {
    const result = await query(
      `
      SELECT
        matched_data->>'country_code' AS country_code,
        MAX(matched_data->>'country_name') AS country_name,
        COUNT(*)::int AS count,
        COUNT(*) FILTER (
          WHERE (matched_data->>'geo_foreign')::boolean IS TRUE
        )::int AS foreign_count
      FROM alerts
      WHERE created_at >= NOW() - ($1 || ' days')::interval
        AND matched_data->>'country_code' IS NOT NULL
        AND matched_data->>'country_code' <> ''
      GROUP BY matched_data->>'country_code'
      ORDER BY count DESC
      LIMIT $2
      `,
      [days, limit]
    );
    return result.rows;
  }
}
