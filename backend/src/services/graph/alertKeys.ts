/**
 * How alerts are looked up by the values their matched_data names: the SQL
 * expression per key, exactly as migration 043 indexes it, and the guard that
 * goes with it. Pure (no database); used by the graph's resolvers, Threat
 * Intel's IP view and Asset-360, so all three are served by the same indexes.
 *
 * The expressions apply entityKey.ts's text rules in SQL (btrim, lower,
 * trailing dots), so an alert is found by the key the graph shows for it.
 *
 * The guard: matched_data values come from logs, so any of them can be huge,
 * and a btree entry can't be larger than about 2.7 kB (a larger one makes the
 * INSERT fail). The indexes are partial, covering values of at most
 * MAX_INDEXED_BYTES; each lookup states the same bound, which is what lets the
 * planner use them. No real key is that long (keys are at most 253
 * characters), so nothing a lookup can match is left out.
 *
 * "The latest alerts naming X" (latestAlerts): one ordered scan per key, never
 * an OR. The planner keeps no statistics for a partial index's expression, so
 * it takes any value for 0.5% of alerts; with an OR of keys under ORDER BY
 * created_at DESC LIMIT n, that guess has it walk idx_alerts_created_at back
 * through every alert for a value that names none (seconds at a million
 * alerts). A single key's `expr = $1 ... ORDER BY created_at DESC LIMIT n` is
 * served in order by that key's (expr, created_at DESC) index and stops after
 * n rows, whatever the estimate, so the union of one such scan per key holds
 * the latest n of them all. Migration 043 also keeps statistics on each
 * expression (alertKeyStatsSql), so a common value's arm is read that way and
 * a rare one's as a small bitmap: either way a few times n rows at most.
 */

export const MAX_INDEXED_BYTES = 2000;

export type AlertKey =
  | 'source_ip'
  | 'client_ip'
  | 'dest_ip'
  | 'user'
  | 'target_user'
  | 'host'
  | 'domain'
  | 'lookalike'
  | 'user_id'
  | 'agent_id';

const EXPRESSIONS: Record<AlertKey, (field: (key: string) => string) => string> = {
  source_ip: (f) => f('source_ip'),
  client_ip: (f) => f('client_ip'),
  dest_ip: (f) => f('dest_ip'),
  user: (f) => `btrim(${f('user')})`,
  target_user: (f) => `btrim(${f('target_user')})`,
  host: (f) => `lower(btrim(${f('host')}))`,
  domain: (f) => `rtrim(lower(btrim(${f('domain')})), '.')`,
  lookalike: (f) => `rtrim(lower(btrim(${f('lookalike')})), '.')`,
  user_id: (f) => f('user_id'),
  agent_id: (f) => `lower(${f('agent_id')})`,
};

/** The expression for `key` on the matched_data column `column` (e.g. `a.matched_data`). */
export function alertKeyExpr(key: AlertKey, column = 'matched_data'): string {
  return EXPRESSIONS[key]((name) => `${column}->>'${name}'`);
}

/** The partial-index guard for `key`. */
export function alertKeyGuard(key: AlertKey, column = 'matched_data'): string {
  return `octet_length(${alertKeyExpr(key, column)}) <= ${MAX_INDEXED_BYTES}`;
}

/** `key` equals `param` (a bound parameter such as `$1`; `any`: a text[] parameter), index-served. */
export function alertKeyEquals(key: AlertKey, param: string, options: { column?: string; any?: boolean } = {}): string {
  const column = options.column ?? 'a.matched_data';
  const value = options.any ? `ANY(${param}::text[])` : param;
  return `(${alertKeyExpr(key, column)} = ${value} AND ${alertKeyGuard(key, column)})`;
}

/** The keys an alert names an IP under. */
export const IP_KEYS = ['source_ip', 'client_ip', 'dest_ip'] as const;

/**
 * An alert names the IP(s) in `param` as its source_ip, client_ip or dest_ip
 * (a BitmapOr over three indexes): for counting them. To list the latest of
 * them, use latestAlerts() over alertIpArms().
 */
export function alertIpMatch(param: string, options: { column?: string; any?: boolean } = {}): string {
  return `(${IP_KEYS.map((key) => alertKeyEquals(key, param, options)).join(' OR ')})`;
}

/** The IP in `param` (one value) under each IP key: latestAlerts() arms. */
export function alertIpArms(param: string): string[] {
  return IP_KEYS.map((key) => alertKeyEquals(key, param));
}

/**
 * The latest `limit` alerts (`a`) matching any of `arms`, as a UNION of one
 * scan per arm, each `ORDER BY a.created_at DESC LIMIT limit` (see the top of
 * this file for why never an OR). Each arm must be a predicate one index
 * serves in created_at order: alertKeyEquals() with a single value (optionally
 * with its source, `a.source = '...' AND ...`), `a.rule_id = $n`;
 * `a.asset_id = $n` is read whole and sorted (an asset's own alerts are few).
 * `where` (e.g. the window) is added to every arm; `select` lists what each
 * arm returns, computed from `a` alone, so an alert that several arms find is
 * one row of the UNION. The caller orders and limits the union again.
 */
export function latestAlerts(arms: readonly string[], select: string, limit: number, where = ''): string {
  if (arms.length === 0) throw new Error('latestAlerts: no arms');
  if (!Number.isInteger(limit) || limit < 1) throw new Error('latestAlerts: limit must be a positive integer');
  const extra = where ? ` AND ${where}` : '';
  return arms.map((arm) => `(SELECT ${select} FROM alerts a WHERE ${arm}${extra} ORDER BY a.created_at DESC LIMIT ${limit})`).join(' UNION ');
}

/** The indexes of migration 043 on alerts' matched_data keys: name, key, and the source they are limited to. */
export const ALERT_KEY_INDEXES: ReadonlyArray<{ name: string; key: AlertKey; source?: string }> = [
  { name: 'idx_graph_alerts_md_source_ip', key: 'source_ip' },
  { name: 'idx_graph_alerts_md_client_ip', key: 'client_ip' },
  { name: 'idx_graph_alerts_md_dest_ip', key: 'dest_ip' },
  { name: 'idx_graph_alerts_md_user', key: 'user' },
  { name: 'idx_graph_alerts_md_target_user', key: 'target_user' },
  { name: 'idx_graph_alerts_md_host', key: 'host' },
  { name: 'idx_graph_alerts_md_domain', key: 'domain' },
  { name: 'idx_graph_alerts_auth_user_id', key: 'user_id', source: 'siembox-auth' },
  { name: 'idx_graph_alerts_edr_agent_id', key: 'agent_id', source: 'edr' },
  { name: 'idx_graph_alerts_dm_lookalike', key: 'lookalike', source: 'domain-monitor' },
];

/** The CREATE INDEX statement migration 043 holds for an entry of ALERT_KEY_INDEXES. */
export function alertKeyIndexSql(entry: (typeof ALERT_KEY_INDEXES)[number]): string {
  const where = entry.source ? `source = '${entry.source}' AND ${alertKeyGuard(entry.key)}` : alertKeyGuard(entry.key);
  return `CREATE INDEX IF NOT EXISTS ${entry.name} ON alerts ((${alertKeyExpr(entry.key)}), created_at DESC) WHERE ${where};`;
}

/** The name of the statistics object migration 043 keeps on an entry's expression. */
export function alertKeyStatsName(entry: (typeof ALERT_KEY_INDEXES)[number]): string {
  return `${entry.name.replace(/^idx_/, '')}_stats`;
}

/**
 * The CREATE STATISTICS statement migration 043 holds for an entry: the
 * planner's statistics on the index's expression, which it keeps for a full
 * index but not a partial one. With them a common value is known to be common,
 * so its arm of latestAlerts() is read in index order and stops at the limit,
 * rather than as a bitmap of every alert naming it.
 */
export function alertKeyStatsSql(entry: (typeof ALERT_KEY_INDEXES)[number]): string {
  return `CREATE STATISTICS IF NOT EXISTS ${alertKeyStatsName(entry)} ON (${alertKeyExpr(entry.key)}) FROM alerts;`;
}
