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

/** An alert names the IP(s) in `param` as its source_ip, client_ip or dest_ip (a BitmapOr over three indexes). */
export function alertIpMatch(param: string, options: { column?: string; any?: boolean } = {}): string {
  return `(${(['source_ip', 'client_ip', 'dest_ip'] as const).map((key) => alertKeyEquals(key, param, options)).join(' OR ')})`;
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
