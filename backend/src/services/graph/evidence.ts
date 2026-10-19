/**
 * GET /api/graph/evidence: the logs behind one dashed log relationship, on one
 * ingest day ("Show logs" on the graph page).
 *
 *   rel   a log relation, a -> b (signed_in_as, seen_on, user_on, connected_to,
 *         queried, sent_by, shipped_by)
 *   a, b  entity keys of the pair, in the relation's direction
 *   day   YYYY-MM-DD (default: the pair's latest day in graph_log_edges)
 *   limit 1-20
 *
 * The predicate per relation is fixed here and uses the rollup's own key
 * functions (graph_ip, graph_user, graph_log_host, graph_domain), so a log is
 * listed exactly when it fed that edge; the caller supplies values only. One
 * day of parsed_logs by idx_parsed_logs_created_at (plus the GIN on
 * parsed_data for an IPv4 actor), under a 2 s statement timeout: a day too
 * busy to list in time answers partial: true. A day past the log retention
 * answers expired: true (its logs are deleted; the edge outlives them only
 * when the retention setting says so).
 */
import net from 'net';
import { runBudgeted, type Query } from './budget';
import { badParam } from './errors';
import type { EntityRef } from './entityKey';
import { sanitizeText } from './labels';
import { readLogEdgeState, LOG_EDGE_RELS, type LogEdgeRel } from './logEdgeRollup';
import { withSlot, type Caller, type GraphDeps } from './neighborhood';
import { shipperTags } from './shipperTags';
import type { EvidenceLog, EvidenceResponse, NodeType } from './types';
import { canSeeType } from './visibility';

export const EVIDENCE_STATEMENT_TIMEOUT_MS = 2000;
export const MAX_EVIDENCE = 20;
export const MAX_MESSAGE = 500;
const MAX_DAYS = 90;

const DEVICE: readonly NodeType[] = ['host', 'ip'];
/** The (a, b) types each relation joins. */
export const EVIDENCE_TYPES: Record<LogEdgeRel, { a: readonly NodeType[]; b: readonly NodeType[] }> = {
  signed_in_as: { a: ['ip'], b: ['user'] },
  seen_on: { a: ['ip'], b: DEVICE },
  user_on: { a: ['user'], b: DEVICE },
  connected_to: { a: ['ip'], b: ['ip'] },
  queried: { a: ['ip'], b: ['domain'] },
  sent_by: { a: ['host'], b: ['ip'] },
  shipped_by: { a: DEVICE, b: ['shipper', 'shipper_tag'] },
};

export function isLogEdgeRel(rel: unknown): rel is LogEdgeRel {
  return typeof rel === 'string' && (LOG_EDGE_RELS as readonly string[]).includes(rel);
}

export interface EvidenceParams {
  rel: LogEdgeRel;
  a: EntityRef;
  b: EntityRef;
  day?: string;
  limit: number;
}

/** Validate the pair against the relation (400 GRAPH_BAD_PARAM otherwise). */
export function checkEvidencePair(params: Pick<EvidenceParams, 'rel' | 'a' | 'b'>): void {
  const types = EVIDENCE_TYPES[params.rel];
  if (!types.a.includes(params.a.type) || !types.b.includes(params.b.type)) {
    throw badParam(`${params.rel} links a ${types.a.join(' or ')} to a ${types.b.join(' or ')}`);
  }
}

const ACTOR = `pl.parser_id IS NOT NULL
  AND graph_ip(pl.parsed_data->>'source_ip') = $A
  AND graph_ip(pl.parsed_data->>'source_ip') IS DISTINCT FROM graph_ip(pl.parsed_data->>'observer_ip')`;

/** The device a log came from: the header host, else the sender. */
function device(ref: EntityRef, slot: string): string {
  return ref.type === 'host'
    ? `graph_log_host(rl.hostname) = ${slot}`
    : `graph_log_host(rl.hostname) IS NULL AND graph_ip(rl.source_ip) = ${slot}`;
}

/** WHERE clause (beyond the day) and its values for $A, $B (and $T: shipper tags). */
function predicate(params: EvidenceParams, tags: string[]): { sql: string; values: Record<string, unknown> } {
  const { rel, a, b } = params;
  // The GIN on parsed_data narrows the day to the actor's logs; the canonical
  // check below is what decides. IPv4 is written one way only.
  const actorGin = net.isIPv4(a.key) ? ` AND pl.parsed_data @> jsonb_build_object('source_ip', $A::text)` : '';
  switch (rel) {
    case 'signed_in_as':
      return { sql: `${ACTOR}${actorGin} AND graph_user(pl.parsed_data->>'user') = $B`, values: { A: a.key, B: b.key } };
    case 'seen_on':
      return { sql: `${ACTOR}${actorGin} AND ${device(b, '$B')}`, values: { A: a.key, B: b.key } };
    case 'user_on':
      return {
        sql: `pl.parser_id IS NOT NULL AND pl.parsed_data @> jsonb_build_object('user', $A::text)
              AND graph_user(pl.parsed_data->>'user') = $A AND ${device(b, '$B')}`,
        values: { A: a.key, B: b.key },
      };
    case 'connected_to':
      return { sql: `${ACTOR}${actorGin} AND graph_ip(pl.parsed_data->>'dest_ip') = $B`, values: { A: a.key, B: b.key } };
    case 'queried':
      return { sql: `${ACTOR}${actorGin} AND graph_domain(pl.parsed_data->>'domain') = $B`, values: { A: a.key, B: b.key } };
    case 'sent_by':
      return { sql: `graph_log_host(rl.hostname) = $A AND graph_ip(rl.source_ip) = $B`, values: { A: a.key, B: b.key } };
    case 'shipped_by':
      return { sql: `${device(a, '$A')} AND lower(btrim(rl.shipper_id)) = ANY($T::text[])`, values: { A: a.key, T: tags } };
  }
}

/** Number the named slots ($A, $B, $T) after $1 (day) and $2 (limit). */
function bindSlots(sql: string, values: Record<string, unknown>): { sql: string; params: unknown[] } {
  const params: unknown[] = [];
  const index = new Map<string, number>();
  const out = sql.replace(/\$([ABT])\b/g, (_m, name: string) => {
    if (!index.has(name)) {
      params.push(values[name]);
      index.set(name, params.length + 2);
    }
    return `$${index.get(name)}`;
  });
  return { sql: out, params };
}

const iso = (value: unknown): string | null => {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  return typeof value === 'string' ? value : null;
};
const text = (value: unknown, max = 255): string | null => (value === null || value === undefined ? null : sanitizeText(String(value), max));

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export function parseDay(raw: string | undefined): string | undefined {
  if (raw === undefined || raw === '') return undefined;
  const ms = Date.parse(`${raw}T00:00:00Z`);
  if (!DAY_PATTERN.test(raw) || Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== raw) {
    throw badParam('day must be a date, YYYY-MM-DD');
  }
  return raw;
}

/** The pair's b-side rows: a shipper is its tags. */
async function bSide(q: Query, b: EntityRef): Promise<{ type: NodeType; values: string[] }> {
  if (b.type === 'shipper') return { type: 'shipper_tag', values: await shipperTags.tagsOf(q, Number(b.key)) };
  return { type: b.type, values: [b.key] };
}

export async function getEvidence(deps: GraphDeps, caller: Caller, params: EvidenceParams): Promise<EvidenceResponse> {
  checkEvidencePair(params);
  for (const ref of [params.a, params.b]) {
    if (!canSeeType(caller.role, ref.type)) throw badParam(`a ${ref.type} isn't something your role can see`);
  }
  const started = deps.now();
  return withSlot(deps, caller, () =>
    runBudgeted(
      deps.acquire,
      async (budget) => {
        const out: EvidenceResponse = { day: null, days: [], logs: [], partial: false, expired: false, elapsed_ms: 0 };
        const meta = await budget.step('evidence_days', async (q) => {
          const state = await readLogEdgeState(q);
          const side = await bSide(q, params.b);
          const rows = side.values.length
            ? await q<{ day: string }>(
                `SELECT DISTINCT to_char(day, 'YYYY-MM-DD') AS day FROM graph_log_edges
                  WHERE a_type = $1 AND a_value = $2 AND rel = $3 AND b_type = $4 AND b_value = ANY($5::text[])
                  ORDER BY day DESC LIMIT ${MAX_DAYS}`,
                [params.a.type, params.a.key, params.rel, side.type, side.values]
              )
            : [];
          return { retention: state.retentionDays, tags: side.type === 'shipper_tag' ? side.values : [], days: rows.map((r) => r.day) };
        });
        if (meta.status !== 'ok') {
          out.partial = true;
          return { ...out, elapsed_ms: deps.now() - started };
        }
        out.days = meta.value.days;
        out.day = params.day ?? out.days[0] ?? null;
        if (!out.day) return { ...out, elapsed_ms: deps.now() - started };
        const retention = meta.value.retention;
        if (retention > 0) {
          const oldest = new Date(deps.now() - retention * 86_400_000).toISOString().slice(0, 10);
          if (out.day < oldest) return { ...out, expired: true, elapsed_ms: deps.now() - started };
        }
        const where = predicate(params, meta.value.tags);
        const bound = bindSlots(where.sql, where.values);
        const logs = await budget.step('evidence_logs', (q) =>
          q<Record<string, unknown>>(
            `SELECT pl.id, pl.created_at, pl."timestamp", pl.event_type, p.name AS parser,
                    pl.parsed_data->>'service' AS service, rl.hostname, rl.source_ip AS sender_ip,
                    left(COALESCE(pl.parsed_data->>'message', rl.raw_message), ${MAX_MESSAGE}) AS message
               FROM parsed_logs pl
               JOIN raw_logs rl ON rl.id = pl.raw_log_id
               LEFT JOIN parsers p ON p.id = pl.parser_id
              WHERE pl.created_at >= $1::date AND pl.created_at < $1::date + 1
                AND ${bound.sql}
              ORDER BY pl.created_at DESC
              LIMIT $2`,
            [out.day, params.limit, ...bound.params]
          )
        );
        if (logs.status !== 'ok') return { ...out, partial: true, elapsed_ms: deps.now() - started };
        out.logs = logs.value.map(
          (row): EvidenceLog => ({
            id: Number(row.id),
            created_at: iso(row.created_at),
            timestamp: iso(row.timestamp),
            event_type: text(row.event_type, 100),
            parser: text(row.parser),
            service: text(row.service),
            hostname: text(row.hostname),
            sender_ip: text(row.sender_ip, 45),
            message: sanitizeText(row.message ?? '', MAX_MESSAGE),
          })
        );
        return { ...out, elapsed_ms: deps.now() - started };
      },
      { ...deps.budget, statementTimeoutMs: deps.budget?.statementTimeoutMs ?? EVIDENCE_STATEMENT_TIMEOUT_MS }
    )
  );
}
