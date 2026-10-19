/**
 * What every relation resolver shares: the relation definition, the page a
 * caller asks for, and helpers for paging in SQL or in memory.
 *
 * A resolver returns neighbour refs and canonical edges only; the node facts
 * are loaded afterwards for all nodes of a type at once (hydrate.ts), so a
 * relation never decides what a node carries. Every SQL value is a bound
 * parameter; JSON keys and ORDER BY expressions are constants of the code.
 */
import type { Query } from '../budget';
import type { EntityRef } from '../entityKey';
import type { ResolvedWindow } from '../window';
import type { EdgeStyle, GraphEdge, NodeType, Origin, RelId, Role } from '../types';
import { TOTAL_CAP } from '../types';
import type { LogEdgeState } from '../logEdgeRollup';

export type SortKey = 'count' | 'last_seen' | 'first_seen';

export interface PageRequest {
  limit: number;
  offset: number;
  /** Lower-cased substring of the neighbour's label. */
  q?: string;
  sort?: SortKey;
  order?: 'asc' | 'desc';
}

/** The centre's own row, for the relations derived from it (an alert's matched_data keys, an asset's IP...). */
export interface CenterInfo {
  exists: boolean;
  row: Record<string, unknown> | null;
}

export interface ResolverCtx {
  role: Role;
  window: ResolvedWindow;
  vulnStatus: 'open' | 'all';
  center: EntityRef;
  centerInfo: CenterInfo;
  /** The rollup's state, read once per request when a log relationship runs. */
  logs?: LogEdgeState;
}

export type EdgeSpec = Omit<GraphEdge, 'id'>;

export interface NeighborItem {
  ref: EntityRef;
  edge: EdgeSpec;
  /** Used when the node's own row gives no label (an account's username for a non-admin). */
  labelHint?: string;
  /** Nodes and edges that come with this neighbour (a log's device brings its shipper). */
  extra?: Array<{ ref: EntityRef; edge: EdgeSpec; labelHint?: string }>;
}

export interface RelationPage {
  items: NeighborItem[];
  /** Distinct neighbours, at most TOTAL_CAP. */
  total: number;
  totalCapped: boolean;
  note?: string;
  /**
   * The neighbours' type when it isn't the definition's: a log's device is a
   * host, or the sender's ip when the log named no host (alert_device).
   */
  neighborType?: NodeType;
  /**
   * The search box's filter is still to be applied: `items` is the whole
   * (small, sorted) list, unpaged, because a record neighbour's label (a
   * rule's name, an asset's host name) is known only once its node is loaded.
   * The caller filters on the labels and pages it with filterByLabel().
   */
  labelFilterPending?: boolean;
}

export interface RelationDef {
  rel: RelId;
  label: string;
  /** The centre type this definition is for: (center, rel) is unique. */
  center: NodeType;
  neighborType: NodeType;
  origin: Origin;
  style: EdgeStyle;
  /** Roles that may run it, beyond seeing the neighbour type (the sign-in relations: admin). */
  roles?: readonly Role[];
  /** Read from graph_log_edges: the request reads the rollup's state first. */
  rollup?: boolean;
  fetch(q: Query, ctx: ResolverCtx, page: PageRequest): Promise<RelationPage>;
}

export const EMPTY_PAGE: RelationPage = { items: [], total: 0, totalCapped: false };

/** `edge` from `source` to `target` (node ids), in the relation's canonical direction. */
export function edgeSpec(
  rel: RelId,
  source: EntityRef,
  target: EntityRef,
  origin: Origin,
  style: EdgeStyle,
  extra: Partial<Omit<GraphEdge, 'id' | 'rel' | 'source' | 'target' | 'origin' | 'style'>> = {}
): EdgeSpec {
  return { source: source.id, target: target.id, rel, origin, style, ...extra };
}

export function edgeId(edge: Pick<GraphEdge, 'rel' | 'source' | 'target'>): string {
  return `${edge.rel}|${edge.source}|${edge.target}`;
}

/** A LIKE pattern matching `text` anywhere, with LIKE's own characters escaped (ESCAPE '\'). */
export function containsPattern(text: string): string {
  return `%${text.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
}

/** A LIKE pattern matching values that start with `text`. */
export function prefixPattern(text: string): string {
  return `${text.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
}

const sortValue = (item: NeighborItem, sort: SortKey): number => {
  if (sort === 'count') return item.edge.count ?? 0;
  const at = sort === 'first_seen' ? item.edge.first_seen : item.edge.last_seen;
  return at ? Date.parse(at) : 0;
};

const counted = (n: number) => ({ total: Math.min(n, TOTAL_CAP), totalCapped: n > TOTAL_CAP });

/**
 * Page a small, already-complete list in memory (the relations read off one
 * row). With a search (`q`) the list comes back whole and sorted, marked
 * labelFilterPending: the filter applies to the neighbours' labels, which
 * the caller has only once it has loaded the nodes (filterByLabel()).
 */
export function pageInMemory(all: NeighborItem[], page: PageRequest, note?: string): RelationPage {
  let items = all;
  if (page.sort) {
    const dir = page.order === 'asc' ? 1 : -1;
    const sort = page.sort;
    items = [...items].sort((a, b) => dir * (sortValue(a, sort) - sortValue(b, sort)));
  } else if (page.order === 'asc') {
    items = [...items].reverse();
  }
  const extra = note ? { note } : {};
  if (page.q) return { items, ...counted(items.length), ...extra, labelFilterPending: true };
  return { items: items.slice(page.offset, page.offset + page.limit), ...counted(items.length), ...extra };
}

/**
 * The page of a labelFilterPending list: the items whose label (`labelOf`;
 * null leaves the item out, e.g. a record that no longer exists) holds the
 * search text, then `offset` and `limit`, as pagedSql() filters on the label
 * in SQL. Anything else passes through unchanged.
 */
export function filterByLabel(result: RelationPage, page: PageRequest, labelOf: (item: NeighborItem) => string | null): RelationPage {
  if (!result.labelFilterPending) return result;
  const needle = (page.q ?? '').toLowerCase();
  const matched = result.items.filter((item) => labelOf(item)?.toLowerCase().includes(needle) ?? false);
  return {
    items: matched.slice(page.offset, page.offset + page.limit),
    ...counted(matched.length),
    ...(result.note ? { note: result.note } : {}),
    ...(result.neighborType ? { neighborType: result.neighborType } : {}),
  };
}

export interface PagedSql<T> {
  rows: T[];
  total: number;
  totalCapped: boolean;
}

/** Where pagedSql() puts the search filter in a relation's WHERE clause. */
export const LABEL_FILTER = '/*label filter*/';

/**
 * Page a relation in SQL. `inner` selects the neighbours, ordered so its first
 * TOTAL_CAP + 1 rows are the ones that count, and holds LABEL_FILTER in its
 * WHERE clause (once per arm of a union): the search box's filter on `label`
 * (the neighbour's label as an SQL expression) goes there, before the cap, so
 * a search finds matches among all of them. `orderBy` orders the page over `c`, the capped rows.
 * Params of `inner` are $1..$n; this adds the rest.
 */
export async function pagedSql<T extends Record<string, unknown>>(
  q: Query,
  inner: string,
  params: unknown[],
  orderBy: string,
  page: PageRequest,
  label: string
): Promise<PagedSql<T>> {
  if (!inner.includes(LABEL_FILTER)) throw new Error('pagedSql: the relation query has no LABEL_FILTER');
  const all = [...params];
  const bind = (value: unknown) => {
    all.push(value);
    return `$${all.length}`;
  };
  const filter = page.q ? `AND (${label}) ILIKE ${bind(containsPattern(page.q))} ESCAPE '\\'` : '';
  // Every LABEL_FILTER gets it (a union of arms has one per arm), all with the same parameter.
  const base = `WITH c AS MATERIALIZED (${inner.split(LABEL_FILTER).join(filter)} LIMIT ${TOTAL_CAP + 1})`;
  const countParams = [...all];
  const rows = await q<T & { graph_total: string }>(
    `${base}
     SELECT c.*, count(*) OVER () AS graph_total
       FROM c ORDER BY ${orderBy} LIMIT ${bind(page.limit)} OFFSET ${bind(page.offset)}`,
    all
  );
  if (rows.length > 0) return { rows, ...counted(Number(rows[0].graph_total)) };
  if (page.offset === 0) return { rows: [], total: 0, totalCapped: false };
  // Past the end: count without a page.
  const [counts] = await q<{ total: string }>(`${base} SELECT count(*) AS total FROM c`, countParams);
  return { rows: [], ...counted(Number(counts?.total ?? 0)) };
}

/** ISO text of a pg timestamp value, or undefined. */
export function iso(value: unknown): string | undefined {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
  if (typeof value === 'string' && value) {
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
  }
  return undefined;
}

/** Order direction SQL for a page (constants only). */
export const dir = (page: PageRequest, fallback: 'ASC' | 'DESC' = 'DESC') =>
  page.order === 'asc' ? 'ASC' : page.order === 'desc' ? 'DESC' : fallback;
