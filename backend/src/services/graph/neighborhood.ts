/**
 * GET /api/graph/neighborhood and /relation: orchestration.
 *
 *   1. The role must be able to expand the centre's type (else 404).
 *   2. Cache (20 s, per visibility class) -> semaphore (4 global, 2 per user,
 *      1 s wait) -> one budgeted read-only transaction (budget.ts).
 *   3. The centre's own row; then each relation the role may run
 *      (relations.ts), each in its own savepoint: the top `limit` neighbours
 *      plus a RelationGroup with the total (counted over at most 1,001 rows).
 *   4. Facts for every node of a type at once (hydrate.ts), the response caps
 *      (300 nodes, 600 edges), then filterGraph() for the role.
 *
 * Partial answers are 200s: a relation that timed out is a group with status
 * 'timeout' and its origin's source 'partial'. Only when every relation timed
 * out (or no slot or connection was free) is the answer 503 GRAPH_BUSY.
 */
import { runBudgeted, type BudgetContext, type BudgetOptions } from './budget';
import type { QueryClient } from '../shippers/snapshotCache';
import { isDatabaseBusy } from '../shippers/snapshotCache';
import { GraphBusyError, notAvailable } from './errors';
import type { EntityRef } from './entityKey';
import { hydrate } from './hydrate';
import type { GraphCache, Semaphore } from './limits';
import { findRelation, loadCenter, RELATIONS, relationsFor, VALUE_TYPES } from './relations';
import { edgeId, filterByLabel, type CenterInfo, type NeighborItem, type PageRequest, type RelationDef, type RelationPage, type ResolverCtx, type SortKey } from './resolvers/common';
import {
  MAX_RESPONSE_EDGES,
  MAX_RESPONSE_NODES,
  VERY_COMMON,
  type GraphEdge,
  type GraphNode,
  type GroupStatus,
  type NeighborhoodResponse,
  type Origin,
  type RelationGroup,
  type RelationResponse,
  type Role,
  type SourceStatus,
  TOTAL_CAP,
} from './types';
import { canExpandType, filterGraph, visibilityClass } from './visibility';
import { dayRange, windowCacheKey, type ResolvedWindow } from './window';
import { logSourceStatus, readLogEdgeState, type LogEdgeState } from './logEdgeRollup';

export interface GraphDeps {
  acquire: () => Promise<QueryClient>;
  semaphore: Semaphore;
  cache: GraphCache;
  now: () => number;
  budget?: Partial<BudgetOptions>;
  catalog?: readonly RelationDef[];
}

export interface Caller {
  id: number;
  role: Role;
}

export interface NeighborhoodParams {
  center: EntityRef;
  window: ResolvedWindow;
  /** Neighbours shown per relation, 1-25. */
  limit: number;
  /** Origins to run (default: every one the role may see). */
  include?: Origin[];
  vulnStatus: 'open' | 'all';
}

export interface RelationParams {
  center: EntityRef;
  rel: string;
  window: ResolvedWindow;
  limit: number;
  offset: number;
  q?: string;
  sort?: SortKey;
  order?: 'asc' | 'desc';
  vulnStatus: 'open' | 'all';
}

/** Run `work` in a semaphore slot; a busy pool is a busy graph. */
export async function withSlot<T>(deps: GraphDeps, caller: Caller, work: () => Promise<T>): Promise<T> {
  const release = await deps.semaphore.acquire(String(caller.id));
  try {
    return await work();
  } catch (err) {
    if (isDatabaseBusy(err)) throw new GraphBusyError();
    throw err;
  } finally {
    release();
  }
}

async function readCenter(budget: BudgetContext, center: EntityRef): Promise<CenterInfo> {
  const result = await budget.step('centre', (q) => loadCenter(q, center));
  if (result.status === 'timeout') throw new GraphBusyError();
  if (result.status === 'unavailable') throw new Error('Context Graph: the centre could not be read');
  return result.value;
}

const fallbackNode = (ref: EntityRef): GraphNode => ({ id: ref.id, type: ref.type, key: ref.key, label: ref.key, facts: {}, flags: [], expandable: true });

/**
 * The rollup's state, when the plan reads it: one small step. Unreadable (a
 * timeout, or the table missing) leaves it undefined: the log relations run
 * as they are and say nothing about lag.
 */
async function readLogs(budget: BudgetContext, plan: RelationDef[]): Promise<LogEdgeState | undefined> {
  if (!plan.some((def) => def.rollup)) return undefined;
  const result = await budget.step('log_state', (q) => readLogEdgeState(q));
  return result.status === 'ok' ? result.value : undefined;
}

/** sources.logs: the groups' own status, then what the rollup says (disabled, building, behind, incomplete days). */
function withRollup(base: SourceStatus, logs: LogEdgeState | undefined, win: ResolvedWindow, nowMs: number): SourceStatus {
  if (!logs) return base;
  const rollup = logSourceStatus(logs, dayRange(win), nowMs);
  const { status, ...facts } = rollup;
  if (status === 'disabled') return base.status === 'ok' || base.status === 'disabled' ? { status: 'disabled' } : base;
  return { ...facts, status: base.status === 'ok' ? status : base.status };
}

function sourceStatus(statuses: GroupStatus[], partialFacts: boolean): SourceStatus {
  if (statuses.length > 0 && statuses.every((s) => s === 'timeout')) return { status: 'timeout' };
  if (statuses.some((s) => s !== 'ok') || partialFacts) return { status: 'partial' };
  return { status: 'ok' };
}

interface Computed<T> {
  value: T;
  /** Something timed out or failed: don't cache it. */
  incomplete: boolean;
}

async function computeNeighborhood(
  deps: GraphDeps,
  caller: Caller,
  params: NeighborhoodParams,
  plan: RelationDef[]
): Promise<Computed<Omit<NeighborhoodResponse, 'cached'>>> {
  const started = deps.now();
  return runBudgeted(
    deps.acquire,
    async (budget) => {
      const centerInfo = await readCenter(budget, params.center);
      const logs = await readLogs(budget, plan);
      const ctx: ResolverCtx = { role: caller.role, window: params.window, vulnStatus: params.vulnStatus, center: params.center, centerInfo, logs };
      const isValue = VALUE_TYPES.has(params.center.type);
      const runs: Array<{ def: RelationDef; status: GroupStatus; page: RelationPage }> = [];
      if (isValue || centerInfo.exists) {
        for (const def of plan) {
          const page: PageRequest = { limit: params.limit, offset: 0 };
          const result = await budget.step(def.rel, (q) => def.fetch(q, ctx, page));
          runs.push(
            result.status === 'ok'
              ? { def, status: 'ok', page: result.value }
              : { def, status: result.status, page: { items: [], total: 0, totalCapped: false } }
          );
        }
      }
      if (runs.length > 0 && runs.every((run) => run.status === 'timeout')) throw new GraphBusyError();

      // Every node the answer may hold, for one facts lookup per type.
      const refs: EntityRef[] = [params.center];
      const hints = new Map<string, string>();
      const note = (item: { ref: EntityRef; labelHint?: string }) => {
        refs.push(item.ref);
        if (item.labelHint && !hints.has(item.ref.id)) hints.set(item.ref.id, item.labelHint);
      };
      for (const run of runs) {
        for (const item of run.page.items) {
          note(item);
          for (const extra of item.extra ?? []) note(extra);
        }
      }
      const facts = await hydrate(budget, caller.role, refs, hints);

      const nodeIds = new Set<string>([params.center.id]);
      const edges = new Map<string, GraphEdge>();
      const groups: RelationGroup[] = [];
      for (const run of runs) {
        let shown = 0;
        for (const item of run.page.items) {
          if (facts.missing.has(item.ref.id)) continue;
          const parts: NeighborItem[] = [item, ...(item.extra ?? [])].filter((part) => !facts.missing.has(part.ref.id));
          const newNodes = new Set(parts.map((part) => part.ref.id).filter((id) => !nodeIds.has(id)));
          const newEdges = parts.map((part) => ({ ...part.edge, id: edgeId(part.edge) })).filter((edge) => !edges.has(edge.id));
          if (nodeIds.size + newNodes.size > MAX_RESPONSE_NODES || edges.size + newEdges.length > MAX_RESPONSE_EDGES) break;
          for (const id of newNodes) nodeIds.add(id);
          for (const edge of newEdges) edges.set(edge.id, edge);
          shown++;
        }
        groups.push({
          rel: run.def.rel,
          label: run.def.label,
          neighbor_type: run.page.neighborType ?? run.def.neighborType,
          origin: run.def.origin,
          total: run.page.total,
          total_capped: run.page.totalCapped,
          shown,
          very_common: run.page.total >= VERY_COMMON,
          status: run.status,
          ...(run.page.note ? { note: run.page.note } : {}),
        });
      }

      const nodes = [...nodeIds].map((id) => {
        const node = facts.nodes.get(id);
        return node ?? fallbackNode(refs.find((ref) => ref.id === id)!);
      });
      const visible = filterGraph(caller.role, nodes, [...edges.values()].filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)));
      const centerNode = visible.nodes.find((node) => node.id === params.center.id) ?? fallbackNode(params.center);
      // A relation that timed out may have held something: only a complete
      // answer with nothing in it says that nothing links to a value.
      const exists = isValue ? groups.some((group) => group.total > 0 || group.status !== 'ok') : centerInfo.exists;

      const sources: Partial<Record<Origin, SourceStatus>> = {};
      for (const origin of new Set(plan.map((def) => def.origin))) {
        const base = sourceStatus(
          groups.filter((group) => group.origin === origin).map((group) => group.status),
          facts.partial
        );
        sources[origin] = origin === 'logs' ? withRollup(base, logs, params.window, deps.now()) : base;
      }

      const value: Omit<NeighborhoodResponse, 'cached'> = {
        center: { ...centerNode, exists },
        window: { from: params.window.from, to: params.window.to, preset: params.window.preset },
        nodes: visible.nodes,
        edges: visible.edges,
        groups,
        sources,
        generated_at: new Date(deps.now()).toISOString(),
        elapsed_ms: deps.now() - started,
      };
      return { value, incomplete: facts.partial || groups.some((group) => group.status !== 'ok') };
    },
    deps.budget
  );
}

export async function getNeighborhood(deps: GraphDeps, caller: Caller, params: NeighborhoodParams): Promise<NeighborhoodResponse> {
  if (!canExpandType(caller.role, params.center.type)) {
    throw notAvailable(`a ${params.center.type} can't be expanded with your role`);
  }
  const plan = relationsFor(params.center.type, caller.role, params.include, deps.catalog ?? RELATIONS);
  const key = JSON.stringify([
    'neighborhood',
    visibilityClass(caller.role),
    params.center.id,
    windowCacheKey(params.window),
    params.limit,
    params.include ? [...params.include].sort() : null,
    params.vulnStatus,
  ]);
  const { value, cached } = await deps.cache.get(
    key,
    () => withSlot(deps, caller, () => computeNeighborhood(deps, caller, params, plan)),
    (result) => !result.incomplete
  );
  return { ...value.value, cached };
}

async function computeRelation(
  deps: GraphDeps,
  caller: Caller,
  params: RelationParams,
  def: RelationDef
): Promise<Computed<Omit<RelationResponse, 'cached'>>> {
  const started = deps.now();
  return runBudgeted(
    deps.acquire,
    async (budget) => {
      const centerInfo = await readCenter(budget, params.center);
      const logs = await readLogs(budget, [def]);
      const ctx: ResolverCtx = { role: caller.role, window: params.window, vulnStatus: params.vulnStatus, center: params.center, centerInfo, logs };
      const page: PageRequest = { limit: params.limit, offset: params.offset, q: params.q, sort: params.sort, order: params.order };
      let status: GroupStatus = 'ok';
      let result: RelationPage = { items: [], total: 0, totalCapped: false };
      if (VALUE_TYPES.has(params.center.type) || centerInfo.exists) {
        const step = await budget.step(def.rel, (q) => def.fetch(q, ctx, page));
        if (step.status === 'timeout') throw new GraphBusyError();
        if (step.status === 'ok') result = step.value;
        else status = step.status;
      }
      const facts = await hydrate(budget, caller.role, result.items.map((item) => item.ref), new Map(result.items.filter((i) => i.labelHint).map((i) => [i.ref.id, i.labelHint!])));
      // A list paged in memory is searched now, on the labels the nodes have.
      result = filterByLabel(result, page, (item) => (facts.missing.has(item.ref.id) ? null : (facts.nodes.get(item.ref.id)?.label ?? null)));
      const items: RelationResponse['items'] = [];
      for (const item of result.items) {
        if (facts.missing.has(item.ref.id)) continue;
        const node = facts.nodes.get(item.ref.id) ?? fallbackNode(item.ref);
        // The edge's other end is the centre: keep only pairs the role sees in full.
        const visible = filterGraph(caller.role, [node, fallbackNode(params.center)], [{ ...item.edge, id: edgeId(item.edge) }]);
        if (visible.nodes.length < 2 || visible.edges.length < 1) continue;
        items.push({ node: visible.nodes.find((n) => n.id === node.id)!, edge: visible.edges[0] });
      }
      const end = params.offset + result.items.length;
      const value: Omit<RelationResponse, 'cached'> = {
        rel: def.rel,
        total: result.total,
        total_capped: result.totalCapped,
        items,
        next_offset: result.items.length > 0 && end < Math.min(result.total, TOTAL_CAP) ? end : null,
        status,
        ...(result.note ? { note: result.note } : {}),
        window: { from: params.window.from, to: params.window.to, preset: params.window.preset },
        generated_at: new Date(deps.now()).toISOString(),
        elapsed_ms: deps.now() - started,
      };
      return { value, incomplete: status !== 'ok' || facts.partial };
    },
    deps.budget
  );
}

export async function getRelation(deps: GraphDeps, caller: Caller, params: RelationParams): Promise<RelationResponse> {
  const def = findRelation(params.center.type, params.rel, caller.role, deps.catalog ?? RELATIONS);
  if (!def) throw notAvailable(`${params.rel} is not a relation of a ${params.center.type} you can expand`);
  const key = JSON.stringify([
    'relation',
    visibilityClass(caller.role),
    params.center.id,
    def.rel,
    windowCacheKey(params.window),
    params.limit,
    params.offset,
    params.q ?? '',
    params.sort ?? '',
    params.order ?? '',
    params.vulnStatus,
  ]);
  const { value, cached } = await deps.cache.get(
    key,
    () => withSlot(deps, caller, () => computeRelation(deps, caller, params, def)),
    (result) => !result.incomplete
  );
  return { ...value.value, cached };
}
