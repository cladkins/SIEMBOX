/**
 * The Context Graph page's state, as pure functions over plain data (so it
 * serializes, undoes and unit-tests without a canvas):
 *
 *   - merge: a neighbourhood answer or rows picked in a relation table join
 *     the graph, de-duplicated by id, within the canvas caps (500 nodes,
 *     1,500 edges); an expansion past them is refused whole;
 *   - groups: each expanded node keeps its relations' totals; what isn't on
 *     the canvas is one "+N more" group node per relation;
 *   - hide: a node goes with the leaves only it held; "Show hidden" brings
 *     them back; node types are hidden by the legend (hide=);
 *   - undo: snapshots of the above, at most 20;
 *   - path: the shortest path between two loaded nodes (breadth-first, over
 *     what is shown);
 *   - URL: the page's address is its state (entity=, window= or around=, x=,
 *     hide=, limit=, include=), parsed and written here.
 */
import { tryParseEntity, typeOfId } from './entityKey.ts';
import {
  DEFAULT_LIMIT,
  MAX_CANVAS_EDGES,
  MAX_CANVAS_NODES,
  MAX_CENTRES,
  MAX_EXPANDED,
  NODE_TYPES,
  ORIGINS,
  RELATION_LIMITS,
  TOTAL_CAP,
  WINDOW_PRESETS,
  type GraphEdge,
  type GraphNode,
  type NeighborhoodResponse,
  type NodeType,
  type Origin,
  type RelationGroup,
  type RelationItem,
  type RelationLimit,
  type RelId,
  type WindowPreset,
} from './types.ts';

export interface GraphModel {
  /** The view's centres, in URL order (1-5 node ids). */
  centres: string[];
  /** Every node loaded and not hidden by the user, by id. */
  nodes: Record<string, GraphNode>;
  edges: Record<string, GraphEdge>;
  /** The relations of each expanded node, from its last neighbourhood answer. */
  groups: Record<string, RelationGroup[]>;
  /** Expanded nodes, in the order they were expanded (centres first). */
  expanded: string[];
  /** Nodes the user hid, with what they took along; restored by showHidden(). */
  hidden: Record<string, GraphNode>;
  hiddenEdges: Record<string, GraphEdge>;
}

export function emptyModel(centres: string[] = []): GraphModel {
  return { centres: [...centres], nodes: {}, edges: {}, groups: {}, expanded: [], hidden: {}, hiddenEdges: {} };
}

export function nodeCount(model: GraphModel): number {
  return Object.keys(model.nodes).length;
}

export function edgeCount(model: GraphModel): number {
  return Object.keys(model.edges).length;
}

export function atNodeCap(model: GraphModel): boolean {
  return nodeCount(model) >= MAX_CANVAS_NODES;
}

export type MergeResult =
  | { ok: true; model: GraphModel; addedNodes: string[]; addedEdges: string[] }
  | { ok: false; reason: 'cap'; model: GraphModel };

/** Room left on the canvas. */
export function capacity(model: GraphModel): { nodes: number; edges: number } {
  return { nodes: MAX_CANVAS_NODES - nodeCount(model), edges: MAX_CANVAS_EDGES - edgeCount(model) };
}

/**
 * Nodes and edges not yet known (hidden ones stay hidden: an expansion
 * that reaches a hidden node updates it without showing it).
 */
function newParts(model: GraphModel, nodes: GraphNode[], edges: GraphEdge[]) {
  const addedNodes = nodes.filter((n) => !model.nodes[n.id] && !model.hidden[n.id]).map((n) => n.id);
  const known = (id: string) => !!model.nodes[id] || addedNodes.includes(id);
  const addedEdges = edges
    .filter((e) => !model.edges[e.id] && !model.hiddenEdges[e.id])
    .filter((e) => known(e.source) && known(e.target))
    .map((e) => e.id);
  return { addedNodes: [...new Set(addedNodes)], addedEdges: [...new Set(addedEdges)] };
}

function withParts(model: GraphModel, nodes: GraphNode[], edges: GraphEdge[]): GraphModel {
  const next: GraphModel = {
    ...model,
    nodes: { ...model.nodes },
    edges: { ...model.edges },
    hidden: { ...model.hidden },
    hiddenEdges: { ...model.hiddenEdges },
  };
  for (const node of nodes) {
    if (next.hidden[node.id]) next.hidden[node.id] = node;
    else next.nodes[node.id] = node;
  }
  const shown = (id: string) => !!next.nodes[id];
  const known = (id: string) => shown(id) || !!next.hidden[id];
  for (const edge of edges) {
    if (next.hiddenEdges[edge.id]) next.hiddenEdges[edge.id] = edge;
    else if (shown(edge.source) && shown(edge.target)) next.edges[edge.id] = edge;
    // An end is hidden: keep the edge with the hidden ones, for showHidden().
    else if (known(edge.source) && known(edge.target)) next.hiddenEdges[edge.id] = edge;
  }
  return next;
}

/**
 * Merge a neighbourhood answer for `expandedId` (a centre or an expanded
 * node; the answer's own centre id wins, as the server canonicalized it).
 * Refused whole when it would take the canvas past its caps.
 */
export function mergeNeighborhood(model: GraphModel, response: NeighborhoodResponse, requestedId?: string): MergeResult {
  const centreId = response.center.id;
  const center: GraphNode = { ...response.center };
  delete (center as Partial<NeighborhoodResponse['center']>).exists;
  const nodes = [center, ...response.nodes.filter((n) => n.id !== centreId)];
  const { addedNodes, addedEdges } = newParts(model, nodes, response.edges);
  const room = capacity(model);
  if (addedNodes.length > room.nodes || addedEdges.length > room.edges) return { ok: false, reason: 'cap', model };
  let next = withParts(model, nodes, response.edges);
  // The URL may have named it in another spelling: the server's id is the node's.
  if (requestedId && requestedId !== centreId) {
    next = renameNode(next, requestedId, centreId);
  }
  next.groups = { ...next.groups, [centreId]: response.groups.map((g) => ({ ...g })) };
  if (!next.expanded.includes(centreId)) next.expanded = [...next.expanded, centreId];
  return { ok: true, model: next, addedNodes, addedEdges };
}

/** `from` becomes `to` in the centres and the expanded list (a canonicalized id). */
function renameNode(model: GraphModel, from: string, to: string): GraphModel {
  const swap = (ids: string[]) => [...new Set(ids.map((id) => (id === from ? to : id)))];
  const nodes = { ...model.nodes };
  delete nodes[from];
  return { ...model, nodes, centres: swap(model.centres), expanded: swap(model.expanded) };
}

/**
 * Rows picked in the relation table of (`centreId`, `rel`) join the graph,
 * as many as fit; each row new to the canvas counts as one more shown in
 * that group, so its "+N more" shrinks.
 */
export function addRelationItems(
  model: GraphModel,
  centreId: string,
  rel: RelId,
  items: RelationItem[]
): { model: GraphModel; added: string[]; refused: number } {
  let next = model;
  const added: string[] = [];
  let refused = 0;
  let newlyShown = 0;
  for (const item of items) {
    const { addedNodes, addedEdges } = newParts(next, [item.node], [item.edge]);
    const room = capacity(next);
    if (addedNodes.length > room.nodes || addedEdges.length > room.edges) {
      refused++;
      continue;
    }
    const wasShown = !!next.edges[item.edge.id];
    next = withParts(next, [item.node], [item.edge]);
    if (!wasShown && next.edges[item.edge.id]) newlyShown++;
    added.push(...addedNodes);
  }
  if (newlyShown > 0 && next.groups[centreId]) {
    next = {
      ...next,
      groups: {
        ...next.groups,
        [centreId]: next.groups[centreId].map((g) => (g.rel === rel ? { ...g, shown: Math.min(g.total, g.shown + newlyShown) } : g)),
      },
    };
  }
  return { model: next, added, refused };
}

/** Neighbours of `id` over the edges shown. */
function adjacency(edges: Record<string, GraphEdge>): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  const link = (a: string, b: string) => {
    if (!adj.has(a)) adj.set(a, new Set());
    adj.get(a)!.add(b);
  };
  for (const edge of Object.values(edges)) {
    link(edge.source, edge.target);
    link(edge.target, edge.source);
  }
  return adj;
}

/**
 * Hide `ids` and the leaves only they held (nodes left with no link, that
 * are neither a centre nor expanded). Returns the model and every id hidden.
 */
export function hideNodes(model: GraphModel, ids: string[]): { model: GraphModel; hidden: string[] } {
  const keep = new Set([...model.centres, ...model.expanded]);
  const toHide = new Set(ids.filter((id) => model.nodes[id]));
  if (toHide.size === 0) return { model, hidden: [] };
  const adj = adjacency(model.edges);
  for (const id of [...toHide]) {
    for (const neighbour of adj.get(id) ?? []) {
      if (toHide.has(neighbour) || keep.has(neighbour)) continue;
      const others = [...(adj.get(neighbour) ?? [])].filter((other) => !toHide.has(other));
      if (others.length === 0) toHide.add(neighbour);
    }
  }
  const nodes = { ...model.nodes };
  const edges = { ...model.edges };
  const hidden = { ...model.hidden };
  const hiddenEdges = { ...model.hiddenEdges };
  for (const id of toHide) {
    hidden[id] = nodes[id];
    delete nodes[id];
  }
  for (const [id, edge] of Object.entries(edges)) {
    if (toHide.has(edge.source) || toHide.has(edge.target)) {
      hiddenEdges[id] = edge;
      delete edges[id];
    }
  }
  const groups = { ...model.groups };
  for (const id of toHide) delete groups[id];
  return {
    model: {
      ...model,
      nodes,
      edges,
      hidden,
      hiddenEdges,
      groups,
      centres: model.centres.filter((c) => !toHide.has(c)),
      expanded: model.expanded.filter((x) => !toHide.has(x)),
    },
    hidden: [...toHide],
  };
}

export function hiddenCount(model: GraphModel): number {
  return Object.keys(model.hidden).length;
}

/** Bring back every hidden node (as far as the caps allow) and the edges between shown nodes. */
export function showHidden(model: GraphModel): GraphModel {
  const nodes = { ...model.nodes };
  const hidden = { ...model.hidden };
  for (const [id, node] of Object.entries(model.hidden)) {
    if (Object.keys(nodes).length >= MAX_CANVAS_NODES) break;
    nodes[id] = node;
    delete hidden[id];
  }
  const edges = { ...model.edges };
  const hiddenEdges = { ...model.hiddenEdges };
  for (const [id, edge] of Object.entries(model.hiddenEdges)) {
    if (Object.keys(edges).length >= MAX_CANVAS_EDGES) break;
    if (nodes[edge.source] && nodes[edge.target]) {
      edges[id] = edge;
      delete hiddenEdges[id];
    }
  }
  return { ...model, nodes, edges, hidden, hiddenEdges };
}

/** What is left of a group off the canvas: a count, or null when it is "1,000+" and more than the canvas shows. */
export function remaining(group: RelationGroup): number | null {
  if (group.total_capped) return null;
  return Math.max(0, group.total - group.shown);
}

export const GROUP_PREFIX = 'group:';

/** The canvas id of the "+N more" node of (`nodeId`, `rel`). */
export function groupNodeId(nodeId: string, rel: RelId): string {
  return `${GROUP_PREFIX}${rel}|${nodeId}`;
}

export function parseGroupNodeId(id: string): { nodeId: string; rel: RelId } | null {
  if (!id.startsWith(GROUP_PREFIX)) return null;
  const rest = id.slice(GROUP_PREFIX.length);
  const bar = rest.indexOf('|');
  if (bar <= 0) return null;
  return { rel: rest.slice(0, bar), nodeId: rest.slice(bar + 1) };
}

export interface GroupNode {
  id: string;
  /** The expanded node it belongs to. */
  owner: string;
  group: RelationGroup;
  /** null: "1,000+". */
  remaining: number | null;
}

export interface VisibleGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  groupNodes: GroupNode[];
}

/**
 * What the canvas and the list show: the nodes not hidden by type, the edges
 * between them, and a group node for each relation with neighbours off the
 * canvas (counted from the server's totals).
 */
export function visibleGraph(model: GraphModel, hiddenTypes: readonly NodeType[] = []): VisibleGraph {
  const hiddenType = new Set(hiddenTypes);
  const nodes = Object.values(model.nodes).filter((n) => !hiddenType.has(n.type) || model.centres.includes(n.id));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = Object.values(model.edges).filter((e) => ids.has(e.source) && ids.has(e.target));
  const groupNodes: GroupNode[] = [];
  for (const owner of model.expanded) {
    if (!ids.has(owner)) continue;
    for (const group of model.groups[owner] ?? []) {
      if (group.status !== 'ok' || hiddenType.has(group.neighbor_type)) continue;
      const left = remaining(group);
      if (left === 0) continue;
      groupNodes.push({ id: groupNodeId(owner, group.rel), owner, group, remaining: left });
    }
  }
  return { nodes, edges, groupNodes };
}

/** Hops from the nearest centre over the edges shown (centres 0; unreachable nodes after the farthest). */
export function hopDistances(model: GraphModel): Record<string, number> {
  const adj = adjacency(model.edges);
  const dist: Record<string, number> = {};
  const queue: string[] = [];
  for (const c of model.centres) {
    if (model.nodes[c]) {
      dist[c] = 0;
      queue.push(c);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    for (const next of adj.get(id) ?? []) {
      if (dist[next] === undefined && model.nodes[next]) {
        dist[next] = dist[id] + 1;
        queue.push(next);
      }
    }
  }
  const far = Math.max(0, ...Object.values(dist)) + 1;
  for (const id of Object.keys(model.nodes)) if (dist[id] === undefined) dist[id] = far;
  return dist;
}

/** The shortest path from `a` to `b` over `edges` (unweighted, breadth-first), or null when they aren't connected. */
export function shortestPath(edges: GraphEdge[], a: string, b: string): { nodes: string[]; edges: string[] } | null {
  if (a === b) return { nodes: [a], edges: [] };
  const adj = new Map<string, Array<{ to: string; edge: string }>>();
  const link = (from: string, to: string, edge: string) => {
    if (!adj.has(from)) adj.set(from, []);
    adj.get(from)!.push({ to, edge });
  };
  for (const e of edges) {
    link(e.source, e.target, e.id);
    link(e.target, e.source, e.id);
  }
  const prev = new Map<string, { from: string; edge: string }>();
  const seen = new Set([a]);
  const queue = [a];
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    if (id === b) break;
    for (const { to, edge } of adj.get(id) ?? []) {
      if (seen.has(to)) continue;
      seen.add(to);
      prev.set(to, { from: id, edge });
      queue.push(to);
    }
  }
  if (!prev.has(b)) return null;
  const nodes = [b];
  const pathEdges: string[] = [];
  let at = b;
  while (at !== a) {
    const step = prev.get(at)!;
    pathEdges.unshift(step.edge);
    nodes.unshift(step.from);
    at = step.from;
  }
  return { nodes, edges: pathEdges };
}

/** Counts per type of the nodes loaded (the legend chips). */
export function typeCounts(model: GraphModel): Partial<Record<NodeType, number>> {
  const counts: Partial<Record<NodeType, number>> = {};
  for (const node of Object.values(model.nodes)) counts[node.type] = (counts[node.type] ?? 0) + 1;
  return counts;
}

// ---------------------------------------------------------------- undo

export const MAX_UNDO = 20;

/** Push a snapshot, keeping the newest MAX_UNDO. */
export function pushUndo(stack: GraphModel[], snapshot: GraphModel): GraphModel[] {
  const next = [...stack, snapshot];
  return next.length > MAX_UNDO ? next.slice(next.length - MAX_UNDO) : next;
}

/** The snapshot to go back to, and the stack without it. */
export function popUndo(stack: GraphModel[]): { snapshot: GraphModel | null; stack: GraphModel[] } {
  if (stack.length === 0) return { snapshot: null, stack };
  return { snapshot: stack[stack.length - 1], stack: stack.slice(0, -1) };
}

// ---------------------------------------------------------------- URL state

export interface GraphView {
  /** Canonical entity ids, 1-5. */
  entities: string[];
  /** A preset, or `around` (an ISO time), never both. */
  window?: WindowPreset;
  around?: string;
  /** Expanded nodes beyond the centres (the centres plus these are at most 10). */
  x: string[];
  /** Node types hidden by the legend. */
  hide: NodeType[];
  limit: RelationLimit;
  /** Origins to run; absent: all the role may see. */
  include?: Origin[];
}

export interface ParsedView {
  view: GraphView;
  /** Entity values the URL gave that aren't valid `type:key` (the "bad link" state). */
  invalid: string[];
}

/** An ISO 8601 date-time with a time zone, as the API's `around` accepts it. */
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

export function isIsoTime(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && ISO_DATE_TIME.test(value) && Number.isFinite(Date.parse(value));
}

/** An alert's created_at as the API's `around`: ISO with a zone (a bare timestamp is read as UTC). */
export function aroundOf(createdAt: unknown): string | null {
  if (typeof createdAt !== 'string' || createdAt.length > 40) return null;
  const ms = Date.parse(createdAt);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

type QueryValue = string | null | undefined | Array<string | null>;

function values(query: Record<string, unknown>, name: string): string[] {
  const raw = query[name] as QueryValue;
  if (raw === undefined || raw === null) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list.filter((v): v is string => typeof v === 'string');
}

function first(query: Record<string, unknown>, name: string): string | undefined {
  return values(query, name)[0];
}

/** The page's view from its URL query (vue-router's route.query). */
export function parseView(query: Record<string, unknown>): ParsedView {
  const invalid: string[] = [];
  const entities: string[] = [];
  for (const raw of values(query, 'entity')) {
    const ref = tryParseEntity(raw);
    if (!ref) {
      invalid.push(raw);
      continue;
    }
    if (!entities.includes(ref.id) && entities.length < MAX_CENTRES) entities.push(ref.id);
  }
  const x: string[] = [];
  for (const raw of values(query, 'x')) {
    const ref = tryParseEntity(raw);
    if (!ref || entities.includes(ref.id) || x.includes(ref.id)) continue;
    if (entities.length + x.length >= MAX_EXPANDED) break;
    x.push(ref.id);
  }
  const hideRaw = values(query, 'hide').flatMap((v) => v.split(','));
  const hide = NODE_TYPES.filter((t) => hideRaw.includes(t));
  const limitRaw = Number(first(query, 'limit'));
  const limit = (RELATION_LIMITS as readonly number[]).includes(limitRaw) ? (limitRaw as RelationLimit) : DEFAULT_LIMIT;
  const includeRaw = values(query, 'include').flatMap((v) => v.split(','));
  const include = ORIGINS.filter((o) => includeRaw.includes(o));
  const view: GraphView = { entities, x, hide, limit };
  if (include.length > 0 && include.length < ORIGINS.length) view.include = include;
  const around = first(query, 'around');
  const window = first(query, 'window');
  if (around !== undefined && isIsoTime(around)) view.around = around;
  else if (window !== undefined && (WINDOW_PRESETS as readonly string[]).includes(window)) view.window = window as WindowPreset;
  else view.window = '7d';
  return { view, invalid };
}

/** The URL query of a view (what router.replace / router.push are given). */
export function viewQuery(view: GraphView): Record<string, string | string[]> {
  const query: Record<string, string | string[]> = {};
  if (view.entities.length > 0) query.entity = view.entities.length === 1 ? view.entities[0] : [...view.entities];
  if (view.around) query.around = view.around;
  else query.window = view.window ?? '7d';
  const x = view.x.filter((id) => !view.entities.includes(id)).slice(0, Math.max(0, MAX_EXPANDED - view.entities.length));
  if (x.length > 0) query.x = x.length === 1 ? x[0] : x;
  if (view.hide.length > 0) query.hide = view.hide.join(',');
  if (view.limit !== DEFAULT_LIMIT) query.limit = String(view.limit);
  if (view.include && view.include.length > 0 && view.include.length < ORIGINS.length) query.include = view.include.join(',');
  return query;
}

/** The view's own key (for per-view storage): centres, window and options, not the expansions. */
export function viewKey(view: GraphView): string {
  return JSON.stringify([view.entities, view.around ?? view.window ?? '7d', view.limit, view.include ?? null]);
}

/** Is `id` a node id of a known type? */
export function isNodeId(id: string): boolean {
  return typeOfId(id) !== null;
}

/** "1,000+" when the server stopped counting. */
export const isCapped = (total: number, capped: boolean) => capped || total > TOTAL_CAP;
