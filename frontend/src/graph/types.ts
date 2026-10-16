/**
 * Context Graph: the shapes the API answers with, mirrored from
 * backend/src/services/graph/types.ts (GET /api/graph/search, /neighborhood
 * and /relation, docs/reference/API.md#context-graph-endpoints).
 *
 * A node id is `${type}:${key}` (entityKey.ts), the same string the URL, the
 * API parameters and the canvas use. An edge id is `${rel}|${source}|${target}`.
 *
 * Pure TypeScript with no imports: src/graph/** must not import the API client
 * or the auth store (eslint.config.js), and runs under `node --test`.
 */

export type NodeType =
  | 'ip'
  | 'host'
  | 'user'
  | 'domain'
  | 'alert'
  | 'rule'
  | 'asset'
  | 'vuln'
  | 'finding'
  | 'identity'
  | 'shipper'
  | 'shipper_tag'
  | 'endpoint'
  | 'account';

export const NODE_TYPES: readonly NodeType[] = [
  'ip',
  'host',
  'user',
  'domain',
  'alert',
  'rule',
  'asset',
  'vuln',
  'finding',
  'identity',
  'shipper',
  'shipper_tag',
  'endpoint',
  'account',
];

/** Where a relationship comes from. */
export type Origin = 'alerts' | 'logs' | 'inventory' | 'risk' | 'accounts';
export const ORIGINS: readonly Origin[] = ['alerts', 'logs', 'inventory', 'risk', 'accounts'];

/** recorded: SIEMBox's own record (solid). logs: a claim a log made (dashed). heuristic: a match (dotted). */
export type EdgeStyle = 'recorded' | 'logs' | 'heuristic';

export type NodeFlag = 'threat_feed' | 'foreign' | 'private' | 'sender_only' | 'critical' | 'open_vulns' | 'closed';

/**
 * Relation ids. The server's catalog is the whitelist; this client renders an
 * id it doesn't know with the group's own label, so a newer backend (the log
 * relationships) needs no client change to be shown.
 */
export type RelId = string;

export type FactValue = string | number | boolean | null;

export interface GraphNode {
  /** `${type}:${key}` */
  id: string;
  type: NodeType;
  key: string;
  /** ≤ 64 characters, sanitized by the server. Render as text only. */
  label: string;
  facts: Record<string, FactValue>;
  flags: NodeFlag[];
  /** false: a label-only account node for a non-admin. */
  expandable: boolean;
}

export interface GraphEdge {
  /** `${rel}|${source}|${target}` */
  id: string;
  source: string;
  target: string;
  rel: RelId;
  origin: Origin;
  style: EdgeStyle;
  /** alert_ips only. */
  role?: 'source' | 'dest' | 'sender';
  count?: number;
  failures?: number;
  successes?: number;
  /** ISO */
  first_seen?: string;
  last_seen?: string;
  /** Log relationships (a later release): a pair first seen in the window. */
  new?: boolean;
  success_after_failures?: boolean;
}

export type GroupStatus = 'ok' | 'timeout' | 'unavailable';

export interface RelationGroup {
  rel: RelId;
  label: string;
  neighbor_type: NodeType;
  origin: Origin;
  /** Distinct neighbours (in the window, where the relation is windowed). */
  total: number;
  /** true: more than 1,000 ("1,000+"). */
  total_capped: boolean;
  /** How many of them are in the response's nodes and edges. */
  shown: number;
  /** total ≥ 200: "very common, likely infrastructure". */
  very_common: boolean;
  status: GroupStatus;
  /** Why it may be empty or short, e.g. 'log_expired'. */
  note?: string;
}

export type SourceState = 'ok' | 'partial' | 'timeout' | 'disabled' | 'building' | 'behind';

export interface SourceStatus {
  status: SourceState;
  covered_from?: string;
  covered_until?: string;
  incomplete_days?: string[];
}

export type WindowPreset = '24h' | '7d' | '30d' | '90d';
export const WINDOW_PRESETS: readonly WindowPreset[] = ['24h', '7d', '30d', '90d'];

export interface GraphWindow {
  from: string;
  to: string;
  preset: WindowPreset | 'around';
}

export interface NeighborhoodResponse {
  center: GraphNode & { exists: boolean };
  window: GraphWindow;
  nodes: GraphNode[];
  edges: GraphEdge[];
  groups: RelationGroup[];
  sources: Partial<Record<Origin, SourceStatus>>;
  generated_at: string;
  cached: boolean;
  elapsed_ms: number;
}

export interface RelationItem {
  node: GraphNode;
  edge: GraphEdge;
}

export interface RelationResponse {
  rel: RelId;
  total: number;
  total_capped: boolean;
  items: RelationItem[];
  next_offset: number | null;
  status: GroupStatus;
  note?: string;
  window: GraphWindow;
  generated_at: string;
  cached: boolean;
  elapsed_ms: number;
}

export interface SearchCandidate {
  /** `${type}:${key}` */
  entity: string;
  type: NodeType;
  label: string;
  hint: string;
}

export interface SearchResponse {
  candidates: SearchCandidate[];
  cached: boolean;
  elapsed_ms: number;
}

/** The server's error envelope for the graph's own refusals. */
export type GraphErrorCode = 'GRAPH_BAD_ENTITY' | 'GRAPH_BAD_PARAM' | 'GRAPH_NOT_AVAILABLE' | 'GRAPH_BUSY';

/** Totals are counted over at most this many rows ("1,000+"). */
export const TOTAL_CAP = 1000;
/** What the canvas holds at most; an expansion past it is refused. */
export const MAX_CANVAS_NODES = 500;
export const MAX_CANVAS_EDGES = 1500;
/** Centres (entity=) in one view. */
export const MAX_CENTRES = 5;
/** Expanded nodes (x=) in one view, the centres included. */
export const MAX_EXPANDED = 10;
/** Neighbours per relation the page may ask for. */
export const RELATION_LIMITS = [5, 10, 25] as const;
export type RelationLimit = (typeof RELATION_LIMITS)[number];
export const DEFAULT_LIMIT: RelationLimit = 5;
/** Rows per page of a relation table. */
export const RELATION_PAGE_SIZE = 50;
