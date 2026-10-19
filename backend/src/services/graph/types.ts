/**
 * Context Graph: the shapes the API answers with. The frontend (PR 2) mirrors
 * these in frontend/src/graph/types.ts.
 *
 * A node id is `${type}:${key}` (entityKey.ts canonicalizes the key), the same
 * string the URL, the API parameters and the canvas use. An edge id is
 * `${rel}|${source}|${target}`, where rel is the edge's canonical relation and
 * source/target its canonical direction (an alert points at the IP it names,
 * whichever of the two was expanded), so the same fact reached from either
 * side is one edge.
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
 * Relation ids: what a group (and /api/graph/relation) is about. Edges carry
 * the canonical one of a pair (entity_alerts from an IP draws alert_ips edges).
 * shipped_by is the edge a log's device has to its shipper (alert_device draws
 * it, as do the log relationships of resolvers/logEdges.ts).
 */
export type RelId =
  | 'alert_ips'
  | 'alert_users'
  | 'alert_hosts'
  | 'alert_domains'
  | 'alert_rule'
  | 'alert_asset'
  | 'alert_finding'
  | 'alert_same_event'
  | 'alert_account'
  | 'alert_endpoint'
  | 'alert_device'
  | 'shipped_by'
  | 'entity_alerts'
  | 'rule_alerts'
  | 'asset_ip'
  | 'ip_asset'
  | 'asset_host'
  | 'host_assets'
  | 'asset_vulns'
  | 'vuln_assets'
  | 'asset_shipper'
  | 'shipper_assets'
  | 'asset_endpoint'
  | 'shipper_address'
  | 'ip_shipper'
  | 'host_shipper'
  | 'finding_identity'
  | 'identity_findings'
  | 'finding_domain'
  | 'domain_findings'
  | 'identity_user'
  | 'identity_domain'
  | 'account_signins'
  | 'ip_signins'
  // Seen in logs (graph_log_edges, migration 044): a -> b, then the b side.
  | 'signed_in_as'
  | 'signed_in_from'
  | 'seen_on'
  | 'actors_seen'
  | 'user_on'
  | 'users_seen'
  | 'connected_to'
  | 'connected_from'
  | 'queried'
  | 'queried_by'
  | 'sent_by'
  | 'sent_hosts'
  | 'shipped_devices';

export type Role = 'admin' | 'operator' | 'analyst' | 'viewer';
export type FactValue = string | number | boolean | null;

export interface GraphNode {
  /** `${type}:${key}` */
  id: string;
  type: NodeType;
  key: string;
  /** ≤ 64 characters, sanitized (labels.ts). */
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
  /** signed_in_as only: the pair was first seen in the window (and the rollup covers the time before it). */
  new?: boolean;
  /** signed_in_as only: both failed and successful sign-ins were seen. */
  success_after_failures?: boolean;
}

export type GroupStatus = 'ok' | 'timeout' | 'unavailable';

export interface RelationGroup {
  rel: RelId;
  label: string;
  /**
   * The type of the neighbours in the group. alert_device's device is a host
   * (the syslog header host) or, when the log named none, an ip (the sender):
   * it says which; 'host' when there is no device to show.
   */
  neighbor_type: NodeType;
  origin: Origin;
  /** Distinct neighbours (in the window, where the relation is windowed). */
  total: number;
  /** true: more than TOTAL_CAP; show "1,000+". */
  total_capped: boolean;
  /** How many of them are in nodes[]/edges[]. */
  shown: number;
  /** total ≥ VERY_COMMON: "very common, likely infrastructure". */
  very_common: boolean;
  status: GroupStatus;
  /** Why it may be empty or short, e.g. 'log_expired'. */
  note?: string;
}

export interface SourceStatus {
  status: 'ok' | 'partial' | 'timeout' | 'disabled' | 'building' | 'behind';
  covered_from?: string;
  covered_until?: string;
  incomplete_days?: string[];
}

export type WindowPreset = '24h' | '7d' | '30d' | '90d';

export interface GraphWindow {
  from: string;
  to: string;
  preset: WindowPreset | 'around';
}

export interface NeighborhoodResponse {
  center: GraphNode & { exists: boolean };
  window: GraphWindow;
  /** ≤ MAX_RESPONSE_NODES, the centre included. */
  nodes: GraphNode[];
  /** ≤ MAX_RESPONSE_EDGES */
  edges: GraphEdge[];
  groups: RelationGroup[];
  /** Only the origins the role can see. */
  sources: Partial<Record<Origin, SourceStatus>>;
  generated_at: string;
  cached: boolean;
  elapsed_ms: number;
}

export interface RelationResponse {
  rel: RelId;
  total: number;
  total_capped: boolean;
  items: Array<{ node: GraphNode; edge: GraphEdge }>;
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

/** Per relation: totals are counted over at most TOTAL_CAP + 1 rows. */
export const TOTAL_CAP = 1000;
/** A group this large is "very common, likely infrastructure". */
export const VERY_COMMON = 200;
export const MAX_RESPONSE_NODES = 300;
export const MAX_RESPONSE_EDGES = 600;

export interface EvidenceLog {
  id: number;
  created_at: string | null;
  timestamp: string | null;
  event_type: string | null;
  parser: string | null;
  service: string | null;
  hostname: string | null;
  sender_ip: string | null;
  /** ≤ 500 characters, sanitized. */
  message: string;
}

/** GET /api/graph/evidence: the logs behind one log relationship on one ingest day. */
export interface EvidenceResponse {
  /** YYYY-MM-DD, or null when the pair has no day in the window. */
  day: string | null;
  /** The pair's days in the window, newest first (the day picker). */
  days: string[];
  logs: EvidenceLog[];
  /** The query timed out: too many events that day to list. */
  partial: boolean;
  /** The day is past the log retention: its logs are deleted. */
  expired: boolean;
  elapsed_ms: number;
}
