/**
 * Who sees what in the Context Graph: the single policy. Never wider than
 * today's routes: every entry names the routes it mirrors, and
 * routes/routeInventory.test.ts fails if a mirrored route is missing or refuses
 * a role the entry admits.
 *
 *   - Resolvers get the role and don't run for types it can't see
 *     (neighborhood.ts asks relationAllowed() before it runs one).
 *   - filterGraph() drops any node the role can't see, and every edge touching
 *     it, as defence in depth.
 *   - Facts go out through per-type allowlists (allowedFacts()).
 *   - Nothing says "N hidden by your role": that would leak that admin-only
 *     data exists.
 *
 * Accounts are special: every role sees an account node a siembox-auth alert
 * names, labelled with the username that alert already shows, and can't expand
 * it; admins get its details and its sign-in IPs.
 */
import crypto from 'crypto';
import type { GraphEdge, GraphNode, NodeType, Role } from './types';
import { NODE_TYPES } from './types';

export const ALL_ROLES: readonly Role[] = ['admin', 'operator', 'analyst', 'viewer'];
const ADMIN: readonly Role[] = ['admin'];

export interface VisibilityEntry {
  roles: readonly Role[];
  /** `METHOD /path` rows of routeInventory.test.ts whose roles must include every role above. */
  mirrors: readonly string[];
}

/**
 * Node types, plus `account_details` (an account's facts beyond the username,
 * expanding it, and the sign-in relations) and `endpoint` (EDR agents).
 */
export const NODE_VISIBILITY: Readonly<Record<NodeType | 'account_details', VisibilityEntry>> = {
  ip: { roles: ALL_ROLES, mirrors: ['GET /api/logs/parsed', 'GET /api/logs/raw'] },
  host: { roles: ALL_ROLES, mirrors: ['GET /api/logs/parsed', 'GET /api/logs/raw'] },
  user: { roles: ALL_ROLES, mirrors: ['GET /api/logs/parsed', 'GET /api/logs/raw'] },
  domain: { roles: ALL_ROLES, mirrors: ['GET /api/logs/parsed', 'GET /api/exposure/domains'] },
  alert: { roles: ALL_ROLES, mirrors: ['GET /api/alerts/:id', 'GET /api/alerts/:id/triage'] },
  rule: { roles: ALL_ROLES, mirrors: ['GET /api/rules/:id'] },
  asset: { roles: ALL_ROLES, mirrors: ['GET /api/assets/:id', 'GET /api/assets/:id/related'] },
  vuln: { roles: ALL_ROLES, mirrors: ['GET /api/vulnerabilities/asset/:assetId', 'GET /api/vulnerabilities/:id'] },
  finding: { roles: ALL_ROLES, mirrors: ['GET /api/exposure/findings'] },
  identity: { roles: ALL_ROLES, mirrors: ['GET /api/exposure/identities'] },
  shipper: { roles: ALL_ROLES, mirrors: ['GET /api/shippers/:id'] },
  shipper_tag: { roles: ALL_ROLES, mirrors: ['GET /api/shippers/unknown-sources', 'GET /api/logs/raw'] },
  // Label only (the username a siembox-auth alert already shows), not expandable.
  account: { roles: ALL_ROLES, mirrors: ['GET /api/alerts/:id'] },
  account_details: { roles: ADMIN, mirrors: ['GET /api/users/:id', 'GET /api/admin/users/:id/activity'] },
  endpoint: { roles: ADMIN, mirrors: ['GET /api/edr/agents/:id'] },
};

export function canSeeType(role: Role, type: NodeType): boolean {
  return NODE_VISIBILITY[type].roles.includes(role);
}

export function canSeeAccountDetails(role: Role): boolean {
  return NODE_VISIBILITY.account_details.roles.includes(role);
}

/** Can this role expand (centre on) a node of this type? Accounts need their details. */
export function canExpandType(role: Role, type: NodeType): boolean {
  if (!canSeeType(role, type)) return false;
  return type === 'account' ? canSeeAccountDetails(role) : true;
}

/**
 * Facts each type may carry, per audience. Never a key, hash or secret
 * (`api_key`, `api_key_hash`, `password_hash`, `mfa_secret`, ...), and never an
 * alert's matched_data.
 */
const FACTS: Readonly<Record<NodeType, readonly string[]>> = {
  ip: ['country', 'country_code', 'private', 'threat_feeds'],
  host: [],
  user: ['is_email'],
  domain: ['watched', 'unicode'],
  alert: ['title', 'severity', 'status', 'source', 'rule_id', 'created_at', 'verdict', 'risk_score'],
  rule: ['name', 'severity', 'enabled'],
  asset: [
    'hostname',
    'ip',
    'asset_type',
    'criticality',
    'status',
    'last_seen',
    'open_vulns',
    'agent_status',
    'agent_version',
    'agent_last_seen',
  ],
  vuln: ['cve_id', 'severity', 'cvss', 'title'],
  finding: ['title', 'source', 'event_type', 'severity', 'first_seen', 'last_seen', 'resolved'],
  identity: ['kind', 'value'],
  shipper: ['name', 'status', 'hostname', 'ip_address', 'version', 'last_seen'],
  shipper_tag: ['tag'],
  endpoint: ['hostname', 'os', 'agent_version', 'status', 'last_seen'],
  account: ['username'],
};
const ACCOUNT_DETAIL_FACTS: readonly string[] = ['role', 'enabled', 'mfa_enabled', 'last_login'];

export function allowedFacts(role: Role, type: NodeType): readonly string[] {
  if (type === 'account' && canSeeAccountDetails(role)) return [...FACTS.account, ...ACCOUNT_DETAIL_FACTS];
  return FACTS[type];
}

/**
 * The cache partition of a role: a hash of the node types it sees, the facts
 * it gets and what it may expand. Roles that see the same graph share cached
 * answers; an admin's answer can never be served to anyone who sees less.
 */
export function visibilityClass(role: Role): string {
  const policy = NODE_TYPES.map((type) => [
    type,
    canSeeType(role, type),
    canExpandType(role, type),
    canSeeType(role, type) ? allowedFacts(role, type) : [],
  ]);
  return crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex').slice(0, 16);
}

/** `node` with only the facts its type may carry for this role, and expandable set for it. */
export function serializeNode(role: Role, node: GraphNode): GraphNode {
  const allowed = allowedFacts(role, node.type);
  const facts: GraphNode['facts'] = {};
  for (const name of allowed) {
    if (Object.prototype.hasOwnProperty.call(node.facts, name)) facts[name] = node.facts[name];
  }
  return { ...node, facts, expandable: node.expandable && canExpandType(role, node.type) };
}

/** Drop every node the role can't see and every edge touching one; trim facts. */
export function filterGraph(role: Role, nodes: GraphNode[], edges: GraphEdge[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const kept = nodes.filter((node) => canSeeType(role, node.type)).map((node) => serializeNode(role, node));
  const ids = new Set(kept.map((node) => node.id));
  return { nodes: kept, edges: edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) };
}
