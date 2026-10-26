/**
 * The relation catalog: the server-side whitelist of what can be asked. A
 * (centre type, rel) pair names one definition; nothing else is queryable.
 * The record relations, then the log relationships (resolvers/logEdges.ts).
 *
 * A role runs a relation only when it may expand the centre, see the
 * neighbour type, and is among the relation's own roles (the sign-in
 * relations: admin): relationAllowed(). The rest never run, and say nothing.
 */
import type { NodeType, Origin, RelId, Role } from './types';
import { canExpandType, canSeeType } from './visibility';
import type { CenterInfo, RelationDef } from './resolvers/common';
import type { Query } from './budget';
import type { EntityRef } from './entityKey';
import { ALERT_RELATIONS, loadAlertCenter } from './resolvers/alerts';
import { INVENTORY_RELATIONS, loadAssetCenter, loadVulnCenter } from './resolvers/inventory';
import { SHIPPER_RELATIONS, loadShipperCenter, loadShipperTagCenter } from './resolvers/shippers';
import { RISK_RELATIONS, loadFindingCenter, loadIdentityCenter } from './resolvers/risk';
import { ACCOUNT_RELATIONS, loadAccountCenter } from './resolvers/accounts';
import { ENDPOINT_RELATIONS, loadEndpointCenter } from './resolvers/endpoints';
import { loadRuleCenter } from './resolvers/rules';
import { LOG_EDGE_RELATIONS } from './resolvers/logEdges';
import { APPLICATION_RELATIONS, loadApplicationCenter } from './resolvers/applications';

export const RELATIONS: readonly RelationDef[] = [
  ...ALERT_RELATIONS,
  ...INVENTORY_RELATIONS,
  ...SHIPPER_RELATIONS,
  ...ENDPOINT_RELATIONS,
  ...RISK_RELATIONS,
  ...ACCOUNT_RELATIONS,
  ...APPLICATION_RELATIONS,
  ...LOG_EDGE_RELATIONS,
];

export function relationAllowed(def: RelationDef, role: Role): boolean {
  return canExpandType(role, def.center) && canSeeType(role, def.neighborType) && (def.roles ?? [role]).includes(role);
}

/** The relations a role runs for a centre type, in catalog order; `include` limits the origins. */
export function relationsFor(
  type: NodeType,
  role: Role,
  include?: readonly Origin[],
  catalog: readonly RelationDef[] = RELATIONS
): RelationDef[] {
  return catalog.filter((def) => def.center === type && relationAllowed(def, role) && (!include || include.includes(def.origin)));
}

/** The definition of (centre type, rel) if the role may run it. */
export function findRelation(type: NodeType, rel: string, role: Role, catalog: readonly RelationDef[] = RELATIONS): RelationDef | null {
  return catalog.find((def) => def.center === type && def.rel === rel && relationAllowed(def, role)) ?? null;
}

/** The rel ids the catalog knows, for parameter validation. */
export function knownRel(rel: string, catalog: readonly RelationDef[] = RELATIONS): rel is RelId {
  return catalog.some((def) => def.rel === rel);
}

/**
 * The centre's own row. Value types (ip, host, user, domain) have none: they
 * are always queryable, and exist when anything links to them.
 */
export async function loadCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  switch (ref.type) {
    case 'alert':
      return loadAlertCenter(q, ref);
    case 'asset':
      return loadAssetCenter(q, ref);
    case 'vuln':
      return loadVulnCenter(q, ref);
    case 'rule':
      return loadRuleCenter(q, ref);
    case 'finding':
      return loadFindingCenter(q, ref);
    case 'identity':
      return loadIdentityCenter(q, ref);
    case 'shipper':
      return loadShipperCenter(q, ref);
    case 'shipper_tag':
      return loadShipperTagCenter(q, ref);
    case 'account':
      return loadAccountCenter(q, ref);
    case 'endpoint':
      return loadEndpointCenter(q, ref);
    case 'application':
      return loadApplicationCenter(q, ref);
    default:
      return { exists: true, row: null };
  }
}

/** Types whose existence is "something links to it" rather than a row. */
export const VALUE_TYPES: ReadonlySet<NodeType> = new Set(['ip', 'host', 'user', 'domain']);
