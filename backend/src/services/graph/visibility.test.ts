/**
 * The role policy: which node types and facts each role gets, that admin-only
 * resolvers never run for anyone else (spied through the real orchestration),
 * and a static check that no SQL under services/graph selects `*` or a secret
 * column. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { allowedFacts, canExpandType, canSeeType, filterGraph, NODE_VISIBILITY, serializeNode } from './visibility';
import { RELATIONS, relationsFor } from './relations';
import { createGraphCache, createSemaphore } from './limits';
import { getNeighborhood, getRelation, type GraphDeps } from './neighborhood';
import { resolveWindow } from './window';
import { entityRef } from './entityKey';
import { GraphError } from './errors';
import type { RelationDef } from './resolvers/common';
import type { GraphEdge, GraphNode, NodeType, Role } from './types';
import { NODE_TYPES } from './types';
import type { QueryClient } from '../shippers/snapshotCache';

const ROLES: Role[] = ['admin', 'operator', 'analyst', 'viewer'];
const NON_ADMIN: Role[] = ['operator', 'analyst', 'viewer'];

test('every role sees every node type except endpoints; only admins see account details', () => {
  for (const type of NODE_TYPES) {
    for (const role of ROLES) {
      assert.equal(canSeeType(role, type), type !== 'endpoint' || role === 'admin', `${role} ${type}`);
    }
  }
  for (const role of NON_ADMIN) {
    assert.equal(canExpandType(role, 'account'), false, `${role} can't expand an account`);
    assert.equal(canExpandType(role, 'endpoint'), false);
    assert.deepEqual(allowedFacts(role, 'account'), ['username']);
  }
  assert.equal(canExpandType('admin', 'account'), true);
  assert.deepEqual(allowedFacts('admin', 'account'), ['username', 'role', 'enabled', 'mfa_enabled', 'last_login']);
  // Every role gets the asset's agent status, as Asset-360 shows it.
  for (const role of ROLES) assert.ok(allowedFacts(role, 'asset').includes('agent_status'));
});

test('applications: every role sees and expands them, with the same facts; nothing else of the signature gets out', () => {
  for (const role of ROLES) {
    assert.equal(canExpandType(role, 'application'), true, role);
    assert.deepEqual(allowedFacts(role, 'application'), ['name', 'vendor', 'category', 'versions', 'locations', 'open_vulns']);
  }
  const node: GraphNode = {
    id: 'application:nginx',
    type: 'application',
    key: 'nginx',
    label: 'nginx',
    facts: { name: 'nginx', vendor: 'F5', category: 'web-server', versions: '1.25.3', locations: 3, open_vulns: 1, definition: '{"match":{}}', evidence: 'raw log 7' },
    flags: ['open_vulns'],
    expandable: true,
  };
  assert.deepEqual(Object.keys(serializeNode('viewer', node).facts), ['name', 'vendor', 'category', 'versions', 'locations', 'open_vulns']);
  // The relations a viewer runs from an application, and the ones that reach it.
  const rels = (type: NodeType) => relationsFor(type, 'viewer').map((def) => def.rel);
  assert.deepEqual(rels('application'), ['app_assets', 'app_hosts', 'app_ips', 'app_shippers', 'app_clients', 'app_vulns']);
  for (const type of ['asset', 'host', 'ip', 'shipper'] as NodeType[]) assert.ok(rels(type).includes('runs_app'), type);
  assert.ok(rels('ip').includes('uses_app'));
  assert.ok(rels('ip').includes('ip_vulns'), 'an IP\'s asset vulnerabilities, one hop');
  assert.ok(rels('host').includes('host_vulns'));
  assert.ok(rels('vuln').includes('vuln_apps'));
});

test('no fact allowlist names a key, a hash, a secret or matched_data', () => {
  for (const type of NODE_TYPES) {
    for (const role of ROLES) {
      for (const fact of allowedFacts(role, type)) {
        assert.doesNotMatch(fact, /key|hash|secret|password|token|matched_data|^email$/i, `${type}.${fact}`);
      }
    }
  }
  assert.ok(Object.values(NODE_VISIBILITY).every((entry) => entry.mirrors.length > 0));
});

test('serializeNode keeps only allowed facts; filterGraph drops invisible nodes and their edges', () => {
  const account: GraphNode = {
    id: 'account:1',
    type: 'account',
    key: '1',
    label: 'admin',
    facts: { username: 'admin', role: 'admin', enabled: true, password_hash: 'x' },
    flags: [],
    expandable: true,
  };
  assert.deepEqual(serializeNode('viewer', account).facts, { username: 'admin' });
  assert.equal(serializeNode('viewer', account).expandable, false);
  assert.deepEqual(serializeNode('admin', account).facts, { username: 'admin', role: 'admin', enabled: true });
  assert.equal(serializeNode('admin', account).expandable, true);

  const endpoint: GraphNode = { ...account, id: 'endpoint:e', type: 'endpoint', key: 'e', facts: {} };
  const asset: GraphNode = { ...account, id: 'asset:1', type: 'asset', key: '1', facts: {} };
  const edge: GraphEdge = { id: 'asset_endpoint|asset:1|endpoint:e', source: 'asset:1', target: 'endpoint:e', rel: 'asset_endpoint', origin: 'inventory', style: 'recorded' };
  const viewer = filterGraph('viewer', [asset, endpoint], [edge]);
  assert.deepEqual(viewer.nodes.map((n) => n.id), ['asset:1']);
  assert.deepEqual(viewer.edges, []);
  assert.equal(filterGraph('admin', [asset, endpoint], [edge]).edges.length, 1);
});

test('the catalog: a role only gets relations whose centre it may expand and whose neighbour it may see', () => {
  for (const role of NON_ADMIN) {
    for (const type of NODE_TYPES) {
      for (const def of relationsFor(type, role)) {
        assert.ok(canSeeType(role, def.neighborType), `${role} ${def.rel}`);
        assert.ok(def.roles === undefined || def.roles.includes(role), `${role} ${def.rel}`);
      }
    }
    assert.deepEqual(relationsFor('account', role), []);
    assert.deepEqual(relationsFor('endpoint', role), []);
    assert.ok(!relationsFor('ip', role).some((def) => def.rel === 'ip_signins'));
    assert.ok(!relationsFor('asset', role).some((def) => def.rel === 'asset_endpoint'));
    assert.ok(!relationsFor('alert', role).some((def) => def.rel === 'alert_endpoint'));
  }
  assert.ok(relationsFor('ip', 'admin').some((def) => def.rel === 'ip_signins'));
  assert.ok(relationsFor('asset', 'admin').some((def) => def.rel === 'asset_endpoint'));
  // (centre, rel) names one definition.
  const pairs = RELATIONS.map((def) => `${def.center} ${def.rel}`);
  assert.deepEqual(pairs.filter((p, i) => pairs.indexOf(p) !== i), []);
});

/** A client that answers every statement with no rows (value centres need no row). */
function emptyClient(): QueryClient {
  return { async query() { return { rows: [] }; }, release() {} };
}

function spiedDeps(): { deps: GraphDeps; calls: string[] } {
  const calls: string[] = [];
  const catalog: RelationDef[] = RELATIONS.map((def) => ({
    ...def,
    async fetch() {
      calls.push(`${def.center} ${def.rel}`);
      return { items: [], total: 0, totalCapped: false };
    },
  }));
  return {
    calls,
    deps: {
      acquire: async () => emptyClient(),
      semaphore: createSemaphore(),
      cache: createGraphCache(),
      now: () => Date.now(),
      catalog,
    },
  };
}

test('admin-only resolvers are never invoked for other roles (spied)', async () => {
  const window = resolveWindow({}, Date.now());
  const adminOnly = new Set(['ip ip_signins', 'account account_signins', 'asset asset_endpoint', 'endpoint asset_endpoint', 'alert alert_endpoint', 'account entity_alerts', 'endpoint entity_alerts', 'endpoint endpoint_vulns']);
  for (const role of NON_ADMIN) {
    const { deps, calls } = spiedDeps();
    for (const type of ['ip', 'asset', 'alert', 'user', 'host', 'domain'] as NodeType[]) {
      const key = type === 'ip' ? '198.51.100.7' : type === 'domain' ? 'example.com' : type === 'user' || type === 'host' ? 'nas' : '1';
      await getNeighborhood(deps, { id: 1, role }, { center: entityRef(type, key), window, limit: 5, vulnStatus: 'open' });
    }
    assert.ok(calls.length > 0);
    assert.deepEqual(calls.filter((call) => adminOnly.has(call)), [], `${role} ran admin-only resolvers`);
    // Centring on an admin-only type is refused before anything runs.
    for (const center of [entityRef('endpoint', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), entityRef('account', '1')]) {
      await assert.rejects(
        getNeighborhood(deps, { id: 1, role }, { center, window, limit: 5, vulnStatus: 'open' }),
        (err: unknown) => err instanceof GraphError && err.statusCode === 404
      );
    }
    await assert.rejects(
      getRelation(deps, { id: 1, role }, { center: entityRef('ip', '198.51.100.7'), rel: 'ip_signins', window, limit: 5, offset: 0, vulnStatus: 'open' }),
      (err: unknown) => err instanceof GraphError && err.code === 'GRAPH_NOT_AVAILABLE'
    );
  }
  const { deps, calls } = spiedDeps();
  await getNeighborhood(deps, { id: 1, role: 'admin' }, { center: entityRef('ip', '198.51.100.7'), window, limit: 5, vulnStatus: 'open' });
  assert.ok(calls.includes('ip ip_signins'), 'an admin does run them');
});

// ---- Static: what the SQL under services/graph may select ------------------------------

const SECRET_COLUMNS = ['api_key', 'api_key_hash', 'http_push_key_hash', 'password_hash', 'mfa_secret', 'mfa_recovery_codes', 'token_hash', 'mask_key'];

/**
 * The only exceptions, removed before the checks run:
 *   - shipperTags.ts computes tags from shipper keys in SQL, as
 *     unknownSources.ts does; only the 8-character tags (which stay
 *     server-side) come out;
 *   - pagedSql() (resolvers/common.ts) re-selects its own CTEs, whose columns
 *     are each relation's explicit list.
 */
const ALLOWED_USES: Record<string, string[]> = {
  'common.ts': ['SELECT c.*, count(*) OVER ()'],
  'shipperTags.ts': [
    `api_key ~ '^([0-9a-fA-F]{2})+$'`,
    `md5(decode(api_key, 'hex'))`,
    `sha256(decode(api_key, 'hex'))`,
    `substring(http_push_key_hash, 1, 8)`,
  ],
};

function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sources(full);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

test('static: no SELECT * and no secret column under services/graph', () => {
  const files = sources(__dirname);
  assert.ok(files.length >= 15, `found ${files.length} files`);
  for (const file of files) {
    let text = fs.readFileSync(file, 'utf8');
    for (const allowed of ALLOWED_USES[path.basename(file)] ?? []) {
      assert.ok(text.includes(allowed), `${path.basename(file)} still has ${allowed}`);
      text = text.split(allowed).join('');
    }
    assert.doesNotMatch(text, /SELECT\s+\*/i, `${path.basename(file)}: SELECT *`);
    assert.doesNotMatch(text, /\b\w+\.\*/, `${path.basename(file)}: alias.* in a select list`);
    // Comments may name them (this rule explains itself); code and SQL may not.
    const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const column of SECRET_COLUMNS) {
      assert.doesNotMatch(code, new RegExp(`\\b${column}\\b`, 'i'), `${path.basename(file)} names ${column}`);
    }
  }
});
