import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  addRelationItems,
  aroundOf,
  emptyModel,
  groupNodeId,
  hideNodes,
  hopDistances,
  mergeNeighborhood,
  nodeCount,
  parseGroupNodeId,
  parseView,
  popUndo,
  pushUndo,
  remaining,
  shortestPath,
  showHidden,
  typeCounts,
  viewQuery,
  visibleGraph,
  MAX_UNDO,
  type GraphModel,
} from './model.ts';
import { MAX_CANVAS_NODES, type GraphEdge, type GraphNode, type NeighborhoodResponse, type NodeType, type RelationGroup } from './types.ts';

function node(id: string, extra: Partial<GraphNode> = {}): GraphNode {
  const colon = id.indexOf(':');
  return { id, type: id.slice(0, colon) as NodeType, key: id.slice(colon + 1), label: id.slice(colon + 1), facts: {}, flags: [], expandable: true, ...extra };
}

function edge(rel: string, source: string, target: string, extra: Partial<GraphEdge> = {}): GraphEdge {
  return { id: `${rel}|${source}|${target}`, source, target, rel, origin: 'alerts', style: 'recorded', ...extra };
}

function group(rel: string, neighbor_type: NodeType, total: number, shown: number, extra: Partial<RelationGroup> = {}): RelationGroup {
  return { rel, label: rel, neighbor_type, origin: 'alerts', total, total_capped: false, shown, very_common: false, status: 'ok', ...extra };
}

function answer(center: string, nodes: GraphNode[], edges: GraphEdge[], groups: RelationGroup[] = []): NeighborhoodResponse {
  return {
    center: { ...node(center), exists: true },
    window: { from: '2026-10-08T00:00:00.000Z', to: '2026-10-15T00:00:00.000Z', preset: '7d' },
    nodes: [node(center), ...nodes],
    edges,
    groups,
    sources: { alerts: { status: 'ok' } },
    generated_at: '2026-10-15T00:00:00.000Z',
    cached: false,
    elapsed_ms: 3,
  };
}

/** alert:1 names ip:10.0.0.1 and ip:10.0.0.2; 7 IPs in all. */
function alertModel(): GraphModel {
  const result = mergeNeighborhood(
    emptyModel(['alert:1']),
    answer(
      'alert:1',
      [node('ip:10.0.0.1'), node('ip:10.0.0.2'), node('rule:5')],
      [edge('alert_ips', 'alert:1', 'ip:10.0.0.1'), edge('alert_ips', 'alert:1', 'ip:10.0.0.2'), edge('alert_rule', 'alert:1', 'rule:5')],
      [group('alert_ips', 'ip', 7, 2), group('alert_rule', 'rule', 1, 1)]
    )
  );
  assert.ok(result.ok);
  return result.model;
}

describe('merge', () => {
  it('adds the centre, its neighbours and its groups, and marks it expanded', () => {
    const model = alertModel();
    assert.deepEqual(Object.keys(model.nodes).sort(), ['alert:1', 'ip:10.0.0.1', 'ip:10.0.0.2', 'rule:5']);
    assert.equal(Object.keys(model.edges).length, 3);
    assert.deepEqual(model.expanded, ['alert:1']);
    assert.equal(model.groups['alert:1'].length, 2);
    assert.equal('exists' in model.nodes['alert:1'], false);
  });

  it('de-duplicates nodes and edges reached twice, keeping the newest facts', () => {
    const model = alertModel();
    const result = mergeNeighborhood(
      model,
      answer(
        'ip:10.0.0.1',
        [node('alert:1', { label: 'newer' }), node('alert:2')],
        [edge('alert_ips', 'alert:1', 'ip:10.0.0.1'), edge('alert_ips', 'alert:2', 'ip:10.0.0.1')],
        [group('entity_alerts', 'alert', 2, 2)]
      )
    );
    assert.ok(result.ok);
    assert.deepEqual(result.addedNodes, ['alert:2']);
    assert.deepEqual(result.addedEdges, ['alert_ips|alert:2|ip:10.0.0.1']);
    assert.equal(result.model.nodes['alert:1'].label, 'newer');
    assert.deepEqual(result.model.expanded, ['alert:1', 'ip:10.0.0.1']);
  });

  it('takes the server’s id for a centre the URL spelt otherwise', () => {
    const result = mergeNeighborhood(emptyModel(['host:NAS']), answer('host:nas', [], []), 'host:NAS');
    assert.ok(result.ok);
    assert.deepEqual(result.model.centres, ['host:nas']);
    assert.deepEqual(result.model.expanded, ['host:nas']);
  });

  it('refuses an expansion past the 500-node cap, whole', () => {
    let model = emptyModel(['ip:10.0.0.1']);
    const many = Array.from({ length: MAX_CANVAS_NODES - 1 }, (_, i) => node(`alert:${i + 1}`));
    const first = mergeNeighborhood(model, answer('ip:10.0.0.1', many, many.map((n) => edge('alert_ips', n.id, 'ip:10.0.0.1'))));
    assert.ok(first.ok);
    model = first.model;
    assert.equal(nodeCount(model), MAX_CANVAS_NODES);
    const more = mergeNeighborhood(model, answer('alert:1', [node('user:root')], [edge('alert_users', 'alert:1', 'user:root')]));
    assert.equal(more.ok, false);
    assert.equal(more.model, model);
    // Nothing new: still fine at the cap.
    const again = mergeNeighborhood(model, answer('alert:1', [], []));
    assert.ok(again.ok);
  });
});

describe('groups', () => {
  it('shows what is off the canvas as one group node per relation', () => {
    const visible = visibleGraph(alertModel());
    assert.equal(visible.groupNodes.length, 1);
    const [g] = visible.groupNodes;
    assert.equal(g.id, groupNodeId('alert:1', 'alert_ips'));
    assert.equal(g.remaining, 5);
    assert.deepEqual(parseGroupNodeId(g.id), { nodeId: 'alert:1', rel: 'alert_ips' });
    assert.equal(parseGroupNodeId('ip:1.2.3.4'), null);
  });

  it('says "1,000+" for a capped total, and nothing for a timed-out group', () => {
    assert.equal(remaining(group('entity_alerts', 'alert', 1000, 5, { total_capped: true })), null);
    const model = alertModel();
    model.groups['alert:1'] = [group('alert_ips', 'ip', 7, 2, { status: 'timeout' })];
    assert.equal(visibleGraph(model).groupNodes.length, 0);
  });

  it('shrinks the group as table rows are added, counting only rows new to the canvas', () => {
    const model = alertModel();
    const { model: next, added } = addRelationItems(model, 'alert:1', 'alert_ips', [
      { node: node('ip:10.0.0.2'), edge: edge('alert_ips', 'alert:1', 'ip:10.0.0.2') },
      { node: node('ip:10.0.0.3'), edge: edge('alert_ips', 'alert:1', 'ip:10.0.0.3') },
      { node: node('ip:10.0.0.4'), edge: edge('alert_ips', 'alert:1', 'ip:10.0.0.4') },
    ]);
    assert.deepEqual(added, ['ip:10.0.0.3', 'ip:10.0.0.4']);
    assert.equal(next.groups['alert:1'].find((g) => g.rel === 'alert_ips')?.shown, 4);
    assert.equal(visibleGraph(next).groupNodes[0].remaining, 3);
  });

  it('adds only what fits under the cap', () => {
    let model = emptyModel(['ip:10.0.0.1']);
    const many = Array.from({ length: MAX_CANVAS_NODES - 2 }, (_, i) => node(`alert:${i + 1}`));
    const merged = mergeNeighborhood(model, answer('ip:10.0.0.1', many, many.map((n) => edge('alert_ips', n.id, 'ip:10.0.0.1')), [group('entity_alerts', 'alert', 900, 498)]));
    assert.ok(merged.ok);
    model = merged.model;
    const items = [1001, 1002, 1003].map((i) => ({ node: node(`alert:${i}`), edge: edge('alert_ips', `alert:${i}`, 'ip:10.0.0.1') }));
    const result = addRelationItems(model, 'ip:10.0.0.1', 'entity_alerts', items);
    assert.equal(result.added.length, 1);
    assert.equal(result.refused, 2);
    assert.equal(nodeCount(result.model), MAX_CANVAS_NODES);
  });

  it('hides group nodes of a hidden type, never the centres', () => {
    const visible = visibleGraph(alertModel(), ['ip', 'alert']);
    assert.deepEqual(visible.nodes.map((n) => n.id).sort(), ['alert:1', 'rule:5']);
    assert.equal(visible.groupNodes.length, 0);
    assert.equal(visible.edges.length, 1);
  });
});

describe('hide', () => {
  it('takes the node and the leaves only it held, and brings them back', () => {
    let model = alertModel();
    const merged = mergeNeighborhood(
      model,
      answer(
        'ip:10.0.0.1',
        [node('alert:2'), node('alert:3'), node('user:root')],
        [edge('alert_ips', 'alert:2', 'ip:10.0.0.1'), edge('alert_ips', 'alert:3', 'ip:10.0.0.1'), edge('alert_users', 'alert:3', 'user:root')]
      )
    );
    assert.ok(merged.ok);
    model = merged.model;
    // Hiding the expanded IP takes alert:2 (linked to it only) but not alert:3,
    // which user:root still holds; alert:1 is the centre.
    const { model: hidden, hidden: ids } = hideNodes(model, ['ip:10.0.0.1']);
    assert.deepEqual(ids.sort(), ['alert:2', 'ip:10.0.0.1']);
    assert.equal(hidden.nodes['ip:10.0.0.1'], undefined);
    assert.equal(hidden.groups['ip:10.0.0.1'], undefined);
    assert.deepEqual(hidden.expanded, ['alert:1']);
    assert.ok(hidden.nodes['alert:3'] && hidden.nodes['user:root'] && hidden.nodes['alert:1']);
    assert.equal(Object.values(hidden.edges).some((e) => e.source === 'alert:2' || e.target === 'ip:10.0.0.1'), false);

    const back = showHidden(hidden);
    assert.ok(back.nodes['ip:10.0.0.1'] && back.nodes['alert:2']);
    assert.equal(Object.keys(back.edges).length, Object.keys(model.edges).length);
    assert.deepEqual(back.hidden, {});
  });

  it('keeps a hidden node hidden when another expansion reaches it', () => {
    const { model } = hideNodes(alertModel(), ['ip:10.0.0.2']);
    const result = mergeNeighborhood(model, answer('rule:5', [node('ip:10.0.0.2'), node('alert:1')], [edge('alert_rule', 'alert:1', 'rule:5')]));
    assert.ok(result.ok);
    assert.equal(result.model.nodes['ip:10.0.0.2'], undefined);
    assert.ok(result.model.hidden['ip:10.0.0.2']);
  });

  it('never hides a centre as an orphan', () => {
    const { hidden } = hideNodes(alertModel(), ['rule:5']);
    assert.deepEqual(hidden, ['rule:5']);
  });
});

describe('undo', () => {
  it('keeps the newest 20 snapshots and pops the last', () => {
    let stack: GraphModel[] = [];
    for (let i = 0; i < 25; i++) stack = pushUndo(stack, emptyModel([`alert:${i + 1}`]));
    assert.equal(stack.length, MAX_UNDO);
    assert.deepEqual(stack[0].centres, ['alert:6']);
    const { snapshot, stack: rest } = popUndo(stack);
    assert.deepEqual(snapshot?.centres, ['alert:25']);
    assert.equal(rest.length, MAX_UNDO - 1);
    assert.equal(popUndo([]).snapshot, null);
  });

  it('restores the model as it was before a merge', () => {
    const before = alertModel();
    const stack = pushUndo([], before);
    const merged = mergeNeighborhood(before, answer('ip:10.0.0.1', [node('alert:9')], [edge('alert_ips', 'alert:9', 'ip:10.0.0.1')]));
    assert.ok(merged.ok);
    assert.ok(merged.model.nodes['alert:9']);
    assert.equal(before.nodes['alert:9'], undefined);
    assert.equal(popUndo(stack).snapshot, before);
  });
});

describe('paths and distances', () => {
  it('finds the shortest path over what is loaded', () => {
    const edges = [edge('a', 'n:1', 'n:2'), edge('a', 'n:2', 'n:3'), edge('a', 'n:3', 'n:4'), edge('a', 'n:1', 'n:4')];
    assert.deepEqual(shortestPath(edges, 'n:1', 'n:3'), { nodes: ['n:1', 'n:2', 'n:3'], edges: ['a|n:1|n:2', 'a|n:2|n:3'] });
    assert.deepEqual(shortestPath(edges, 'n:4', 'n:1'), { nodes: ['n:4', 'n:1'], edges: ['a|n:1|n:4'] });
    assert.equal(shortestPath(edges, 'n:1', 'n:9'), null);
    assert.deepEqual(shortestPath(edges, 'n:2', 'n:2'), { nodes: ['n:2'], edges: [] });
  });

  it('counts hops from the nearest centre', () => {
    const model = alertModel();
    const merged = mergeNeighborhood(model, answer('ip:10.0.0.1', [node('alert:2')], [edge('alert_ips', 'alert:2', 'ip:10.0.0.1')]));
    assert.ok(merged.ok);
    const hops = hopDistances(merged.model);
    assert.equal(hops['alert:1'], 0);
    assert.equal(hops['ip:10.0.0.1'], 1);
    assert.equal(hops['alert:2'], 2);
  });

  it('counts the types on the canvas', () => {
    assert.deepEqual(typeCounts(alertModel()), { alert: 1, ip: 2, rule: 1 });
  });
});

describe('URL state', () => {
  it('round-trips a view', () => {
    const query = {
      entity: ['ip:198.51.100.7', 'alert:812'],
      window: '30d',
      x: ['user:root', 'host:nas'],
      hide: 'domain,shipper_tag',
      limit: '10',
      include: 'alerts,inventory',
    };
    const { view, invalid } = parseView(query);
    assert.deepEqual(invalid, []);
    assert.deepEqual(view, {
      entities: ['ip:198.51.100.7', 'alert:812'],
      window: '30d',
      x: ['user:root', 'host:nas'],
      hide: ['domain', 'shipper_tag'],
      limit: 10,
      include: ['alerts', 'inventory'],
    });
    assert.deepEqual(viewQuery(view), query);
    assert.deepEqual(parseView(viewQuery(view)).view, view);
  });

  it('canonicalizes entities, drops repeats, and keeps at most 5 centres and 10 expanded', () => {
    const entities = ['host:NAS', 'host:nas', ...Array.from({ length: 6 }, (_, i) => `alert:${i + 1}`)];
    const x = Array.from({ length: 12 }, (_, i) => `rule:${i + 1}`);
    const { view } = parseView({ entity: entities, x });
    assert.deepEqual(view.entities, ['host:nas', 'alert:1', 'alert:2', 'alert:3', 'alert:4']);
    assert.equal(view.x.length, 5);
  });

  it('reports invalid entities for the "bad link" state', () => {
    const { view, invalid } = parseView({ entity: ['ip:999.1.1.1', 'nonsense', 'alert:7'] });
    assert.deepEqual(invalid, ['ip:999.1.1.1', 'nonsense']);
    assert.deepEqual(view.entities, ['alert:7']);
  });

  it('takes around over window, and defaults to 7 days', () => {
    assert.equal(parseView({ entity: 'alert:1', around: '2026-10-14T09:12:00Z', window: '30d' }).view.around, '2026-10-14T09:12:00Z');
    assert.equal(parseView({ entity: 'alert:1', around: 'yesterday' }).view.window, '7d');
    assert.equal(parseView({ entity: 'alert:1', window: '1y' }).view.window, '7d');
    assert.deepEqual(viewQuery(parseView({ entity: 'alert:1', around: '2026-10-14T09:12:00Z' }).view), {
      entity: 'alert:1',
      around: '2026-10-14T09:12:00Z',
    });
  });

  it('ignores unknown options', () => {
    const { view } = parseView({ entity: 'alert:1', hide: 'process,ip', limit: '7', include: 'everything' });
    assert.deepEqual(view.hide, ['ip']);
    assert.equal(view.limit, 5);
    assert.equal(view.include, undefined);
  });

  it('turns an alert’s created_at into the API’s around', () => {
    assert.equal(aroundOf('2026-10-14T09:12:00.123Z'), '2026-10-14T09:12:00.123Z');
    assert.equal(aroundOf('2026-10-14T11:12:00+02:00'), '2026-10-14T09:12:00.000Z');
    assert.equal(aroundOf('not a time'), null);
    assert.equal(aroundOf(undefined), null);
  });
});
