import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { placeAround, MIN_GAP } from './layout.ts';
import { emptyModel, mergeNeighborhood, visibleGraph } from './model.ts';
import { applicationEdgeLabel, edgeLabel, edgeWidth, glyphImage, nodeColor, outcomeLabel, stylesheet, toElements, typeColor, TYPE_STYLES, versionsLabel } from './style.ts';
import { NODE_TYPES, type NeighborhoodResponse } from './types.ts';
import { SEVERITY_COLORS } from '../utils/severity.ts';

describe('visual encoding', () => {
  it('gives every type a shape and glyph pair of its own, so colour is never the only cue', () => {
    const pairs = NODE_TYPES.map((t) => `${TYPE_STYLES[t].shape}/${TYPE_STYLES[t].glyph}`);
    assert.equal(new Set(pairs).size, NODE_TYPES.length);
    const glyphs = NODE_TYPES.map((t) => TYPE_STYLES[t].glyph);
    assert.equal(new Set(glyphs).size, NODE_TYPES.length);
  });

  it('uses severity colours on alerts and vulnerabilities only', () => {
    assert.equal(nodeColor({ type: 'alert', facts: { severity: 'critical' } }, false), SEVERITY_COLORS.critical);
    assert.equal(nodeColor({ type: 'vuln', facts: { severity: 'HIGH' } }, true), SEVERITY_COLORS.high);
    const severity = new Set(Object.values(SEVERITY_COLORS).map((c) => c.toLowerCase()));
    for (const type of NODE_TYPES) {
      for (const dark of [false, true]) {
        assert.equal(severity.has(nodeColor({ type, facts: {} }, dark).toLowerCase()), false, `${type} dark=${dark}`);
      }
    }
  });

  it('widens edges with their count, within bounds', () => {
    assert.equal(edgeWidth(undefined), 1);
    assert.equal(edgeWidth(1), 1);
    assert.equal(edgeWidth(100), 3);
    assert.equal(edgeWidth(10 ** 9), 6);
  });

  it('labels sign-in outcomes and relations', () => {
    assert.equal(outcomeLabel({ failures: 4118, successes: 2 }), '4,118 failed / 2 succeeded');
    assert.equal(outcomeLabel({}), '');
    assert.equal(edgeLabel('alert_hosts'), 'Host named in the log');
    assert.equal(edgeLabel('signed_in_as'), 'Signed in as (seen in logs)');
    assert.equal(edgeLabel('some_future_rel'), 'some future rel', 'an unknown id shows as written');
  });

  it('draws glyphs as an inline SVG image (no request)', () => {
    const uri = glyphImage('<');
    assert.match(uri, /^data:image\/svg\+xml;charset=utf-8,/);
    assert.match(decodeURIComponent(uri), />&lt;</);
  });
});

describe('canvas elements', () => {
  const response: NeighborhoodResponse = {
    center: { id: 'alert:1', type: 'alert', key: '1', label: '#1 SSH brute force from a very long place name', facts: { severity: 'high' }, flags: ['closed'], expandable: true, exists: true },
    window: { from: '2026-10-08T00:00:00.000Z', to: '2026-10-15T00:00:00.000Z', preset: '7d' },
    nodes: [
      { id: 'ip:198.51.100.7', type: 'ip', key: '198.51.100.7', label: '198.51.100.7', facts: {}, flags: ['threat_feed'], expandable: true },
      { id: 'account:3', type: 'account', key: '3', label: 'admin', facts: {}, flags: [], expandable: false },
    ],
    edges: [
      { id: 'alert_ips|alert:1|ip:198.51.100.7', source: 'alert:1', target: 'ip:198.51.100.7', rel: 'alert_ips', origin: 'alerts', style: 'recorded', role: 'sender' },
      { id: 'account_signins|account:3|ip:198.51.100.7', source: 'account:3', target: 'ip:198.51.100.7', rel: 'account_signins', origin: 'accounts', style: 'recorded', failures: 3, successes: 1, count: 4 },
    ],
    groups: [{ rel: 'alert_ips', label: 'IPs', neighbor_type: 'ip', origin: 'alerts', total: 1204, total_capped: false, shown: 1, very_common: true, status: 'ok' }],
    sources: {},
    generated_at: '',
    cached: false,
    elapsed_ms: 1,
  };
  const merged = mergeNeighborhood(emptyModel(['alert:1']), response);
  assert.ok(merged.ok);
  const elements = toElements(visibleGraph(merged.model), { centres: ['alert:1'], dark: false });
  const byId = new Map(elements.map((e) => [e.data.id as string, e]));

  it('cuts labels to 24 characters and marks the centre and flags', () => {
    const centre = byId.get('alert:1')!;
    assert.equal((centre.data.label as string).length, 24);
    assert.match(centre.classes, /\bcentre\b/);
    assert.match(centre.classes, /\bf-closed\b/);
    assert.match(byId.get('ip:198.51.100.7')!.classes, /\bf-threat_feed\b/);
  });

  it('draws the rest of a relation as one group node', () => {
    const g = byId.get('group:alert_ips|alert:1')!;
    assert.equal(g.data.label, '+1,203 ips\nvery common');
    assert.match(g.classes, /very-common/);
    assert.ok(byId.get('group:alert_ips|alert:1|edge'));
  });

  it('labels the sender role and sign-in outcomes on edges', () => {
    assert.equal(byId.get('alert_ips|alert:1|ip:198.51.100.7')!.data.label, 'sender');
    const signins = byId.get('account_signins|account:3|ip:198.51.100.7')!;
    assert.equal(signins.data.label, '3 failed / 1 succeeded');
    assert.match(signins.classes, /auth-failures/);
  });

  it('builds a stylesheet with solid, dashed and dotted edges', () => {
    const sheet = stylesheet({ dark: false, text: '#000', textMuted: '#666', background: '#fff', card: '#fff', border: '#ccc', edge: '#999', primary: '#409eff', danger: '#f56c6c', warning: '#e6a23c', highlight: '#7048e8' });
    const find = (selector: string) => sheet.find((s) => s.selector === selector)?.style;
    assert.equal(find('edge.s-logs')?.['line-style'], 'dashed');
    assert.equal(find('edge.s-heuristic')?.['line-style'], 'dotted');
    assert.equal(find('node.f-threat_feed')?.['border-color'], '#f56c6c');
  });
});

describe('application nodes', () => {
  const response: NeighborhoodResponse = {
    center: { id: 'application:nginx', type: 'application', key: 'nginx', label: 'nginx', facts: { vendor: 'F5', versions: '1.24.0, 1.25.3' }, flags: ['open_vulns'], expandable: true, exists: true },
    window: { from: '2026-10-08T00:00:00.000Z', to: '2026-10-15T00:00:00.000Z', preset: '7d' },
    nodes: [
      { id: 'asset:4', type: 'asset', key: '4', label: 'nas', facts: {}, flags: [], expandable: true },
      { id: 'ip:198.51.100.9', type: 'ip', key: '198.51.100.9', label: '198.51.100.9', facts: {}, flags: [], expandable: true },
      { id: 'vuln:7', type: 'vuln', key: '7', label: 'CVE-2024-1', facts: { severity: 'high' }, flags: [], expandable: true },
      { id: 'application:zoom', type: 'application', key: 'zoom', label: 'Zoom', facts: {}, flags: ['unmanaged'], expandable: true },
    ],
    edges: [
      { id: 'runs_app|asset:4|application:nginx', source: 'asset:4', target: 'application:nginx', rel: 'runs_app', origin: 'inventory', style: 'recorded', versions: ['1.24.0', '1.25.3'], sources: ['service_scan'], count: 2 },
      { id: 'uses_app|ip:198.51.100.9|application:nginx', source: 'ip:198.51.100.9', target: 'application:nginx', rel: 'uses_app', origin: 'inventory', style: 'recorded', versions: ['128.0'], network: true },
      { id: 'app_vulns|application:nginx|vuln:7', source: 'application:nginx', target: 'vuln:7', rel: 'app_vulns', origin: 'inventory', style: 'heuristic', match: 'best_effort' },
    ],
    groups: [{ rel: 'app_clients', label: 'Clients using it (seen on the network)', neighbor_type: 'ip', origin: 'inventory', total: 500, total_capped: false, shown: 1, very_common: true, status: 'ok' }],
    sources: {},
    generated_at: '',
    cached: false,
    elapsed_ms: 1,
  };
  const merged = mergeNeighborhood(emptyModel(['application:nginx']), response);
  assert.ok(merged.ok);
  const elements = toElements(visibleGraph(merged.model), { centres: ['application:nginx'], dark: false });
  const byId = new Map(elements.map((e) => [e.data.id as string, e]));

  it('draws an application as a green pentagon with its own glyph, in both themes', () => {
    assert.deepEqual([TYPE_STYLES.application.shape, TYPE_STYLES.application.glyph, TYPE_STYLES.application.label], ['pentagon', 'P', 'Application']);
    const node = byId.get('application:nginx')!;
    assert.equal(node.data.shape, 'pentagon');
    assert.equal(node.data.color, typeColor('application', false));
    assert.notEqual(typeColor('application', true), typeColor('application', false));
    assert.match(node.classes, /\bt-application\b/);
    assert.match(byId.get('application:zoom')!.classes, /\bf-unmanaged\b/);
  });

  it('captions inventory edges with the newest version, network evidence and best-effort matches', () => {
    assert.equal(byId.get('runs_app|asset:4|application:nginx')!.data.label, '1.25.3 +1');
    assert.match(byId.get('runs_app|asset:4|application:nginx')!.classes, /\bs-recorded\b.*\blabelled\b/);
    assert.equal(byId.get('uses_app|ip:198.51.100.9|application:nginx')!.data.label, '128.0 · network');
    const vuln = byId.get('app_vulns|application:nginx|vuln:7')!;
    assert.equal(vuln.data.label, 'best effort');
    assert.match(vuln.classes, /\bs-heuristic\b/);
    assert.equal(applicationEdgeLabel({ rel: 'app_vulns', match: 'exact', versions: ['1.24.0'] }), '', 'an exact match needs no caption');
    assert.equal(applicationEdgeLabel({ rel: 'alert_ips', versions: ['1'] }), '', 'only application edges');
    assert.equal(applicationEdgeLabel({ rel: 'runs_app', versions: ['x'.repeat(40)] }).length, 24, 'cut like a label');
    assert.equal(versionsLabel(['1.24.0', '1.25.3‮']), '1.24.0, 1.25.3');
    assert.equal(versionsLabel(undefined), '');
  });

  it('labels the relations and the very-common group', () => {
    assert.equal(edgeLabel('runs_app'), 'Runs this application (inventory)');
    assert.equal(edgeLabel('uses_app'), 'Uses this application (seen on the network)');
    assert.equal(edgeLabel('app_vulns'), 'Open vulnerability of the application');
    assert.equal(byId.get('group:app_clients|application:nginx')!.data.label, '+499 clients using it (seen on the network)\nvery common');
  });

  it('styles an unmanaged application with a double border', () => {
    const sheet = stylesheet({ dark: true, text: '#fff', textMuted: '#999', background: '#000', card: '#111', border: '#333', edge: '#666', primary: '#409eff', danger: '#f56c6c', warning: '#e6a23c', highlight: '#7048e8' });
    assert.equal(sheet.find((s) => s.selector === 'node.f-unmanaged')?.style['border-style'], 'double');
  });
});

describe('placement', () => {
  it('puts the first neighbours of a lone centre on a full circle', () => {
    const points = placeAround({ x: 0, y: 0 }, 4, [{ x: 0, y: 0 }]);
    assert.equal(points.length, 4);
    const angles = points.map((p) => Math.atan2(p.y, p.x));
    assert.ok(Math.max(...angles) - Math.min(...angles) > Math.PI);
  });

  it('places new nodes clear of the ones already there, facing away from them', () => {
    const existing = [{ x: 0, y: 0 }, { x: 200, y: 0 }, { x: -60, y: 40 }, { x: -60, y: -40 }];
    const points = placeAround({ x: 200, y: 0 }, 6, existing);
    assert.equal(points.length, 6);
    for (const p of points) {
      for (const o of existing) assert.ok(Math.hypot(p.x - o.x, p.y - o.y) >= MIN_GAP - 1, JSON.stringify([p, o]));
      assert.ok(p.x > 100, 'away from the rest');
    }
  });

  it('places nothing for nothing', () => {
    assert.deepEqual(placeAround({ x: 0, y: 0 }, 0, []), []);
  });
});
