/**
 * How the graph looks (pure): shape and a one-letter glyph per type, so
 * colour is never the only cue; severity colours only on alerts and
 * vulnerabilities; solid, dashed and dotted edges for recorded, seen-in-logs
 * and heuristic links; and the Cytoscape elements and stylesheet built from
 * them. Colours come from the page's CSS variables (Element Plus and
 * --siembox-*), read by the canvas and passed in, so dark mode re-applies them.
 */
import { SEVERITY_COLORS } from '../utils/severity.ts';
import { canvasLabel, formatCount } from './labels.ts';
import type { GroupNode, VisibleGraph } from './model.ts';
import type { EdgeStyle, GraphEdge, GraphNode, NodeType, Origin } from './types.ts';

export type CyShape =
  | 'ellipse'
  | 'round-rectangle'
  | 'hexagon'
  | 'diamond'
  | 'rectangle'
  | 'triangle'
  | 'tag'
  | 'barrel'
  | 'star'
  | 'pentagon';

export interface TypeStyle {
  label: string;
  plural: string;
  shape: CyShape;
  glyph: string;
  /** Width over height (a user is an ellipse, an IP a circle). */
  aspect: number;
}

export const TYPE_STYLES: Record<NodeType, TypeStyle> = {
  ip: { label: 'IP', plural: 'IPs', shape: 'ellipse', glyph: 'I', aspect: 1 },
  host: { label: 'Host', plural: 'Hosts', shape: 'round-rectangle', glyph: 'H', aspect: 1.3 },
  user: { label: 'User', plural: 'Users', shape: 'ellipse', glyph: 'U', aspect: 1.45 },
  domain: { label: 'Domain', plural: 'Domains', shape: 'hexagon', glyph: 'D', aspect: 1.15 },
  alert: { label: 'Alert', plural: 'Alerts', shape: 'diamond', glyph: '!', aspect: 1 },
  rule: { label: 'Rule', plural: 'Rules', shape: 'barrel', glyph: 'R', aspect: 1.2 },
  asset: { label: 'Asset', plural: 'Assets', shape: 'rectangle', glyph: 'A', aspect: 1 },
  vuln: { label: 'Vulnerability', plural: 'Vulnerabilities', shape: 'triangle', glyph: 'V', aspect: 1.1 },
  finding: { label: 'Finding', plural: 'Findings', shape: 'tag', glyph: 'F', aspect: 1.3 },
  identity: { label: 'Identity', plural: 'Identities', shape: 'round-rectangle', glyph: '@', aspect: 1.3 },
  shipper: { label: 'Log shipper', plural: 'Log shippers', shape: 'rectangle', glyph: 'S', aspect: 1.5 },
  shipper_tag: { label: 'Unknown shipper', plural: 'Unknown shippers', shape: 'rectangle', glyph: '?', aspect: 1.5 },
  endpoint: { label: 'Endpoint agent', plural: 'Endpoint agents', shape: 'rectangle', glyph: 'E', aspect: 1.5 },
  account: { label: 'SIEMBox account', plural: 'SIEMBox accounts', shape: 'star', glyph: 'K', aspect: 1 },
  application: { label: 'Application', plural: 'Applications', shape: 'pentagon', glyph: 'P', aspect: 1.1 },
};

export const ORIGIN_LABELS: Record<Origin, string> = {
  alerts: 'Alerts',
  logs: 'Logs',
  inventory: 'Inventory',
  risk: 'Digital Risk',
  accounts: 'Accounts',
};

export const STYLE_MEANINGS: Record<EdgeStyle, string> = {
  recorded: 'Recorded by SIEMBox (solid line)',
  logs: 'Seen in logs: what a log said (dashed line)',
  heuristic: 'Matched by name or address (dotted line)',
};

/** What an edge says, by its canonical relation. Unknown ids show as written. */
export const EDGE_LABELS: Record<string, string> = {
  alert_ips: 'IP named in the alert',
  alert_users: 'User named in the alert',
  alert_hosts: 'Host named in the log',
  alert_domains: 'Domain named in the alert',
  alert_rule: 'Raised by this rule',
  alert_asset: 'Alert on this asset',
  alert_finding: 'Raised by this Digital Risk finding',
  alert_same_event: 'Raised on the same event',
  alert_account: 'SIEMBox account in the alert',
  alert_endpoint: 'Endpoint agent that detected it',
  alert_device: 'Device that logged it',
  shipped_by: 'Shipped by',
  asset_ip: 'Current IP of the asset',
  asset_host: 'Host name of the asset',
  asset_vulns: 'Vulnerability on the asset',
  ip_vulns: 'Vulnerability on the asset with this IP',
  host_vulns: 'Vulnerability on an asset with this host name',
  endpoint_vulns: 'Vulnerability on the endpoint',
  asset_shipper: 'Shipper matched by host name or IP',
  asset_endpoint: 'Endpoint agent on the asset',
  shipper_address: 'Address the shipper reported',
  finding_identity: 'Finding for this identity',
  finding_domain: 'Finding about this domain',
  identity_user: 'User with this address',
  identity_domain: 'Email domain',
  account_signins: 'Signed in to SIEMBox from',
  signed_in_as: 'Signed in as (seen in logs)',
  seen_on: 'Seen on this device (in its logs)',
  user_on: 'User seen on this device (in its logs)',
  connected_to: 'Connected to (seen in logs)',
  queried: 'Queried this domain (seen in logs)',
  sent_by: 'Logs sent from this IP',
  runs_app: 'Runs this application (inventory)',
  uses_app: 'Uses this application (seen on the network)',
  app_vulns: 'Open vulnerability of the application',
};

export const edgeLabel = (rel: string): string => EDGE_LABELS[rel] ?? rel.replace(/_/g, ' ');

const ROLE_LABELS: Record<NonNullable<GraphEdge['role']>, string> = {
  source: 'source IP',
  dest: 'destination IP',
  sender: 'sender: the device that sent the log',
};
export const roleLabel = (role: GraphEdge['role']): string => (role ? ROLE_LABELS[role] : '');

/** "312 failed / 1 succeeded", or '' when the edge counts no outcomes. */
export function outcomeLabel(edge: Pick<GraphEdge, 'failures' | 'successes'>): string {
  const failures = edge.failures ?? 0;
  const successes = edge.successes ?? 0;
  if (failures === 0 && successes === 0) return '';
  return `${failures.toLocaleString('en-US')} failed / ${successes.toLocaleString('en-US')} succeeded`;
}

/** Edge width: 1 + log10(count), at most 6. */
export function edgeWidth(count: number | undefined): number {
  const n = typeof count === 'number' && count > 1 ? count : 1;
  return Math.min(6, 1 + Math.log10(n));
}

export interface GraphPalette {
  dark: boolean;
  text: string;
  textMuted: string;
  background: string;
  card: string;
  border: string;
  edge: string;
  primary: string;
  danger: string;
  warning: string;
  /** Path and selection highlight. */
  highlight: string;
}

/** Type colours (never the severity colours, which are for alerts and vulnerabilities only). */
const TYPE_COLORS_LIGHT: Record<NodeType, string> = {
  ip: '#4c6ef5',
  host: '#0c8599',
  user: '#ae3ec9',
  domain: '#1971c2',
  alert: '#909399',
  rule: '#846358',
  asset: '#495057',
  vuln: '#909399',
  finding: '#c2255c',
  identity: '#d6336c',
  shipper: '#5f3dc4',
  shipper_tag: '#868e96',
  endpoint: '#364fc7',
  account: '#9c36b5',
  application: '#2b8a3e',
};
const TYPE_COLORS_DARK: Record<NodeType, string> = {
  ip: '#748ffc',
  host: '#3bc9db',
  user: '#da77f2',
  domain: '#4dabf7',
  alert: '#a3a6ad',
  rule: '#bc8f7c',
  asset: '#adb5bd',
  vuln: '#a3a6ad',
  finding: '#f06595',
  identity: '#faa2c1',
  shipper: '#9775fa',
  shipper_tag: '#a3a6ad',
  endpoint: '#748ffc',
  account: '#e599f7',
  application: '#69db7c',
};

/** The fill of a node: severity for alerts and vulnerabilities, else its type's colour. */
export function nodeColor(node: Pick<GraphNode, 'type' | 'facts'>, dark: boolean): string {
  if (node.type === 'alert' || node.type === 'vuln') {
    const severity = typeof node.facts.severity === 'string' ? node.facts.severity.toLowerCase() : '';
    if (SEVERITY_COLORS[severity]) return SEVERITY_COLORS[severity];
  }
  return (dark ? TYPE_COLORS_DARK : TYPE_COLORS_LIGHT)[node.type];
}

export const typeColor = (type: NodeType, dark: boolean): string => (dark ? TYPE_COLORS_DARK : TYPE_COLORS_LIGHT)[type];

/**
 * The canvas caption of an application edge: the newest version seen (an
 * edge from the inventory), "network" for evidence seen only on the wire, and
 * "best effort" for a vulnerability matched by product name. '' otherwise.
 */
export function applicationEdgeLabel(edge: Pick<GraphEdge, 'rel' | 'versions' | 'network' | 'match'>): string {
  if (edge.rel !== 'runs_app' && edge.rel !== 'uses_app' && edge.rel !== 'app_vulns') return '';
  const parts: string[] = [];
  const newest = edge.versions?.length ? edge.versions[edge.versions.length - 1] : '';
  if (newest && edge.rel !== 'app_vulns') parts.push(canvasLabel(edge.versions!.length > 1 ? `${newest} +${edge.versions!.length - 1}` : newest));
  if (edge.network) parts.push('network');
  if (edge.match === 'best_effort') parts.push('best effort');
  return parts.join(' · ');
}

/** "1.24.0, 1.25.3", for the details panel. */
export const versionsLabel = (versions: readonly string[] | undefined): string => (versions ?? []).map((v) => canvasLabel(v)).join(', ');

const glyphCache = new Map<string, string>();

/** The glyph as an SVG data URI drawn inside the node (white on its fill). */
export function glyphImage(glyph: string): string {
  const cached = glyphCache.get(glyph);
  if (cached) return cached;
  const escaped = glyph.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">` +
    `<text x="16" y="17" text-anchor="middle" dominant-baseline="middle" font-family="Helvetica, Arial, sans-serif" ` +
    `font-size="15" font-weight="700" fill="#ffffff">${escaped}</text></svg>`;
  const uri = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  glyphCache.set(glyph, uri);
  return uri;
}

const NODE_HEIGHT = 30;

export interface ElementDefinition {
  group: 'nodes' | 'edges';
  data: Record<string, unknown>;
  classes: string;
}

export interface ElementOptions {
  centres: readonly string[];
  /** The node each group node and new node is anchored to, for placement. */
  dark: boolean;
}

function groupLabel(g: GroupNode): string {
  const count = g.remaining === null ? formatCount(g.group.total, true) : formatCount(g.remaining);
  const what = g.group.label.toLowerCase();
  return `+${count} ${what}${g.group.very_common ? '\nvery common' : ''}`;
}

/** The Cytoscape elements for what is shown. Labels are cut to 24 characters; the panel shows them in full. */
export function toElements(visible: VisibleGraph, options: ElementOptions): ElementDefinition[] {
  const out: ElementDefinition[] = [];
  const centres = new Set(options.centres);
  for (const node of visible.nodes) {
    const style = TYPE_STYLES[node.type];
    const classes = [`t-${node.type}`, ...node.flags.map((f) => `f-${f}`)];
    if (centres.has(node.id)) classes.push('centre');
    if (node.type === 'asset' && typeof node.facts.criticality === 'string') classes.push(`crit-${node.facts.criticality}`);
    out.push({
      group: 'nodes',
      data: {
        id: node.id,
        kind: 'node',
        type: node.type,
        label: canvasLabel(node.label),
        shape: style.shape,
        color: nodeColor(node, options.dark),
        glyph: glyphImage(style.glyph),
        w: Math.round(NODE_HEIGHT * style.aspect),
        h: NODE_HEIGHT,
      },
      classes: classes.join(' '),
    });
  }
  for (const g of visible.groupNodes) {
    out.push({
      group: 'nodes',
      data: { id: g.id, kind: 'group', owner: g.owner, rel: g.group.rel, label: groupLabel(g) },
      classes: `group${g.group.very_common ? ' very-common' : ''}`,
    });
    out.push({
      group: 'edges',
      data: { id: `${g.id}|edge`, kind: 'group-edge', source: g.owner, target: g.id },
      classes: 'group-edge',
    });
  }
  for (const edge of visible.edges) {
    const classes = [`s-${edge.style}`];
    const outcome = outcomeLabel(edge);
    let label = '';
    if (outcome) {
      label = outcome;
      if ((edge.failures ?? 0) > 0) classes.push('auth-failures');
    } else if (edge.role === 'dest' || edge.role === 'sender') {
      label = edge.role === 'dest' ? 'dest' : 'sender';
    }
    const appLabel = applicationEdgeLabel(edge);
    if (appLabel) label = label ? `${label} · ${appLabel}` : appLabel;
    if (edge.new) label = label ? `NEW · ${label}` : 'NEW';
    if (edge.success_after_failures) label = `${label ? `${label} · ` : ''}success after failures`;
    if (label) classes.push('labelled');
    out.push({
      group: 'edges',
      data: { id: edge.id, kind: 'edge', source: edge.source, target: edge.target, rel: edge.rel, width: edgeWidth(edge.count), label },
      classes: classes.join(' '),
    });
  }
  return out;
}

/** Cytoscape's stylesheet for a palette. */
export function stylesheet(p: GraphPalette): Array<{ selector: string; style: Record<string, unknown> }> {
  return [
    {
      selector: 'node',
      style: {
        shape: 'data(shape)',
        width: 'data(w)',
        height: 'data(h)',
        'background-color': 'data(color)',
        'background-image': 'data(glyph)',
        'background-fit': 'contain',
        'background-clip': 'none',
        'border-width': 1,
        'border-color': p.border,
        label: 'data(label)',
        color: p.text,
        'font-size': 10,
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 4,
        'text-background-color': p.background,
        'text-background-opacity': 0.85,
        'text-background-padding': 1,
        'min-zoomed-font-size': 6,
      },
    },
    { selector: 'node.centre', style: { 'border-width': 3, 'border-color': p.primary } },
    { selector: 'node.crit-critical, node.crit-high', style: { 'border-width': 3, 'border-color': p.warning } },
    { selector: 'node.f-threat_feed', style: { 'border-width': 4, 'border-color': p.danger } },
    { selector: 'node.f-unmanaged', style: { 'border-style': 'double', 'border-width': 3, 'border-color': p.textMuted } },
    { selector: 'node.t-shipper_tag', style: { 'border-style': 'dashed', 'border-width': 2, 'border-color': p.textMuted } },
    { selector: 'node.f-closed', style: { opacity: 0.45 } },
    {
      selector: 'node.group',
      style: {
        shape: 'round-rectangle',
        width: 'label',
        height: 'label',
        padding: 6,
        'background-color': p.card,
        'background-image': 'none',
        'border-style': 'dashed',
        'border-width': 1,
        'border-color': p.textMuted,
        color: p.textMuted,
        'font-size': 10,
        'text-valign': 'center',
        'text-margin-y': 0,
        'text-wrap': 'wrap',
        'text-background-opacity': 0,
      },
    },
    { selector: 'node.group.very-common', style: { 'border-color': p.warning } },
    { selector: 'node.pulse', style: { 'overlay-color': p.primary, 'overlay-opacity': 0.25, 'overlay-padding': 8 } },
    { selector: 'node.selected', style: { 'border-width': 4, 'border-color': p.highlight, 'underlay-color': p.highlight, 'underlay-opacity': 0.18, 'underlay-padding': 6 } },
    {
      selector: 'edge',
      style: {
        width: 'data(width)',
        'line-color': p.edge,
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'target-arrow-color': p.edge,
        'arrow-scale': 0.6,
        opacity: 0.85,
      },
    },
    { selector: 'edge.s-logs', style: { 'line-style': 'dashed' } },
    { selector: 'edge.s-heuristic', style: { 'line-style': 'dotted' } },
    { selector: 'edge.auth-failures', style: { 'line-color': p.warning, 'target-arrow-color': p.warning } },
    {
      selector: 'edge.labelled',
      style: {
        label: 'data(label)',
        'font-size': 9,
        color: p.textMuted,
        'text-rotation': 'autorotate',
        'text-background-color': p.background,
        'text-background-opacity': 0.85,
        'text-background-padding': 1,
      },
    },
    { selector: 'edge.group-edge', style: { 'line-style': 'dashed', 'line-color': p.border, 'target-arrow-shape': 'none', width: 1 } },
    { selector: 'edge.selected', style: { 'line-color': p.highlight, 'target-arrow-color': p.highlight, width: 3 } },
    { selector: '.dim', style: { opacity: 0.12 } },
    { selector: 'node.path', style: { 'border-width': 4, 'border-color': p.highlight } },
    { selector: 'edge.path', style: { 'line-color': p.highlight, 'target-arrow-color': p.highlight, width: 4, opacity: 1 } },
  ];
}
