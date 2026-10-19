/**
 * Settings -> Display links: the shapes of /api/display-links, the panel
 * catalogue and presets the editor offers, and the list's status and device
 * texts (docs/architecture/BIG-DISPLAY.md §5.3, §5.4, §8.3). Pure, so
 * displayLinks.test.ts runs it under node --test.
 *
 * The panel kinds mirror backend/src/services/display/config.ts PANEL_KINDS;
 * the server validates every config again and answers a 400 with the field.
 */

export type Privacy = 'operations' | 'public';
export type LinkStatus = 'live' | 'idle' | 'never_used' | 'paused' | 'expired' | 'revoked';

export type PanelSpec =
  | { id: 'open_alerts' | 'alert_pulse' | 'ingest' | 'shippers' | 'digital_risk' | 'vulnerabilities' | 'top_sources' }
  | { id: 'recent_alerts'; min_severity: 'critical' | 'high' | 'medium' }
  | { id: 'top_rules'; window_hours: 1 | 24 }
  | { id: 'sources'; silent_after_minutes: 5 | 15 | 30 | 60 }
  | { id: 'threat_map'; window_days: 1 | 7 | 30 };

export type PanelId = PanelSpec['id'];

export interface DisplayConfig {
  privacy: Privacy;
  refresh_seconds: 15 | 30 | 60 | 120;
  rotation: { enabled: boolean; seconds: number };
  timezone: string | null;
  clock: boolean;
  burn_in_shift: boolean;
  views: Array<{ title: string; panels: PanelSpec[] }>;
}

export interface DisplayLinkSummary {
  id: number;
  name: string;
  token_hint: string;
  status: LinkStatus;
  privacy: Privacy;
  view_count: number;
  panel_keys: string[];
  enabled: boolean;
  expires_at: string | null;
  revoked_at: string | null;
  allowed_cidrs: string[];
  created_by: { id: number; username: string } | null;
  created_at: string;
  updated_at: string;
  token_rotated_at: string;
  last_used_at: string | null;
  last_client: { ip: string; user_agent: string | null } | null;
  clients_24h: number;
}

export interface DisplayLinkClient {
  ip: string;
  user_agent: string | null;
  first_seen: string;
  last_seen: string;
}

export interface DisplayLinkDetail extends DisplayLinkSummary {
  config: DisplayConfig | null;
  config_version: number;
  clients: DisplayLinkClient[];
}

/** create and rotate: the only answers with the secret. */
export interface DisplayLinkSecret {
  link: DisplayLinkDetail;
  token: string;
  path: string;
}

/** What the editor opens with: a saved link, or a duplicate's starting point. */
export interface EditorInitial {
  name: string;
  config: DisplayConfig;
  expires_at: string | null;
  allowed_cidrs: string[];
}

export const MAX_VIEWS = 6;
export const MAX_PANELS_PER_VIEW = 6;
export const ROTATION_SECONDS = { min: 10, max: 600 };
export const REFRESH_OPTIONS = [15, 30, 60, 120] as const;

interface ParamInfo {
  name: string;
  label: string;
  options: Array<{ value: string | number; label: string }>;
  default: string | number;
}

export interface PanelInfo {
  id: PanelId;
  label: string;
  /** One line: what it shows. */
  what: string;
  /** Lists of labels are refused on a public-area display. */
  publicAllowed: boolean;
  param?: ParamInfo;
}

/** The kinds a display link may show (endpoint health is signed-in admins only). */
export const PANEL_CATALOGUE: readonly PanelInfo[] = [
  { id: 'open_alerts', label: 'Open alerts', what: 'Open alerts by severity, and how many nobody has picked up yet.', publicAllowed: true },
  { id: 'alert_pulse', label: 'Alert pulse', what: 'Alerts in the last 24 hours, hour by hour, against the 24 hours before.', publicAllowed: true },
  {
    id: 'recent_alerts',
    label: 'Recent alerts',
    what: 'The newest open alerts: severity, rule name and age (never the alert title).',
    publicAllowed: true,
    param: {
      name: 'min_severity',
      label: 'From',
      options: [
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High and above' },
        { value: 'medium', label: 'Medium and above' },
      ],
      default: 'high',
    },
  },
  {
    id: 'top_rules',
    label: 'Top detections',
    what: 'The rules that fired most.',
    publicAllowed: false,
    param: {
      name: 'window_hours',
      label: 'Window',
      options: [
        { value: 1, label: '1 hour' },
        { value: 24, label: '24 hours' },
      ],
      default: 24,
    },
  },
  { id: 'ingest', label: 'Log ingestion', what: 'Logs per minute, whether they are flowing, and how many parsers matched.', publicAllowed: true },
  {
    id: 'sources',
    label: 'Sources',
    what: 'The log sources that went silent.',
    publicAllowed: true,
    param: {
      name: 'silent_after_minutes',
      label: 'Silent after',
      options: [5, 15, 30, 60].map((m) => ({ value: m, label: `${m} min` })),
      default: 15,
    },
  },
  { id: 'shippers', label: 'Shippers', what: 'Log shippers online, stale and offline.', publicAllowed: true },
  {
    id: 'threat_map',
    label: 'Alert origins map',
    what: 'Where alerting addresses are, by country.',
    publicAllowed: true,
    param: {
      name: 'window_days',
      label: 'Window',
      options: [
        { value: 1, label: '24 hours' },
        { value: 7, label: '7 days' },
        { value: 30, label: '30 days' },
      ],
      default: 1,
    },
  },
  { id: 'top_sources', label: 'Top alerting addresses', what: 'The addresses behind the most alerts in 24 hours.', publicAllowed: false },
  { id: 'digital_risk', label: 'Digital risk', what: 'Exposure findings: lookalike domains and breached identities, as counts.', publicAllowed: true },
  { id: 'vulnerabilities', label: 'Vulnerabilities', what: 'Open vulnerabilities by severity.', publicAllowed: true },
];

export function panelInfo(id: PanelId): PanelInfo {
  return PANEL_CATALOGUE.find((p) => p.id === id) ?? PANEL_CATALOGUE[0];
}

/** A panel of this kind with its default option. */
export function newPanel(id: PanelId): PanelSpec {
  const param = panelInfo(id).param;
  return (param ? { id, [param.name]: param.default } : { id }) as PanelSpec;
}

export const PUBLIC_REFUSED_REASON = 'Lists names or addresses: not on a public-area display.';

export interface Preset {
  key: string;
  label: string;
  privacy: Privacy;
  views: Array<{ title: string; panels: PanelSpec[] }>;
}

/** BIG-DISPLAY.md §5.4: the starting points in the editor. */
export const PRESETS: readonly Preset[] = [
  {
    key: 'soc',
    label: 'SOC overview',
    privacy: 'operations',
    views: [
      {
        title: 'SOC overview',
        panels: [
          newPanel('open_alerts'),
          newPanel('alert_pulse'),
          newPanel('ingest'),
          { id: 'sources', silent_after_minutes: 15 },
          newPanel('shippers'),
          { id: 'recent_alerts', min_severity: 'high' },
        ],
      },
    ],
  },
  {
    key: 'threats',
    label: 'Threats',
    privacy: 'operations',
    views: [
      {
        title: 'Threats',
        panels: [{ id: 'threat_map', window_days: 1 }, newPanel('top_sources'), { id: 'top_rules', window_hours: 24 }, newPanel('open_alerts')],
      },
    ],
  },
  {
    key: 'health',
    label: 'Health',
    privacy: 'operations',
    views: [{ title: 'Health', panels: [newPanel('ingest'), { id: 'sources', silent_after_minutes: 15 }, newPanel('shippers'), newPanel('vulnerabilities')] }],
  },
  {
    key: 'public',
    label: 'Public area',
    privacy: 'public',
    views: [{ title: 'Overview', panels: [newPanel('open_alerts'), newPanel('alert_pulse'), newPanel('ingest'), newPanel('digital_risk')] }],
  },
];

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** A new link: Operations room (the owner's default), the SOC overview, Threats and Health views rotating. */
export function defaultConfig(): DisplayConfig {
  return {
    privacy: 'operations',
    refresh_seconds: 30,
    rotation: { enabled: true, seconds: 20 },
    timezone: null,
    clock: true,
    burn_in_shift: true,
    views: clone(PRESETS.filter((p) => p.privacy === 'operations').flatMap((p) => p.views)),
  };
}

export function presetViews(key: string): { privacy: Privacy; views: DisplayConfig['views'] } | null {
  const preset = PRESETS.find((p) => p.key === key);
  return preset ? { privacy: preset.privacy, views: clone(preset.views) } : null;
}

/** The panels a public-area display refuses, as "View 1 panel 3" labels. */
export function publicConflicts(config: DisplayConfig): string[] {
  if (config.privacy !== 'public') return [];
  const out: string[] = [];
  config.views.forEach((view, v) =>
    view.panels.forEach((panel, p) => {
      if (!panelInfo(panel.id).publicAllowed) out.push(`${view.title || `View ${v + 1}`}: ${panelInfo(panel.id).label} (panel ${p + 1})`);
    })
  );
  return out;
}

/** Moves item i of a list by -1 or +1 (a no-op at the ends). */
export function moveItem<T>(list: T[], i: number, direction: -1 | 1): T[] {
  const j = i + direction;
  if (j < 0 || j >= list.length) return list;
  const next = [...list];
  [next[i], next[j]] = [next[j], next[i]];
  return next;
}

// --- The list's texts --------------------------------------------------------

/** 12 s, 5 min, 3 h, 2 d. */
export function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

const DAY_MONTH = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' });

export function dayMonth(iso: string): string {
  return DAY_MONTH.format(new Date(iso));
}

export interface StatusText {
  text: string;
  tone: 'success' | 'warning' | 'info' | 'danger';
}

/** The Status column (BIG-DISPLAY.md §8.3). */
export function statusText(link: Pick<DisplayLinkSummary, 'status' | 'last_used_at' | 'expires_at'>, now: number): StatusText {
  const expiry = link.expires_at ? ` · expires ${dayMonth(link.expires_at)}` : '';
  switch (link.status) {
    case 'revoked':
      return { text: 'Revoked', tone: 'danger' };
    case 'expired':
      return { text: link.expires_at ? `Expired ${dayMonth(link.expires_at)}` : 'Expired', tone: 'danger' };
    case 'paused':
      return { text: `Paused${expiry}`, tone: 'info' };
    case 'never_used':
      return { text: `Never opened${expiry}`, tone: 'info' };
    case 'idle':
      return {
        text: `Not seen for ${link.last_used_at ? ago(now - Date.parse(link.last_used_at)) : '?'}${expiry}`,
        tone: 'warning',
      };
    case 'live':
    default:
      return {
        text: `Live — refreshed ${link.last_used_at ? ago(now - Date.parse(link.last_used_at)) : '?'} ago${expiry}`,
        tone: 'success',
      };
  }
}

/** A short browser name from a user agent: 'Chrome', 'Silk', 'Firefox', ... */
export function shortBrowser(userAgent: string | null | undefined): string {
  if (!userAgent) return 'unknown browser';
  const rules: Array<[RegExp, string]> = [
    [/\bSilk\//, 'Silk'],
    [/\bEdg(e|A|iOS)?\//, 'Edge'],
    [/\bOPR\//, 'Opera'],
    [/\bSamsungBrowser\//, 'Samsung Internet'],
    [/\b(Firefox|FxiOS)\//, 'Firefox'],
    [/\bChromium\//, 'Chromium'],
    [/(Chrome|CriOS)\//, 'Chrome'],
    [/\bVersion\/[\d.]+.*Safari\//, 'Safari'],
    [/\bcurl\//, 'curl'],
  ];
  const name = rules.find(([re]) => re.test(userAgent))?.[1] ?? 'other browser';
  const os = /Android/.test(userAgent)
    ? 'Android'
    : /iPhone|iPad/.test(userAgent)
      ? 'iOS'
      : /Windows/.test(userAgent)
        ? 'Windows'
        : /Mac OS X/.test(userAgent)
          ? 'macOS'
          : /Linux/.test(userAgent)
            ? 'Linux'
            : '';
  return os ? `${name} on ${os}` : name;
}

/** An expiry choice as the API's expires_at. */
export function expiresAtFor(choice: 'never' | '30' | '90' | 'date', date: Date | null, now: number): string | null {
  if (choice === 'never') return null;
  if (choice === 'date') return date ? date.toISOString() : null;
  return new Date(now + Number(choice) * 86_400_000).toISOString();
}

/** One CIDR per line or comma: trimmed, blanks dropped. */
export function parseCidrList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
