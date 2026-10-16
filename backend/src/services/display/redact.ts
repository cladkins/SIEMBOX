/**
 * Privacy enforcement for the Big Display (docs/architecture/BIG-DISPLAY.md
 * §7.8). Pure; runs last on every snapshot.
 *
 * Labels are the only free strings a screen ever gets, and they come only from
 * configuration (rule and shipper names) or validated identifiers (host names,
 * IP addresses, country codes). Public-area displays get none of them: counts,
 * enums, timestamps and the fixed category labels only.
 *
 * Never read for a display, in any mode: alert titles and descriptions, any
 * matched_data key but source_ip and country_code, raw or parsed log text,
 * usernames, account names and email addresses, breach names, lookalike
 * domains. The panel SQL (panels.ts) doesn't select them; assertDisplaySafe()
 * is the backstop: it walks each panel's data against the shape declared for
 * it, and a panel holding anything else (a string where an enum belongs, an
 * email address, a key it doesn't declare) goes out `unavailable` instead.
 */
import net from 'node:net';
import { PANEL_KINDS, type PanelId, type Privacy } from './config';
import type { Category, PanelEnvelope } from './types';

// --- Labels ----------------------------------------------------------------------

export const LABEL_MAX = 64;

// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;

/** Control characters out, whitespace collapsed, at most 64 characters (an ellipsis marks a cut). */
export function safeLabel(text: string): string {
  const clean = text.replace(CONTROL, ' ').replace(/\s+/g, ' ').trim();
  const chars = Array.from(clean);
  return chars.length > LABEL_MAX ? `${chars.slice(0, LABEL_MAX - 1).join('')}…` : clean;
}

/** A configured name (rule, shipper) as a label, or null when nothing is left or it holds an email address. */
export function configLabel(name: unknown): string | null {
  if (typeof name !== 'string') return null;
  const label = safeLabel(name);
  return label && !EMAIL.test(label) ? label : null;
}

export const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/;

/** An address net.isIP accepts, else null. */
export function safeIp(ip: unknown): string | null {
  return typeof ip === 'string' && net.isIP(ip) ? ip : null;
}

/** A host's label: its name if it is a plain host name, else its address, else null. */
export function safeHost(hostname: unknown, ip?: unknown): string | null {
  if (typeof hostname === 'string' && HOSTNAME.test(hostname)) return hostname;
  return safeIp(ip);
}

export const COUNTRY = /^[A-Z]{2}$/;

export function safeCountry(code: unknown): string | null {
  return typeof code === 'string' && COUNTRY.test(code) ? code : null;
}

/** alerts.source -> category. NULL is a detection rule's alert. */
export function categoryOf(source: string | null): Category {
  switch (source) {
    case null:
    case undefined:
      return 'rule';
    case 'siembox-auth':
      return 'sign_in';
    case 'leaked-creds':
      return 'leaked_credentials';
    case 'domain-monitor':
      return 'domain_monitoring';
    case 'edr':
      return 'endpoint';
    default:
      return 'other';
  }
}

/** The closed set of labels a public-area display may show for an alert. */
export const CATEGORY_LABELS: Readonly<Record<Category, string>> = {
  rule: 'Detection rule',
  sign_in: 'Sign-in protection',
  leaked_credentials: 'Leaked credentials',
  domain_monitoring: 'Domain monitoring',
  endpoint: 'Endpoint detection',
  other: 'Other',
};
const CATEGORY_LABEL_SET = new Set(Object.values(CATEGORY_LABELS));

/** An alert's label: the rule's name for a rule alert in operations mode, else the category's fixed label. */
export function alertLabel(category: Category, ruleName: unknown, privacy: Privacy): string {
  if (category === 'rule' && privacy === 'operations') return configLabel(ruleName) ?? CATEGORY_LABELS.rule;
  return CATEGORY_LABELS[category];
}

// --- Declared shapes -------------------------------------------------------------

/**
 * A leaf or a container. Label kinds:
 *   alert   — an alert's label: any configured name in operations, a category label in public;
 *   name    — a configured name (shipper, source label); operations only;
 *   host    — a host name or an address; operations only;
 *   ip      — an address; operations only;
 *   country — an ISO 3166 alpha-2 code.
 */
type Shape =
  | 'count'
  | 'number'
  | 'boolean'
  | 'iso'
  | { enum: readonly (string | number)[] }
  | { label: 'alert' | 'name' | 'host' | 'ip' | 'country' }
  | { nullable: Shape }
  | { array: Shape; max: number; length?: number; publicEmpty?: boolean }
  | { object: Record<string, Shape> }
  | { sevs: Shape };

const SEV = { enum: ['critical', 'high', 'medium', 'low'] } as const;
const CATEGORY = { enum: Object.keys(CATEGORY_LABELS) } as const;
const nullable = (shape: Shape): Shape => ({ nullable: shape });
const obj = (fields: Record<string, Shape>): Shape => ({ object: fields });
const paramValues = (id: PanelId) => PANEL_KINDS[id].param!.values;

export const PANEL_SHAPES: Readonly<Record<PanelId, Shape>> = {
  open_alerts: obj({ total: 'count', by_severity: { sevs: obj({ open: 'count', untouched: 'count', oldest_at: nullable('iso') }) } }),
  alert_pulse: obj({
    total_24h: 'count',
    prev_24h: 'count',
    last_hour: 'count',
    by_severity_24h: { sevs: 'count' },
    hourly: { array: obj({ total: 'count', critical: 'count' }), max: 24, length: 24 },
  }),
  recent_alerts: obj({
    min_severity: { enum: paramValues('recent_alerts') },
    more: 'boolean',
    items: {
      array: obj({ severity: SEV, status: { enum: ['new', 'investigating'] }, category: CATEGORY, label: { label: 'alert' }, at: 'iso' }),
      max: 6,
    },
  }),
  top_rules: obj({
    window_hours: { enum: paramValues('top_rules') },
    total: 'count',
    items: { array: obj({ category: CATEGORY, label: { label: 'alert' }, worst_severity: SEV, count: 'count' }), max: 6 },
  }),
  ingest: obj({
    state: { enum: ['flowing', 'slow', 'stalled', 'idle'] },
    last_log_at: nullable('iso'),
    stall_minutes: 'count',
    logs_last_minute: nullable('count'),
    per_minute: nullable({ array: 'count', max: 60, length: 60 }),
    rate_15m_per_minute: nullable('number'),
    baseline_per_minute: nullable('number'),
    hourly: { array: obj({ total: 'count', unparsed: 'count' }), max: 24, length: 24 },
    parsed_pct_24h: nullable('number'),
    udp_dropped_15m: nullable('count'),
    rollup_since: nullable('iso'),
  }),
  sources: obj({
    silent_after_minutes: { enum: paramValues('sources') },
    active: 'count',
    silent: 'count',
    quiet: 'count',
    unknown: 'count',
    unknown_shippers: 'count',
    since: nullable('iso'),
    more_active: 'count',
    rows: {
      array: obj({
        kind: { enum: ['shipper', 'poller', 'direct'] },
        label: nullable({ label: 'name' }),
        state: { enum: ['silent', 'active', 'quiet', 'unknown'] },
        logs_per_minute: 'number',
        last_seen_at: 'iso',
        silent_minutes: nullable('count'),
      }),
      max: 8,
      publicEmpty: true,
    },
  }),
  shippers: obj({
    total: 'count',
    online: 'count',
    offline: 'count',
    pending: 'count',
    error: 'count',
    unknown_shippers_24h: nullable('count'),
    offline_list: { array: obj({ name: { label: 'name' }, last_seen_at: nullable('iso') }), max: 6, publicEmpty: true },
  }),
  endpoints: obj({
    total: 'count',
    online: 'count',
    offline: 'count',
    detections_24h: 'count',
    offline_list: { array: obj({ hostname: nullable({ label: 'host' }), last_seen_at: nullable('iso') }), max: 6, publicEmpty: true },
  }),
  threat_map: obj({
    window_days: { enum: paramValues('threat_map') },
    located: 'count',
    total_in_window: 'count',
    countries: { array: obj({ code: { label: 'country' }, count: 'count' }), max: 50 },
  }),
  top_sources: obj({
    items: {
      array: obj({ ip: { label: 'ip' }, country_code: nullable({ label: 'country' }), alerts: 'count', worst_severity: SEV, last_at: 'iso' }),
      max: 6,
      publicEmpty: true,
    },
  }),
  digital_risk: obj({
    configured: 'boolean',
    open_total: 'count',
    open_by_severity: { sevs: 'count' },
    new_7d: 'count',
    accounts_to_reset: 'count',
    impersonation_open: 'count',
  }),
  vulnerabilities: obj({ scanned: 'boolean', open_by_severity: { sevs: 'count' }, affected_assets: 'count' }),
};

/** The fixed wording of a panel that isn't set up (§5.3); nothing else may be a not_configured message. */
export const NOT_CONFIGURED: Readonly<Partial<Record<PanelId, string>>> = {
  shippers: 'No shippers registered',
  endpoints: 'No endpoint agents enrolled',
  digital_risk: 'Digital Risk is not set up',
  vulnerabilities: 'No scans yet',
};

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const isPlainObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function labelProblem(kind: 'alert' | 'name' | 'host' | 'ip' | 'country', value: unknown, privacy: Privacy): string | null {
  if (typeof value !== 'string') return 'is not a string';
  if (kind === 'country') return COUNTRY.test(value) ? null : 'is not a country code';
  if (kind === 'alert' && CATEGORY_LABEL_SET.has(value)) return null;
  if (privacy === 'public') return 'is a label a public-area display may not show';
  switch (kind) {
    case 'ip':
      return net.isIP(value) ? null : 'is not an IP address';
    case 'host':
      return HOSTNAME.test(value) || net.isIP(value) ? null : 'is not a host name or address';
    default:
      if (EMAIL.test(value)) return 'holds an email address';
      return safeLabel(value) === value && value.length > 0 ? null : 'is not a clean label';
  }
}

function check(shape: Shape, value: unknown, path: string, privacy: Privacy): string | null {
  if (shape === 'count') return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? null : `${path} is not a count`;
  if (shape === 'number') return typeof value === 'number' && Number.isFinite(value) ? null : `${path} is not a number`;
  if (shape === 'boolean') return typeof value === 'boolean' ? null : `${path} is not true or false`;
  if (shape === 'iso') return typeof value === 'string' && ISO.test(value) ? null : `${path} is not an ISO timestamp`;
  if ('enum' in shape) return shape.enum.includes(value as string | number) ? null : `${path} is not one of its values`;
  if ('label' in shape) {
    const problem = labelProblem(shape.label, value, privacy);
    return problem ? `${path} ${problem}` : null;
  }
  if ('nullable' in shape) return value === null ? null : check(shape.nullable, value, path, privacy);
  if ('array' in shape) {
    if (!Array.isArray(value)) return `${path} is not a list`;
    if (value.length > shape.max) return `${path} has more than ${shape.max} entries`;
    if (shape.length !== undefined && value.length !== shape.length) return `${path} must have ${shape.length} entries`;
    if (shape.publicEmpty && privacy === 'public' && value.length > 0) return `${path} must be empty on a public-area display`;
    for (let i = 0; i < value.length; i++) {
      const problem = check(shape.array, value[i], `${path}[${i}]`, privacy);
      if (problem) return problem;
    }
    return null;
  }
  const fields: Record<string, Shape> =
    'sevs' in shape ? { critical: shape.sevs, high: shape.sevs, medium: shape.sevs, low: shape.sevs } : shape.object;
  if (!isPlainObject(value)) return `${path} is not an object`;
  for (const key of Object.keys(value)) {
    if (!(key in fields)) return `${path}.${key} is not declared`;
  }
  for (const [key, inner] of Object.entries(fields)) {
    if (!(key in value)) return `${path}.${key} is missing`;
    const problem = check(inner, value[key], `${path}.${key}`, privacy);
    if (problem) return problem;
  }
  return null;
}

/** The panel id of a key ('top_rules:24' -> 'top_rules'), or null when it isn't one. */
export function panelIdOf(key: string): PanelId | null {
  const id = key.split(':')[0];
  return id in PANEL_SHAPES ? (id as PanelId) : null;
}

/** The first thing wrong with a panel's data for this privacy level, or null. */
export function panelDataProblem(id: PanelId, data: unknown, privacy: Privacy): string | null {
  return check(PANEL_SHAPES[id], data, id, privacy);
}

/** The first thing wrong with an envelope, or null. */
export function envelopeProblem(key: string, envelope: unknown, privacy: Privacy): string | null {
  const id = panelIdOf(key);
  if (!id) return `${key} is not a panel`;
  if (!isPlainObject(envelope)) return `${key} is not an envelope`;
  const allowed: Record<string, string[]> = {
    ok: ['state', 'as_of', 'data'],
    stale: ['state', 'as_of', 'reason', 'data'],
    unavailable: ['state', 'reason'],
    not_configured: ['state', 'message'],
    forbidden: ['state'],
  };
  const state = envelope.state as string;
  const keys = allowed[state];
  if (!keys) return `${key}.state is not a panel state`;
  const extra = Object.keys(envelope).find((k) => !keys.includes(k));
  if (extra) return `${key}.${extra} is not declared`;
  const missing = keys.find((k) => !(k in envelope));
  if (missing) return `${key}.${missing} is missing`;
  if ('as_of' in envelope && !(typeof envelope.as_of === 'string' && ISO.test(envelope.as_of))) return `${key}.as_of is not an ISO timestamp`;
  if ('reason' in envelope && envelope.reason !== 'busy' && envelope.reason !== 'error') return `${key}.reason is not a reason`;
  if (state === 'not_configured' && envelope.message !== NOT_CONFIGURED[id]) return `${key}.message is not this panel's wording`;
  if ('data' in envelope) return panelDataProblem(id, envelope.data, privacy);
  return null;
}

export interface RedactLog {
  error: (msg: string, meta?: unknown) => void;
}

/**
 * Every envelope checked against its declared shape for this privacy level.
 * One that fails is replaced by `unavailable` and logged (with the path of the
 * problem, never the value): it is never sent.
 */
export function assertDisplaySafe(
  panels: Record<string, PanelEnvelope>,
  privacy: Privacy,
  log: RedactLog
): Record<string, PanelEnvelope> {
  const out: Record<string, PanelEnvelope> = {};
  for (const [key, envelope] of Object.entries(panels)) {
    const problem = envelopeProblem(key, envelope, privacy);
    if (problem) {
      log.error('Big Display: a panel failed the privacy check and was withheld', { panel: key, problem });
      out[key] = { state: 'unavailable', reason: 'error' };
    } else {
      out[key] = envelope;
    }
  }
  return out;
}
