/**
 * What a display link shows, and the admin's inputs for a link, validated
 * (docs/architecture/BIG-DISPLAY.md §7.4). Pure: no database, no clock except
 * the `now` passed in.
 *
 * A config is views of panels. Each panel kind is one row in PANEL_KINDS: its
 * one optional enum parameter, the lowest role whose data it mirrors, and
 * whether a public-area display may show it. That table is the only place a
 * new kind (a future graph view, say) is added: links, their secret and their
 * auth stay one mechanism for every board.
 *
 * Unknown keys and out-of-range values are refused with the path of the field
 * (`config.views[0].panels[2].id`), never ignored. A config holds no free-form
 * filters, JSON paths or SQL: the token never selects what is queried, and the
 * server always reads the config from the link's own row.
 */
import net from 'node:net';

export type Sev = 'critical' | 'high' | 'medium' | 'low';
export type Privacy = 'operations' | 'public';

export type PanelSpec =
  | { id: 'open_alerts' }
  | { id: 'alert_pulse' }
  | { id: 'ingest' }
  | { id: 'shippers' }
  | { id: 'digital_risk' }
  | { id: 'vulnerabilities' }
  | { id: 'top_sources' }
  | { id: 'endpoints' } // signed-in admins only (refused in link configs)
  | { id: 'recent_alerts'; min_severity: 'critical' | 'high' | 'medium' }
  | { id: 'top_rules'; window_hours: 1 | 24 }
  | { id: 'sources'; silent_after_minutes: 5 | 15 | 30 | 60 }
  | { id: 'threat_map'; window_days: 1 | 7 | 30 };

export type PanelId = PanelSpec['id'];

export interface DisplayConfig {
  privacy: Privacy;
  refresh_seconds: 15 | 30 | 60 | 120;
  /** Ignored with one view. */
  rotation: { enabled: boolean; seconds: number };
  /** IANA name; null = the screen's own. */
  timezone: string | null;
  clock: boolean;
  burn_in_shift: boolean;
  views: Array<{ title: string; panels: PanelSpec[] }>;
}

interface PanelKind {
  /** The kind's one variant, if it has one: an enum with a default. */
  param?: { name: string; values: readonly (string | number)[]; default: string | number };
  /**
   * The lowest role whose data the panel mirrors. Display links may only use
   * 'viewer' kinds: a link never shows what some signed-in role can't read.
   */
  minRole: 'viewer' | 'admin';
  /** Public-area displays show counts only; kinds that are lists of labels are refused there. */
  publicAllowed: boolean;
}

export const PANEL_KINDS: Readonly<Record<PanelId, PanelKind>> = {
  open_alerts: { minRole: 'viewer', publicAllowed: true },
  alert_pulse: { minRole: 'viewer', publicAllowed: true },
  recent_alerts: {
    param: { name: 'min_severity', values: ['critical', 'high', 'medium'], default: 'high' },
    minRole: 'viewer',
    publicAllowed: true,
  },
  top_rules: { param: { name: 'window_hours', values: [1, 24], default: 24 }, minRole: 'viewer', publicAllowed: false },
  ingest: { minRole: 'viewer', publicAllowed: true },
  sources: {
    param: { name: 'silent_after_minutes', values: [5, 15, 30, 60], default: 15 },
    minRole: 'viewer',
    publicAllowed: true,
  },
  shippers: { minRole: 'viewer', publicAllowed: true },
  endpoints: { minRole: 'admin', publicAllowed: false },
  threat_map: { param: { name: 'window_days', values: [1, 7, 30], default: 1 }, minRole: 'viewer', publicAllowed: true },
  top_sources: { minRole: 'viewer', publicAllowed: false },
  digital_risk: { minRole: 'viewer', publicAllowed: true },
  vulnerabilities: { minRole: 'viewer', publicAllowed: true },
};

export const PANEL_IDS = Object.keys(PANEL_KINDS) as PanelId[];

export const LIMITS = {
  views: 6,
  panelsPerView: 6,
  /** Distinct panel keys per config: bounds the work per snapshot. */
  distinctPanels: 12,
  viewTitle: 40,
  linkName: 80,
  /** Serialized config, in bytes. */
  configBytes: 16 * 1024,
  allowedCidrs: 32,
  rotationSeconds: { min: 10, max: 600 },
  /** Live (not revoked) links per install. */
  liveLinks: 50,
} as const;

const REFRESH_SECONDS = [15, 30, 60, 120] as const;
const PRIVACY: readonly Privacy[] = ['operations', 'public'];

export const DEFAULTS = {
  privacy: 'operations' as Privacy,
  refresh_seconds: 30 as const,
  rotation: { enabled: true, seconds: 20 },
  timezone: null,
  clock: true,
  burn_in_shift: true,
};

/** The panel's key: its id plus its variant ('recent_alerts:high', 'top_rules:24'); variant-free ids are bare. */
export function panelKey(panel: PanelSpec): string {
  const param = PANEL_KINDS[panel.id].param;
  return param ? `${panel.id}:${(panel as unknown as Record<string, string | number>)[param.name]}` : panel.id;
}

/** Every distinct panel key of a config, in the order the views first use them. */
export function configPanelKeys(config: DisplayConfig): string[] {
  return [...new Set(config.views.flatMap((view) => view.panels.map(panelKey)))];
}

/** The `display` block of a snapshot: the layout a screen renders, with panel keys. */
export function describeDisplay(name: string, configVersion: number, config: DisplayConfig) {
  return {
    name,
    config_version: configVersion,
    privacy: config.privacy,
    refresh_seconds: config.refresh_seconds,
    rotation: { ...config.rotation },
    timezone: config.timezone,
    clock: config.clock,
    burn_in_shift: config.burn_in_shift,
    views: config.views.map((view) => ({ title: view.title, panels: view.panels.map(panelKey) })),
  };
}

// --- Results -----------------------------------------------------------------

export type Invalid = { ok: false; code: 'DISPLAY_CONFIG_INVALID' | 'DISPLAY_LINK_BAD_REQUEST'; field: string; message: string };
export type Parsed<T> = { ok: true; value: T } | Invalid;

const configError = (field: string, message: string): Invalid => ({ ok: false, code: 'DISPLAY_CONFIG_INVALID', field, message });
const requestError = (field: string, message: string): Invalid => ({ ok: false, code: 'DISPLAY_LINK_BAD_REQUEST', field, message });

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The first key of `obj` not in `allowed`. */
function unknownKey(obj: Record<string, unknown>, allowed: readonly string[]): string | undefined {
  return Object.keys(obj).find((key) => !allowed.includes(key));
}

// Control characters (C0, DEL, C1) and the Unicode line/paragraph separators.
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/** Length in code points, as Postgres char_length counts. */
const codePoints = (text: string) => Array.from(text).length;

/** A short label typed by an admin: trimmed, 1..max code points, no control characters. */
function parseLabel(input: unknown, field: string, max: number, fail: (f: string, m: string) => Invalid): Parsed<string> {
  if (typeof input !== 'string') return fail(field, `${field} must be a string`);
  const text = input.trim();
  if (!text) return fail(field, `${field} is required`);
  if (codePoints(text) > max) return fail(field, `${field} must be at most ${max} characters`);
  if (CONTROL_CHARS.test(text)) return fail(field, `${field} must not contain control characters or line breaks`);
  return { ok: true, value: text };
}

// --- Time zones ----------------------------------------------------------------

let zones: Set<string> | null = null;
function knownZones(): Set<string> {
  // Intl's canonical list leaves out 'UTC' on Node 22; it is the most common choice.
  zones ??= new Set([...Intl.supportedValuesOf('timeZone'), 'UTC']);
  return zones;
}

const ZONE_SHAPE = /^[A-Za-z][A-Za-z0-9_+/-]{0,63}$/;

/** An IANA zone name, canonicalized ('Asia/Calcutta' as the runtime names it), or null. */
export function canonicalTimeZone(input: string): string | null {
  if (!ZONE_SHAPE.test(input)) return null;
  let resolved: string;
  try {
    resolved = new Intl.DateTimeFormat('en-US', { timeZone: input }).resolvedOptions().timeZone;
  } catch {
    return null;
  }
  return knownZones().has(resolved) ? resolved : null;
}

// --- Config ------------------------------------------------------------------

const CONFIG_KEYS = ['privacy', 'refresh_seconds', 'rotation', 'timezone', 'clock', 'burn_in_shift', 'views'] as const;
const ROTATION_KEYS = ['enabled', 'seconds'] as const;
const VIEW_KEYS = ['title', 'panels'] as const;

export interface ConfigOptions {
  /**
   * A display link's config (the default): only panels every role may read.
   * False for the signed-in board, which filters by the viewer's role itself.
   */
  forLink?: boolean;
  /** The field path of the config, for messages. */
  path?: string;
}

function parsePanel(input: unknown, field: string, privacy: Privacy, forLink: boolean): Parsed<PanelSpec> {
  if (!isPlainObject(input)) return configError(field, `${field} must be an object such as { "id": "open_alerts" }`);
  const id = input.id;
  if (typeof id !== 'string' || !(PANEL_IDS as string[]).includes(id)) {
    return configError(`${field}.id`, `${field}.id must be one of: ${PANEL_IDS.join(', ')}`);
  }
  const kind = PANEL_KINDS[id as PanelId];
  const extra = unknownKey(input, kind.param ? ['id', kind.param.name] : ['id']);
  if (extra !== undefined) return configError(`${field}.${extra}`, `${field}.${extra} is not an option of "${id}"`);
  if (forLink && kind.minRole !== 'viewer') {
    return configError(
      `${field}.id`,
      id === 'endpoints'
        ? "Endpoint health is admin-only and can't be shown on a display link in this version."
        : `"${id}" is only for signed-in ${kind.minRole}s and can't be shown on a display link.`
    );
  }
  if (privacy === 'public' && !kind.publicAllowed) {
    return configError(`${field}.id`, `"${id}" is not available on a public-area display`);
  }
  if (!kind.param) return { ok: true, value: { id } as PanelSpec };
  const { name, values } = kind.param;
  const value = input[name] === undefined ? kind.param.default : input[name];
  if (!values.includes(value as string | number)) {
    return configError(`${field}.${name}`, `${field}.${name} must be one of: ${values.join(', ')}`);
  }
  return { ok: true, value: { id, [name]: value } as unknown as PanelSpec };
}

/**
 * A config as an admin sent it, normalized with every default filled in, or
 * the first problem with its field path.
 */
export function parseDisplayConfig(input: unknown, options: ConfigOptions = {}): Parsed<DisplayConfig> {
  const forLink = options.forLink ?? true;
  const path = options.path ?? 'config';
  if (!isPlainObject(input)) return configError(path, `${path} must be an object`);
  let bytes: number;
  try {
    bytes = Buffer.byteLength(JSON.stringify(input), 'utf8');
  } catch {
    return configError(path, `${path} must be plain JSON`);
  }
  if (bytes > LIMITS.configBytes) return configError(path, `${path} must be at most 16 kB`);
  const extra = unknownKey(input, CONFIG_KEYS);
  if (extra !== undefined) return configError(`${path}.${extra}`, `${path}.${extra} is not a display setting`);

  const privacy = input.privacy === undefined ? DEFAULTS.privacy : input.privacy;
  if (!PRIVACY.includes(privacy as Privacy)) {
    return configError(`${path}.privacy`, `${path}.privacy must be "operations" or "public"`);
  }

  const refresh = input.refresh_seconds === undefined ? DEFAULTS.refresh_seconds : input.refresh_seconds;
  if (!(REFRESH_SECONDS as readonly unknown[]).includes(refresh)) {
    return configError(`${path}.refresh_seconds`, `${path}.refresh_seconds must be one of: ${REFRESH_SECONDS.join(', ')}`);
  }

  const rotation = { ...DEFAULTS.rotation };
  if (input.rotation !== undefined) {
    if (!isPlainObject(input.rotation)) return configError(`${path}.rotation`, `${path}.rotation must be an object`);
    const extraRotation = unknownKey(input.rotation, ROTATION_KEYS);
    if (extraRotation !== undefined) {
      return configError(`${path}.rotation.${extraRotation}`, `${path}.rotation.${extraRotation} is not a rotation setting`);
    }
    const { enabled, seconds } = input.rotation;
    if (enabled !== undefined) {
      if (typeof enabled !== 'boolean') return configError(`${path}.rotation.enabled`, `${path}.rotation.enabled must be true or false`);
      rotation.enabled = enabled;
    }
    if (seconds !== undefined) {
      const { min, max } = LIMITS.rotationSeconds;
      if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds < min || seconds > max) {
        return configError(`${path}.rotation.seconds`, `${path}.rotation.seconds must be a whole number from ${min} to ${max}`);
      }
      rotation.seconds = seconds;
    }
  }

  let timezone: string | null = DEFAULTS.timezone;
  if (input.timezone !== undefined && input.timezone !== null) {
    const zone = typeof input.timezone === 'string' ? canonicalTimeZone(input.timezone.trim()) : null;
    if (!zone) {
      return configError(`${path}.timezone`, `${path}.timezone must be an IANA time zone such as "Europe/London", or null for the screen's own`);
    }
    timezone = zone;
  }

  const flags = { clock: DEFAULTS.clock, burn_in_shift: DEFAULTS.burn_in_shift };
  for (const flag of ['clock', 'burn_in_shift'] as const) {
    const value = input[flag];
    if (value === undefined) continue;
    if (typeof value !== 'boolean') return configError(`${path}.${flag}`, `${path}.${flag} must be true or false`);
    flags[flag] = value;
  }

  const views = input.views;
  if (!Array.isArray(views) || views.length === 0) {
    return configError(`${path}.views`, `${path}.views must list 1 to ${LIMITS.views} views`);
  }
  if (views.length > LIMITS.views) return configError(`${path}.views`, `a display has at most ${LIMITS.views} views`);
  const parsedViews: DisplayConfig['views'] = [];
  const keys = new Set<string>();
  for (let v = 0; v < views.length; v++) {
    const field = `${path}.views[${v}]`;
    const view = views[v];
    if (!isPlainObject(view)) return configError(field, `${field} must be an object with a title and panels`);
    const extraView = unknownKey(view, VIEW_KEYS);
    if (extraView !== undefined) return configError(`${field}.${extraView}`, `${field}.${extraView} is not a view setting`);
    const title = parseLabel(view.title, `${field}.title`, LIMITS.viewTitle, configError);
    if (!title.ok) return title;
    const panels = view.panels;
    if (!Array.isArray(panels) || panels.length === 0) {
      return configError(`${field}.panels`, `${field}.panels must list 1 to ${LIMITS.panelsPerView} panels`);
    }
    if (panels.length > LIMITS.panelsPerView) {
      return configError(`${field}.panels`, `a view has at most ${LIMITS.panelsPerView} panels`);
    }
    const parsedPanels: PanelSpec[] = [];
    const inView = new Set<string>();
    for (let p = 0; p < panels.length; p++) {
      const panel = parsePanel(panels[p], `${field}.panels[${p}]`, privacy as Privacy, forLink);
      if (!panel.ok) return panel;
      const key = panelKey(panel.value);
      if (inView.has(key)) return configError(`${field}.panels[${p}]`, `"${key}" is already in this view`);
      inView.add(key);
      keys.add(key);
      parsedPanels.push(panel.value);
    }
    parsedViews.push({ title: title.value, panels: parsedPanels });
  }
  if (keys.size > LIMITS.distinctPanels) {
    return configError(`${path}.views`, `a display shows at most ${LIMITS.distinctPanels} different panels (this one has ${keys.size})`);
  }

  return {
    ok: true,
    value: {
      privacy: privacy as Privacy,
      refresh_seconds: refresh as DisplayConfig['refresh_seconds'],
      rotation,
      timezone,
      ...flags,
      views: parsedViews,
    },
  };
}

// --- Link inputs ---------------------------------------------------------------

export function parseLinkName(input: unknown): Parsed<string> {
  return parseLabel(input, 'name', LIMITS.linkName, requestError);
}

// A date, optionally with a time and an offset: the forms the admin UI and
// scripts send (ISO 8601). Each part is a fixed-width run, so this is linear.
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

/** expires_at: null (never), or an ISO 8601 date that is still in the future. */
export function parseExpiresAt(input: unknown, now: Date): Parsed<Date | null> {
  if (input === null) return { ok: true, value: null };
  if (typeof input !== 'string' || input.length > 40 || !ISO_DATE.test(input.trim())) {
    return requestError('expires_at', 'expires_at must be an ISO 8601 date such as "2027-03-01T09:00:00Z", or null for never');
  }
  const date = new Date(input.trim());
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() > 9999) {
    return requestError('expires_at', 'expires_at is not a valid date');
  }
  if (date.getTime() <= now.getTime()) return requestError('expires_at', 'expires_at must be in the future');
  return { ok: true, value: date };
}

/** An address's bytes: 4 for IPv4, 16 for IPv6; null when it is neither. */
function addressBytes(ip: string): number[] | null {
  const family = net.isIP(ip);
  if (family === 4) return ip.split('.').map(Number);
  if (family !== 6) return null;
  let text = ip.toLowerCase();
  let tail: number[] = [];
  // An embedded IPv4 tail ('::ffff:192.0.2.1') is the last two groups.
  const lastColon = text.lastIndexOf(':');
  const last = text.slice(lastColon + 1);
  if (last.includes('.')) {
    tail = last.split('.').map(Number);
    text = text.slice(0, lastColon + 1);
    // The colon before the IPv4 part separates groups, unless it is half of '::'.
    if (text.endsWith(':') && !text.endsWith('::')) text = text.slice(0, -1);
  }
  const groupsWanted = tail.length ? 6 : 8;
  const [head, rest] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = rest === undefined ? [] : rest ? rest.split(':') : [];
  const fill = rest === undefined ? [] : new Array<string>(groupsWanted - left.length - right.length).fill('0');
  const groups = [...left, ...fill, ...right].map((group) => parseInt(group, 16));
  if (groups.length !== groupsWanted || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return [...groups.flatMap((g) => [g >> 8, g & 255]), ...tail];
}

/** RFC 5952 text of 16 bytes: lower-case, the longest run of two or more zero groups as '::'. */
function formatIpv6(bytes: number[]): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

/**
 * One allow-list entry in network form ('10.20.0.0/16'), or null. An address
 * alone is its /32 or /128; host bits are cleared ('10.20.30.12/16' is
 * '10.20.0.0/16'); an IPv4-mapped IPv6 network (::ffff:a.b.c.d/96 and longer)
 * becomes its IPv4 network, since client addresses are compared in IPv4 form.
 */
export function normalizeCidr(input: string): string | null {
  const text = input.trim();
  if (!text || text.length > 64 || text.includes('%')) return null;
  const slash = text.indexOf('/');
  const address = slash === -1 ? text : text.slice(0, slash);
  const prefixText = slash === -1 ? null : text.slice(slash + 1);
  const bytes = addressBytes(address);
  if (!bytes) return null;
  const bits = bytes.length * 8;
  let prefix = bits;
  if (prefixText !== null) {
    if (!/^\d{1,3}$/.test(prefixText)) return null;
    prefix = Number(prefixText);
    if (prefix > bits) return null;
  }
  let network = bytes.map((byte, i) => {
    const keep = Math.max(0, Math.min(8, prefix - i * 8));
    return keep === 0 ? 0 : byte & ((0xff << (8 - keep)) & 0xff);
  });
  if (bits === 128 && prefix >= 96 && network.slice(0, 10).every((b) => b === 0) && network[10] === 0xff && network[11] === 0xff) {
    network = network.slice(12);
    prefix -= 96;
  }
  return network.length === 4 ? `${network.join('.')}/${prefix}` : `${formatIpv6(network)}/${prefix}`;
}

/** allowed_cidrs: up to 32 addresses or CIDR networks, normalized and de-duplicated; [] = any network. */
export function parseAllowedCidrs(input: unknown): Parsed<string[]> {
  if (!Array.isArray(input)) return requestError('allowed_cidrs', 'allowed_cidrs must be a list of networks such as "10.20.0.0/16"');
  if (input.length > LIMITS.allowedCidrs) {
    return requestError('allowed_cidrs', `allowed_cidrs has at most ${LIMITS.allowedCidrs} entries`);
  }
  const out: string[] = [];
  for (let i = 0; i < input.length; i++) {
    const entry = input[i];
    const cidr = typeof entry === 'string' ? normalizeCidr(entry) : null;
    if (!cidr) {
      return requestError(`allowed_cidrs[${i}]`, `allowed_cidrs[${i}] must be an IP address or a network such as "10.20.0.0/16"`);
    }
    if (!out.includes(cidr)) out.push(cidr);
  }
  return { ok: true, value: out };
}

// --- Request bodies --------------------------------------------------------------

export interface CreateLinkInput {
  name: string;
  config: DisplayConfig;
  expiresAt: Date | null;
  allowedCidrs: string[];
}

export interface UpdateLinkInput {
  name?: string;
  config?: DisplayConfig;
  enabled?: boolean;
  expiresAt?: Date | null;
  allowedCidrs?: string[];
}

const CREATE_KEYS = ['name', 'config', 'expires_at', 'allowed_cidrs'] as const;
const UPDATE_KEYS = ['name', 'config', 'enabled', 'expires_at', 'allowed_cidrs'] as const;

/** POST /api/display-links: { name, config, expires_at?, allowed_cidrs? }. */
export function parseCreateLink(body: unknown, now: Date): Parsed<CreateLinkInput> {
  if (!isPlainObject(body)) return requestError('body', 'Send a JSON object with name and config');
  const extra = unknownKey(body, CREATE_KEYS);
  if (extra !== undefined) return requestError(extra, `${extra} is not a display link field`);
  const name = parseLinkName(body.name);
  if (!name.ok) return name;
  if (body.config === undefined) return configError('config', 'config is required');
  const config = parseDisplayConfig(body.config);
  if (!config.ok) return config;
  const expiresAt = body.expires_at === undefined ? ({ ok: true, value: null } as const) : parseExpiresAt(body.expires_at, now);
  if (!expiresAt.ok) return expiresAt;
  const cidrs: Parsed<string[]> = body.allowed_cidrs === undefined ? { ok: true, value: [] } : parseAllowedCidrs(body.allowed_cidrs);
  if (!cidrs.ok) return cidrs;
  return { ok: true, value: { name: name.value, config: config.value, expiresAt: expiresAt.value, allowedCidrs: cidrs.value } };
}

/** PUT /api/display-links/:id: any of { name, config, enabled, expires_at, allowed_cidrs }. */
export function parseUpdateLink(body: unknown, now: Date): Parsed<UpdateLinkInput> {
  if (!isPlainObject(body)) return requestError('body', 'Send a JSON object with the fields to change');
  const extra = unknownKey(body, UPDATE_KEYS);
  if (extra !== undefined) return requestError(extra, `${extra} is not a display link field`);
  const out: UpdateLinkInput = {};
  if (body.name !== undefined) {
    const name = parseLinkName(body.name);
    if (!name.ok) return name;
    out.name = name.value;
  }
  if (body.config !== undefined) {
    const config = parseDisplayConfig(body.config);
    if (!config.ok) return config;
    out.config = config.value;
  }
  if (body.enabled !== undefined) {
    if (typeof body.enabled !== 'boolean') return requestError('enabled', 'enabled must be true or false');
    out.enabled = body.enabled;
  }
  if (body.expires_at !== undefined) {
    const expiresAt = parseExpiresAt(body.expires_at, now);
    if (!expiresAt.ok) return expiresAt;
    out.expiresAt = expiresAt.value;
  }
  if (body.allowed_cidrs !== undefined) {
    const cidrs = parseAllowedCidrs(body.allowed_cidrs);
    if (!cidrs.ok) return cidrs;
    out.allowedCidrs = cidrs.value;
  }
  if (Object.keys(out).length === 0) return requestError('body', 'Nothing to change: send name, config, enabled, expires_at or allowed_cidrs');
  return { ok: true, value: out };
}
