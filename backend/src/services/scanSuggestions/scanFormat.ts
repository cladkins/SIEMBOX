/**
 * The suggested-scan format (siembox.scan/v1) and its validator. DB-free and
 * network-free: the catalog's CI runs it through `npm run validate-scans`, the
 * app runs it on every suggestion it reads from the catalog, and the bundled
 * starter set passes it too (scanCatalog.test).
 *
 * A suggestion lives in the catalog as `scans/<id>.scan.yaml`:
 *
 *   schema: siembox.scan/v1
 *   id: asset-host-discovery-daily     # kebab-case, the file name
 *   name: Daily host discovery
 *   kind: asset                        # asset | vulnerability | container | log_discovery | endpoint_policy
 *   category: inventory                # one of SCAN_CATEGORIES
 *   tags: [nmap, ping]                 # optional
 *   description: What it does.
 *   why: When and why to use it.
 *   intrusive: false                   # true: may change state on the target (logins, payloads)
 *   intrusive_note: ...                # required when intrusive is true
 *   load: light                        # light | moderate | heavy (on the network or the endpoint)
 *   schedule:                          # calendar timing (Scheduled Scans), WITHOUT a timezone:
 *     frequency: daily                 # the person adding it gets their browser's
 *     time: "02:30"
 *   options:                           # the scan's options, WITHOUT targets
 *     scanType: ping
 *   inputs:                            # what the person fills in after adding it
 *     - field: targets
 *       label: Subnets to sweep
 *       hint: Your LAN subnets in CIDR form.
 *
 * Per kind (options are checked with the functions the Scheduled Scans and
 * endpoint scan-policy routes use, so an added suggestion is one they accept):
 *
 *   asset           options { scanType }                           inputs targets (required), shipper
 *   vulnerability   options { templateSelection, rateLimit?, timeout? }   target (required), shipper
 *   container       options { all_images? }                        image_ref (required unless all_images)
 *   log_discovery   options { mode }                               cidrs, shipper (both optional)
 *   endpoint_policy options { scans: { vuln, yara, packages, inventory } }   endpoints (required)
 *                   each entry as a scan policy's: { enabled, schedule | interval_minutes, window? },
 *                   schedules and windows without a timezone; no top-level schedule.
 *
 * Safety: a suggestion never names a target. Options may not carry target
 * keys (targets, target, image_ref, manual_cidrs, assignedShipperId), and no
 * string in options or inputs may look like an IP address, a CIDR or a host
 * name (nor may any other text hold an IP or CIDR). A vulnerability
 * suggestion whose template selection can run intrusive templates (all
 * templates, an intrusive tag such as default-login, or without excluding the
 * intrusive, dos and fuzz tags) must say intrusive: true with a note.
 */
import net from 'net';
import { normalizeCalendarSchedule, type CalendarSchedule } from '../../utils/scheduleTiming';
import { ASSET_SCAN_TYPES, DISCOVERY_MODES, scanOptionsShapeError, type ScheduledScanKind } from '../scanner/scheduleOptions';
import { normalizePolicyScans } from '../edr/scanPolicies';
import { SCAN_TYPES as ENDPOINT_SCAN_TYPES } from '../edr/edrScans';

export const SCAN_SCHEMA = 'siembox.scan/v1';
/** Catalog file name: scans/<id>.scan.yaml. */
export const SCAN_FILE_SUFFIX = '.scan.yaml';

export const SUGGESTION_KINDS = ['asset', 'vulnerability', 'container', 'log_discovery', 'endpoint_policy'] as const;
export type SuggestionKind = (typeof SUGGESTION_KINDS)[number];

export const SCAN_CATEGORIES = [
  'inventory',
  'services',
  'cves',
  'exposure',
  'misconfiguration',
  'credentials',
  'tls',
  'dns',
  'containers',
  'log-sources',
  'endpoints',
] as const;
export type ScanCategory = (typeof SCAN_CATEGORIES)[number];

export const LOAD_LEVELS = ['light', 'moderate', 'heavy'] as const;

/** Fields a person fills in after adding a suggestion, per kind; `true` = required. */
export const INPUT_FIELDS: Record<SuggestionKind, Record<string, boolean>> = {
  asset: { targets: true, shipper: false },
  vulnerability: { target: true, shipper: false },
  container: { image_ref: true },
  log_discovery: { cidrs: false, shipper: false },
  endpoint_policy: { endpoints: true },
};

/** Option keys each kind may carry (target keys never). */
export const OPTION_KEYS: Record<SuggestionKind, readonly string[]> = {
  asset: ['scanType'],
  vulnerability: ['templateSelection', 'rateLimit', 'timeout'],
  container: ['all_images'],
  log_discovery: ['mode'],
  endpoint_policy: ['scans'],
};

/** Template tags whose templates log in, brute-force, fuzz or can disrupt a service. */
export const INTRUSIVE_NUCLEI_TAGS = ['intrusive', 'dos', 'fuzz', 'fuzzing', 'bruteforce', 'brute-force', 'default-login'] as const;
/** What a non-intrusive selection excludes. */
export const REQUIRED_EXCLUDE_TAGS = ['intrusive', 'dos', 'fuzz'] as const;

/** Common nuclei-templates tags; one outside this list is a warning (it may be newer), not an error. */
export const KNOWN_NUCLEI_TAGS = new Set([
  'cve', 'kev', 'vkev', 'rce', 'sqli', 'xss', 'lfi', 'ssrf', 'auth-bypass', 'default-login', 'exposure', 'exposures',
  'misconfig', 'misconfiguration', 'tech', 'panel', 'login', 'takeover', 'token', 'unauth', 'config', 'files', 'backup',
  'git', 'logs', 'debug', 'disclosure', 'ssl', 'tls', 'dns', 'network', 'headers', 'cors', 'intrusive', 'dos', 'fuzz',
  'bruteforce', 'oast', 'seclists', 'apache', 'nginx', 'iis', 'wordpress', 'joomla', 'drupal', 'jenkins', 'grafana',
  'kubernetes', 'docker', 'devops', 'iot', 'router', 'camera', 'printer', 'nas', 'vpn', 'firewall', 'smtp', 'ftp',
  'ssh', 'rdp', 'smb', 'mysql', 'postgres', 'redis', 'mongodb', 'elasticsearch', 'cloud', 'aws', 'azure', 'gcp',
  'detect', 'enum', 'osint', 'expired', 'self-signed', 'mismatched', 'weak-cipher', 'deprecated-tls', 'revoked',
  'spf', 'dmarc', 'dkim', 'caa', 'ns', 'mx', 'txt', 'zone-transfer', 'axfr', 'http', 'generic', 'phpmyadmin',
  'adminer', 'cpanel', 'webmin', 'proxmox', 'portainer', 'homeassistant', 'pihole', 'synology', 'qnap', 'unifi',
]);

export const SCAN_LIMITS = {
  id: 64,
  name: 80,
  tags: 10,
  tag: 32,
  description: 500,
  why: 1000,
  note: 300,
  label: 80,
  hint: 300,
} as const;

export interface SuggestionInput {
  field: string;
  required: boolean;
  label: string | null;
  hint: string | null;
}

/** A validated suggestion, as the API returns it. */
export interface ScanSuggestion {
  id: string;
  name: string;
  kind: SuggestionKind;
  category: ScanCategory;
  tags: string[];
  description: string;
  why: string;
  intrusive: boolean;
  intrusive_note: string | null;
  load: (typeof LOAD_LEVELS)[number];
  /** Calendar timing without its timezone (null for an endpoint policy, whose entries carry their own). */
  schedule: Omit<CalendarSchedule, 'timezone'> | null;
  options: Record<string, any>;
  inputs: SuggestionInput[];
}

export interface ValidateOptions {
  /** Unknown keys are errors (CI) rather than warnings (a newer catalog read by an older SIEMBox). */
  strict?: boolean;
  /** The id the file name implies. */
  expectId?: string;
}

export interface ScanValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
  suggestion?: ScanSuggestion;
}

const ID = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
const TAG = /^[a-z0-9][a-z0-9-]*$/;
const TOP_KEYS = [
  'schema', 'id', 'name', 'kind', 'category', 'tags', 'description', 'why', 'intrusive', 'intrusive_note', 'load',
  'schedule', 'options', 'inputs',
];
/** Keys that hold a target; never in a suggestion's options. */
const TARGET_KEYS = ['targets', 'target', 'image_ref', 'manual_cidrs', 'cidrs', 'assignedShipperId', 'assigned_shipper_id', 'publicTargetsConfirmation'];

function isObject(v: unknown): v is Record<string, any> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

const IPV4 = /(^|[^\d.])(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d])/;
const HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;

/** Whether `text` contains an IPv4/IPv6 address or CIDR. */
export function containsAddress(text: string): boolean {
  if (IPV4.test(text)) return true;
  for (const token of text.split(/[\s,;()"'`<>[\]]+/)) {
    const bare = token.replace(/\/\d{1,3}$/, '');
    if (bare.includes(':') && (net.isIP(bare) === 6 || net.isIP(bare.replace(/[.:]$/, '')) === 6)) return true;
  }
  return false;
}

/** Whether `text` contains something that reads as a host name (a.b.tld). */
export function containsHostname(text: string): boolean {
  return text.split(/[\s,;()"'`<>[\]/@]+/).some((token) => HOSTNAME.test(token.replace(/[.:]+$/, '').replace(/:\d+$/, '')));
}

function walkStrings(v: unknown, path: string, out: Array<[string, string]>): void {
  if (typeof v === 'string') out.push([path, v]);
  else if (Array.isArray(v)) v.forEach((x, i) => walkStrings(x, `${path}[${i}]`, out));
  else if (isObject(v)) for (const [k, x] of Object.entries(v)) walkStrings(x, `${path}.${k}`, out);
}

function walkKeys(v: unknown, path: string, out: Array<[string, string]>): void {
  if (Array.isArray(v)) v.forEach((x, i) => walkKeys(x, `${path}[${i}]`, out));
  else if (isObject(v)) {
    for (const [k, x] of Object.entries(v)) {
      out.push([`${path}.${k}`, k]);
      walkKeys(x, `${path}.${k}`, out);
    }
  }
}

function text(doc: Record<string, any>, key: string, max: number, errors: string[], required = true): string | null {
  const v = doc[key];
  if (v === undefined || v === null) {
    if (required) errors.push(`${key} is required`);
    return null;
  }
  if (typeof v !== 'string' || !v.trim()) {
    errors.push(`${key} must be a non-empty string`);
    return null;
  }
  if (v.length > max) errors.push(`${key} is longer than ${max} characters`);
  return v.trim();
}

/** A suggestion's schedule with a placeholder timezone, so it can go through normalizeCalendarSchedule. */
function checkSchedule(raw: unknown, label: string, errors: string[]): Omit<CalendarSchedule, 'timezone'> | null {
  if (!isObject(raw)) {
    errors.push(`${label} must be an object (frequency, time, days, day_of_month, minute, every_hours)`);
    return null;
  }
  if (raw.timezone !== undefined) {
    errors.push(`${label}.timezone must not be set: the person adding the suggestion gets their own time zone`);
    return null;
  }
  try {
    const { timezone: _tz, ...rest } = normalizeCalendarSchedule({ ...raw, timezone: 'UTC' });
    void _tz;
    const extra = Object.keys(raw).filter((k) => k !== 'mode' && !(k in rest));
    if (extra.length > 0) errors.push(`${label}: ${extra.join(', ')} not used by a ${String(raw.frequency)} schedule`);
    return rest;
  } catch (err) {
    errors.push(`${label}: ${err instanceof Error ? err.message.replace(/^schedule\./, '') : 'invalid schedule'}`);
    return null;
  }
}

/** Whether a Nuclei template selection can run intrusive templates (see the header). */
export function selectionMayBeIntrusive(sel: Record<string, any>): string | null {
  if (sel.all === true) return 'it runs all templates';
  const picked = [...(sel.tags ?? []), ...(sel.templates ?? [])].map((t: string) => t.toLowerCase());
  const tag = picked.find((t) => (INTRUSIVE_NUCLEI_TAGS as readonly string[]).some((i) => t === i || t.split('/').includes(i) || t.split('/').includes(`${i}s`)));
  if (tag) return `it selects "${tag}"`;
  const excluded = new Set((sel.excludeTags ?? []).map((t: string) => t.toLowerCase()));
  const notExcluded = REQUIRED_EXCLUDE_TAGS.filter((t) => !excluded.has(t));
  if (notExcluded.length > 0) return `it does not exclude the ${notExcluded.join(', ')} tag(s)`;
  return null;
}

/** An endpoint policy suggestion's scans with a placeholder timezone in every schedule and window. */
export function withTimezone(scans: unknown, timezone: string): unknown {
  if (!isObject(scans)) return scans;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(scans)) {
    if (!isObject(v)) {
      out[k] = v;
      continue;
    }
    const entry: Record<string, unknown> = { ...v };
    if (isObject(v.schedule)) entry.schedule = { ...v.schedule, timezone };
    if (isObject(v.window)) entry.window = { ...v.window, timezone };
    out[k] = entry;
  }
  return out;
}

function checkOptions(kind: SuggestionKind, opts: unknown, errors: string[], warnings: string[]): Record<string, any> | null {
  if (!isObject(opts)) {
    errors.push('options must be an object');
    return null;
  }
  const keys: Array<[string, string]> = [];
  walkKeys(opts, 'options', keys);
  for (const [path, key] of keys) {
    if (TARGET_KEYS.includes(key)) errors.push(`${path}: a suggestion never names targets (the person adding it fills them in; list it under inputs)`);
  }
  for (const k of Object.keys(opts)) {
    if (!OPTION_KEYS[kind].includes(k) && !TARGET_KEYS.includes(k)) errors.push(`options.${k}: not an option of a ${kind} suggestion (${OPTION_KEYS[kind].join(', ')})`);
  }

  if (kind === 'endpoint_policy') {
    const scans = opts.scans;
    if (!isObject(scans)) {
      errors.push(`options.scans must be an object with an entry for each of: ${ENDPOINT_SCAN_TYPES.join(', ')}`);
      return null;
    }
    for (const [t, entry] of Object.entries(scans)) {
      if (isObject(entry) && isObject(entry.schedule) && entry.schedule.timezone !== undefined) {
        errors.push(`options.scans.${t}.schedule.timezone must not be set: the person adding it gets their own time zone`);
      }
      if (isObject(entry) && isObject(entry.window) && entry.window.timezone !== undefined) {
        errors.push(`options.scans.${t}.window.timezone must not be set: the person adding it gets their own time zone`);
      }
    }
    try {
      normalizePolicyScans(withTimezone(scans, 'UTC'));
    } catch (err) {
      errors.push(`options.${err instanceof Error ? err.message : 'scans are invalid'}`);
    }
    return opts;
  }

  if (kind === 'asset' && !(ASSET_SCAN_TYPES as readonly unknown[]).includes(opts.scanType)) {
    errors.push(`options.scanType is required: one of ${ASSET_SCAN_TYPES.join(', ')}`);
  }
  if (kind === 'log_discovery' && !(DISCOVERY_MODES as readonly unknown[]).includes(opts.mode)) {
    errors.push(`options.mode is required: one of ${DISCOVERY_MODES.join(', ')}`);
  }
  if (kind === 'vulnerability') {
    if (opts.templateSelection === undefined) errors.push('options.templateSelection is required');
    else if (isObject(opts.templateSelection)) {
      for (const t of [...(opts.templateSelection.tags ?? []), ...(opts.templateSelection.excludeTags ?? [])]) {
        if (typeof t === 'string' && !KNOWN_NUCLEI_TAGS.has(t.toLowerCase())) warnings.push(`options.templateSelection: "${t}" is not a common nuclei-templates tag; check it exists`);
      }
    }
  }
  const shape = scanOptionsShapeError(kind as ScheduledScanKind, opts);
  if (shape) errors.push(shape.replace(/^scan_options/, 'options'));
  return opts;
}

/** Validate one suggestion document. */
export function validateSuggestion(input: unknown, opts: ValidateOptions = {}): ScanValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!isObject(input)) return { ok: false, errors: ['a suggestion must be a YAML mapping'], warnings };
  const doc = input;

  for (const k of Object.keys(doc)) {
    if (!TOP_KEYS.includes(k)) (opts.strict ? errors : warnings).push(`unknown key "${k.slice(0, 40)}"`);
  }
  if (doc.schema !== SCAN_SCHEMA) errors.push(`schema must be ${SCAN_SCHEMA}`);

  const id = text(doc, 'id', SCAN_LIMITS.id, errors);
  if (id && !ID.test(id)) errors.push('id must be kebab-case (a-z, 0-9, -)');
  if (id && opts.expectId !== undefined && id !== opts.expectId) errors.push(`id "${id}" must match the file name (${opts.expectId}${SCAN_FILE_SUFFIX})`);
  const name = text(doc, 'name', SCAN_LIMITS.name, errors);
  const description = text(doc, 'description', SCAN_LIMITS.description, errors);
  const why = text(doc, 'why', SCAN_LIMITS.why, errors);

  const kind = doc.kind as SuggestionKind;
  if (!(SUGGESTION_KINDS as readonly unknown[]).includes(kind)) {
    errors.push(`kind must be one of: ${SUGGESTION_KINDS.join(', ')}`);
    return { ok: false, errors, warnings };
  }
  if (!(SCAN_CATEGORIES as readonly unknown[]).includes(doc.category)) errors.push(`category must be one of: ${SCAN_CATEGORIES.join(', ')}`);
  if (!(LOAD_LEVELS as readonly unknown[]).includes(doc.load)) errors.push(`load must be one of: ${LOAD_LEVELS.join(', ')}`);

  let tags: string[] = [];
  if (doc.tags !== undefined) {
    if (!Array.isArray(doc.tags) || doc.tags.length > SCAN_LIMITS.tags || !doc.tags.every((t) => typeof t === 'string' && t.length <= SCAN_LIMITS.tag && TAG.test(t))) {
      errors.push(`tags must be at most ${SCAN_LIMITS.tags} kebab-case strings of up to ${SCAN_LIMITS.tag} characters`);
    } else if (new Set(doc.tags).size !== doc.tags.length) errors.push('tags has duplicates');
    else tags = doc.tags;
  }

  if (typeof doc.intrusive !== 'boolean') errors.push('intrusive is required: true or false');
  const note = text(doc, 'intrusive_note', SCAN_LIMITS.note, errors, doc.intrusive === true);
  if (doc.intrusive !== true && doc.intrusive_note !== undefined) errors.push('intrusive_note is only for intrusive: true');

  let schedule: ScanSuggestion['schedule'] = null;
  if (kind === 'endpoint_policy') {
    if (doc.schedule !== undefined) errors.push('schedule: an endpoint policy suggestion sets each scan type\'s timing under options.scans instead');
  } else if (doc.schedule === undefined) errors.push('schedule is required');
  else schedule = checkSchedule(doc.schedule, 'schedule', errors);

  const options = checkOptions(kind, doc.options, errors, warnings);

  // Intrusiveness must be declared honestly.
  if (kind === 'vulnerability' && options && isObject(options.templateSelection) && doc.intrusive === false) {
    const why = selectionMayBeIntrusive(options.templateSelection);
    if (why) errors.push(`intrusive: false, but ${why}: exclude ${REQUIRED_EXCLUDE_TAGS.join(', ')} (excludeTags), or set intrusive: true with an intrusive_note`);
  }

  // Inputs: every required field listed, nothing a kind doesn't have.
  const inputs: SuggestionInput[] = [];
  const fields = INPUT_FIELDS[kind];
  if (!Array.isArray(doc.inputs)) errors.push('inputs must be a list of the fields the person fills in (field, label, hint)');
  else {
    for (const [i, raw] of doc.inputs.entries()) {
      if (!isObject(raw) || typeof raw.field !== 'string') {
        errors.push(`inputs[${i}] must have a field`);
        continue;
      }
      for (const k of Object.keys(raw)) if (!['field', 'label', 'hint'].includes(k)) (opts.strict ? errors : warnings).push(`inputs[${i}]: unknown key "${k.slice(0, 40)}"`);
      if (!(raw.field in fields)) {
        errors.push(`inputs[${i}].field "${raw.field.slice(0, 40)}" is not an input of a ${kind} suggestion (${Object.keys(fields).join(', ')})`);
        continue;
      }
      if (inputs.some((x) => x.field === raw.field)) errors.push(`inputs: "${raw.field}" is listed twice`);
      for (const [k, max] of [['label', SCAN_LIMITS.label], ['hint', SCAN_LIMITS.hint]] as const) {
        if (raw[k] !== undefined && (typeof raw[k] !== 'string' || raw[k].length > max)) errors.push(`inputs[${i}].${k} must be a string of up to ${max} characters`);
      }
      let required = fields[raw.field];
      if (kind === 'container' && raw.field === 'image_ref' && options?.all_images === true) {
        errors.push('inputs: image_ref is not needed when options.all_images is true');
        required = false;
      }
      inputs.push({ field: raw.field, required, label: typeof raw.label === 'string' ? raw.label : null, hint: typeof raw.hint === 'string' ? raw.hint : null });
    }
    for (const [field, required] of Object.entries(fields)) {
      const notNeeded = kind === 'container' && field === 'image_ref' && options?.all_images === true;
      if (required && !notNeeded && !inputs.some((x) => x.field === field)) errors.push(`inputs: "${field}" is required for a ${kind} suggestion`);
    }
  }

  // No concrete targets anywhere.
  const strings: Array<[string, string]> = [];
  walkStrings(doc, '', strings);
  for (const [path, value] of strings) {
    const where = path.replace(/^\./, '');
    if (containsAddress(value)) errors.push(`${where}: names an IP address or CIDR; suggestions never name targets`);
    else if ((where.startsWith('options') || where.startsWith('inputs')) && containsHostname(value)) {
      errors.push(`${where}: names a host; suggestions never name targets`);
    }
  }

  if (errors.length > 0) return { ok: false, errors, warnings };
  return {
    ok: true,
    errors,
    warnings,
    suggestion: {
      id: id!,
      name: name!,
      kind,
      category: doc.category,
      tags,
      description: description!,
      why: why!,
      intrusive: doc.intrusive,
      intrusive_note: note,
      load: doc.load,
      schedule,
      options: options!,
      inputs,
    },
  };
}

/** Problems across a set: duplicate ids and names. */
export function crossCheckSuggestions(list: ScanSuggestion[]): Array<{ id: string; error: string }> {
  const out: Array<{ id: string; error: string }> = [];
  const ids = new Map<string, number>();
  const names = new Map<string, string>();
  for (const s of list) {
    ids.set(s.id, (ids.get(s.id) ?? 0) + 1);
    const key = s.name.toLowerCase();
    if (names.has(key) && names.get(key) !== s.id) out.push({ id: s.id, error: `name "${s.name}" is also used by ${names.get(key)}` });
    else names.set(key, s.id);
  }
  for (const [id, n] of ids) if (n > 1) out.push({ id, error: `id "${id}" is used ${n} times` });
  return out;
}
