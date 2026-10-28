/**
 * What a scheduled scan's scan_options may hold, per scan type. Pure (no DB):
 * the Scheduled Scans routes check every save with it, and so does the
 * suggested-scans validator (validate-scans) for each catalog suggestion, so
 * a suggestion that passes CI is one the route would accept once its targets
 * are filled in.
 *
 *   asset          { targets: [IP/CIDR...], scanType?: ping|port|service|os, assignedShipperId? }
 *   vulnerability  { target, templateSelection?, rateLimit?, timeout?, assignedShipperId? }
 *   container      { image_ref } | { all_images: true }
 *   log_discovery  { mode?: passive|active|full, manual_cidrs?: [CIDR...], assignedShipperId? }
 *                  (no manual_cidrs: each run sweeps the saved Log Discovery scope)
 *
 * Two checks, so a schedule can be saved before its targets are known (a
 * suggestion added from the catalog is a disabled schedule without targets):
 * scanOptionsShapeError() is everything except the targets, and
 * missingScanInputs() names what is still to be filled in. A schedule can only
 * be enabled or run with nothing missing.
 */

export const SCHEDULED_SCAN_TYPES = ['asset', 'vulnerability', 'container', 'log_discovery'] as const;
export type ScheduledScanKind = (typeof SCHEDULED_SCAN_TYPES)[number];

export const ASSET_SCAN_TYPES = ['ping', 'port', 'service', 'os'] as const;
export const DISCOVERY_MODES = ['passive', 'active', 'full'] as const;
export const NUCLEI_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical', 'unknown'] as const;
/** Top-level directories of the nuclei-templates repo, selectable as "<dir>/". */
export const NUCLEI_TEMPLATE_DIRS = ['http', 'network', 'dns', 'ssl', 'file', 'headless', 'cloud', 'code', 'javascript', 'dast'] as const;

export const SELECTION_LIMITS = { entries: 100, tag: 64, template: 200 } as const;
export const MAX_RATE_LIMIT = 10_000;
/** Nuclei timeout, ms (the scanner's own default is 30 minutes). */
export const MIN_NUCLEI_TIMEOUT_MS = 60_000;
export const MAX_NUCLEI_TIMEOUT_MS = 24 * 3600_000;

const TAG = /^[a-z0-9][a-z0-9_.-]*$/i;
const TEMPLATE = /^[A-Za-z0-9][A-Za-z0-9_./-]*$/;

export function isScheduledScanKind(v: unknown): v is ScheduledScanKind {
  return typeof v === 'string' && (SCHEDULED_SCAN_TYPES as readonly string[]).includes(v);
}

function isObject(v: unknown): v is Record<string, any> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function stringList(v: unknown, label: string, max: number, pattern: RegExp, what: string): string | null {
  if (!Array.isArray(v)) return `${label} must be an array of ${what}`;
  if (v.length > SELECTION_LIMITS.entries) return `${label}: at most ${SELECTION_LIMITS.entries} entries`;
  for (const item of v) {
    if (typeof item !== 'string' || item.length === 0 || item.length > max || !pattern.test(item) || item.includes('..')) {
      return `${label}: "${String(item).slice(0, 40)}" is not a valid ${what.replace(/s$/, '')}`;
    }
  }
  return null;
}

/**
 * The problem with a Nuclei template selection, or null. The shape the
 * Scheduled Scans form and the scanner use: all | cves | templates (template
 * ids or "<dir>/" directories) | tags, plus optional severities, exclude
 * (template ids) and excludeTags.
 */
export function templateSelectionError(sel: unknown, label = 'scan_options.templateSelection'): string | null {
  if (!isObject(sel)) return `${label} must be an object`;
  const allowed = ['all', 'cves', 'templates', 'tags', 'severities', 'exclude', 'excludeTags'];
  for (const k of Object.keys(sel)) if (!allowed.includes(k)) return `${label}: unknown key "${k.slice(0, 32)}"`;
  if (sel.all !== undefined && typeof sel.all !== 'boolean') return `${label}.all must be a boolean`;
  if (sel.cves !== undefined && typeof sel.cves !== 'boolean') return `${label}.cves must be a boolean`;
  for (const key of ['templates', 'exclude'] as const) {
    if (sel[key] === undefined) continue;
    const e = stringList(sel[key], `${label}.${key}`, SELECTION_LIMITS.template, TEMPLATE, 'template ids or directories');
    if (e) return e;
  }
  for (const key of ['tags', 'excludeTags'] as const) {
    if (sel[key] === undefined) continue;
    const e = stringList(sel[key], `${label}.${key}`, SELECTION_LIMITS.tag, TAG, 'tags');
    if (e) return e;
  }
  if (sel.severities !== undefined) {
    if (!Array.isArray(sel.severities) || !sel.severities.every((s: unknown) => (NUCLEI_SEVERITIES as readonly unknown[]).includes(s))) {
      return `${label}.severities must be an array of: ${NUCLEI_SEVERITIES.join(', ')}`;
    }
  }
  const picks = sel.all === true || sel.cves === true || (sel.templates?.length ?? 0) > 0 || (sel.tags?.length ?? 0) > 0;
  if (!picks) return `${label} selects no templates: set all, cves, templates or tags`;
  return null;
}

function shipperError(opts: Record<string, any>): string | null {
  const id = opts.assignedShipperId;
  if (id !== undefined && id !== null && (!Number.isInteger(id) || id <= 0)) {
    return 'scan_options.assignedShipperId must be a positive integer';
  }
  return null;
}

/**
 * The problem with `opts` for `type`, other than missing targets (see
 * missingScanInputs), or null. Targets that are present must be well formed.
 */
export function scanOptionsShapeError(type: ScheduledScanKind, opts: unknown): string | null {
  if (!isObject(opts)) return 'scan_options must be an object';
  if (type === 'container') {
    // Either one image, or every image discovered when the schedule runs.
    if (opts.all_images !== undefined && typeof opts.all_images !== 'boolean') return 'scan_options.all_images must be a boolean';
    if (opts.image_ref !== undefined && opts.image_ref !== null && typeof opts.image_ref !== 'string') {
      return 'scan_options.image_ref must be a string (an image reference)';
    }
    return null;
  }
  const shipper = shipperError(opts);
  if (shipper) return shipper;
  if (type === 'asset') {
    if (opts.targets !== undefined && (!Array.isArray(opts.targets) || !opts.targets.every((t: unknown) => typeof t === 'string'))) {
      return 'scan_options.targets must be an array of IPs/CIDRs';
    }
    if (opts.scanType !== undefined && !(ASSET_SCAN_TYPES as readonly unknown[]).includes(opts.scanType)) {
      return `scan_options.scanType must be one of: ${ASSET_SCAN_TYPES.join(', ')}`;
    }
    return null;
  }
  if (type === 'vulnerability') {
    if (opts.target !== undefined && opts.target !== null && typeof opts.target !== 'string') {
      return 'scan_options.target must be a host/IP string';
    }
    if (opts.templateSelection !== undefined) {
      const e = templateSelectionError(opts.templateSelection);
      if (e) return e;
    }
    if (opts.rateLimit !== undefined && opts.rateLimit !== null && (!Number.isInteger(opts.rateLimit) || opts.rateLimit < 1 || opts.rateLimit > MAX_RATE_LIMIT)) {
      return `scan_options.rateLimit must be an integer from 1 to ${MAX_RATE_LIMIT} (requests per second)`;
    }
    if (
      opts.timeout !== undefined &&
      opts.timeout !== null &&
      (!Number.isInteger(opts.timeout) || opts.timeout < MIN_NUCLEI_TIMEOUT_MS || opts.timeout > MAX_NUCLEI_TIMEOUT_MS)
    ) {
      return `scan_options.timeout must be an integer from ${MIN_NUCLEI_TIMEOUT_MS} to ${MAX_NUCLEI_TIMEOUT_MS} (milliseconds)`;
    }
    return null;
  }
  // log_discovery
  if (opts.mode !== undefined && !(DISCOVERY_MODES as readonly unknown[]).includes(opts.mode)) {
    return `scan_options.mode must be one of: ${DISCOVERY_MODES.join(', ')}`;
  }
  if (opts.manual_cidrs !== undefined && opts.manual_cidrs !== null) {
    if (!Array.isArray(opts.manual_cidrs) || !opts.manual_cidrs.every((c: unknown) => typeof c === 'string')) {
      return 'scan_options.manual_cidrs must be an array of CIDR strings (or omitted, to sweep the saved Log Discovery scope)';
    }
  }
  return null;
}

/** The inputs a schedule still needs before it can be enabled or run: [] when complete. */
export function missingScanInputs(type: ScheduledScanKind, opts: unknown): Array<'targets' | 'target' | 'image_ref'> {
  const o = isObject(opts) ? opts : {};
  if (type === 'asset') return Array.isArray(o.targets) && o.targets.some((t: unknown) => typeof t === 'string' && t.trim()) ? [] : ['targets'];
  if (type === 'vulnerability') return typeof o.target === 'string' && o.target.trim() ? [] : ['target'];
  if (type === 'container') return o.all_images === true || (typeof o.image_ref === 'string' && o.image_ref.trim()) ? [] : ['image_ref'];
  return [];
}

/** The error a save gets when an input is missing (the messages the route has always sent). */
export function missingInputMessage(type: ScheduledScanKind): string {
  if (type === 'asset') return 'Asset scans require scan_options.targets (a non-empty array of IPs/CIDRs)';
  if (type === 'container') return 'Container scans require scan_options.image_ref (an image reference) or scan_options.all_images: true';
  return 'Vulnerability scans require scan_options.target (a host/IP string)';
}

/** The targets a schedule's scan_options name (none for a container scan; log discovery: its manual CIDRs). */
export function scheduleTargets(type: ScheduledScanKind, opts: any): string[] {
  if (type === 'container' || !opts) return [];
  if (type === 'asset') return Array.isArray(opts.targets) ? opts.targets.map(String) : [];
  if (type === 'log_discovery') return Array.isArray(opts.manual_cidrs) ? opts.manual_cidrs.map(String) : [];
  return opts.target ? [String(opts.target)] : [];
}
