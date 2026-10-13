// The poll target of a Log Discovery source: the address, port, scheme and
// endpoint path the API poller requests, and the admin overrides behind them.
//
// Where an admin's settings live depends on where the source came from:
// - a MANUALLY added source keeps them in evidence ({manual, target_port, tls,
//   endpoint}), written by POST /sources/manual and the edit route; its address
//   is the row's own ip_address, which only the edit route changes.
// - a SCAN-DISCOVERED source's evidence belongs to the scanner and is rewritten
//   by every re-scan, so its overrides live in poll_overrides ({port, tls,
//   endpoint}, migration 036), which scans never write. Its address is always
//   the scanned one: nothing here can point its poller at another host.
// No override means the adapter's own default, so a discovered source without
// overrides is polled at exactly the URL it always was.
import { DiscoverySource } from '../../../models/DiscoverySource';
import { getFingerprintById } from '../fingerprintLoader';
import { FingerprintEntry, LogAccessMethod } from '../types';
import { getAdapter } from './registry';
import { ApiPollAdapter, PollTarget } from './types';

export interface PollTargetOverrides {
  port?: number;
  tls?: boolean;
  endpoint?: string;
}

export const MAX_ENDPOINT_LENGTH = 256;

// RFC 3986 path characters (unreserved, sub-delims, ":", "@", "/"), minus "%":
// no percent-encoding, so what is validated is exactly what is requested.
const ENDPOINT_CHARS_RE = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f-\u009f]/;

export type EndpointValidation = { ok: true; value: string | null } | { ok: false; message: string };

/**
 * Validate an admin's endpoint override. It must be a plain absolute path on the
 * source's own host, like /api/hassio/core/logs: it starts with "/" (not "//"),
 * has no scheme or host, query string or fragment, no "." or ".." segment,
 * no control characters, whitespace, backslash or percent-encoding, and is at
 * most MAX_ENDPOINT_LENGTH characters. Surrounding whitespace is trimmed. An
 * empty string or null means "no override" (value null).
 */
export function validateEndpointPath(raw: unknown): EndpointValidation {
  if (raw === null || raw === undefined) return { ok: true, value: null };
  if (typeof raw !== 'string') {
    return { ok: false, message: 'endpoint must be a path string such as /api/error_log, or empty for the default' };
  }
  const value = raw.trim();
  if (value === '') return { ok: true, value: null };
  if (value.length > MAX_ENDPOINT_LENGTH) {
    return { ok: false, message: `endpoint must be at most ${MAX_ENDPOINT_LENGTH} characters` };
  }
  if (CONTROL_CHARS_RE.test(value)) {
    return { ok: false, message: 'endpoint must not contain control characters' };
  }
  if (!value.startsWith('/') || value.startsWith('//')) {
    return {
      ok: false,
      message: 'endpoint must be a path on the source itself, starting with a single "/" (no scheme or host), e.g. /api/error_log',
    };
  }
  if (/[?#]/.test(value)) {
    return { ok: false, message: 'endpoint must be a path only, without a query string or fragment' };
  }
  if (!ENDPOINT_CHARS_RE.test(value)) {
    return {
      ok: false,
      message: "endpoint may only contain letters, digits and - . _ ~ ! $ & ' ( ) * + , ; = : @ / (no spaces, backslashes or %-encoding)",
    };
  }
  if (value.split('/').some((segment) => segment === '.' || segment === '..')) {
    return { ok: false, message: 'endpoint must not contain "." or ".." path segments' };
  }
  return { ok: true, value };
}

function isPort(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 65535;
}

export function isManualSource(source: Pick<DiscoverySource, 'evidence'>): boolean {
  return (source.evidence as Record<string, unknown> | null)?.manual === true;
}

/**
 * A source's admin overrides (see the header comment for where each kind of
 * source keeps them). A value that isn't well-formed is ignored rather than
 * passed to an adapter, and the endpoint is re-validated on read.
 */
export function readTargetOverrides(source: Pick<DiscoverySource, 'evidence' | 'poll_overrides'>): PollTargetOverrides {
  const evidence = (source.evidence || {}) as Record<string, unknown>;
  const stored: Record<string, unknown> = isManualSource(source)
    ? { port: evidence.target_port, tls: evidence.tls, endpoint: evidence.endpoint }
    : ((source.poll_overrides || {}) as Record<string, unknown>);
  const overrides: PollTargetOverrides = {};
  if (isPort(stored.port)) overrides.port = stored.port;
  if (typeof stored.tls === 'boolean') overrides.tls = stored.tls;
  const endpoint = validateEndpointPath(stored.endpoint);
  if (endpoint.ok && endpoint.value) overrides.endpoint = endpoint.value;
  return overrides;
}

/** The PollTarget an adapter gets for this source. */
export function buildPollTarget(
  source: Pick<DiscoverySource, 'id' | 'ip_address' | 'open_ports' | 'evidence' | 'poll_overrides'>,
  logAccess: LogAccessMethod
): PollTarget {
  const overrides = readTargetOverrides(source);
  return {
    sourceId: source.id,
    ip: source.ip_address,
    openPorts: source.open_ports || [],
    evidence: source.evidence || {},
    port: overrides.port,
    tls: overrides.tls,
    endpoint: overrides.endpoint,
    logAccess,
  };
}

export interface ApiPullResolution {
  fingerprint: FingerprintEntry;
  logAccess: LogAccessMethod;
  adapter: ApiPollAdapter;
}

/** The fingerprint, its api_pull log-access entry and the poll adapter for a fingerprint id; null when any is missing. */
export function resolveApiPull(fingerprintId: string | null | undefined): ApiPullResolution | null {
  if (!fingerprintId) return null;
  const fingerprint = getFingerprintById(fingerprintId);
  const logAccess = fingerprint?.log_access.find((la) => la.method === 'api_pull');
  const adapter = getAdapter(fingerprintId);
  if (!fingerprint || !logAccess || !adapter) return null;
  return { fingerprint, logAccess, adapter };
}

/** What the edit dialog and API clients see of a source's poll target. Never includes a credential. */
export interface PollTargetView {
  fingerprint_id: string;
  /** Only a manually added source's address can be changed. */
  manual: boolean;
  ip_address: string;
  /** What polling uses now: the override where one is set, else the default. */
  port: number;
  tls: boolean;
  /** The URL being polled: scheme, host, port and path, without any credential or query string. */
  effective_url: string;
  /** The stored settings: for a discovered source, null where no override is set. */
  overrides: { port: number | null; tls: boolean | null; endpoint: string | null };
  /** What applies without overrides (the fingerprint's endpoint and the adapter's port/scheme). */
  defaults: { port: number; tls: boolean; endpoint: string };
}

function portAndScheme(url: URL): { port: number; tls: boolean } {
  const tls = url.protocol === 'https:';
  return { tls, port: url.port ? Number(url.port) : tls ? 443 : 80 };
}

/** The poll target view of `source`, polled with `fingerprintId`'s adapter; null when it has no api_pull adapter. */
export function describePollTarget(
  source: DiscoverySource,
  fingerprintId: string | null | undefined,
  cursor: string | null
): PollTargetView | null {
  const resolved = resolveApiPull(fingerprintId);
  if (!resolved) return null;
  const { adapter, logAccess, fingerprint } = resolved;
  const target = buildPollTarget(source, logAccess);
  const effectiveUrl = adapter.describeUrl(target, cursor);
  const defaultUrl = new URL(adapter.describeUrl({ ...target, port: undefined, tls: undefined, endpoint: undefined }, null));
  const overrides = readTargetOverrides(source);
  return {
    fingerprint_id: fingerprint.id,
    manual: isManualSource(source),
    ip_address: source.ip_address,
    ...portAndScheme(new URL(effectiveUrl)),
    effective_url: effectiveUrl,
    overrides: { port: overrides.port ?? null, tls: overrides.tls ?? null, endpoint: overrides.endpoint ?? null },
    defaults: { ...portAndScheme(defaultUrl), endpoint: defaultUrl.pathname },
  };
}

/** Just the polled URL, for the sources list; null when it can't be worked out (it must never break the list). */
export function effectivePollUrl(
  source: DiscoverySource,
  fingerprintId: string | null | undefined,
  cursor: string | null
): string | null {
  try {
    const resolved = resolveApiPull(fingerprintId);
    if (!resolved) return null;
    return resolved.adapter.describeUrl(buildPollTarget(source, resolved.logAccess), cursor);
  } catch {
    return null;
  }
}
