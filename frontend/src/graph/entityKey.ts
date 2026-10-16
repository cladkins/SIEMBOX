/**
 * Entity keys: `<type>:<key>`, one canonical string per thing, used as the
 * node id, in URLs and in API parameters. The browser's copy of
 * backend/src/services/graph/entityKey.ts: the same rules, without Node's
 * `net` module. entityKey.test.ts runs both against the backend's
 * ENTITY_KEY_FIXTURES parity list, so a key means the same thing on both sides.
 *
 *   ip           IPv4 dotted; IPv6 lower-case canonical (RFC 5952); ::ffff:a.b.c.d folds to IPv4
 *   host         spaces trimmed, lower-cased; 1-253 characters; no whitespace, control or bidi characters
 *   user         spaces trimmed, case preserved; 1-128 characters; no control or bidi characters; junk refused
 *   domain       spaces trimmed, lower-cased, trailing dots removed; 1-253 characters; at least one dot
 *   alert, rule, asset, vuln, finding, identity, shipper, account
 *                a positive integer id
 *   shipper_tag  8 lower-case hex characters
 *   endpoint     a UUID, lower-case
 *
 * The page canonicalizes the URL's entities with these before it asks the
 * API, so `?entity=host:NAS` and `?entity=host:nas` are one view. The server
 * validates again: what it answers with is authoritative.
 */
import { hasUnsafeChars } from './labels.ts';
import { NODE_TYPES, type NodeType } from './types.ts';

export interface EntityRef {
  type: NodeType;
  key: string;
  /** `${type}:${key}` */
  id: string;
}

/** Usernames that mean "nobody": never a user node. */
export const JUNK_USERS: ReadonlySet<string> = new Set(['-', 'unknown', 'null', 'none', '(null)', 'n/a', 'nobody', '?']);

export const MAX_ENTITY_LENGTH = 300;
const MAX_HOST = 253;
const MAX_USER = 128;
const MAX_INT_ID = 2_147_483_647;

const ID_TYPES: ReadonlySet<NodeType> = new Set(['alert', 'rule', 'asset', 'vuln', 'finding', 'identity', 'shipper', 'account']);
const ID_PATTERN = /^[1-9][0-9]{0,9}$/;
const TAG_PATTERN = /^[0-9a-f]{8}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Dotted quad, no leading zeros (as Node's net.isIPv4).
const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
const IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);
const MAPPED_V4 = new RegExp(`^::ffff:(${OCTET}(?:\\.${OCTET}){3})$`, 'i');
const IPV6_CHARS = /^[0-9a-f:.]+$/i;

const hasWhitespace = (value: string) => /\s/u.test(value);

/** `value` without leading and trailing ASCII spaces: what SQL's btrim(value) does. */
export function trimSpaces(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) === 0x20) start++;
  while (end > start && value.charCodeAt(end - 1) === 0x20) end--;
  return value.slice(start, end);
}

export function isIPv4(value: string): boolean {
  return IPV4.test(value);
}

/** The RFC 5952 form of an IPv6 address, or null (the WHATWG URL parser validates and prints it). */
function canonicalIPv6(value: string): string | null {
  if (!value.includes(':') || !IPV6_CHARS.test(value)) return null;
  try {
    const host = new URL(`http://[${value}]/`).hostname;
    if (!host.startsWith('[') || !host.endsWith(']')) return null;
    return host.slice(1, -1);
  } catch {
    return null;
  }
}

/** The canonical form of an IP address, or null when `value` is not one (compared as written: no trimming). */
export function canonicalIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const s = value;
  if (s.length === 0 || s.length > 45) return null;
  const mapped = MAPPED_V4.exec(s);
  if (mapped) return mapped[1];
  if (isIPv4(s)) return s;
  const canonical = canonicalIPv6(s);
  if (canonical === null) return null;
  // [::ffff:1.2.3.4] serializes as ::ffff:102:304: fold it like the dotted form.
  if (canonical.startsWith('::ffff:')) {
    const parts = canonical.slice(7).split(':');
    if (parts.length === 2) {
      const hi = parseInt(parts[0], 16);
      const lo = parseInt(parts[1], 16);
      return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    }
  }
  return canonical;
}

/** The canonical host name, or null. */
export function canonicalHost(value: unknown): string | null {
  if (typeof value !== 'string' || hasUnsafeChars(value)) return null;
  const s = trimSpaces(value).toLowerCase();
  if (s.length === 0 || s.length > MAX_HOST || hasWhitespace(s)) return null;
  return s;
}

/** The canonical user name (case preserved), or null for junk. */
export function canonicalUser(value: unknown): string | null {
  if (typeof value !== 'string' || hasUnsafeChars(value)) return null;
  const s = trimSpaces(value);
  if (s.length === 0 || s.length > MAX_USER) return null;
  if (JUNK_USERS.has(s.toLowerCase())) return null;
  return s;
}

/** The canonical domain, or null. */
export function canonicalDomain(value: unknown): string | null {
  if (typeof value !== 'string' || hasUnsafeChars(value)) return null;
  let s = trimSpaces(value).toLowerCase();
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x2e) end--;
  s = s.slice(0, end);
  if (s.length === 0 || s.length > MAX_HOST || !s.includes('.') || s.startsWith('.') || hasWhitespace(s)) return null;
  return s;
}

/** A positive INTEGER id as its decimal string, or null. */
export function canonicalId(value: unknown): string | null {
  const s = typeof value === 'number' && Number.isInteger(value) ? String(value) : typeof value === 'string' ? value.trim() : '';
  if (!ID_PATTERN.test(s) || Number(s) > MAX_INT_ID) return null;
  return s;
}

export function canonicalShipperTag(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const s = value.trim().toLowerCase();
  return TAG_PATTERN.test(s) ? s : null;
}

export function canonicalUuid(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const s = value.trim().toLowerCase();
  return UUID_PATTERN.test(s) ? s : null;
}

/** The canonical key of `value` as a `type`, or null when it isn't a valid one. */
export function canonicalKey(type: NodeType, value: unknown): string | null {
  switch (type) {
    case 'ip':
      return canonicalIp(value);
    case 'host':
      return canonicalHost(value);
    case 'user':
      return canonicalUser(value);
    case 'domain':
      return canonicalDomain(value);
    case 'shipper_tag':
      return canonicalShipperTag(value);
    case 'endpoint':
      return canonicalUuid(value);
    default:
      return ID_TYPES.has(type) ? canonicalId(value) : null;
  }
}

export function isNodeType(value: string): value is NodeType {
  return (NODE_TYPES as readonly string[]).includes(value);
}

export function entityRef(type: NodeType, key: string): EntityRef {
  return { type, key, id: `${type}:${key}` };
}

/** The ref for `value` as a `type`, or null when it isn't a valid one. */
export function toEntity(type: NodeType, value: unknown): EntityRef | null {
  const key = canonicalKey(type, value);
  return key === null ? null : entityRef(type, key);
}

/** Parse `type:key` (the type is everything before the first ':'), or null. */
export function tryParseEntity(value: unknown): EntityRef | null {
  if (typeof value !== 'string' || value.length > MAX_ENTITY_LENGTH) return null;
  const colon = value.indexOf(':');
  if (colon <= 0) return null;
  const type = value.slice(0, colon).trim().toLowerCase();
  if (!isNodeType(type)) return null;
  return toEntity(type, value.slice(colon + 1));
}

/** The type part of a node id (`ip` of `ip:1.2.3.4`), or null. */
export function typeOfId(id: string): NodeType | null {
  const colon = id.indexOf(':');
  if (colon <= 0) return null;
  const type = id.slice(0, colon);
  return isNodeType(type) ? type : null;
}

/** The key part of a node id. */
export function keyOfId(id: string): string {
  const colon = id.indexOf(':');
  return colon < 0 ? id : id.slice(colon + 1);
}
