/**
 * Entity keys: `<type>:<key>`, one canonical string per thing, used as the node
 * id, in URLs and in API parameters. Mirrored by frontend/src/graph/entityKey.ts
 * (PR 2) and, for the values logs carry, by the SQL functions graph_value() and
 * graph_ip() of the log-relationship rollup (PR 3); ENTITY_KEY_FIXTURES below is
 * the parity list all three are tested against.
 *
 *   ip           IPv4 dotted; IPv6 lower-case canonical (RFC 5952); ::ffff:a.b.c.d folds to IPv4
 *   host         spaces trimmed, lower-cased; 1-253 characters; no whitespace, control or bidi characters
 *   user         spaces trimmed, case preserved; 1-128 characters; no control or bidi characters; junk refused
 *   domain       spaces trimmed, lower-cased, trailing dots removed; 1-253 characters; at least one dot
 *   alert, rule, asset, vuln, finding, identity, shipper, account
 *                a positive integer id (vuln = vulnerabilities.id, account = users.id)
 *   shipper_tag  8 lower-case hex characters (a raw_logs.shipper_id no shipper matches)
 *   endpoint     an edr_agents.agent_id UUID, lower-case
 *
 * Validation runs before any value reaches SQL (`::inet` only after net.isIP).
 *
 * The text rules are ones SQL computes too, so an alert's own values find
 * their way back to it: btrim() trims spaces only (and a control character
 * anywhere, a tab or newline included, makes the value no key at all); lower();
 * rtrim(..., '.'). The lookups in resolvers/alerts.ts (ALERT_KEY_SQL) and the
 * indexes of migration 043 use exactly those expressions. IPs are compared as
 * written, in their canonical form (and IPv4 also as ::ffff:a.b.c.d, IPv6 in
 * the other spellings ipForms() lists).
 */
import net from 'net';
import { badEntity } from './errors';
import { hasUnsafeChars } from './labels';
import { NODE_TYPES, type NodeType } from './types';

export interface EntityRef {
  type: NodeType;
  key: string;
  /** `${type}:${key}` */
  id: string;
}

/** Usernames that mean "nobody": never a user node (mirrored by graph_value()). */
export const JUNK_USERS: ReadonlySet<string> = new Set(['-', 'unknown', 'null', 'none', '(null)', 'n/a', 'nobody', '?']);

export const MAX_ENTITY_LENGTH = 300;
const MAX_HOST = 253;
const MAX_USER = 128;
const MAX_INT_ID = 2_147_483_647;

const ID_TYPES: ReadonlySet<NodeType> = new Set(['alert', 'rule', 'asset', 'vuln', 'finding', 'identity', 'shipper', 'account']);
const ID_PATTERN = /^[1-9][0-9]{0,9}$/;
const TAG_PATTERN = /^[0-9a-f]{8}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAPPED_V4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

const hasWhitespace = (value: string) => /\s/u.test(value);

/** `value` without leading and trailing ASCII spaces: what SQL's btrim(value) does. */
export function trimSpaces(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) === 0x20) start++;
  while (end > start && value.charCodeAt(end - 1) === 0x20) end--;
  return value.slice(start, end);
}

/** The canonical form of an IP address, or null when `value` is not one (compared as written: no trimming). */
export function canonicalIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const s = value;
  if (s.length === 0 || s.length > 45) return null;
  const mapped = MAPPED_V4.exec(s);
  if (mapped && net.isIPv4(mapped[1])) return mapped[1];
  if (net.isIPv4(s)) return s;
  // Zone ids (fe80::1%eth0) are local to one machine: not an entity.
  if (s.includes('%') || !net.isIPv6(s)) return null;
  try {
    // The WHATWG URL serializer prints IPv6 in its RFC 5952 form.
    const host = new URL(`http://[${s}]/`).hostname;
    const canonical = host.slice(1, -1);
    const folded = MAPPED_V4.exec(canonical);
    // [::ffff:1.2.3.4] serializes as ::ffff:102:304: fold it like the dotted form.
    if (canonical.startsWith('::ffff:') && !folded) {
      const parts = canonical.slice(7).split(':');
      if (parts.length === 2) {
        const hi = parseInt(parts[0], 16);
        const lo = parseInt(parts[1], 16);
        return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      }
    }
    return canonical;
  } catch {
    return null;
  }
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

/** A shipper tag (raw_logs.shipper_id) as 8 lower-case hex characters, or null. */
export function canonicalShipperTag(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const s = value.trim().toLowerCase();
  return TAG_PATTERN.test(s) ? s : null;
}

/** An endpoint agent id (UUID), lower-case, or null. */
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

/** The ref for a canonical (type, key). */
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

/** Parse `type:key`, or throw 400 GRAPH_BAD_ENTITY. */
export function parseEntity(value: unknown): EntityRef {
  if (typeof value !== 'string' || value.length === 0) {
    throw badEntity('entity is required, as type:key (for example ip:198.51.100.7 or alert:812)');
  }
  if (value.length > MAX_ENTITY_LENGTH) throw badEntity(`entity is longer than ${MAX_ENTITY_LENGTH} characters`);
  const colon = value.indexOf(':');
  const type = colon > 0 ? value.slice(0, colon).trim().toLowerCase() : '';
  if (!isNodeType(type)) {
    throw badEntity(`entity must start with one of ${NODE_TYPES.join(', ')} and a colon`);
  }
  const ref = toEntity(type, value.slice(colon + 1));
  if (!ref) throw badEntity(`that is not a valid ${type}`);
  return ref;
}

/**
 * The parity list: [type, input, canonical key or null]. The rollup's SQL
 * functions (PR 3) and the frontend's copy (PR 2) are tested against the same
 * list, so a key means the same thing everywhere.
 */
export const ENTITY_KEY_FIXTURES: ReadonlyArray<readonly [NodeType, string, string | null]> = [
  ['ip', '198.51.100.7', '198.51.100.7'],
  ['ip', ' 198.51.100.7 ', null],
  ['ip', '::ffff:198.51.100.7', '198.51.100.7'],
  ['ip', '::FFFF:198.51.100.7', '198.51.100.7'],
  ['ip', '2001:DB8:0:0:0:0:0:1', '2001:db8::1'],
  ['ip', '2001:0db8::0001', '2001:db8::1'],
  ['ip', '::1', '::1'],
  ['ip', 'fe80::1%eth0', null],
  ['ip', '256.1.1.1', null],
  ['ip', '01.2.3.4', null],
  ['ip', 'nas', null],
  ['ip', '', null],
  ['host', 'NAS.lan', 'nas.lan'],
  ['host', ' nas ', 'nas'],
  ['host', 'two words', null],
  ['host', 'evil‮exe', null],
  ['host', 'tab\there', null],
  ['host', '\tnas', null],
  ['host', 'a'.repeat(254), null],
  ['user', 'Root', 'Root'],
  ['user', ' alice@corp.example ', 'alice@corp.example'],
  ['user', 'root\n', null],
  ['user', '\u00a0root', '\u00a0root'],
  ['user', 'John Smith', 'John Smith'],
  ['user', '-', null],
  ['user', 'UNKNOWN', null],
  ['user', '(null)', null],
  ['user', 'n/a', null],
  ['user', 'nobody', null],
  ['user', '?', null],
  ['user', '   ', null],
  ['user', 'bell\u0007', null],
  ['user', 'rtl⁦x', null],
  ['user', 'u'.repeat(129), null],
  ['domain', 'Example.COM.', 'example.com'],
  ['domain', ' example.com.. ', 'example.com'],
  ['domain', 'xn--bcher-kva.example', 'xn--bcher-kva.example'],
  ['domain', 'localhost', null],
  ['domain', '.example.com', null],
  ['domain', 'exa mple.com', null],
  ['alert', '812', '812'],
  ['alert', '0', null],
  ['alert', '012', null],
  ['alert', '-1', null],
  ['alert', '2147483648', null],
  ['vuln', '1', '1'],
  ['shipper_tag', 'DEADBEEF', 'deadbeef'],
  ['shipper_tag', 'deadbee', null],
  ['shipper_tag', 'deadbeefz', null],
  ['endpoint', '3F2504E0-4F89-11D3-9A0C-0305E82C3301', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'],
  ['endpoint', 'not-a-uuid', null],
];
