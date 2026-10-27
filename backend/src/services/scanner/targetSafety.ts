/**
 * Scan-target safety: is a scan target inside private or reserved address
 * space, and does a public one look like a typo of a private range?
 *
 * Scans are meant for the operator's own network. A target outside private and
 * reserved space (RFC 1918, RFC 6598 100.64.0.0/10, loopback, link-local, the
 * documentation and benchmarking ranges, multicast, IPv6 ULA fc00::/7 and
 * link-local fe80::/10) is public address space somebody else owns, and is
 * usually a typo: 192.169.1.0/24 for 192.168.1.0/24. The scan routes refuse such
 * targets unless the request confirms them (allow_public_targets: true), and the
 * scan dialogs warn before submit.
 *
 * Literal IPv4/IPv6 addresses, IPv4 CIDRs and nmap octet ranges
 * (192.168.1.1-254), bare or inside a URL, are classified. Hostnames are not
 * resolved: they come back as 'hostname' and get a generic warning only.
 *
 * THIS FILE EXISTS TWICE, byte for byte: backend/src/services/scanner/targetSafety.ts
 * (the server's gate) and frontend/src/utils/targetSafety.ts (the dialogs'
 * warning). backend/src/services/scanner/targetSafety.test.ts fails when they
 * differ. It is dependency-free so both builds compile it as is.
 */

export type TargetClass = 'private' | 'public' | 'hostname' | 'invalid';

export interface TargetAssessment {
  /** The target as given (trimmed). */
  target: string;
  kind: TargetClass;
  /** The address part the class was decided on (a URL's host without its port). */
  address?: string;
  /** Public only: the range also covers some private or reserved space (e.g. 10.0.0.0/7). */
  partlyPrivate?: boolean;
  /** Public only: the private target this probably meant, e.g. 192.168.1.0/24 for 192.169.1.0/24. */
  suggestion?: string;
}

export interface PublicTargetReport {
  /** Targets in (or reaching into) public address space. */
  publicTargets: TargetAssessment[];
  /** Hostnames: not resolved, so not classified. */
  hostnames: string[];
}

// ---------------------------------------------------------------------------
// Address space
// ---------------------------------------------------------------------------

/** Non-public IPv4 blocks: private, shared, loopback, link-local and reserved space. */
const IPV4_NON_PUBLIC: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // RFC 6598 shared address space (CGNAT)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1 (documentation)
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2 (documentation)
  ['203.0.113.0', 24], // TEST-NET-3 (documentation)
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, and the limited broadcast address
];

/** Non-public IPv6 blocks. IPv4-mapped addresses (::ffff:a.b.c.d) are judged by their IPv4 address. */
const IPV6_NON_PUBLIC: Array<[string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local (ULA)
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV4_CIDR_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;
/** nmap's octet ranges: 192.168.1.1-254, 10.0-3.0.1. */
const IPV4_OCTET_RANGE_RE = /^(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)$/;
const IPV6_CIDR_RE = /^([0-9a-fA-F:.]+)\/(\d{1,3})$/;
const ALL_NUMERIC_LABELS_RE = /^[\d.-]+$/;

function ipv4ToNumber(ip: string): number | null {
  const m = IPV4_RE.exec(ip);
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return null;
  return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
}

/** Parse an IPv6 address (optionally with a %zone) to a 128-bit BigInt, or null. */
function ipv6ToBigInt(input: string): bigint | null {
  let ip = input.split('%')[0];
  if (!ip.includes(':')) return null;
  // An embedded IPv4 tail (::ffff:192.0.2.1) becomes two hextets.
  const lastColon = ip.lastIndexOf(':');
  const tail = ip.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToNumber(tail);
    if (v4 === null) return null;
    ip = `${ip.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  let value = BigInt(0);
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << BigInt(16)) + BigInt(parseInt(group, 16));
  }
  return value;
}

interface Span<T> {
  lo: T;
  hi: T;
}

function v4Span(base: number, prefix: number): Span<number> {
  const size = 2 ** (32 - prefix);
  const lo = Math.floor(base / size) * size;
  return { lo, hi: lo + size - 1 };
}

function v6Span(base: bigint, prefix: number): Span<bigint> {
  const hostBits = BigInt(128 - prefix);
  const lo = (base >> hostBits) << hostBits;
  return { lo, hi: lo + (BigInt(1) << hostBits) - BigInt(1) };
}

const V4_BLOCKS: Array<Span<number>> = IPV4_NON_PUBLIC.map(([ip, prefix]) => v4Span(ipv4ToNumber(ip) as number, prefix));
const V6_BLOCKS: Array<Span<bigint>> = IPV6_NON_PUBLIC.map(([ip, prefix]) => v6Span(ipv6ToBigInt(ip) as bigint, prefix));
const V4_MAPPED: Span<bigint> = v6Span(ipv6ToBigInt('::ffff:0:0') as bigint, 96);

type SpanVerdict = { kind: 'private' } | { kind: 'public'; partlyPrivate: boolean };

function judgeSpan<T extends number | bigint>(span: Span<T>, blocks: Array<Span<T>>): SpanVerdict {
  if (blocks.some((b) => span.lo >= b.lo && span.hi <= b.hi)) return { kind: 'private' };
  return { kind: 'public', partlyPrivate: blocks.some((b) => span.lo <= b.hi && span.hi >= b.lo) };
}

function judgeV6Span(span: Span<bigint>): SpanVerdict {
  // Wholly inside ::ffff:0:0/96: judge the IPv4 addresses it maps.
  if (span.lo >= V4_MAPPED.lo && span.hi <= V4_MAPPED.hi) {
    const mask = BigInt(0xffffffff);
    return judgeSpan({ lo: Number(span.lo & mask), hi: Number(span.hi & mask) }, V4_BLOCKS);
  }
  return judgeSpan(span, V6_BLOCKS);
}

// ---------------------------------------------------------------------------
// Typo hints
// ---------------------------------------------------------------------------

/** Optimal-string-alignment distance <= 1: one substitution, insertion, deletion or adjacent swap. */
function oneEditApart(a: string, b: string): boolean {
  // Only ever compares octets (1-3 digits); anything longer is no slip of one.
  if (a === b || a.length > 3 || b.length > 3) return false;
  if (a.length === b.length) {
    const diffs: number[] = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diffs.push(i);
    if (diffs.length === 1) return true;
    return diffs.length === 2 && diffs[1] === diffs[0] + 1 && a[diffs[0]] === b[diffs[1]] && a[diffs[1]] === b[diffs[0]];
  }
  const [short, long] = a.length < b.length ? [a, b] : [b, a];
  if (long.length - short.length !== 1) return false;
  for (let i = 0; i < long.length; i++) {
    if (long.slice(0, i) + long.slice(i + 1) === short) return true;
  }
  return false;
}

function isTransposition(a: string, b: string): boolean {
  return a.length === 2 && b.length === 2 && a[0] === b[1] && a[1] === b[0] && a !== b;
}

/** Likely slips for the 10 of 10.0.0.0/8 (every 10.x address is already private). */
const TEN_SLIPS = new Set(['9', '11', '01', '100', '110', '101']);

/**
 * The first two octets this address probably meant, when it is a slip of a
 * private range: 192.169 -> 192.168, 193.168 -> 192.168, 172.32 -> 172.31,
 * 172.61 -> 172.16, 11.x -> 10.x. Null when nothing is close.
 */
function intendedPrefix(first: string, second: string): [string, string] | null {
  const b = Number(second);
  if (first === '192' && second !== '168' && oneEditApart(second, '168')) return ['192', '168'];
  if (first !== '192' && second === '168' && oneEditApart(first, '192')) return ['192', '168'];
  if (first === '172' && (b < 16 || b > 31)) {
    // Just past either end (172.15, 172.32) first, then swapped digits
    // (172.61), then the nearest one-edit slip.
    if (b === 15 || b === 32) return ['172', b === 15 ? '16' : '31'];
    let best: number | null = null;
    for (let c = 16; c <= 31; c++) {
      const cs = String(c);
      if (isTransposition(second, cs)) return ['172', cs];
      if (oneEditApart(second, cs) && (best === null || Math.abs(b - c) < Math.abs(b - best))) best = c;
    }
    return best === null ? null : ['172', String(best)];
  }
  if (first !== '172' && b >= 16 && b <= 31 && oneEditApart(first, '172')) return ['172', second];
  if (TEN_SLIPS.has(first)) return ['10', second];
  return null;
}

/** The private target `address` (an IPv4 address, CIDR or octet range) probably meant, or undefined. */
function suggestFor(target: string, address: string): string | undefined {
  const octets = address.split('/')[0].split('.');
  if (octets.length !== 4) return undefined;
  const intended = intendedPrefix(octets[0].split('-')[0], octets[1].split('-')[0]);
  if (!intended) return undefined;
  const fixedAddress = [intended[0], intended[1], ...address.split('.').slice(2)].join('.');
  // Only a hint that actually lands in private space is worth showing.
  const fixedTarget = target.replace(address, fixedAddress);
  const check = classify(fixedTarget, false);
  return check.kind === 'private' ? fixedTarget : undefined;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/** The host (address) part of a target: a URL's host without userinfo or port; a bare value as is. */
function hostPart(target: string): string {
  let rest = target;
  const scheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.exec(rest);
  if (scheme) {
    rest = rest.slice(scheme[0].length).split(/[/?#]/)[0];
    rest = rest.slice(rest.lastIndexOf('@') + 1);
  } else if (!IPV4_CIDR_RE.test(rest) && !IPV6_CIDR_RE.test(rest)) {
    rest = rest.split(/[/?#]/)[0];
  }
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(rest);
  if (bracketed) return bracketed[1];
  const withPort = /^([^:]+):\d+$/.exec(rest);
  return withPort ? withPort[1] : rest;
}

function classify(rawTarget: string, withHint: boolean): TargetAssessment {
  const target = rawTarget.trim();
  if (!target) return { target, kind: 'invalid' };
  const address = hostPart(target);
  if (!address) return { target, kind: 'invalid' };

  const finish = (verdict: SpanVerdict, ipv4: boolean): TargetAssessment => {
    if (verdict.kind === 'private') return { target, kind: 'private', address };
    const out: TargetAssessment = { target, kind: 'public', address };
    if (verdict.partlyPrivate) out.partlyPrivate = true;
    if (withHint && ipv4) {
      const suggestion = suggestFor(target, address);
      if (suggestion) out.suggestion = suggestion;
    }
    return out;
  };

  // IPv4 address
  const v4 = ipv4ToNumber(address);
  if (v4 !== null) return finish(judgeSpan({ lo: v4, hi: v4 }, V4_BLOCKS), true);

  // IPv4 CIDR
  const cidr = IPV4_CIDR_RE.exec(address);
  if (cidr) {
    const base = ipv4ToNumber(cidr[1]);
    const prefix = Number(cidr[2]);
    if (base === null || prefix > 32) return { target, kind: 'invalid', address };
    return finish(judgeSpan(v4Span(base, prefix), V4_BLOCKS), true);
  }

  // nmap octet range: judged by its bounding addresses (every address of the
  // range lies between them, so a range wholly inside one block is private).
  const range = IPV4_OCTET_RANGE_RE.exec(address);
  if (range) {
    const bounds = range.slice(1, 5).map((part) => part.split('-').map(Number));
    if (bounds.some((b) => b.some((o) => o > 255) || (b.length === 2 && b[0] > b[1]))) {
      return { target, kind: 'invalid', address };
    }
    const lo = ipv4ToNumber(bounds.map((b) => b[0]).join('.')) as number;
    const hi = ipv4ToNumber(bounds.map((b) => b[b.length - 1]).join('.')) as number;
    return finish(judgeSpan({ lo, hi }, V4_BLOCKS), true);
  }

  // IPv6 address or CIDR
  const v6cidr = IPV6_CIDR_RE.exec(address);
  const v6 = ipv6ToBigInt(v6cidr ? v6cidr[1] : address);
  if (v6 !== null) {
    const prefix = v6cidr ? Number(v6cidr[2]) : 128;
    if (prefix > 128) return { target, kind: 'invalid', address };
    return finish(judgeV6Span(v6Span(v6, prefix)), false);
  }
  if (address.includes(':') || v6cidr) return { target, kind: 'invalid', address };

  if (address.toLowerCase() === 'localhost') return { target, kind: 'private', address };

  // Something made only of digits and dots that isn't a full address
  // (192.169.1, 3232235777): resolvers and nmap may still read it as an IPv4
  // address, so it can't be shown to be private.
  if (ALL_NUMERIC_LABELS_RE.test(address)) return { target, kind: 'public', address };

  return { target, kind: 'hostname', address };
}

/** Classify one scan target (an IP, CIDR, nmap octet range, hostname or URL). */
export function assessTarget(target: string): TargetAssessment {
  return classify(String(target ?? ''), true);
}

/** The public targets (with typo hints) and the unresolved hostnames among `targets`. */
export function findPublicTargets(targets: readonly string[]): PublicTargetReport {
  const report: PublicTargetReport = { publicTargets: [], hostnames: [] };
  for (const t of targets) {
    const a = assessTarget(t);
    if (a.kind === 'public') report.publicTargets.push(a);
    else if (a.kind === 'hostname') report.hostnames.push(a.target);
  }
  return report;
}

/** One public target for a message: "192.169.1.0/24 (did you mean 192.168.1.0/24?)". */
export function describePublicTarget(a: TargetAssessment): string {
  const notes: string[] = [];
  if (a.partlyPrivate) notes.push('partly public');
  if (a.suggestion) notes.push(`did you mean ${a.suggestion}?`);
  return notes.length > 0 ? `${a.target} (${notes.join('; ')})` : a.target;
}

/** Split free-text target input (commas, spaces, newlines) into a list. */
export function splitTargets(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}
