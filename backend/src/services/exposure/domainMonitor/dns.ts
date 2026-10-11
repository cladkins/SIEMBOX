/**
 * DNS drift collector: NS, MX, TXT, DMARC (the TXT record at _dmarc.<name>),
 * A and AAAA for the watched name, compared with the stored baseline.
 *
 * Resolution uses the system resolver. An optional second resolver
 * (exposure_dns_secondary_resolver, an IP address) is OFF by default so the
 * feature never sends DNS traffic anywhere the operator didn't choose; when
 * set, both must agree on a record set before it is trusted.
 *
 * A lookup that FAILS (timeout, SERVFAIL, NXDOMAIN for the watched name,
 * resolvers disagreeing, or NODATA for NS at a delegated domain — which every
 * real resolver answers) yields a failure sentinel. A sentinel is never
 * compared: it is neither "unchanged" nor "removed", and the baseline keeps
 * the last good value for that type. NODATA (the name exists, no records of
 * that type) is a real, empty answer.
 *
 * Values are normalised and sorted so the comparison is order-insensitive.
 * NS, MX, TXT and DMARC compare as exact sets. A/AAAA are judged against the
 * addresses seen in the last 90 days too, so a CDN rotating through its pool
 * doesn't alert; a never-seen address (or all addresses vanishing) does.
 *
 * Severity: NS/MX critical (mail and the whole zone can be redirected),
 * TXT/DMARC high (SPF, DKIM and DMARC are called out — loosening them enables
 * spoofing), A/AAAA medium. The first run records the baseline silently.
 */
import crypto from 'crypto';
import {
  NODATA,
  NXDOMAIN,
  createResolver,
  timedQuery,
  type DnsResolverLike,
  type QueryOutcome,
} from './resolver';
import { normalizeName, registrableDomain } from './names';
import {
  CollectorError,
  capList,
  domainFinding,
  fingerprint,
  isPlainObject,
  sameList,
  sortedUnique,
  type Collector,
  type CollectorContext,
  type CollectorOutput,
} from './types';
import type { ExposureSeverity } from '../../../models/Exposure';
import type { FindingInput } from '../findingWriter';

export const DNS_RECORD_TYPES = ['NS', 'MX', 'TXT', 'DMARC', 'A', 'AAAA'] as const;
export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];
type AddressType = 'A' | 'AAAA';

export const DNS_DRIFT_SEVERITY: Record<DnsRecordType, ExposureSeverity> = {
  NS: 'critical',
  MX: 'critical',
  TXT: 'high',
  DMARC: 'high',
  A: 'medium',
  AAAA: 'medium',
};

/** A resolved record set, or the failure sentinel. */
export type RecordSet = { ok: true; values: string[] } | { ok: false; error: string };

const MAX_VALUES = 100;
const MAX_VALUE_CHARS = 2048;
const MAX_SEEN_ADDRESSES = 256;
const SEEN_TTL_SECONDS = 90 * 86_400;
const DEFAULT_QUERY_TIMEOUT_MS = 5_000;

/** Long TXT values (DKIM keys) are stored as a prefix plus a digest of the whole value. */
function clampValue(value: string): string {
  if (value.length <= MAX_VALUE_CHARS) return value;
  const digest = crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
  return `${value.slice(0, 1024)}...[sha256:${digest}]`;
}

const isAddressType = (type: DnsRecordType): type is AddressType => type === 'A' || type === 'AAAA';

export async function lookupRecordSet(
  resolver: DnsResolverLike,
  name: string,
  type: DnsRecordType,
  options: { apex: boolean; timeoutMs?: number }
): Promise<RecordSet> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS;
  const target = type === 'DMARC' ? `_dmarc.${name}` : name;
  let outcome: QueryOutcome<string[]>;
  switch (type) {
    case 'A':
      outcome = await timedQuery(() => resolver.resolve4(target), timeoutMs);
      break;
    case 'AAAA':
      outcome = await timedQuery(
        async () => (await resolver.resolve6(target)).map((v) => v.toLowerCase()),
        timeoutMs
      );
      break;
    case 'MX':
      outcome = await timedQuery(
        async () =>
          (await resolver.resolveMx(target)).map(
            (r) => `${r.priority} ${normalizeName(r.exchange) || '.'}`
          ),
        timeoutMs
      );
      break;
    case 'NS':
      outcome = await timedQuery(
        async () => (await resolver.resolveNs(target)).map(normalizeName),
        timeoutMs
      );
      break;
    default:
      outcome = await timedQuery(
        async () => (await resolver.resolveTxt(target)).map((chunks) => chunks.join('')),
        timeoutMs
      );
  }
  if (outcome.ok) {
    return { ok: true, values: sortedUnique(outcome.value.map(clampValue)).slice(0, MAX_VALUES) };
  }
  if (outcome.code === NODATA) {
    // Every delegated domain has NS records: NODATA there is a filtering or broken resolver.
    if (type === 'NS' && options.apex) {
      return { ok: false, error: 'the resolver returned no NS records for a delegated domain' };
    }
    return { ok: true, values: [] };
  }
  if (outcome.code === NXDOMAIN) {
    if (type === 'DMARC') return { ok: true, values: [] }; // no _dmarc name = no DMARC record
    return { ok: false, error: `${name} does not resolve (NXDOMAIN)` };
  }
  return { ok: false, error: outcome.code };
}

/** With a second resolver, a record set is only trusted when both agree. */
export function combineRecordSets(primary: RecordSet, secondary: RecordSet | null): RecordSet {
  if (!secondary) return primary;
  if (primary.ok && secondary.ok) {
    return sameList(primary.values, secondary.values)
      ? primary
      : { ok: false, error: 'the two resolvers disagree' };
  }
  if (primary.ok) return primary; // the second resolver failed: fall back to the first alone
  if (secondary.ok) return secondary;
  return primary;
}

// ---- Snapshot & diff --------------------------------------------------------------------------

export interface DnsSnapshot {
  v: 1;
  /** Last good value per type; a type that has never resolved is absent. */
  records: Partial<Record<DnsRecordType, string[]>>;
  /** A/AAAA addresses seen recently (address -> last seen, epoch seconds). */
  seen: Partial<Record<AddressType, Record<string, number>>>;
}

export function parseDnsSnapshot(value: unknown): DnsSnapshot | null {
  if (!isPlainObject(value) || value.v !== 1 || !isPlainObject(value.records)) return null;
  const records: DnsSnapshot['records'] = {};
  for (const type of DNS_RECORD_TYPES) {
    const list = value.records[type];
    if (Array.isArray(list)) records[type] = list.filter((v): v is string => typeof v === 'string');
  }
  const seen: DnsSnapshot['seen'] = {};
  if (isPlainObject(value.seen)) {
    for (const type of ['A', 'AAAA'] as const) {
      const map = value.seen[type];
      if (!isPlainObject(map)) continue;
      seen[type] = Object.fromEntries(
        Object.entries(map).filter(
          (entry): entry is [string, number] => typeof entry[1] === 'number'
        )
      );
    }
  }
  return { v: 1, records, seen };
}

export interface DnsChange {
  type: DnsRecordType;
  severity: ExposureSeverity;
  before: string[];
  after: string[];
  added: string[];
  removed: string[];
}

function updateSeen(
  previous: Record<string, number> | undefined,
  values: readonly string[],
  nowSeconds: number
): Record<string, number> {
  const merged: Record<string, number> = {};
  for (const [address, at] of Object.entries(previous ?? {})) {
    if (at >= nowSeconds - SEEN_TTL_SECONDS) merged[address] = at;
  }
  for (const address of values) merged[address] = nowSeconds;
  return Object.fromEntries(
    Object.entries(merged)
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .slice(0, MAX_SEEN_ADDRESSES)
  );
}

export function diffDns(
  previous: DnsSnapshot | null,
  current: Partial<Record<DnsRecordType, RecordSet>>,
  nowSeconds: number
): { next: DnsSnapshot; changes: DnsChange[] } {
  const next: DnsSnapshot = {
    v: 1,
    records: { ...(previous?.records ?? {}) },
    seen: { ...(previous?.seen ?? {}) },
  };
  const changes: DnsChange[] = [];
  for (const type of DNS_RECORD_TYPES) {
    const set = current[type];
    if (!set || !set.ok) continue; // failure sentinel: keep the last good value, compare nothing
    const before = previous?.records[type];
    next.records[type] = set.values;
    if (isAddressType(type))
      next.seen[type] = updateSeen(previous?.seen[type], set.values, nowSeconds);
    if (!previous || before === undefined) continue; // first good answer for this type: baseline
    if (sameList(before, set.values)) continue;
    if (isAddressType(type)) {
      const recent = Object.entries(previous.seen[type] ?? {})
        .filter(([, at]) => at >= nowSeconds - SEEN_TTL_SECONDS)
        .map(([address]) => address);
      const known = new Set([...before, ...recent]);
      const novel = set.values.some((v) => !known.has(v));
      const vanished = set.values.length === 0 && before.length > 0;
      if (!novel && !vanished) continue; // rotation among addresses seen recently
    }
    changes.push({
      type,
      severity: DNS_DRIFT_SEVERITY[type],
      before,
      after: set.values,
      added: set.values.filter((v) => !before.includes(v)),
      removed: before.filter((v) => !set.values.includes(v)),
    });
  }
  return { next, changes };
}

// ---- Findings -------------------------------------------------------------------------------------

export type TxtKind = 'spf' | 'dmarc' | 'dkim' | 'verification' | 'other';

export function classifyTxt(value: string): TxtKind {
  const v = value.trim().toLowerCase();
  if (v.startsWith('v=spf1')) return 'spf';
  if (v.startsWith('v=dmarc1')) return 'dmarc';
  if (v.startsWith('v=dkim1') || /(^|;)\s*k=(rsa|ed25519)\s*;/.test(v)) return 'dkim';
  if (/verification|verify/.test(v)) return 'verification';
  return 'other';
}

/** The p= tag of a DMARC record ("reject", "quarantine", "none"), if any. */
export function dmarcPolicy(values: readonly string[]): string | null {
  for (const value of values) {
    const match = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(value);
    if (match && /^v=dmarc1/i.test(value.trim())) return match[1].toLowerCase();
  }
  return null;
}

const TYPE_LABEL: Record<DnsRecordType, string> = {
  NS: 'Nameserver (NS) records',
  MX: 'Mail (MX) records',
  TXT: 'TXT records',
  DMARC: 'DMARC record',
  A: 'A records',
  AAAA: 'AAAA records',
};

function driftTitle(change: DnsChange, name: string, kinds: TxtKind[]): string {
  if (change.type === 'DMARC') {
    const before = dmarcPolicy(change.before);
    const after = dmarcPolicy(change.after);
    if (before !== after)
      return `DMARC policy changed for ${name}: ${before ?? 'none set'} -> ${after ?? 'none set'}`;
  }
  if (change.type === 'TXT') {
    const called = (['spf', 'dkim', 'dmarc'] as const).filter((k) => kinds.includes(k));
    if (called.length)
      return `${called.map((k) => k.toUpperCase()).join('/')} record changed for ${name}`;
  }
  return `${TYPE_LABEL[change.type]} changed for ${name}`;
}

const WHY: Record<DnsRecordType, string> = {
  NS: 'whoever runs these nameservers controls every record in the zone.',
  MX: "it decides where the domain's mail is delivered.",
  TXT: 'SPF, DKIM and DMARC live in TXT records; loosening them lets others send mail as this domain.',
  DMARC: 'a weaker DMARC policy lets spoofed mail through.',
  A: 'it decides where the web site and other services point.',
  AAAA: 'it decides where the web site and other services point over IPv6.',
};

function driftFinding(ctx: CollectorContext, change: DnsChange, resolvers: string): FindingInput {
  const name = ctx.domain.domain;
  const kinds =
    change.type === 'TXT'
      ? (sortedUnique([...change.added, ...change.removed].map(classifyTxt)) as TxtKind[])
      : [];
  return domainFinding({
    domainId: ctx.domain.id,
    eventType: 'dns_drift',
    fingerprint: fingerprint('dns', name, change.type, change.before, change.after),
    severity: change.severity,
    title: driftTitle(change, name, kinds),
    description:
      `${TYPE_LABEL[change.type]} for ${name} changed: added ${change.added.join(', ') || 'nothing'}; ` +
      `removed ${change.removed.join(', ') || 'nothing'}. This matters because ${WHY[change.type]} ` +
      'If the change was not planned, check your DNS provider and registrar accounts.',
    detail: {
      collector: 'dns',
      domain: name,
      record_type: change.type,
      before: capList(change.before, 20),
      after: capList(change.after, 20),
      added: capList(change.added, 20),
      removed: capList(change.removed, 20),
      ...(kinds.length ? { txt_kinds: kinds } : {}),
      resolvers,
    },
  });
}

export interface DnsCollectorDeps {
  resolver?: DnsResolverLike;
  /** undefined: from settings (off unless configured); null: never. */
  secondary?: DnsResolverLike | null;
  queryTimeoutMs?: number;
}

export function createDnsCollector(deps: DnsCollectorDeps = {}): Collector {
  return async (ctx: CollectorContext): Promise<CollectorOutput> => {
    const name = ctx.domain.domain;
    const apex = registrableDomain(name) === name;
    const primary = deps.resolver ?? createResolver();
    const secondary =
      deps.secondary !== undefined
        ? deps.secondary
        : ctx.config.secondaryResolver
          ? createResolver({ servers: [ctx.config.secondaryResolver] })
          : null;
    const resolvers = secondary
      ? `system + ${ctx.config.secondaryResolver ?? 'second resolver'}`
      : 'system';

    const sets = Object.fromEntries(
      await Promise.all(
        DNS_RECORD_TYPES.map(async (type) => {
          const options = { apex, timeoutMs: deps.queryTimeoutMs };
          const first = await lookupRecordSet(primary, name, type, options);
          const second = secondary ? await lookupRecordSet(secondary, name, type, options) : null;
          return [type, combineRecordSets(first, second)] as const;
        })
      )
    ) as Record<DnsRecordType, RecordSet>;

    const failed = DNS_RECORD_TYPES.filter((type) => !sets[type].ok);
    const describeFailure = (type: DnsRecordType) => {
      const set = sets[type];
      return `${type}: ${set.ok ? 'ok' : set.error}`;
    };
    if (failed.length === DNS_RECORD_TYPES.length) {
      throw new CollectorError(
        `every DNS lookup for ${name} failed (${failed.map(describeFailure).join('; ')}); will retry`,
        true
      );
    }

    const previous = parseDnsSnapshot(ctx.previous);
    const { next, changes } = diffDns(previous, sets, Math.floor(ctx.now.getTime() / 1000));
    const counts = Object.fromEntries(
      DNS_RECORD_TYPES.map((type) => {
        const set = sets[type];
        return [type, set.ok ? set.values.length : null];
      })
    );
    const summary = DNS_RECORD_TYPES.map((type) => {
      const set = sets[type];
      return `${type} ${set.ok ? set.values.length : 'failed'}`;
    }).join(', ');
    return {
      snapshot: next,
      findings: changes.map((change) => driftFinding(ctx, change, resolvers)),
      status: previous ? 'ok' : 'baseline',
      note: previous ? `${summary}; ${changes.length} change(s)` : `baseline recorded: ${summary}`,
      details: { records: counts, resolvers },
      ...(failed.length ? { warnings: failed.map(describeFailure) } : {}),
    };
  };
}
