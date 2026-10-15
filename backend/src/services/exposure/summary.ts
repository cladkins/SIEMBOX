/**
 * The Digital Risk page's summary (GET /api/exposure/summary): its response
 * shape and the pure folds that turn the snapshot's query rows into it. The
 * queries themselves are getExposureSummary in models/Exposure.ts, which runs
 * them in one REPEATABLE READ transaction.
 *
 * Nothing here touches the database or the network, so every rule (zero
 * filling, the running open backlog, the lookalike inventory's order and
 * states) is tested without Postgres (summary.test.ts).
 *
 * Lookalikes that were already registered when a domain was first checked are
 * recorded silently (no finding): they exist only in the lookalike baseline,
 * so the inventory reads the baselines with the collectors' own parsers rather
 * than walking their JSON a second way.
 */
import { ApiError } from '../../middleware/errorHandler';
import type {
  DomainCollectors,
  DomainScope,
  ExposureFindingSource,
  ExposureSeverity,
} from '../../models/Exposure';
import { parseLookalikeSnapshot } from './domainMonitor/lookalike';
import { parseCtSnapshot } from './domainMonitor/ct';
import { isPlainObject } from './domainMonitor/types';

// ---- Window ------------------------------------------------------------------------

/** The windows the page offers, in days. Anything else is a 400. */
export const SUMMARY_DAYS = [30, 90, 180, 365] as const;
export type SummaryDays = (typeof SUMMARY_DAYS)[number];
export const DEFAULT_SUMMARY_DAYS: SummaryDays = 90;
export type SummaryBucket = 'day' | 'week' | 'month';

/** Each window's bucket (a Postgres date_trunc unit): 31 days, 13-14 or 26-27 weeks, 13 months. */
export const BUCKET_FOR_DAYS: Readonly<Record<SummaryDays, SummaryBucket>> = {
  30: 'day',
  90: 'week',
  180: 'week',
  365: 'month',
};

/**
 * How far back each window reaches (a Postgres interval) before its start is
 * rounded down to a bucket boundary. The year is 12 calendar months rather
 * than 365 days: 365 days back from a day between Feb 29 and the next Jan 31
 * lands on the 1st of the following month, which would leave 12 monthly
 * buckets instead of 13. Whitelisted and bound as text, never interpolated.
 */
export const WINDOW_BACK: Readonly<Record<SummaryDays, string>> = {
  30: '30 days',
  90: '90 days',
  180: '180 days',
  365: '12 months',
};

export const SUMMARY_DAYS_ERROR = `days must be one of ${SUMMARY_DAYS.join(', ')}`;

/**
 * `?days=`: absent or '' is the default (90); otherwise a string equal to one
 * of SUMMARY_DAYS. No parsing, so '90abc', '1e2', ' 90' and a repeated key (an
 * array) are all refused.
 */
export function parseSummaryDays(raw: unknown): SummaryDays {
  if (raw === undefined || raw === '') return DEFAULT_SUMMARY_DAYS;
  const match = typeof raw === 'string' ? SUMMARY_DAYS.find((d) => String(d) === raw) : undefined;
  if (match === undefined) throw new ApiError(400, SUMMARY_DAYS_ERROR);
  return match;
}

// ---- Vocabulary ----------------------------------------------------------------------

export const SEVERITIES: readonly ExposureSeverity[] = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK: Readonly<Record<ExposureSeverity, number>> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** The severity for SEV_RANK_SQL's number (anything unexpected reads as low). */
export function severityFromRank(rank: unknown): ExposureSeverity {
  const n = Number(rank);
  return n >= 4 ? 'critical' : n === 3 ? 'high' : n === 2 ? 'medium' : 'low';
}

/** CATEGORY_SQL's values, in the page's order. */
export const RISK_CATEGORIES = ['credentials', 'impersonation', 'domain_changes'] as const;
export type RiskCategory = (typeof RISK_CATEGORIES)[number];

type SummarySource = ExposureFindingSource;

/**
 * The (source, event type, category) pairs the collectors write, zero-filled in
 * by_type so the page's list is stable. Anything else in the data is passed
 * through after them. unexpected_ca is raised for owned domains only.
 */
export const KNOWN_FINDING_TYPES: ReadonlyArray<{ source: SummarySource; event_type: string; category: RiskCategory }> = [
  { source: 'leaked-creds', event_type: 'breach', category: 'credentials' },
  { source: 'domain-monitor', event_type: 'lookalike_registered', category: 'impersonation' },
  { source: 'domain-monitor', event_type: 'new_cert', category: 'impersonation' },
  { source: 'domain-monitor', event_type: 'new_cert', category: 'domain_changes' },
  { source: 'domain-monitor', event_type: 'unexpected_ca', category: 'domain_changes' },
  { source: 'domain-monitor', event_type: 'dns_drift', category: 'domain_changes' },
  { source: 'domain-monitor', event_type: 'rdap_change', category: 'domain_changes' },
  { source: 'domain-monitor', event_type: 'expiry_warning', category: 'domain_changes' },
];

// ---- Response ------------------------------------------------------------------------

export type SeverityCounts = Record<ExposureSeverity, number>;

export interface SummaryTypeRow {
  source: string;
  event_type: string;
  category: RiskCategory;
  open: number;
  open_by_severity: SeverityCounts;
  /** First seen in the window. */
  new: number;
  /** Resolved in the window. */
  resolved: number;
}

export interface SummaryTrendBucket {
  /** The bucket's start (UTC midnight; weeks start on Monday). */
  start: string;
  /** Findings first seen in the bucket, per category. */
  new: Record<RiskCategory, number>;
  resolved: number;
  /** Open findings when the bucket ended (for the last bucket: now). */
  open_at_end: number;
  /** Identities and domains added in the bucket: their first check reports everything already exposed. */
  monitoring_added: { identities: number; domains: number };
}

export interface SummaryAccount {
  account: string;
  identity_id: number | null;
  /** Open breach findings for the account. */
  open: number;
  /** Of those, breaches that exposed passwords, historical passwords or auth tokens, or were stealer logs. */
  credential_exposures: number;
  stealer_log: boolean;
  worst_severity: ExposureSeverity;
  /** Up to three distinct breaches, newest breach date first. */
  breaches: Array<{ title: string; date: string | null }>;
  /**
   * Distinct breaches among the open findings. An account monitored through
   * two identities (an address and its email domain) has two findings for one
   * breach, so this can be less than `open`; the page's "+N more" counts from it.
   */
  breach_count: number;
  last_detected: string;
}

export type LookalikeCerts = 'current' | 'none' | 'not_checked';

export interface SummaryLookalike {
  lookalike: string;
  domain_id: number;
  watched_domain: string;
  scope: DomainScope;
  /** The fuzzer that generated it (homoglyph, omission, ...); null when unknown. */
  technique: string | null;
  /** null: every lookup so far failed. */
  has_mx: boolean | null;
  has_address: boolean | null;
  certs: LookalikeCerts;
  /** When it was reported as newly registered; null: already registered when first checked (no finding). */
  reported_at: string | null;
  open_findings: { count: number; worst_severity: ExposureSeverity } | null;
}

export interface SummaryLookalikes {
  /** not_watched: no enabled domain runs the lookalike check; not_checked: none has run it yet. */
  state: 'not_watched' | 'not_checked' | 'checked';
  candidates_checked: number;
  /**
   * Distinct registered lookalike names. Two watched domains can share one
   * (acme.com and acme.net both have acme.co as a TLD swap): it counts once,
   * and a flag counts when any domain's checks saw it.
   */
  registered: number;
  with_mx: number;
  with_address: number;
  with_current_cert: number;
  /** At most LOOKALIKE_TOP, riskiest first; one row per (watched domain, name). */
  top: SummaryLookalike[];
}

export interface ExposureSummary {
  generated_at: string;
  window: { days: SummaryDays; bucket: SummaryBucket; since: string };
  open: {
    total: number;
    by_severity: SeverityCounts;
    by_source: Record<SummarySource, number>;
    oldest_critical_high_first_seen: string | null;
  };
  in_window: {
    new: number;
    new_by_severity: SeverityCounts;
    resolved: number;
    /** First seen in the window of the same length just before it. */
    prev_new: number;
  };
  by_type: SummaryTypeRow[];
  trend: SummaryTrendBucket[];
  accounts: {
    /** Distinct accounts in open breach findings. */
    total: number;
    /** Of those, accounts with credentials exposed or a stealer log. */
    to_reset: number;
    top: SummaryAccount[];
  };
  lookalikes: SummaryLookalikes;
}

// ---- Folds ---------------------------------------------------------------------------

const zeroSeverities = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0 });
const isSeverity = (v: unknown): v is ExposureSeverity =>
  typeof v === 'string' && Object.prototype.hasOwnProperty.call(SEVERITY_RANK, v);
const isCategory = (v: unknown): v is RiskCategory =>
  typeof v === 'string' && (RISK_CATEGORIES as readonly string[]).includes(v);
const toIso = (v: unknown): string | null => {
  if (v === null || v === undefined) return null;
  const d = v instanceof Date ? v : new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};

/** One row of the breakdown query: counts per (source, event type, category, severity). */
export interface BreakdownRow {
  source: string;
  event_type: string;
  category: string;
  severity: string;
  open_n: number;
  new_n: number;
  resolved_n: number;
  prev_new_n: number;
  /** The oldest open finding's first_seen; null when none is open. */
  oldest_open: Date | string | null;
}

/** open, in_window and by_type from the breakdown rows. */
export function foldBreakdown(
  rows: readonly BreakdownRow[]
): Pick<ExposureSummary, 'open' | 'in_window' | 'by_type'> {
  const open: ExposureSummary['open'] = {
    total: 0,
    by_severity: zeroSeverities(),
    by_source: { 'leaked-creds': 0, 'domain-monitor': 0 },
    oldest_critical_high_first_seen: null,
  };
  const inWindow: ExposureSummary['in_window'] = {
    new: 0,
    new_by_severity: zeroSeverities(),
    resolved: 0,
    prev_new: 0,
  };
  const key = (source: string, eventType: string, category: string) => `${source}\u0000${eventType}\u0000${category}`;
  const types = new Map<string, SummaryTypeRow>();
  const typeRow = (source: string, event_type: string, category: RiskCategory): SummaryTypeRow => {
    const k = key(source, event_type, category);
    let row = types.get(k);
    if (!row) {
      row = { source, event_type, category, open: 0, open_by_severity: zeroSeverities(), new: 0, resolved: 0 };
      types.set(k, row);
    }
    return row;
  };
  for (const t of KNOWN_FINDING_TYPES) typeRow(t.source, t.event_type, t.category);

  let oldest = Infinity;
  for (const r of rows) {
    const openN = Number(r.open_n) || 0;
    const newN = Number(r.new_n) || 0;
    const resolvedN = Number(r.resolved_n) || 0;
    const severity = isSeverity(r.severity) ? r.severity : 'low';
    const category = isCategory(r.category) ? r.category : 'domain_changes';

    open.total += openN;
    open.by_severity[severity] += openN;
    if (r.source === 'leaked-creds' || r.source === 'domain-monitor') open.by_source[r.source] += openN;
    if ((severity === 'critical' || severity === 'high') && openN > 0 && r.oldest_open) {
      const at = new Date(r.oldest_open).getTime();
      if (Number.isFinite(at) && at < oldest) oldest = at;
    }
    inWindow.new += newN;
    inWindow.new_by_severity[severity] += newN;
    inWindow.resolved += resolvedN;
    inWindow.prev_new += Number(r.prev_new_n) || 0;

    const t = typeRow(r.source, r.event_type, category);
    t.open += openN;
    t.open_by_severity[severity] += openN;
    t.new += newN;
    t.resolved += resolvedN;
  }
  if (Number.isFinite(oldest)) open.oldest_critical_high_first_seen = new Date(oldest).toISOString();

  // Known pairs first, in their order; anything else after them, by category then name.
  const known = new Set(KNOWN_FINDING_TYPES.map((t) => key(t.source, t.event_type, t.category)));
  const extra = [...types.entries()]
    .filter(([k]) => !known.has(k))
    .map(([, row]) => row)
    .sort(
      (a, b) =>
        RISK_CATEGORIES.indexOf(a.category) - RISK_CATEGORIES.indexOf(b.category) ||
        a.event_type.localeCompare(b.event_type) ||
        a.source.localeCompare(b.source)
    );
  const byType = [
    ...KNOWN_FINDING_TYPES.map((t) => types.get(key(t.source, t.event_type, t.category))!),
    ...extra,
  ].sort((a, b) => RISK_CATEGORIES.indexOf(a.category) - RISK_CATEGORIES.indexOf(b.category));
  return { open, in_window: inWindow, by_type: byType };
}

/** One row of the trend query: a count in one bucket. */
export interface TrendRow {
  kind: 'new' | 'resolved' | 'identities' | 'domains';
  /** The bucket the timestamp falls in. */
  start: Date | string;
  /** For 'new': the finding's category. */
  category: string | null;
  n: number;
}

/**
 * The trend, one entry per bucket (oldest first), with every category key
 * present. open_at_end runs from the backlog open before the window. A count
 * whose bucket is past the last one (a row committed with a slightly later
 * NOW() than the snapshot's) is added to the last bucket, so the trend always
 * sums to the window's counts.
 */
export function foldTrend(
  bucketStarts: ReadonlyArray<Date | string>,
  rows: readonly TrendRow[],
  openBefore: number
): SummaryTrendBucket[] {
  const buckets: SummaryTrendBucket[] = bucketStarts.map((start) => ({
    start: toIso(start) ?? String(start),
    new: { credentials: 0, impersonation: 0, domain_changes: 0 },
    resolved: 0,
    open_at_end: 0,
    monitoring_added: { identities: 0, domains: 0 },
  }));
  if (buckets.length === 0) return buckets;
  const times = buckets.map((b) => Date.parse(b.start));
  const indexOf = (start: Date | string): number => {
    const t = new Date(start).getTime();
    let i = times.length - 1;
    while (i > 0 && times[i] > t) i--;
    return i;
  };
  for (const r of rows) {
    const n = Number(r.n) || 0;
    const b = buckets[indexOf(r.start)];
    if (r.kind === 'new') b.new[isCategory(r.category) ? r.category : 'domain_changes'] += n;
    else if (r.kind === 'resolved') b.resolved += n;
    else if (r.kind === 'identities') b.monitoring_added.identities += n;
    else if (r.kind === 'domains') b.monitoring_added.domains += n;
  }
  let running = Number(openBefore) || 0;
  for (const b of buckets) {
    running += b.new.credentials + b.new.impersonation + b.new.domain_changes - b.resolved;
    b.open_at_end = running;
  }
  return buckets;
}

// ---- Accounts ------------------------------------------------------------------------

export const ACCOUNTS_TOP = 10;
const BREACHES_SHOWN = 3;

/** One row of the accounts query. */
export interface AccountRow {
  account: string;
  identity_id: number | string | null;
  open_n: number;
  credential_exposures: number;
  stealer_log: boolean | null;
  worst_rank: number;
  /** COUNT(DISTINCT breach): the same key the breaches are told apart by. */
  breach_count?: number | string | null;
  /** Newest breach date first (up to ten): { key (the breach's name), title, date }. */
  breaches: unknown;
  last_detected: Date | string;
}

/**
 * The accounts list, in query order, each with up to three distinct breaches
 * (told apart by the breach's name, as breach_count counts them) and the
 * number of distinct breaches in all.
 */
export function buildAccounts(rows: readonly AccountRow[]): SummaryAccount[] {
  return rows.slice(0, ACCOUNTS_TOP).map((r) => {
    const breaches: SummaryAccount['breaches'] = [];
    const seen = new Set<string>();
    for (const b of Array.isArray(r.breaches) ? r.breaches : []) {
      if (!isPlainObject(b) || typeof b.title !== 'string' || !b.title) continue;
      const key = typeof b.key === 'string' && b.key ? b.key : b.title;
      if (seen.has(key)) continue;
      seen.add(key);
      breaches.push({ title: b.title, date: typeof b.date === 'string' && b.date ? b.date : null });
      if (breaches.length === BREACHES_SHOWN) break;
    }
    return {
      account: r.account,
      identity_id: r.identity_id === null || r.identity_id === undefined ? null : Number(r.identity_id),
      open: Number(r.open_n) || 0,
      credential_exposures: Number(r.credential_exposures) || 0,
      stealer_log: r.stealer_log === true,
      worst_severity: severityFromRank(r.worst_rank),
      breaches,
      breach_count: Math.max(Number(r.breach_count) || 0, breaches.length),
      last_detected: toIso(r.last_detected) ?? '',
    };
  });
}

// ---- Lookalikes ----------------------------------------------------------------------

export const LOOKALIKE_TOP = 25;

/** An enabled watched domain with its lookalike and CT baselines (raw snapshots; null when none). */
export interface LookalikeDomainInput {
  id: number;
  domain: string;
  scope: DomainScope;
  collectors: Partial<DomainCollectors> | null;
  last_summary: unknown;
  lookalike: unknown;
  ct: unknown;
}

/** Open domain-monitor findings that name a lookalike, per (domain, lookalike). */
export interface LookalikeFindingRow {
  domain_id: number;
  lookalike: string;
  n: number;
  worst_rank: number;
}

function candidatesChecked(lastSummary: unknown): number {
  if (!isPlainObject(lastSummary) || !isPlainObject(lastSummary.collectors)) return 0;
  const run = lastSummary.collectors.lookalike;
  if (!isPlainObject(run) || !isPlainObject(run.details)) return 0;
  const n = run.details.candidates;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * The registered lookalikes of every enabled domain that runs the lookalike
 * check, read from its baseline (which also holds the ones recorded silently
 * on the first run), with what CT knows of their certificates and the open
 * findings about them. Riskiest first: mail (MX), then a current certificate,
 * then an address, then the worst open finding, then the newest report.
 */
export function buildLookalikeInventory(
  domains: readonly LookalikeDomainInput[],
  findings: readonly LookalikeFindingRow[],
  nowSeconds: number
): SummaryLookalikes {
  const out: SummaryLookalikes = {
    state: 'not_watched',
    candidates_checked: 0,
    registered: 0,
    with_mx: 0,
    with_address: 0,
    with_current_cert: 0,
    top: [],
  };
  const eligible = domains.filter((d) => d.collectors?.lookalike !== false);
  if (eligible.length === 0) return out;

  const open = new Map<string, { count: number; rank: number }>();
  for (const f of findings) {
    const k = `${f.domain_id}\u0000${f.lookalike}`;
    const prev = open.get(k);
    open.set(k, {
      count: (prev?.count ?? 0) + (Number(f.n) || 0),
      rank: Math.max(prev?.rank ?? 0, Number(f.worst_rank) || 0),
    });
  }

  const rows: Array<{ row: SummaryLookalike; rank: number }> = [];
  // The totals are per name: one name in two domains' baselines is one lookalike.
  const names = new Map<string, { mx: boolean; addr: boolean; current: boolean }>();
  let checked = false;
  for (const d of eligible) {
    out.candidates_checked += candidatesChecked(d.last_summary);
    const snapshot = parseLookalikeSnapshot(d.lookalike);
    if (!snapshot) continue;
    checked = true;
    const ct = parseCtSnapshot(d.ct)?.lookalikes ?? {};
    for (const [name, info] of Object.entries(snapshot.registered)) {
      const entry = Object.prototype.hasOwnProperty.call(ct, name) ? ct[name] : undefined;
      const certs: LookalikeCerts = !entry
        ? 'not_checked'
        : Object.values(entry.certs).some((notAfter) => notAfter > nowSeconds)
          ? 'current'
          : 'none';
      const found = open.get(`${d.id}\u0000${name}`);
      const row: SummaryLookalike = {
        lookalike: name,
        domain_id: d.id,
        watched_domain: d.domain,
        scope: d.scope,
        technique: info.fuzzer === 'unknown' ? null : info.fuzzer,
        has_mx: info.mx,
        has_address: info.addr,
        certs,
        reported_at: info.since === null ? null : new Date(info.since * 1000).toISOString(),
        open_findings: found && found.count > 0 ? { count: found.count, worst_severity: severityFromRank(found.rank) } : null,
      };
      rows.push({ row, rank: found && found.count > 0 ? found.rank : 0 });
      const seen = names.get(name);
      names.set(name, {
        mx: (seen?.mx ?? false) || info.mx === true,
        addr: (seen?.addr ?? false) || info.addr === true,
        current: (seen?.current ?? false) || certs === 'current',
      });
    }
  }
  out.state = checked ? 'checked' : 'not_checked';
  out.registered = names.size;
  for (const n of names.values()) {
    if (n.mx) out.with_mx++;
    if (n.addr) out.with_address++;
    if (n.current) out.with_current_cert++;
  }

  const flag = (v: boolean) => (v ? 1 : 0);
  const reported = (r: SummaryLookalike) => (r.reported_at ? Date.parse(r.reported_at) : 0);
  rows.sort(
    ({ row: a, rank: ra }, { row: b, rank: rb }) =>
      flag(b.has_mx === true) - flag(a.has_mx === true) ||
      flag(b.certs === 'current') - flag(a.certs === 'current') ||
      flag(b.has_address === true) - flag(a.has_address === true) ||
      rb - ra ||
      reported(b) - reported(a) ||
      a.lookalike.localeCompare(b.lookalike) ||
      a.watched_domain.localeCompare(b.watched_domain)
  );
  out.top = rows.slice(0, LOOKALIKE_TOP).map((r) => r.row);
  return out;
}
