/**
 * Pure helpers for the Digital Risk page (/digital-risk): the finding-type
 * vocabulary, the "Open findings by type" items, the queue's filters and the
 * deep-link parser. No Vue and no requests, so every rule is plain data in,
 * plain data out.
 */
import { format } from 'date-fns';
import {
  EXPOSURE_EVENT_TYPES,
  EXPOSURE_SEVERITIES,
  RISK_CATEGORY_KEYS,
  SUMMARY_DAYS,
  type ExposureEventType,
  type ExposureFindingSource,
  type ExposureSeverity,
  type ExposureStatus,
  type ExposureSummary,
  type MonitoredIdentity,
  type RiskCategory,
  type SummaryDays,
} from '@/services/exposureService';
import { checkStatusTag, hibpDomainLine, isSkippedHibpState, riskCategoryInfo, type TagType } from '@/utils/exposure';

// ---- Finding types ----------------------------------------------------------------

export interface FindingTypeInfo {
  event_type: ExposureEventType;
  category: RiskCategory;
  label: string;
}

/**
 * What the page calls each kind of finding, in its order. A certificate is
 * either for a lookalike (impersonation) or for the watched domain itself
 * (domain_changes), which only the category tells apart.
 */
export const FINDING_TYPES: readonly FindingTypeInfo[] = [
  { event_type: 'breach', category: 'credentials', label: 'Account in a breach' },
  { event_type: 'lookalike_registered', category: 'impersonation', label: 'Lookalike registered' },
  { event_type: 'new_cert', category: 'impersonation', label: 'Certificate for a lookalike' },
  { event_type: 'new_cert', category: 'domain_changes', label: 'New certificate for your domain' },
  { event_type: 'unexpected_ca', category: 'domain_changes', label: 'Certificate from an unexpected CA' },
  { event_type: 'dns_drift', category: 'domain_changes', label: 'DNS change' },
  { event_type: 'rdap_change', category: 'domain_changes', label: 'Registration change' },
  { event_type: 'expiry_warning', category: 'domain_changes', label: 'Registration expiry' },
];

/** A finding type's label; the raw event type for one this page doesn't know. */
export function findingTypeLabel(eventType: string, category?: string | null): string {
  const exact = FINDING_TYPES.find((t) => t.event_type === eventType && t.category === category);
  if (exact) return exact.label;
  const byType = FINDING_TYPES.filter((t) => t.event_type === eventType);
  if (byType.length === 1) return byType[0].label;
  if (eventType === 'new_cert') return 'New certificate';
  return eventType;
}

/** The Type filter's value: "event_type|category", either part possibly empty. */
export function typeKey(eventType?: string, category?: string): string {
  return `${eventType ?? ''}|${category ?? ''}`;
}

export function parseTypeKey(key: string): { event_type?: ExposureEventType; category?: RiskCategory } {
  const [eventType, category] = key.split('|');
  return {
    event_type: isEventType(eventType) ? eventType : undefined,
    category: isCategory(category) ? category : undefined,
  };
}

/** The Type filter's options, grouped by category: "any" for the category, then each type. */
export function typeFilterGroups(): Array<{ label: string; options: Array<{ value: string; label: string }> }> {
  return RISK_CATEGORY_KEYS.map((category) => {
    const info = riskCategoryInfo(category);
    return {
      label: info.label,
      options: [
        { value: typeKey(undefined, category), label: `Any: ${info.label.toLowerCase()}` },
        ...FINDING_TYPES.filter((t) => t.category === category).map((t) => ({
          value: typeKey(t.event_type, t.category),
          label: t.label,
        })),
      ],
    };
  });
}

/** "Open findings by type": the types with open findings, by category, then most first. */
export function typeItems(
  byType: ExposureSummary['by_type'],
  dark: boolean
): Array<{ key: string; label: string; value: number; color: string }> {
  const order = (c: string) => {
    const i = (RISK_CATEGORY_KEYS as readonly string[]).indexOf(c);
    return i === -1 ? RISK_CATEGORY_KEYS.length : i;
  };
  return byType
    .filter((t) => t.open > 0)
    .slice()
    .sort((a, b) => order(a.category) - order(b.category) || b.open - a.open)
    .map((t) => {
      const info = riskCategoryInfo(t.category);
      return {
        key: typeKey(t.event_type, t.category),
        label: findingTypeLabel(t.event_type, t.category),
        value: t.open,
        color: dark ? info.dark : info.light,
      };
    });
}

// ---- Page state ---------------------------------------------------------------------

/** Nothing is watched at all: the page shows its setup card instead of the dashboard. */
export function isNotSetUp(status: ExposureStatus): boolean {
  return status.counts.identities === 0 && status.counts.domains === 0;
}

export interface IdentityAttention {
  id: number;
  value: string;
  tag: { type: TagType; label: string };
  note: string;
}

/**
 * Enabled identities that need a look: the last check failed, or HIBP won't
 * search the email domain for this account (not verified, or no domain search
 * on the plan).
 */
export function breachAttention(identities: readonly MonitoredIdentity[]): IdentityAttention[] {
  const out: IdentityAttention[] = [];
  for (const identity of identities) {
    if (!identity.enabled) continue;
    const tag = checkStatusTag(identity);
    const skipped = identity.kind === 'email_domain' && !!identity.hibp_domain && isSkippedHibpState(identity.hibp_domain.state);
    if (tag.type !== 'danger' && !skipped) continue;
    const line = hibpDomainLine(identity);
    const note =
      tag.type === 'danger'
        ? identity.last_error || 'The last check failed'
        : [line?.text, line?.parentNote].filter(Boolean).join(' ');
    out.push({ id: identity.id, value: identity.value, tag: skipped && tag.type !== 'danger' ? { type: 'warning', label: 'Skipped' } : tag, note });
  }
  return out;
}

// ---- The findings queue's filters -----------------------------------------------------

export type FindingsSort = 'newest' | 'severity';

/** Everything the findings queue can be filtered by (what the page's click-throughs and deep links set). */
export interface FindingsFilters {
  open_only?: boolean;
  severity?: ExposureSeverity;
  event_type?: ExposureEventType;
  category?: RiskCategory;
  /** Kept for old links; the Type filter covers it on this page. */
  source?: ExposureFindingSource;
  domain_id?: number;
  identity_id?: number;
  /** First seen in the last N days (1-365). */
  since_days?: number;
  /** First seen at or after this ISO time (the summary window's start). */
  since?: string;
  alert_id?: number;
  search?: string;
  /** One breached account, whole (the Accounts card's rows). */
  account?: string;
  /** One lookalike domain, whole (the Lookalike card's finding badges). */
  lookalike?: string;
  sort?: FindingsSort;
}

export const MAX_SEARCH_LENGTH = 200;
const MAX_ACCOUNT_LENGTH = 254;
const MAX_DOMAIN_LENGTH = 253;

const isEventType = (v: unknown): v is ExposureEventType =>
  typeof v === 'string' && (EXPOSURE_EVENT_TYPES as readonly string[]).includes(v);
const isCategory = (v: unknown): v is RiskCategory =>
  typeof v === 'string' && (RISK_CATEGORY_KEYS as readonly string[]).includes(v);
const isSeverity = (v: unknown): v is ExposureSeverity =>
  typeof v === 'string' && (EXPOSURE_SEVERITIES as readonly string[]).includes(v);
const MAX_ID = 2_147_483_647;

/** A positive int4 id from a query value ("12"), else undefined. */
function idOf(value: unknown): number | undefined {
  if (typeof value !== 'string' || !/^\d{1,10}$/.test(value)) return undefined;
  const n = Number(value);
  return n >= 1 && n <= MAX_ID ? n : undefined;
}

/**
 * The page's deep link (/digital-risk?days=365&severity=high&...), read once
 * on load. Every value is checked against what the API accepts; anything
 * else (an unknown value, a repeated key) is dropped without a word.
 */
export function parseDeepLink(query: Record<string, unknown>): { days?: SummaryDays; filters: FindingsFilters } {
  const one = (name: string): string | undefined => {
    const v = query[name];
    return typeof v === 'string' && v !== '' ? v : undefined;
  };
  const filters: FindingsFilters = {};
  const daysRaw = one('days');
  const days = SUMMARY_DAYS.find((d) => String(d) === daysRaw);

  const severity = one('severity');
  if (isSeverity(severity)) filters.severity = severity;
  const eventType = one('event_type');
  if (isEventType(eventType)) filters.event_type = eventType;
  const category = one('category');
  if (isCategory(category)) filters.category = category;
  const source = one('source');
  if (source === 'leaked-creds' || source === 'domain-monitor') filters.source = source;
  const domainId = idOf(one('domain_id'));
  if (domainId !== undefined) filters.domain_id = domainId;
  const identityId = idOf(one('identity_id'));
  if (identityId !== undefined) filters.identity_id = identityId;
  const alertId = idOf(one('alert_id'));
  if (alertId !== undefined) filters.alert_id = alertId;
  const sinceDays = one('since_days');
  if (sinceDays && /^\d{1,3}$/.test(sinceDays) && Number(sinceDays) >= 1 && Number(sinceDays) <= 365) {
    filters.since_days = Number(sinceDays);
  }
  const search = one('search')?.trim();
  if (search && search.length <= MAX_SEARCH_LENGTH) filters.search = search;
  const account = one('account')?.trim();
  if (account && account.length <= MAX_ACCOUNT_LENGTH) filters.account = account;
  const lookalike = one('lookalike')?.trim();
  if (lookalike && lookalike.length <= MAX_DOMAIN_LENGTH) filters.lookalike = lookalike;
  const open = one('open');
  if (open === '1') filters.open_only = true;
  else if (open === '0') filters.open_only = false;
  const sort = one('sort');
  if (sort === 'newest' || sort === 'severity') filters.sort = sort;

  // A type the Type filter names by its event type alone gets its category, so the filter shows it.
  if (filters.event_type && !filters.category) {
    const types = FINDING_TYPES.filter((t) => t.event_type === filters.event_type);
    if (types.length === 1) filters.category = types[0].category;
  }
  return { days, filters };
}

// ---- Trend ----------------------------------------------------------------------------

/** A trend bucket's start as the chart labels it (UTC): "Oct 13" (day, week) or "Oct 2026" (month). */
export function formatBucketLabel(start: string, bucket: 'day' | 'week' | 'month', long = false): string {
  const ms = Date.parse(start);
  if (Number.isNaN(ms)) return start;
  const d = new Date(ms);
  // date-fns formats in local time, so hand it the UTC date as a local one.
  const local = new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  if (bucket === 'month') return format(local, long ? 'MMMM yyyy' : 'MMM yyyy');
  if (!long) return format(local, 'MMM d');
  return bucket === 'week' ? `Week of ${format(local, 'MMM d, yyyy')}` : format(local, 'MMM d, yyyy');
}
