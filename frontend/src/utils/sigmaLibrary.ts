/**
 * Display helpers for the SigmaHQ library (Detection Rules > SigmaHQ) and the
 * SigmaHQ chip on the Rules list. Pure, unit-tested (sigmaLibrary.test.ts).
 * The API shapes are GET /api/sigma/library rows and GET /api/rules `sigma`.
 */

export interface SigmaCompat {
  compatible: boolean;
  keyword?: boolean;
  parsers: Array<{ parser_name: string; parts: number[]; matched?: number; sampled: number }>;
  missing_field?: string | null;
  logsource_mismatch?: string | null;
}

export interface SigmaLibraryRow {
  sigma_id: string;
  title: string;
  level: string | null;
  status: string | null;
  logsource: { product: string | null; category: string | null; service: string | null };
  convertible: boolean;
  parts: number;
  compatibility: SigmaCompat | null;
  installed: { rule_ids: number[]; enabled: number; update_available: boolean } | null;
  installable: boolean;
  not_installable_reason: string | null;
  regex_safety?: { status: string };
}

export interface SigmaState {
  release_tag: string | null;
  fetched_at: string | null;
  last_attempt_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  rule_count: number;
}

export interface SigmaProvenance {
  sigma_id: string;
  release: string | null;
  url: string | null;
  author: string | null;
  update_available: boolean;
  deprecated: boolean;
}

/** "proxy" / "linux · sshd" / "windows · process_creation". */
export function logsourceLabel(ls: SigmaLibraryRow['logsource'] | null | undefined): string {
  if (!ls) return '';
  return [ls.product, ls.category, ls.service].filter(Boolean).join(' · ');
}

/** Element Plus tag type for a Sigma level. */
export function levelType(level: string | null | undefined): 'danger' | 'warning' | 'primary' | 'info' {
  switch (level) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'primary';
    default:
      return 'info';
  }
}

/** The compatibility cell: a short label and the sentence behind it. */
export function compatibilityText(row: Pick<SigmaLibraryRow, 'compatibility' | 'convertible'>): {
  label: string;
  type: 'success' | 'info' | 'warning';
  detail: string;
} {
  const c = row.compatibility;
  if (!row.convertible) return { label: 'Not convertible', type: 'warning', detail: 'SIEMBox cannot express this rule faithfully.' };
  if (!c) return { label: 'Unknown', type: 'info', detail: 'Compatibility has not been computed yet.' };
  if (c.compatible) {
    const names = c.parsers.map((p) => p.parser_name);
    const shown = names[0] + (names.length > 1 ? ` +${names.length - 1}` : '');
    const fired = c.parsers.reduce((n, p) => n + (p.matched ?? 0), 0);
    const sampled = c.parsers.reduce((n, p) => n + p.sampled, 0);
    const matchNote =
      fired > 0
        ? ` ${fired} of ${sampled} sampled logs already match: expect alerts (or noise) once enabled.`
        : '';
    return { label: shown, type: 'success', detail: `Your logs from ${names.join(', ')} carry every field this rule needs.${matchNote}` };
  }
  if (c.logsource_mismatch) {
    return {
      label: 'No matching logs yet',
      type: 'info',
      detail: `Your parsers have the fields, but none is a ${c.logsource_mismatch} source.`,
    };
  }
  return {
    label: 'No matching logs yet',
    type: 'info',
    detail: c.missing_field ? `No parser of yours emits "${c.missing_field}".` : 'No recent logs to compare with.',
  };
}

export type SigmaAction = 'add' | 'added' | 'update' | 'blocked';

/** What the row's button does. */
export function sigmaAction(row: Pick<SigmaLibraryRow, 'installed' | 'installable'>): SigmaAction {
  if (row.installed?.update_available) return 'update';
  if (row.installed) return 'added';
  return row.installable ? 'add' : 'blocked';
}

/** The library's source line: release and age, or why it is empty / stale. */
export function libraryStatus(state: SigmaState | null | undefined, now = Date.now()): { type: 'info' | 'warning' | 'error'; text: string } {
  if (!state || (!state.release_tag && !state.last_error)) {
    return { type: 'info', text: 'The SigmaHQ library is empty: Refresh downloads the latest SigmaHQ release.' };
  }
  const failedLast = !!state.last_error && (!state.fetched_at || (state.last_error_at ?? '') >= (state.fetched_at ?? ''));
  if (!state.release_tag) {
    return { type: 'error', text: `SigmaHQ is unreachable (${state.last_error}). Nothing is cached yet.` };
  }
  const age = state.fetched_at ? ageText(now - new Date(state.fetched_at).getTime()) : 'unknown';
  if (failedLast) {
    return {
      type: 'warning',
      text: `SigmaHQ is unreachable (${state.last_error}). Showing the cached release ${state.release_tag}, fetched ${age} ago.`,
    };
  }
  return { type: 'info', text: `SigmaHQ release ${state.release_tag}, ${state.rule_count} rules, fetched ${age} ago.` };
}

function ageText(ms: number): string {
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h`;
  return `${Math.round(h / 24)} days`;
}

/** The Rules list chip for a rule added from SigmaHQ. */
export function provenanceBadge(p: SigmaProvenance | null | undefined): { label: string; type: 'warning' | 'danger' } | null {
  if (!p) return null;
  if (p.deprecated) return { label: 'Deprecated in SigmaHQ', type: 'danger' };
  if (p.update_available) return { label: 'Update available', type: 'warning' };
  return null;
}
