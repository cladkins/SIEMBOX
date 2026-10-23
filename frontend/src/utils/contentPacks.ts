/**
 * Content Packs page helpers (DOM-free, unit-tested): the shape GET /api/packs
 * returns, and the labels the page shows for packs, items and what's new.
 */

export interface PackSetupStep {
  title: string;
  text: string;
  code?: string;
  code_language?: string;
}

export interface PackItem {
  name: string;
  installed: boolean;
  inCatalog: boolean;
  new: boolean;
}

export type SigmaItemState = 'installed' | 'available' | 'pending' | 'not_convertible';

export interface PackSigmaItem {
  id: string;
  title: string;
  installed: boolean;
  enabled_parts: number;
  state: SigmaItemState;
  reason: string | null;
  compatible: boolean | null;
  missing_field: string | null;
  level: string | null;
  new: boolean;
}

export interface PackWhatsNew {
  from_version: number;
  to_version: number;
  version_bumped: boolean;
  parsers: string[];
  detections: string[];
  sigma: Array<{ id: string; title: string }>;
  count: number;
}

export interface PackStatus {
  id: string;
  name: string;
  description: string;
  icon: string;
  version: number;
  setup: PackSetupStep[];
  parserTotal: number;
  parserInstalled: number;
  detectionTotal: number;
  detectionInstalled: number;
  sigmaTotal: number;
  sigmaInstalled: number;
  status: 'installed' | 'partial' | 'not_installed';
  catalogUnavailable: boolean;
  parsers: PackItem[];
  detections: PackItem[];
  sigma: PackSigmaItem[];
  install: {
    version: number;
    installed_at: string;
    installed_by_username: string | null;
    source: string;
    pending: Array<{ kind: string; name: string; reason: string }>;
  } | null;
  whats_new: PackWhatsNew | null;
}

export interface PackSource {
  source: 'catalog' | 'cache' | 'bundled';
  repo: string;
  ref: string;
  invalid: Array<{ path: string; errors: string[] }>;
  fetched_at: string | null;
  error: string | null;
}

export interface PacksOverview {
  source: PackSource;
  sigma_library: { loaded: boolean; release: string | null; last_error: string | null };
  packs: PackStatus[];
}

export type TagType = 'success' | 'warning' | 'info' | 'danger' | 'primary';

export function statusType(s: PackStatus['status']): TagType {
  return s === 'installed' ? 'success' : s === 'partial' ? 'warning' : 'info';
}

export function statusLabel(s: PackStatus['status']): string {
  return s === 'installed' ? 'Installed' : s === 'partial' ? 'Partially installed' : 'Not installed';
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "5 parsers · 9 detections · 2 Sigma rules", leaving out the kinds a pack has none of. */
export function countsLine(p: Pick<PackStatus, 'parserTotal' | 'detectionTotal' | 'sigmaTotal' | 'catalogUnavailable'>): string {
  const parts = [plural(p.parserTotal, 'parser')];
  if (!p.catalogUnavailable && p.detectionTotal > 0) parts.push(plural(p.detectionTotal, 'detection'));
  if (p.sigmaTotal > 0) parts.push(plural(p.sigmaTotal, 'Sigma rule'));
  return parts.join(' · ');
}

/** "1 parser, 1 detection and 1 Sigma rule" for the What's new badge and dialog. */
export function whatsNewSummary(w: PackWhatsNew | null): string {
  if (!w || w.count === 0) return '';
  const parts = [
    w.parsers.length ? plural(w.parsers.length, 'parser') : '',
    w.detections.length ? plural(w.detections.length, 'detection') : '',
    w.sigma.length ? plural(w.sigma.length, 'Sigma rule') : '',
  ].filter(Boolean);
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : parts[0];
}

export interface ItemBadge {
  label: string;
  type: TagType;
  /** Hover text: why (pending, missing, not compatible). */
  detail?: string;
}

export function parserBadge(p: PackItem): ItemBadge {
  if (p.installed) return { label: 'Installed', type: 'success' };
  if (!p.inCatalog) return { label: 'Missing from catalog', type: 'danger', detail: 'The pack names a parser the catalog does not have.' };
  return { label: 'Not installed', type: 'info' };
}

export function detectionBadge(d: PackItem): ItemBadge {
  if (d.installed) return { label: 'Installed', type: 'success' };
  if (!d.inCatalog) return { label: 'Missing from catalog', type: 'danger', detail: 'The pack names a detection the catalog does not have.' };
  return { label: 'Not installed', type: 'info' };
}

export function sigmaBadge(s: PackSigmaItem): ItemBadge {
  switch (s.state) {
    case 'installed':
      return s.enabled_parts > 0
        ? { label: 'Installed', type: 'success' }
        : { label: 'Added (off)', type: 'info', detail: 'Added from the SigmaHQ library and switched off; a pack install leaves it as it is.' };
    case 'pending':
      return { label: 'Pending', type: 'warning', detail: s.reason ?? 'The SigmaHQ library is not available.' };
    case 'not_convertible':
      return { label: 'Not compatible', type: 'danger', detail: s.reason ?? 'Does not convert to a SIEMBox rule.' };
    default:
      return { label: 'Not installed', type: 'info' };
  }
}

/** A note under a Sigma item about this install's logs (null when nothing to say). */
export function sigmaCompatNote(s: PackSigmaItem): string | null {
  if (s.compatible === false) return s.missing_field ? `no matching logs yet (no parser emits ${s.missing_field})` : 'no matching logs yet';
  return null;
}

/** The banner when the packs shown are not a fresh catalog read (null when they are). */
export function sourceNotice(src: PackSource | null | undefined): { type: 'info' | 'warning'; title: string; text: string } | null {
  if (!src) return null;
  if (src.source === 'bundled') {
    return {
      type: 'info',
      title: 'Showing the packs built into SIEMBox',
      text: `${src.error ?? 'The catalog has no packs yet.'} Installing still pulls each parser and detection from the catalog.`,
    };
  }
  if (src.source === 'cache') return { type: 'warning', title: 'Catalog unreachable', text: src.error ?? '' };
  if (src.invalid.length > 0) return { type: 'warning', title: 'Some catalog packs were left out', text: src.error ?? '' };
  return null;
}

/** The install button's label for a pack. */
export function installLabel(p: Pick<PackStatus, 'status' | 'install'>): string {
  if (p.status === 'not_installed' && !p.install) return 'Install';
  return p.status === 'installed' ? 'Reinstall' : 'Install missing';
}
