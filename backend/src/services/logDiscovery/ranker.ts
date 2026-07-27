// Module 4: ranker. Sorts confirmed/candidate sources by security_value, dedupes
// repeat detections of the same host, groups the long tail under "advanced", and
// attaches a plain-language reason drawn from the matched fingerprint.
import { FingerprintEntry, RankedResult, RankedSource, RuntimeSource } from './types';

/** Sources at or above this security_value surface at the top; below it, under "advanced". */
export const ADVANCED_SECURITY_VALUE_THRESHOLD = 7;

export interface RankableItem {
  source: RuntimeSource;
  fingerprint: FingerprintEntry | null;
}

/** A short, human-readable reason a source is worth onboarding, drawn from its fingerprint. */
export function buildReason(fingerprint: FingerprintEntry): string {
  const dataSources = fingerprint.attack_data_sources.slice(0, 3).join(', ');
  return dataSources
    ? `${fingerprint.name} can provide ${dataSources}.`
    : `${fingerprint.name} is a ${fingerprint.category} source worth collecting.`;
}

function toRanked(item: RankableItem): RankedSource {
  const { source, fingerprint } = item;
  return {
    ...source,
    security_value: source.security_value ?? fingerprint?.security_value ?? 0,
    reason: fingerprint
      ? buildReason(fingerprint)
      : 'Unidentified host on the network. Confirm what it is before onboarding.',
  };
}

/**
 * Rank a batch of discovered sources. Ignored sources are dropped entirely --
 * once a user dismisses a host it should not resurface in either list.
 */
export function rankSources(items: RankableItem[]): RankedResult {
  const seenIps = new Set<string>();
  const deduped = items.filter(({ source }) => {
    if (source.status === 'ignored') return false;
    if (seenIps.has(source.ip)) return false;
    seenIps.add(source.ip);
    return true;
  });

  const ranked = deduped
    .map(toRanked)
    .sort((a, b) => (b.security_value ?? 0) - (a.security_value ?? 0) || b.confidence - a.confidence);

  return {
    top: ranked.filter((r) => (r.security_value ?? 0) >= ADVANCED_SECURITY_VALUE_THRESHOLD),
    advanced: ranked.filter((r) => (r.security_value ?? 0) < ADVANCED_SECURITY_VALUE_THRESHOLD),
  };
}
