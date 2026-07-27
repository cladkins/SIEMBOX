// Module 3: matcher. Sums signal weights across every fingerprint for a
// discovered host, converts the total to a confidence percentage, and flags
// the match as a guess when it's below the fingerprint's own confidence_floor.
// Pure functions only -- no I/O -- so this stays unit-testable without a
// live network or database.
import { DiscoveredSignals, FingerprintEntry, FingerprintMatch } from './types';

function macOuiOf(mac: string): string {
  return mac.toUpperCase().split(':').slice(0, 3).join(':');
}

/** Sum every signal a fingerprint declares against what was observed on a host. */
export function scoreSource(source: DiscoveredSignals, fp: FingerprintEntry): { weight: number; matched: string[] } {
  let weight = 0;
  const matched: string[] = [];
  const signals = fp.signals;

  for (const s of signals.ports) {
    if (source.open_ports.includes(s.port)) {
      weight += s.weight;
      matched.push(`port ${s.port}`);
    }
  }

  for (const s of signals.http) {
    const hit = source.http_responses.find((r) => r.path === s.path);
    if (hit && (!s.expect || hit.body.toLowerCase().includes(s.expect.toLowerCase()))) {
      weight += s.weight;
      matched.push(`http ${s.path}`);
    }
  }

  for (const s of signals.mdns) {
    if (source.mdns_services.includes(s.service)) {
      weight += s.weight;
      matched.push(`mdns ${s.service}`);
    }
  }

  for (const s of signals.ssdp) {
    const hit = source.ssdp_services.find(
      (svc) =>
        (s.st && svc.st === s.st) ||
        (s.server_contains && svc.server?.toLowerCase().includes(s.server_contains.toLowerCase()))
    );
    if (hit) {
      weight += s.weight;
      matched.push(`ssdp ${s.st || s.server_contains}`);
    }
  }

  for (const s of signals.tls) {
    const hit = source.tls_subjects.find(
      (t) => s.subject_cn && t.subject_cn?.toLowerCase().includes(s.subject_cn.toLowerCase())
    );
    if (hit) {
      weight += s.weight;
      matched.push(`tls cn~"${s.subject_cn}"`);
    }
  }

  if (source.mac) {
    const oui = macOuiOf(source.mac);
    for (const s of signals.mac_oui) {
      if (s.oui && oui === s.oui.toUpperCase()) {
        weight += s.weight;
        matched.push(`mac_oui ${s.oui}`);
      }
    }
  }

  return { weight, matched };
}

/** Weight -> confidence percentage. Capped at 100; a fingerprint with no matched signals scores 0. */
export function confidenceFromWeight(weight: number): number {
  return Math.max(0, Math.min(100, Math.round(weight)));
}

/**
 * Match a discovered host against the whole fingerprint library. Returns every
 * fingerprint that matched at least one signal, sorted by confidence
 * descending, so callers can inspect runner-up guesses as well as the best match.
 */
export function matchHost(source: DiscoveredSignals, library: FingerprintEntry[]): FingerprintMatch[] {
  const matches: FingerprintMatch[] = [];

  for (const fp of library) {
    const { weight, matched } = scoreSource(source, fp);
    if (weight <= 0) continue;
    const confidence = confidenceFromWeight(weight);
    matches.push({
      fingerprint: fp,
      weight,
      confidence,
      is_guess: confidence < fp.confidence_floor,
      matched_signals: matched,
    });
  }

  return matches.sort((a, b) => b.confidence - a.confidence);
}

/** The single best-matching fingerprint for a host, or null if nothing matched at all. */
export function pickBestMatch(source: DiscoveredSignals, library: FingerprintEntry[]): FingerprintMatch | null {
  const matches = matchHost(source, library);
  return matches[0] || null;
}
