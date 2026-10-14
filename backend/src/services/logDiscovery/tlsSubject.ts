// The one place that understands the shape of a TLS probe result's subject CN.
//
// Node's getPeerCertificate() reports a subject field as a plain string, but as
// an ARRAY when the certificate repeats it -- `openssl req -subj
// "/CN=proxmox.local/CN=pve"` gives `subject.CN === ['proxmox.local', 'pve']`
// (@types/node still types it as string). The matcher used to call
// .toLowerCase() on it and threw, which failed the whole discovery scan.
//
// Shape rule, kept for backward compatibility with stored evidence
// (discovery_sources.evidence.tls_subjects) and with shipper discovery agents
// built before this change: a certificate with one CN is stored as a string,
// exactly as before; only a certificate with several CNs is stored as an array.
// Readers go through commonNames() and never care which form they got.
//
// Pure and dependency-free: activeDiscovery.ts (bundled into the shipper's
// discovery agent) and the backend's ingest/matcher paths all import it.
import { TlsProbeResult } from './types';

/** Every CN in a subject_cn value: a string, an array of strings (repeated CN), or anything else (none). */
export function commonNames(value: unknown): string[] {
  const values = Array.isArray(value) ? value : [value];
  return values.filter((v): v is string => typeof v === 'string' && v.length > 0);
}

/** The stored form of a subject CN: undefined for none, a string for one, an array only for several. */
function storedCommonName(value: unknown): string | string[] | undefined {
  const names = commonNames(value);
  if (names.length === 0) return undefined;
  return names.length === 1 ? names[0] : names;
}

/**
 * Coerce a raw TLS result -- built from a peer certificate by the probe, or
 * posted by a shipper -- into a TlsProbeResult. Returns null when it has no
 * usable port. SAN entries that aren't strings are dropped.
 */
export function normalizeTlsSubject(raw: unknown): TlsProbeResult | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (!Number.isInteger(r.port)) return null;

  const result: TlsProbeResult = { port: r.port as number };
  const subjectCn = storedCommonName(r.subject_cn);
  if (subjectCn !== undefined) result.subject_cn = subjectCn;
  if (Array.isArray(r.san)) result.san = r.san.filter((s): s is string => typeof s === 'string');
  return result;
}
