/**
 * MISP for Threat Hunting: read a MISP feed's manifest and turn a MISP event
 * into a hunt.
 *
 * A MISP feed (the format MISP's "feed" export and CIRCL's OSINT feed use) is
 * a directory with a manifest.json, which maps each event's UUID to a short
 * summary ({ info, date, timestamp, Orgc, ... }), and one <uuid>.json file
 * per event: { "Event": { info, Attribute: [...], Object: [{ Attribute }],
 * Tag, Galaxy, ... } }.
 *
 * From an event, SIEMBox keeps the attributes MISP marks for detection
 * (to_ids), from the event and from its objects, mapped to SIEMBox indicator
 * types and validated like any other (iocExtract.normalizeIoc: no private
 * addresses, real TLDs). ATT&CK techniques come from the event's galaxies and
 * tags. The result has the same shape as a STIX import (stix.ts ImportedHunt),
 * so the rest of the hunt pipeline is shared.
 *
 * Pure: no database, no network.
 */
import { randomUUID } from 'crypto';
import { isIP } from 'net';
import { IocType, normalizeIoc } from './iocExtract';
import { ImportedHunt, ImportedIndicator, stableUuid } from './stix';

/** Most indicators one MISP event adds to a hunt (a hunt searches at most 600 terms). */
export const MAX_MISP_INDICATORS = 500;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json => !!v && typeof v === 'object' && !Array.isArray(v);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown, max = 2000): string | null =>
  typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null;

// ---- Recognising MISP documents -------------------------------------------------------

/** The Event object of a MISP event document ({ Event }, { response: [{ Event }] } or a bare event), or null. */
export function mispEventOf(doc: unknown): Json | null {
  if (!isObject(doc)) return null;
  if (isObject(doc.Event)) return doc.Event;
  const first = list(doc.response)[0];
  if (isObject(first) && isObject(first.Event)) return first.Event;
  // A bare event: has the fields every MISP event carries.
  if (typeof doc.info === 'string' && (Array.isArray(doc.Attribute) || Array.isArray(doc.Object)) && typeof doc.uuid === 'string') {
    return doc;
  }
  return null;
}

export function isMispEvent(doc: unknown): boolean {
  return mispEventOf(doc) !== null;
}

export interface ManifestEntry {
  uuid: string;
  info: string | null;
  date: string | null;
  /** Unix seconds of the event's last change (0 when missing). */
  timestamp: number;
  org: string | null;
}

/** A MISP feed manifest: an object keyed by event UUID whose values carry `info`. */
export function isMispManifest(doc: unknown): boolean {
  if (!isObject(doc)) return false;
  const keys = Object.keys(doc);
  if (!keys.length) return false;
  const sample = keys.slice(0, 20);
  return sample.every((k) => UUID_RE.test(k) && isObject(doc[k])) && sample.some((k) => 'info' in (doc[k] as Json));
}

/** The manifest's events, most recently changed first. */
export function parseMispManifest(doc: unknown): ManifestEntry[] {
  if (!isObject(doc)) return [];
  const out: ManifestEntry[] = [];
  for (const [uuid, raw] of Object.entries(doc)) {
    if (!UUID_RE.test(uuid) || !isObject(raw)) continue;
    const orgc = isObject(raw.Orgc) ? raw.Orgc : null;
    out.push({
      uuid: uuid.toLowerCase(),
      info: str(raw.info, 500),
      date: str(raw.date, 20),
      timestamp: Number(raw.timestamp) || 0,
      org: str(orgc?.name, 200),
    });
  }
  out.sort((a, b) => b.timestamp - a.timestamp || (b.date ?? '').localeCompare(a.date ?? ''));
  return out;
}

/**
 * The feed's base directory and manifest URL for a source URL: the feed
 * directory itself, its manifest.json, or any event file in it.
 */
export function mispFeedUrls(sourceUrl: string): { base: string; manifest: string } {
  const u = new URL(sourceUrl);
  u.search = '';
  u.hash = '';
  let path = u.pathname;
  if (/\/manifest\.json$/i.test(path) || /\/[0-9a-f-]{36}\.json$/i.test(path)) path = path.replace(/[^/]*$/, '');
  if (!path.endsWith('/')) path += '/';
  u.pathname = path;
  const base = u.toString();
  return { base, manifest: `${base}manifest.json` };
}

/** A directory listing that links to manifest.json: a MISP feed seen through its index page. */
export function looksLikeMispFeedIndex(html: string): boolean {
  return /href=["']?(?:\.\/)?manifest\.json["'\s>]/i.test(html);
}

// ---- Events to hunts ---------------------------------------------------------------------

/**
 * One MISP attribute's indicators, as [type, raw value] pairs. Composite types
 * ("domain|ip", "ip-dst|port", "filename|sha256") are split; types SIEMBox
 * doesn't hunt for (filenames alone, regkeys, mutexes, links...) give none.
 */
export function attributeValues(type: string, value: string): Array<[IocType, string]> {
  const t = type.toLowerCase();
  const parts = value.split('|');
  const ip = (v: string): Array<[IocType, string]> => {
    const fam = isIP(v.trim());
    return fam === 4 ? [['ipv4', v]] : fam === 6 ? [['ipv6', v]] : [];
  };
  switch (t) {
    case 'ip-src':
    case 'ip-dst':
      return ip(value);
    case 'ip-src|port':
    case 'ip-dst|port':
      return ip(parts[0]);
    case 'domain':
    case 'hostname':
      return [['domain', value]];
    case 'domain|ip':
      return [['domain', parts[0]], ...ip(parts[1] ?? '')];
    case 'hostname|port':
      return [['domain', parts[0]]];
    case 'url':
      return [['url', value]];
    case 'email':
    case 'email-src':
    case 'email-dst':
    case 'email-reply-to':
      return [['email', value]];
    case 'md5':
    case 'sha1':
    case 'sha256':
      return [[t as IocType, value]];
    case 'filename|md5':
    case 'filename|sha1':
    case 'filename|sha256':
      return [[t.split('|')[1] as IocType, parts[1] ?? '']];
    case 'vulnerability':
      return [['cve', value]];
    default:
      return [];
  }
}

const isToIds = (a: Json) => a.to_ids === true || a.to_ids === 1 || a.to_ids === '1';
const isDeleted = (a: Json) => a.deleted === true || a.deleted === 1 || a.deleted === '1';

/** Every ATT&CK technique ID in the event's galaxies and tags (event, objects and attributes). */
function eventTechniques(event: Json): string[] {
  const found = new Set<string>();
  const fromText = (s: unknown) => {
    if (typeof s === 'string') for (const m of s.matchAll(TECHNIQUE_RE)) found.add(m[0]);
  };
  const fromTags = (tags: unknown) => {
    for (const tag of list(tags)) if (isObject(tag) && /mitre-attack-pattern|mitre-attack|attack-pattern/i.test(String(tag.name))) fromText(tag.name);
  };
  const fromGalaxies = (galaxies: unknown) => {
    for (const g of list(galaxies)) {
      if (!isObject(g) || !/mitre-attack-pattern|attack-pattern/i.test(String(g.type ?? g.name))) continue;
      for (const c of list(g.GalaxyCluster)) {
        if (!isObject(c)) continue;
        const meta = isObject(c.meta) ? c.meta : {};
        for (const id of list(meta.external_id)) fromText(id);
        fromText(c.value);
      }
    }
  };
  fromTags(event.Tag);
  fromGalaxies(event.Galaxy);
  const walk = (attrs: unknown) => {
    for (const a of list(attrs)) {
      if (!isObject(a)) continue;
      fromTags(a.Tag);
      fromGalaxies(a.Galaxy);
    }
  };
  walk(event.Attribute);
  for (const o of list(event.Object)) if (isObject(o)) walk(o.Attribute);
  return [...found].sort();
}

/**
 * A MISP event as a hunt. Only to_ids attributes become indicators; when the
 * event marks none, every huntable attribute is used (and the stats say so).
 */
export function parseMispEvent(doc: unknown): ImportedHunt & { stats: ImportedHunt['stats'] & { all_attributes: boolean; truncated: number } } {
  const event = mispEventOf(doc);
  if (!event) throw new Error('Not a MISP event: expected a JSON object with an "Event".');

  // Every attribute, with where it came from.
  const attrs: Array<{ a: Json; object: string | null }> = [];
  for (const a of list(event.Attribute)) if (isObject(a) && !isDeleted(a)) attrs.push({ a, object: null });
  for (const o of list(event.Object)) {
    if (!isObject(o) || isDeleted(o)) continue;
    for (const a of list(o.Attribute)) if (isObject(a) && !isDeleted(a)) attrs.push({ a, object: str(o.name, 100) });
  }

  const flagged = attrs.filter(({ a }) => isToIds(a));
  const useAll = flagged.length === 0;
  const chosen = useAll ? attrs : flagged;

  const indicators: ImportedIndicator[] = [];
  const seen = new Set<string>();
  const usedIds = new Set<string>();
  let truncated = 0;
  for (const { a, object } of chosen) {
    const type = String(a.type ?? '');
    const value = String(a.value ?? '');
    for (const [iocType, raw] of attributeValues(type, value)) {
      const v = normalizeIoc(iocType, raw);
      if (!v) continue;
      const key = `${iocType}:${v}`;
      if (seen.has(key)) continue;
      if (indicators.length >= MAX_MISP_INDICATORS) {
        truncated++;
        continue;
      }
      seen.add(key);
      const kind = iocType === 'cve' ? 'vulnerability' : 'indicator';
      const attrUuid = String(a.uuid ?? '');
      let id = UUID_RE.test(attrUuid) ? `${kind}--${attrUuid.toLowerCase()}` : '';
      if (!id || usedIds.has(id)) id = `${kind}--${stableUuid(`misp|${attrUuid}|${key}`)}`;
      usedIds.add(id);
      const context = [object ? `${object} object` : null, str(a.category, 100), str(a.comment, 300)]
        .filter(Boolean)
        .join(' · ');
      indicators.push({ stix_id: id, type: iocType, value: v, context: context || null });
    }
  }

  const techniques = eventTechniques(event);
  const title = str(event.info, 500) || 'MISP event';
  const orgc = isObject(event.Orgc) ? str(event.Orgc.name, 200) : null;
  const tags = list(event.Tag)
    .map((t) => (isObject(t) ? str(t.name, 120) : null))
    .filter((t): t is string => !!t && !/mitre-attack/i.test(t))
    .slice(0, 12);
  const links = attrs
    .filter(({ a }) => String(a.type) === 'link')
    .map(({ a }) => str(a.value, 2048))
    .filter((v): v is string => !!v && /^https?:\/\//i.test(v));
  const summaryParts = [
    `MISP event${orgc ? ` from ${orgc}` : ''}${str(event.date, 20) ? `, ${str(event.date, 20)}` : ''}.`,
    tags.length ? `Tags: ${tags.join(', ')}.` : null,
    links.length ? `Report: ${links[0]}` : null,
  ];

  return {
    title,
    summary: summaryParts.filter(Boolean).join(' '),
    source_url: links[0] ?? null,
    indicators,
    hypotheses: techniques.length
      ? [
          {
            stix_id: `note--${stableUuid(`misp-hypothesis|${String(event.uuid)}|${randomUUID()}`)}`,
            title: `Techniques from this MISP event are in use here (${techniques.slice(0, 5).join(', ')}${techniques.length > 5 ? ', …' : ''})`,
            description:
              'The MISP event tags these ATT&CK techniques. Add log search terms (process names, file paths, command fragments) to test for them.',
            attack_techniques: techniques,
            search_terms: [],
          },
        ]
      : [],
    stats: { objects: attrs.length, skipped_patterns: 0, all_attributes: useAll && attrs.length > 0, truncated },
  };
}
