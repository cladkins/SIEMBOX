/**
 * STIX 2.1 for Threat Hunting: build a hunt's bundle, and read one back.
 *
 * STIX 2.1 has no "hunt" object, so a hunt is expressed with standard ones:
 *   report         the hunt itself (the source article: name, summary, URL),
 *                  with the hunt's state in the custom x_siembox_hunt property
 *   indicator      one per IOC, with a STIX pattern ([ipv4-addr:value = '...'])
 *   vulnerability  one per CVE the report names
 *   attack-pattern one per ATT&CK technique the hypotheses name
 *   note           one per hypothesis (abstract = the hypothesis, content =
 *                  its reasoning), with its log search terms in the custom
 *                  x_siembox_search_terms property
 *   sighting       one per indicator, vulnerability or hypothesis the last run
 *                  found in the logs: count, first_seen and last_seen, sighted
 *                  by the SIEMBox identity
 * Every object is created_by_ref the SIEMBox identity. IDs are stable: a
 * hunt's report keeps its UUID, and the other objects take UUIDv5 IDs derived
 * from it, so a re-export (or a TAXII poll) returns the same IDs with a newer
 * `modified`.
 *
 * Pure: no database, no network.
 */
import { createHash, randomUUID } from 'crypto';
import { IocType, normalizeIoc } from './iocExtract';

export const STIX_MEDIA_TYPE = 'application/stix+json;version=2.1';

/**
 * A UUID in version-4 form derived from `name` (SHA-256, then the v4 version
 * and variant bits). STIX 2.1 asks for UUIDv4 identifiers on everything but
 * cyber observables; deriving them keeps an object's id the same on every
 * export and TAXII poll without storing it.
 */
export function stableUuid(name: string): string {
  const hash = createHash('sha256').update(`siembox-stix|${name}`, 'utf8').digest();
  hash[6] = (hash[6] & 0x0f) | 0x40;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export const SIEMBOX_IDENTITY_ID = `identity--${stableUuid('siembox')}`;
const IDENTITY_CREATED = '2026-01-01T00:00:00.000Z';

export function siemboxIdentity(): StixObject {
  return {
    type: 'identity',
    spec_version: '2.1',
    id: SIEMBOX_IDENTITY_ID,
    created: IDENTITY_CREATED,
    modified: IDENTITY_CREATED,
    name: 'SIEMBox',
    identity_class: 'system',
    description: 'SIEMBox threat hunting: indicators and hypotheses hunted in this SIEM\'s logs.',
  };
}

export type StixObject = Record<string, unknown> & { type: string; id: string };

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

// ---- Patterns ----------------------------------------------------------------

function quote(value: string): string {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/** The STIX pattern for one indicator; null for a CVE (a vulnerability object, not an indicator). */
export function stixPattern(type: IocType, value: string): string | null {
  switch (type) {
    case 'ipv4':
      return `[ipv4-addr:value = ${quote(value)}]`;
    case 'ipv6':
      return `[ipv6-addr:value = ${quote(value)}]`;
    case 'domain':
      return `[domain-name:value = ${quote(value)}]`;
    case 'url':
      return `[url:value = ${quote(value)}]`;
    case 'email':
      return `[email-addr:value = ${quote(value)}]`;
    case 'md5':
      return `[file:hashes.MD5 = ${quote(value)}]`;
    case 'sha1':
      return `[file:hashes.'SHA-1' = ${quote(value)}]`;
    case 'sha256':
      return `[file:hashes.'SHA-256' = ${quote(value)}]`;
    default:
      return null;
  }
}

/** The STIX id SIEMBox gives a hunt's indicator (or vulnerability, for a CVE). */
export function indicatorStixId(huntUuid: string, type: IocType, value: string): string {
  const kind = type === 'cve' ? 'vulnerability' : 'indicator';
  return `${kind}--${stableUuid(`${huntUuid}|${type}|${value}`)}`;
}

export function hypothesisStixId(huntUuid: string, title: string): string {
  return `note--${stableUuid(`${huntUuid}|hypothesis|${title}|${randomUUID()}`)}`;
}

function attackPatternId(technique: string): string {
  return `attack-pattern--${stableUuid(`mitre-attack|${technique}`)}`;
}

// ---- Building a bundle -----------------------------------------------------------

export interface StixHuntIndicator {
  stix_id: string;
  ioc_type: IocType;
  value: string;
  context: string | null;
  enabled: boolean;
  match_count: number;
  first_seen: Date | string | null;
  last_seen: Date | string | null;
  created_at: Date | string;
}

export interface StixHuntHypothesis {
  stix_id: string;
  title: string;
  description: string | null;
  attack_techniques: string[];
  search_terms: string[];
  enabled: boolean;
  match_count: number;
  first_seen: Date | string | null;
  last_seen: Date | string | null;
  created_at: Date | string;
}

export interface StixHunt {
  id: number;
  stix_uuid: string;
  title: string;
  summary: string | null;
  origin: string;
  source_url: string | null;
  status: string;
  lookback_days: number;
  match_count: number;
  last_run_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  indicators: StixHuntIndicator[];
  hypotheses: StixHuntHypothesis[];
}

function ts(value: Date | string | null | undefined, fallback: string): string {
  if (!value) return fallback;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

/** Name a technique for its attack-pattern object (the caller passes the ATT&CK lookup). */
export type TechniqueNamer = (id: string) => string;

/**
 * The objects of one hunt, in a stable order: report, indicators and
 * vulnerabilities, attack-patterns, notes, sightings. The identity is not
 * included (bundle and TAXII add it once).
 */
export function huntStixObjects(hunt: StixHunt, nameTechnique: TechniqueNamer = (id) => id): StixObject[] {
  const created = ts(hunt.created_at, IDENTITY_CREATED);
  const modified = ts(hunt.updated_at, created);
  const reportId = `report--${hunt.stix_uuid}`;
  const by = { created_by_ref: SIEMBOX_IDENTITY_ID };
  const sightingTime = ts(hunt.last_run_at, modified);

  const content: StixObject[] = [];
  const sightings: StixObject[] = [];

  const addSighting = (targetId: string, count: number, first: Date | string | null, last: Date | string | null) => {
    if (!hunt.last_run_at || count <= 0) return;
    sightings.push({
      type: 'sighting',
      spec_version: '2.1',
      id: `sighting--${stableUuid(`${hunt.stix_uuid}|sighting|${targetId}`)}`,
      created: sightingTime,
      modified: sightingTime,
      ...by,
      sighting_of_ref: targetId,
      count: Math.min(count, 999_999_999),
      first_seen: ts(first, sightingTime),
      last_seen: ts(last, sightingTime),
      where_sighted_refs: [SIEMBOX_IDENTITY_ID],
      description: `Found in SIEMBox logs by hunt #${hunt.id} (last ${hunt.lookback_days} days).`,
    });
  };

  for (const ind of hunt.indicators) {
    if (!ind.enabled) continue;
    const indCreated = ts(ind.created_at, created);
    if (ind.ioc_type === 'cve') {
      content.push({
        type: 'vulnerability',
        spec_version: '2.1',
        id: ind.stix_id,
        created: indCreated,
        modified: modified < indCreated ? indCreated : modified,
        ...by,
        name: ind.value,
        ...(ind.context ? { description: ind.context } : {}),
        external_references: [{ source_name: 'cve', external_id: ind.value }],
      });
    } else {
      const pattern = stixPattern(ind.ioc_type, ind.value);
      if (!pattern) continue;
      content.push({
        type: 'indicator',
        spec_version: '2.1',
        id: ind.stix_id,
        created: indCreated,
        modified: modified < indCreated ? indCreated : modified,
        ...by,
        name: ind.value,
        ...(ind.context ? { description: ind.context } : {}),
        indicator_types: ['malicious-activity'],
        pattern,
        pattern_type: 'stix',
        pattern_version: '2.1',
        valid_from: indCreated,
        labels: [ind.ioc_type],
      });
    }
    addSighting(ind.stix_id, ind.match_count, ind.first_seen, ind.last_seen);
  }

  const techniques = [
    ...new Set(hunt.hypotheses.filter((h) => h.enabled).flatMap((h) => h.attack_techniques || [])),
  ].sort();
  for (const t of techniques) {
    content.push({
      type: 'attack-pattern',
      spec_version: '2.1',
      id: attackPatternId(t),
      created: IDENTITY_CREATED,
      modified: IDENTITY_CREATED,
      ...by,
      name: nameTechnique(t),
      external_references: [
        {
          source_name: 'mitre-attack',
          external_id: t,
          url: `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`,
        },
      ],
    });
  }

  for (const h of hunt.hypotheses) {
    if (!h.enabled) continue;
    const hCreated = ts(h.created_at, created);
    const terms = (h.search_terms || []).filter(Boolean);
    content.push({
      type: 'note',
      spec_version: '2.1',
      id: h.stix_id,
      created: hCreated,
      modified: modified < hCreated ? hCreated : modified,
      ...by,
      abstract: h.title,
      content:
        (h.description || h.title) + (terms.length ? `\n\nLog search terms: ${terms.join(', ')}` : ''),
      authors: ['SIEMBox'],
      object_refs: [reportId, ...(h.attack_techniques || []).map(attackPatternId)],
      x_siembox_hypothesis: true,
      x_siembox_search_terms: terms,
      x_siembox_attack_techniques: h.attack_techniques || [],
    });
    addSighting(h.stix_id, h.match_count, h.first_seen, h.last_seen);
  }

  const refs = [...content, ...sightings].map((o) => o.id);
  const report: StixObject = {
    type: 'report',
    spec_version: '2.1',
    id: reportId,
    created,
    modified,
    ...by,
    name: hunt.title,
    ...(hunt.summary ? { description: hunt.summary } : {}),
    report_types: ['threat-report'],
    published: created,
    object_refs: refs.length ? refs : [SIEMBOX_IDENTITY_ID],
    labels: ['threat-hunt'],
    ...(hunt.source_url
      ? { external_references: [{ source_name: 'source', url: hunt.source_url }] }
      : {}),
    x_siembox_hunt: {
      id: hunt.id,
      status: hunt.status,
      origin: hunt.origin,
      lookback_days: hunt.lookback_days,
      match_count: hunt.match_count,
      last_run_at: hunt.last_run_at ? ts(hunt.last_run_at, modified) : null,
    },
  };

  return [report, ...content, ...sightings];
}

export function huntBundle(hunt: StixHunt, nameTechnique?: TechniqueNamer): StixBundle {
  return {
    type: 'bundle',
    id: `bundle--${randomUUID()}`,
    objects: [siemboxIdentity(), ...huntStixObjects(hunt, nameTechnique)],
  };
}

// ---- Reading a bundle -------------------------------------------------------------

export interface ImportedIndicator {
  stix_id: string;
  type: IocType;
  value: string;
  context: string | null;
}

export interface ImportedHypothesis {
  stix_id: string;
  title: string;
  description: string | null;
  attack_techniques: string[];
  search_terms: string[];
}

export interface ImportedHunt {
  title: string;
  summary: string | null;
  source_url: string | null;
  indicators: ImportedIndicator[];
  hypotheses: ImportedHypothesis[];
  /** Objects read, and indicator patterns SIEMBox could not turn into a value. */
  stats: { objects: number; skipped_patterns: number };
}

export class StixImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StixImportError';
  }
}

export const MAX_IMPORT_OBJECTS = 10_000;

const SCO_TYPES: Record<string, IocType> = {
  'ipv4-addr': 'ipv4',
  'ipv6-addr': 'ipv6',
  'domain-name': 'domain',
  url: 'url',
  'email-addr': 'email',
};

const HASH_TYPES: Record<string, IocType> = {
  md5: 'md5',
  'sha-1': 'sha1',
  sha1: 'sha1',
  'sha-256': 'sha256',
  sha256: 'sha256',
};

function unescapeStix(s: string): string {
  return s.replace(/\\(.)/g, '$1');
}

/** Every simple equality comparison in a STIX pattern, as [type, value]. */
export function patternComparisons(pattern: string): Array<[IocType, string]> {
  const out: Array<[IocType, string]> = [];
  const valueRe = /(ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*'((?:\\.|[^'\\]){1,2048})'/g;
  for (const m of pattern.matchAll(valueRe)) out.push([SCO_TYPES[m[1]], unescapeStix(m[2])]);
  const hashRe = /file:hashes\.(?:'([A-Za-z0-9-]{2,10})'|([A-Za-z0-9-]{2,10}))\s*=\s*'((?:\\.|[^'\\]){1,256})'/g;
  for (const m of pattern.matchAll(hashRe)) {
    const kind = HASH_TYPES[(m[1] || m[2]).toLowerCase()];
    if (kind) out.push([kind, unescapeStix(m[3])]);
  }
  return out;
}

function str(v: unknown, max = 10_000): string | null {
  return typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null;
}

function mitreIds(obj: Record<string, unknown>): string[] {
  const refs = Array.isArray(obj.external_references) ? obj.external_references : [];
  return refs
    .filter((r: any) => r && typeof r === 'object' && /^mitre-/.test(String(r.source_name || '')))
    .map((r: any) => String(r.external_id || ''))
    .filter((id) => /^T\d{4}(?:\.\d{3})?$/.test(id));
}

/**
 * Read a STIX 2.x bundle (or a TAXII envelope, a bare array of objects, or a
 * single object) into a hunt. Indicators come from indicator patterns (simple
 * equality comparisons; anything else is counted as skipped), from cyber
 * observables, and from vulnerability objects (CVEs). Hypotheses come from
 * notes (SIEMBox's own x_siembox_search_terms is read back) and, failing that,
 * from the ATT&CK techniques the attack-patterns name.
 */
export function parseStixInput(input: unknown): ImportedHunt {
  let objects: unknown[];
  if (Array.isArray(input)) objects = input;
  else if (input && typeof input === 'object' && Array.isArray((input as any).objects)) objects = (input as any).objects;
  else if (input && typeof input === 'object' && typeof (input as any).type === 'string') objects = [input];
  else throw new StixImportError('Expected a STIX bundle: a JSON object with an "objects" array.');
  if (objects.length > MAX_IMPORT_OBJECTS) {
    throw new StixImportError(`The bundle has ${objects.length} objects; the limit is ${MAX_IMPORT_OBJECTS}.`);
  }

  const result: ImportedHunt = {
    title: '',
    summary: null,
    source_url: null,
    indicators: [],
    hypotheses: [],
    stats: { objects: objects.length, skipped_patterns: 0 },
  };
  const seen = new Set<string>();
  const usedIds = new Set<string>();
  const addIndicator = (baseId: string, type: IocType, raw: string, context: string | null) => {
    const value = normalizeIoc(type, raw);
    if (!value) return false;
    const key = `${type}:${value}`;
    if (seen.has(key)) return true;
    seen.add(key);
    const kind = type === 'cve' ? 'vulnerability' : 'indicator';
    let id = /^[a-z][a-z0-9-]*--[0-9a-f-]{36}$/.test(baseId) && baseId.startsWith(`${kind}--`) ? baseId : '';
    if (!id || usedIds.has(id)) id = `${kind}--${stableUuid(`${baseId}|${key}`)}`;
    usedIds.add(id);
    result.indicators.push({ stix_id: id, type, value, context });
    return true;
  };

  const techniques = new Set<string>();
  let reportTitle: string | null = null;
  let otherTitle: string | null = null;

  for (const raw of objects) {
    if (!raw || typeof raw !== 'object') continue;
    const obj = raw as Record<string, unknown>;
    const type = String(obj.type || '');
    const id = String(obj.id || '');
    switch (type) {
      case 'report': {
        if (!reportTitle) {
          reportTitle = str(obj.name, 500);
          result.summary = str(obj.description);
          const refs = Array.isArray(obj.external_references) ? obj.external_references : [];
          const withUrl = refs.find((r: any) => r && typeof r.url === 'string' && /^https?:\/\//i.test(r.url));
          if (withUrl) result.source_url = String((withUrl as any).url).slice(0, 2048);
        }
        break;
      }
      case 'grouping':
      case 'campaign':
      case 'intrusion-set':
      case 'malware':
      case 'threat-actor':
        if (!otherTitle) otherTitle = str(obj.name, 500);
        break;
      case 'indicator': {
        const pattern = typeof obj.pattern === 'string' ? obj.pattern : '';
        const ptype = String(obj.pattern_type || 'stix');
        const comparisons = ptype === 'stix' ? patternComparisons(pattern) : [];
        let any = false;
        for (const [t, v] of comparisons) any = addIndicator(id, t, v, str(obj.description, 500) ?? str(obj.name, 500)) || any;
        if (!any) result.stats.skipped_patterns++;
        break;
      }
      case 'vulnerability': {
        const name = str(obj.name, 50);
        const ext = Array.isArray(obj.external_references)
          ? (obj.external_references as any[]).find((r) => r && r.source_name === 'cve')
          : null;
        const cve = (ext && String(ext.external_id || '')) || name || '';
        addIndicator(id, 'cve', cve, str(obj.description, 500));
        break;
      }
      case 'attack-pattern':
        for (const t of mitreIds(obj)) techniques.add(t);
        break;
      case 'note': {
        const abstract = str(obj.abstract, 500);
        const content = str(obj.content);
        if (!abstract && !content) break;
        const terms = Array.isArray(obj.x_siembox_search_terms)
          ? (obj.x_siembox_search_terms as unknown[]).map((t) => String(t)).filter(Boolean)
          : [];
        const own = Array.isArray(obj.x_siembox_attack_techniques)
          ? (obj.x_siembox_attack_techniques as unknown[]).map((t) => String(t)).filter((t) => /^T\d{4}(?:\.\d{3})?$/.test(t))
          : [];
        let description = content;
        if (description && terms.length) description = description.replace(/\n\nLog search terms: .*$/s, '');
        result.hypotheses.push({
          stix_id: /^note--[0-9a-f-]{36}$/.test(id) ? id : `note--${stableUuid(`${id}|${abstract}|${content}`)}`,
          title: abstract || (content as string).slice(0, 120),
          description,
          attack_techniques: own,
          search_terms: terms,
        });
        for (const t of own) techniques.delete(t);
        break;
      }
      default: {
        const sco = SCO_TYPES[type];
        if (sco && typeof obj.value === 'string') addIndicator(id, sco, obj.value, null);
        if (type === 'file' && obj.hashes && typeof obj.hashes === 'object') {
          for (const [k, v] of Object.entries(obj.hashes as Record<string, unknown>)) {
            const kind = HASH_TYPES[k.toLowerCase()];
            if (kind && typeof v === 'string') addIndicator(id, kind, v, str(obj.name, 200));
          }
        }
      }
    }
  }

  // Techniques no hypothesis carries become one hypothesis of their own.
  const named = new Set(result.hypotheses.flatMap((h) => h.attack_techniques));
  const loose = [...techniques].filter((t) => !named.has(t)).sort();
  if (loose.length) {
    result.hypotheses.push({
      stix_id: `note--${stableUuid(`techniques|${loose.join(',')}|${randomUUID()}`)}`,
      title: `Techniques from the bundle are in use here (${loose.slice(0, 5).join(', ')}${loose.length > 5 ? ', …' : ''})`,
      description: 'The imported bundle names these ATT&CK techniques. Add log search terms to test for them.',
      attack_techniques: loose,
      search_terms: [],
    });
  }

  result.title = reportTitle || otherTitle || 'Imported STIX bundle';
  return result;
}
