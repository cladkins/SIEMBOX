// Loads fingerprints/*.yaml into memory at startup and validates each file against
// fingerprint.schema.yaml. A fingerprint that fails validation is rejected (logged
// and skipped) rather than crashing the whole library load -- one bad community
// contribution shouldn't take down every other fingerprint.
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { logger } from '../../utils/logger';
import { FingerprintEntry } from './types';

const FINGERPRINTS_DIR = path.join(__dirname, 'fingerprints');
const SCHEMA_PATH = path.join(__dirname, 'fingerprint.schema.yaml');

const ID_PATTERN = /^[a-z0-9-]+$/;

interface FingerprintSchema {
  required: string[];
}

function loadSchema(): FingerprintSchema {
  const raw = fs.readFileSync(SCHEMA_PATH, 'utf8');
  const parsed = yaml.load(raw) as FingerprintSchema;
  if (!parsed || !Array.isArray(parsed.required)) {
    throw new Error(`fingerprint.schema.yaml is missing a top-level "required" array`);
  }
  return parsed;
}

/**
 * Validate a parsed fingerprint document. Returns a list of human-readable
 * errors; an empty list means the fingerprint is valid.
 */
export function validateFingerprint(doc: any, schema: FingerprintSchema): string[] {
  const errors: string[] = [];
  if (!doc || typeof doc !== 'object') {
    return ['not an object'];
  }

  for (const field of schema.required) {
    if (doc[field] === undefined || doc[field] === null) {
      errors.push(`missing required field "${field}"`);
    }
  }
  if (errors.length > 0) return errors; // no point checking shapes of absent fields

  if (typeof doc.id !== 'string' || !ID_PATTERN.test(doc.id)) {
    errors.push(`id must match ${ID_PATTERN} (got ${JSON.stringify(doc.id)})`);
  }
  if (typeof doc.name !== 'string' || doc.name.length === 0) {
    errors.push('name must be a non-empty string');
  }
  if (typeof doc.category !== 'string' || doc.category.length === 0) {
    errors.push('category must be a non-empty string');
  }
  if (!Number.isInteger(doc.security_value) || doc.security_value < 1 || doc.security_value > 10) {
    errors.push('security_value must be an integer between 1 and 10');
  }
  if (!Number.isInteger(doc.confidence_floor) || doc.confidence_floor < 0 || doc.confidence_floor > 100) {
    errors.push('confidence_floor must be an integer between 0 and 100');
  }

  const signals = doc.signals;
  if (!signals || typeof signals !== 'object') {
    errors.push('signals must be an object');
  } else {
    for (const key of ['ports', 'http', 'mdns', 'ssdp', 'tls', 'mac_oui']) {
      if (signals[key] !== undefined && !Array.isArray(signals[key])) {
        errors.push(`signals.${key} must be an array`);
      }
    }
    (signals.ports || []).forEach((s: any, i: number) => {
      if (typeof s.port !== 'number' || typeof s.weight !== 'number') {
        errors.push(`signals.ports[${i}] requires numeric "port" and "weight"`);
      }
    });
    (signals.http || []).forEach((s: any, i: number) => {
      if (typeof s.path !== 'string' || typeof s.weight !== 'number') {
        errors.push(`signals.http[${i}] requires "path" (string) and "weight" (number)`);
      }
    });
    (signals.mdns || []).forEach((s: any, i: number) => {
      if (typeof s.service !== 'string' || typeof s.weight !== 'number') {
        errors.push(`signals.mdns[${i}] requires "service" (string) and "weight" (number)`);
      }
    });
  }

  if (!Array.isArray(doc.attack_data_sources)) {
    errors.push('attack_data_sources must be an array');
  }

  if (!Array.isArray(doc.log_access) || doc.log_access.length === 0) {
    errors.push('log_access must be a non-empty array');
  } else {
    doc.log_access.forEach((entry: any, i: number) => {
      if (!entry || typeof entry.method !== 'string') {
        errors.push(`log_access[${i}] requires a "method" string`);
      }
    });
  }

  if (typeof doc.onboard_template !== 'string' || doc.onboard_template.length === 0) {
    errors.push('onboard_template must be a non-empty string');
  }

  if (!doc.credentials || typeof doc.credentials.required !== 'boolean') {
    errors.push('credentials.required must be a boolean');
  }

  return errors;
}

function normalizeSignals(raw: any): FingerprintEntry['signals'] {
  const signals = raw || {};
  return {
    ports: signals.ports || [],
    http: signals.http || [],
    mdns: signals.mdns || [],
    ssdp: signals.ssdp || [],
    tls: signals.tls || [],
    mac_oui: signals.mac_oui || [],
  };
}

let cachedLibrary: FingerprintEntry[] | null = null;

/**
 * Parse + validate every fingerprints/*.yaml file and return the in-memory
 * library. Cached after the first successful load; pass `force: true` to
 * re-read from disk (e.g. after a user drops in a new community fingerprint).
 */
export function loadFingerprintLibrary(opts: { force?: boolean } = {}): FingerprintEntry[] {
  if (cachedLibrary && !opts.force) return cachedLibrary;

  const schema = loadSchema();
  const files = fs.readdirSync(FINGERPRINTS_DIR).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));

  const library: FingerprintEntry[] = [];
  const seenIds = new Set<string>();

  for (const file of files) {
    const fullPath = path.join(FINGERPRINTS_DIR, file);
    try {
      const doc = yaml.load(fs.readFileSync(fullPath, 'utf8'));
      const errors = validateFingerprint(doc, schema);
      if (errors.length > 0) {
        logger.warn(`[logDiscovery] rejected fingerprint ${file}: ${errors.join('; ')}`);
        continue;
      }
      const entry = doc as FingerprintEntry;
      if (seenIds.has(entry.id)) {
        logger.warn(`[logDiscovery] rejected fingerprint ${file}: duplicate id "${entry.id}"`);
        continue;
      }
      seenIds.add(entry.id);
      library.push({ ...entry, signals: normalizeSignals(entry.signals) });
    } catch (err: any) {
      logger.warn(`[logDiscovery] failed to parse fingerprint ${file}: ${err?.message || err}`);
    }
  }

  cachedLibrary = library;
  return library;
}

export function getFingerprintById(id: string): FingerprintEntry | undefined {
  return loadFingerprintLibrary().find((f) => f.id === id);
}
