/**
 * Portable parser format — the on-disk/over-the-wire representation of a parser,
 * shared by in-app export/import AND the community catalog's CI. A `.parser.json`
 * file is self-contained and self-validating: pattern + field_mappings +
 * declarative derivations + `test_samples` that assert the canonical fields the
 * parser must produce. The SAME validator + self-test runner is used by the
 * import endpoint and by the catalog repo's CI, so "passes CI" == "imports and
 * behaves identically here".
 */
import { runParser, ParserDef } from './runParser';
import { validateDerivations } from './derive';

export const PARSER_SCHEMA_VERSION = 'siembox.parser/v1';
const PARSER_TYPES = ['regex', 'grok', 'json'] as const;

/** One self-test: a raw log line and the canonical fields it must yield. */
export interface ParserTestSample {
  /** Raw log line fed to the parser. */
  input: string;
  /** Canonical field -> expected value. `null` asserts the field is absent. */
  expect: Record<string, string | number | boolean | null>;
  /** Optional syslog packet sender (actor-IP fallback) for this sample. */
  packet_source_ip?: string;
  /** Optional human note shown in failure output. */
  description?: string;
}

export interface PortableParser {
  schema: string;
  name: string;
  description?: string;
  parser_type: (typeof PARSER_TYPES)[number];
  priority?: number;
  pattern: string;
  field_mappings: Record<string, string>;
  derivations?: any[] | null;
  event_type?: string | null;
  enabled?: boolean;
  test_samples?: ParserTestSample[];
  metadata?: {
    author?: string;
    references?: string[];
    tags?: string[];
    log_source?: string;
  };
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  parser?: PortableParser;
}

function isPlainObject(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Structurally validate a portable parser. `strict` (the catalog's CI mode) turns
 * catalog-hygiene recommendations (name style, presence of test_samples) into
 * errors; non-strict (in-app import of a single user parser) leaves them warnings.
 */
export function validatePortableParser(obj: unknown, opts: { strict?: boolean } = {}): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const strict = !!opts.strict;
  const note = (msg: string) => (strict ? errors : warnings).push(msg);

  if (!isPlainObject(obj)) return { ok: false, errors: ['parser must be a JSON object'], warnings };
  const p = obj as Record<string, any>;

  // schema
  if (p.schema === undefined) {
    note(`missing "schema" (expected "${PARSER_SCHEMA_VERSION}")`);
  } else if (typeof p.schema !== 'string' || !p.schema.startsWith('siembox.parser/')) {
    errors.push(`unsupported schema "${p.schema}" (expected "${PARSER_SCHEMA_VERSION}")`);
  }

  // name
  if (typeof p.name !== 'string' || p.name.trim() === '') {
    errors.push('name is required (non-empty string)');
  } else {
    if (p.name.length > 100) errors.push('name must be <= 100 characters');
    if (!/^[a-z0-9][a-z0-9-]*$/.test(p.name)) {
      note(`name "${p.name}" should be kebab-case ([a-z0-9-]) for the catalog`);
    }
  }

  // parser_type
  if (!PARSER_TYPES.includes(p.parser_type)) {
    errors.push(`parser_type must be one of ${PARSER_TYPES.join(', ')}`);
  }

  // pattern (+ compiles for regex/grok)
  if (typeof p.pattern !== 'string') {
    errors.push('pattern must be a string');
  } else if (p.parser_type !== 'json') {
    if (p.pattern === '') {
      errors.push('pattern is required for regex/grok parsers');
    } else {
      try { new RegExp(p.pattern); } catch (e) {
        errors.push(`pattern is not a valid regex: ${(e as Error).message}`);
      }
    }
  }

  // field_mappings: string -> string
  if (!isPlainObject(p.field_mappings)) {
    errors.push('field_mappings must be an object');
  } else {
    for (const [k, v] of Object.entries(p.field_mappings)) {
      if (typeof v !== 'string') errors.push(`field_mappings.${k} must map to a string field name`);
    }
  }

  // derivations
  for (const e of validateDerivations(p.derivations)) errors.push(e);

  // optional scalars
  if (p.priority !== undefined && (typeof p.priority !== 'number' || p.priority < 1 || p.priority > 1000)) {
    errors.push('priority must be a number between 1 and 1000');
  }
  if (p.event_type !== undefined && p.event_type !== null && typeof p.event_type !== 'string') {
    errors.push('event_type must be a string or null');
  }
  if (p.enabled !== undefined && typeof p.enabled !== 'boolean') {
    errors.push('enabled must be a boolean');
  }

  // test_samples
  if (p.test_samples === undefined || (Array.isArray(p.test_samples) && p.test_samples.length === 0)) {
    note('no test_samples provided — catalog parsers must ship at least one self-test');
  } else if (!Array.isArray(p.test_samples)) {
    errors.push('test_samples must be an array');
  } else {
    p.test_samples.forEach((s: any, i: number) => {
      if (!isPlainObject(s)) { errors.push(`test_samples[${i}] must be an object`); return; }
      if (typeof s.input !== 'string' || s.input === '') errors.push(`test_samples[${i}].input must be a non-empty string`);
      if (!isPlainObject(s.expect) || Object.keys(s.expect).length === 0) {
        errors.push(`test_samples[${i}].expect must be a non-empty object of canonical field -> value`);
      }
    });
  }

  return { ok: errors.length === 0, errors, warnings, parser: errors.length === 0 ? (p as PortableParser) : undefined };
}

export interface SampleFailure {
  index: number;
  description?: string;
  matched: boolean;
  mismatches: Array<{ field: string; expected: any; actual: any }>;
}
export interface SelfTestResult {
  ok: boolean;
  total: number;
  passed: number;
  failures: SampleFailure[];
}

function eq(actual: any, expected: any): boolean {
  if (expected === null) return actual === undefined || actual === null; // assert-absent
  if (actual === undefined || actual === null) return false;
  if (typeof expected === 'boolean') return Boolean(actual) === expected;
  return String(actual) === String(expected); // parser fields are strings; coerce
}

/**
 * Run a parser's `test_samples` through the real pipeline (runParser) and check
 * every `expect`ed field. The promise the catalog makes to users: this parser,
 * on this input, yields these canonical fields.
 */
export function runSelfTests(parser: PortableParser): SelfTestResult {
  const def: ParserDef = {
    name: parser.name,
    parser_type: parser.parser_type,
    pattern: parser.pattern,
    field_mappings: parser.field_mappings || {},
    derivations: parser.derivations,
    event_type: parser.event_type,
  };
  const samples = parser.test_samples || [];
  const failures: SampleFailure[] = [];

  samples.forEach((s, index) => {
    const result = runParser(def, s.input, { packetSourceIp: s.packet_source_ip });
    const fields = result?.fields ?? {};
    const matched = result !== null;
    const mismatches: SampleFailure['mismatches'] = [];
    for (const [field, expected] of Object.entries(s.expect || {})) {
      if (!eq(fields[field], expected)) {
        mismatches.push({ field, expected, actual: fields[field] });
      }
    }
    // A sample that expects real fields but the parser didn't match at all is a failure.
    const expectsPresence = Object.values(s.expect || {}).some((v) => v !== null);
    if (mismatches.length > 0 || (!matched && expectsPresence)) {
      failures.push({ index, description: s.description, matched, mismatches });
    }
  });

  return { ok: failures.length === 0, total: samples.length, passed: samples.length - failures.length, failures };
}

/** Convert a DB parser row to the portable format (for export). */
export function toPortableParser(row: {
  name: string;
  description?: string | null;
  parser_type: any;
  priority?: number;
  pattern: string;
  field_mappings: Record<string, string>;
  derivations?: any[] | null;
  event_type?: string | null;
  enabled?: boolean;
  test_samples?: any[] | null;
}): PortableParser {
  const out: PortableParser = {
    schema: PARSER_SCHEMA_VERSION,
    name: row.name,
    parser_type: row.parser_type,
    pattern: row.pattern,
    field_mappings: row.field_mappings || {},
  };
  if (row.description) out.description = row.description;
  if (row.priority !== undefined) out.priority = row.priority;
  if (row.derivations) out.derivations = row.derivations;
  if (row.event_type) out.event_type = row.event_type;
  if (row.enabled !== undefined) out.enabled = row.enabled;
  if (Array.isArray(row.test_samples) && row.test_samples.length) out.test_samples = row.test_samples as ParserTestSample[];
  return out;
}
