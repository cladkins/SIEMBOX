/**
 * Sigma -> portable detection conversion (DB-free, unit-tested).
 *
 * Sigma (https://sigmahq.io) is the community standard for shareable detections.
 * This turns a Sigma YAML rule into SIEMBox's PortableRule shape so the huge body
 * of public Sigma content can be imported. The SIEMBox engine evaluates a flat
 * AND-list of conditions, so this converter faithfully maps everything that fits
 * that model and is HONEST about what does not: constructs that need OR / NOT /
 * "1 of" / event counting are reported as warnings/errors instead of being
 * silently mistranslated into a rule that quietly never (or always) fires.
 *
 * Supported:
 *   - condition: a single selection, `A and B`, `all of them`, `all of sel*`
 *   - field modifiers: contains, startswith, endswith, re, plus `|all` (AND list)
 *     and numeric gt/lt
 *   - list values as OR membership (`in`), wildcard values (`*`,`?`) as regex
 *   - level -> severity, tags, description/references rollup
 *
 * Not representable in a flat AND-list (reported, never guessed):
 *   - `or`, `not`, `1 of ...`, `| count(...)`, parentheses
 *   - OR-lists combined with contains/startswith/endswith
 */
import yaml from 'js-yaml';
import { PortableRule, RuleCondition, RULE_SEVERITIES } from './rulePortable';

export interface SigmaConvertResult {
  /** The converted rule, or null when conversion failed (see errors). */
  rule: PortableRule | null;
  errors: string[];
  warnings: string[];
  /** Source rule title, for display even when conversion failed. */
  title?: string;
  /** Canonical/raw field names the converted conditions key on (verify vs parser output). */
  fieldsUsed?: string[];
}

/** Sigma severity ladder -> SIEMBox severity. */
function sigmaLevelToSeverity(level: unknown): (typeof RULE_SEVERITIES)[number] {
  switch (String(level || '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'low':
    case 'informational':
      return 'low';
    case 'medium':
    default:
      return 'medium';
  }
}

/** Escape regex metacharacters in a literal. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** True if a Sigma value uses glob wildcards. */
function hasWildcard(s: string): boolean {
  return /[*?]/.test(s);
}

/** Convert a Sigma glob (with * and ?) to an anchored regex source. */
function globToRegex(s: string): string {
  // Escape everything, then turn the escaped wildcards back into regex.
  const escaped = escapeRegex(s).replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
  return `^${escaped}$`;
}

/**
 * Convert one Sigma keyword/value to an UN-anchored regex fragment, honoring
 * Sigma escaping: `\*` `\?` `\\` are literals; bare `*`/`?` are wildcards. Used
 * for keyword (string-list) selections, which match anywhere in the event.
 */
function sigmaToRegexFragment(input: string): string {
  // Sigma string matching is case-INSENSITIVE by default, but the engine compiles
  // `regex` with a flagless `new RegExp` (and we must not flip the global operator
  // to /i — that would change every existing rule). So encode case-insensitivity
  // inline as per-letter classes ([Dd]) rather than relying on the `i` flag.
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '\\') {
      const next = input[i + 1];
      if (next === '*' || next === '?' || next === '\\') {
        out += escapeRegex(next); // escaped -> literal
        i++;
      } else {
        out += '\\\\'; // lone backslash -> literal backslash
      }
    } else if (ch === '*') {
      out += '.*';
    } else if (ch === '?') {
      out += '.';
    } else if (/[a-zA-Z]/.test(ch)) {
      out += `[${ch.toUpperCase()}${ch.toLowerCase()}]`;
    } else {
      out += escapeRegex(ch);
    }
  }
  return out;
}

/**
 * A Sigma selection that is a LIST OF STRINGS is a "keywords" search: match if
 * ANY string appears anywhere in the event. Represent it as a single regex
 * (alternation, un-anchored = contains) against the raw `message` field, which
 * runParser populates with the whole log line.
 */
function keywordsToCondition(values: any[]): RuleCondition {
  const alt = values.map((v) => sigmaToRegexFragment(String(v))).join('|');
  return { field: 'message', operator: 'regex', value: `(?:${alt})` };
}

/**
 * Common Sigma field names -> SIEMBox canonical fields. Best-effort: anything not
 * mapped is lowercased and kept as-is, with a warning telling the user to confirm
 * the field exists in their parser output. Sigma's huge Windows/Sysmon corpus
 * (Image, CommandLine, ...) generally has no SIEMBox parser, so web/proxy/auth
 * rules convert most usefully.
 */
const SIGMA_FIELD_MAP: Record<string, string> = {
  sourceip: 'source_ip',
  src_ip: 'source_ip',
  srcip: 'source_ip',
  source_ip: 'source_ip',
  clientip: 'source_ip',
  client_ip: 'source_ip',
  c_ip: 'source_ip',
  'c-ip': 'source_ip',
  ipaddress: 'source_ip',
  destinationip: 'dest_ip',
  dst_ip: 'dest_ip',
  dstip: 'dest_ip',
  destination_ip: 'dest_ip',
  user: 'user',
  username: 'user',
  user_name: 'user',
  targetusername: 'user',
  subjectusername: 'user',
  account: 'user',
  method: 'method',
  http_method: 'method',
  'cs-method': 'method',
  cs_method: 'method',
  uri: 'path',
  url: 'path',
  request: 'path',
  request_uri: 'path',
  'c-uri': 'path',
  cs_uri_stem: 'path',
  'cs-uri-stem': 'path',
  useragent: 'user_agent',
  user_agent: 'user_agent',
  'c-useragent': 'user_agent',
  'cs-user-agent': 'user_agent',
  status: 'status_code',
  status_code: 'status_code',
  'sc-status': 'status_code',
  sc_status: 'status_code',
  http_status: 'status_code',
};

function mapField(raw: string): string {
  const key = String(raw).toLowerCase();
  return SIGMA_FIELD_MAP[key] || key;
}

/**
 * Convert one `field[|mod...]: value` entry from a selection into zero or more
 * AND conditions. Returns { conditions } on success, or { unsupported } with a
 * reason when the entry's semantics need OR/NOT the engine can't express.
 */
function convertEntry(
  rawField: string,
  value: any
): { conditions: RuleCondition[] } | { unsupported: string } {
  const parts = String(rawField).split('|');
  const baseField = parts[0];
  const mods = parts.slice(1).map((m) => m.toLowerCase());
  const field = mapField(baseField);

  const isAll = mods.includes('all'); // AND across a list instead of OR
  const valueMod = mods.find((m) => ['contains', 'startswith', 'endswith', 're', 'gt', 'gte', 'lt', 'lte'].includes(m));

  if (mods.some((m) => m === 'base64' || m === 'base64offset' || m === 'utf16' || m === 'wide' || m === 'cidr' || m === 'expand')) {
    return { unsupported: `field "${rawField}" uses an unsupported modifier (${mods.join('|')})` };
  }
  if (valueMod === 'gte' || valueMod === 'lte') {
    return { unsupported: `field "${rawField}" uses "${valueMod}" (engine has strict greater_than/less_than only)` };
  }

  const values: any[] = Array.isArray(value) ? value : [value];

  // null means "field exists" in Sigma.
  if (values.length === 1 && (values[0] === null || values[0] === undefined)) {
    return { conditions: [{ field, operator: 'exists', value: true }] };
  }

  const buildOne = (v: any): RuleCondition | { unsupported: string } => {
    const sv = String(v);
    switch (valueMod) {
      case 'contains':
        return { field, operator: 'contains', value: sv };
      case 'startswith':
        return { field, operator: 'regex', value: `^${escapeRegex(sv)}` };
      case 'endswith':
        return { field, operator: 'regex', value: `${escapeRegex(sv)}$` };
      case 're':
        return { field, operator: 'regex', value: sv };
      case 'gt':
        return { field, operator: 'greater_than', value: Number(v) };
      case 'lt':
        return { field, operator: 'less_than', value: Number(v) };
      default:
        // No value modifier: wildcard -> regex, else equals.
        return hasWildcard(sv)
          ? { field, operator: 'regex', value: globToRegex(sv) }
          : { field, operator: 'equals', value: sv };
    }
  };

  // Multiple values:
  if (values.length > 1) {
    // `|all` = every value must match -> AND of conditions (representable).
    if (isAll) {
      const out: RuleCondition[] = [];
      for (const v of values) {
        const c = buildOne(v);
        if ('unsupported' in c) return c;
        out.push(c);
      }
      return { conditions: out };
    }
    // Plain equality list with no wildcards -> OR membership via `in`.
    if (!valueMod && values.every((v) => !hasWildcard(String(v)))) {
      return { conditions: [{ field, operator: 'in', value: values.map((v) => String(v)) }] };
    }
    // Equality list WITH wildcards -> regex alternation of globs (still OR, representable).
    if (!valueMod) {
      const alt = values.map((v) => globToRegex(String(v)).replace(/^\^|\$$/g, '')).join('|');
      return { conditions: [{ field, operator: 'regex', value: `^(?:${alt})$` }] };
    }
    // OR of contains/startswith/endswith/re across a list can't be a single AND condition.
    return { unsupported: `field "${rawField}" is an OR-list with "${valueMod}", which needs OR the engine can't express` };
  }

  const one = buildOne(values[0]);
  if ('unsupported' in one) return one;
  return { conditions: [one] };
}

/**
 * Decide which selection identifiers contribute to an AND-only condition, or
 * report why the condition can't be represented. Accepts: a single name,
 * `a and b and ...`, `all of them`, `all of <prefix>*`.
 */
function resolveSelections(
  condition: string,
  detection: Record<string, any>
): { selections: string[] } | { unsupported: string } {
  const cond = String(condition).trim();
  const selectionNames = Object.keys(detection).filter((k) => k !== 'condition');
  const lowered = cond.toLowerCase();

  if (/\bor\b|\bnot\b|\b1 of\b|\bany of\b|\|/.test(lowered) || cond.includes('(') || cond.includes(')')) {
    return { unsupported: `condition "${cond}" uses OR/NOT/"1 of"/count, which a flat AND-list can't express` };
  }

  // `all of them`
  if (/^all of them$/.test(lowered)) {
    return { selections: selectionNames };
  }
  // `all of <prefix>*`
  const allOf = lowered.match(/^all of (\S+)$/);
  if (allOf) {
    const pat = allOf[1];
    if (pat.endsWith('*')) {
      const prefix = pat.slice(0, -1);
      const matched = selectionNames.filter((n) => n.toLowerCase().startsWith(prefix));
      if (matched.length === 0) return { unsupported: `condition "${cond}" matched no selections` };
      return { selections: matched };
    }
    return selectionNames.includes(allOf[1])
      ? { selections: [allOf[1]] }
      : { unsupported: `condition references unknown selection "${allOf[1]}"` };
  }

  // `a and b and c`
  const names = cond.split(/\s+and\s+/i).map((s) => s.trim());
  for (const n of names) {
    if (!selectionNames.includes(n)) {
      return { unsupported: `condition references unknown selection "${n}"` };
    }
  }
  return { selections: names };
}

/** Convert a single parsed Sigma document object into a portable rule. */
export function sigmaToPortable(doc: any): SigmaConvertResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { rule: null, errors: ['not a Sigma rule mapping'], warnings };
  }

  const title = typeof doc.title === 'string' ? doc.title : undefined;
  if (!title) errors.push('Sigma rule needs a title');

  const detection = doc.detection;
  if (!detection || typeof detection !== 'object') {
    errors.push('Sigma rule needs a detection block');
    return { rule: null, errors, warnings, title };
  }
  if (typeof detection.condition !== 'string') {
    // Sigma also allows a list of conditions (implicit OR) — not representable.
    errors.push('detection.condition must be a single string expression (lists/OR are unsupported)');
    return { rule: null, errors, warnings, title };
  }

  const resolved = resolveSelections(detection.condition, detection);
  if ('unsupported' in resolved) {
    errors.push(resolved.unsupported);
    return { rule: null, errors, warnings, title };
  }

  const conditions: RuleCondition[] = [];
  const fieldsUsed = new Set<string>();
  let usedKeywords = false;
  for (const selName of resolved.selections) {
    const sel = detection[selName];
    if (Array.isArray(sel)) {
      // A list of STRINGS is a Sigma "keywords" search (match any, anywhere) —
      // representable as one regex alternation on `message`. A list of MAPS is a
      // genuine OR of field-sets, which a flat AND-list can't express.
      if (sel.length > 0 && sel.every((v) => v === null || typeof v !== 'object')) {
        conditions.push(keywordsToCondition(sel));
        fieldsUsed.add('message');
        usedKeywords = true;
        continue;
      }
      errors.push(`selection "${selName}" is a list of maps (OR), which a flat AND-list can't express`);
      return { rule: null, errors, warnings, title };
    }
    if (!sel || typeof sel !== 'object') {
      errors.push(`selection "${selName}" must be a mapping of field: value`);
      return { rule: null, errors, warnings, title };
    }
    for (const [rawField, value] of Object.entries(sel)) {
      const conv = convertEntry(rawField, value);
      if ('unsupported' in conv) {
        warnings.push(`Skipped ${conv.unsupported}`);
        continue;
      }
      for (const c of conv.conditions) {
        conditions.push(c);
        fieldsUsed.add(c.field);
      }
    }
  }

  if (conditions.length === 0) {
    errors.push('no representable conditions were produced from this Sigma rule');
    return { rule: null, errors, warnings, title, fieldsUsed: [...fieldsUsed] };
  }

  // Roll references / falsepositives into the description so context isn't lost.
  const descParts: string[] = [];
  if (typeof doc.description === 'string' && doc.description.trim()) descParts.push(doc.description.trim());
  if (Array.isArray(doc.references) && doc.references.length) {
    descParts.push(`References: ${doc.references.join(', ')}`);
  }
  if (Array.isArray(doc.falsepositives) && doc.falsepositives.length) {
    descParts.push(`Known false positives: ${doc.falsepositives.join('; ')}`);
  }
  const description = descParts.join('\n\n') || undefined;

  // Carry Sigma tags (attack.t1234, etc.) plus provenance markers.
  const tags = ['sigma', 'imported'];
  if (Array.isArray(doc.tags)) {
    for (const t of doc.tags) if (typeof t === 'string') tags.push(t);
  }

  const rule: PortableRule = {
    name: title!,
    description,
    severity: sigmaLevelToSeverity(doc.level),
    enabled: false, // imported rules start disabled so the user reviews them first
    tags,
    conditions,
    alert: {
      title: title!,
      description: description || `Sigma detection "${title}" matched`,
    },
  };

  warnings.push(
    `Verify these field names exist in your parsed logs: ${[...fieldsUsed].join(', ')}. ` +
      `Sigma field names often differ from your parser output.`
  );
  if (usedKeywords) {
    warnings.push(
      `Keyword search matches against the raw "message" field (the whole log line). ` +
        `Make sure your parser keeps the full message.`
    );
  }

  return { rule, errors, warnings, title, fieldsUsed: [...fieldsUsed] };
}

/**
 * Convert a Sigma YAML string that may contain multiple `---`-separated docs.
 * Returns one result per document, in order.
 */
export function convertSigmaYaml(yamlText: string): SigmaConvertResult[] {
  let docs: any[];
  try {
    docs = yaml.loadAll(yamlText) as any[];
  } catch (e) {
    return [{ rule: null, errors: [`YAML parse error: ${(e as Error).message}`], warnings: [] }];
  }
  const real = docs.filter((d) => d !== null && d !== undefined);
  if (real.length === 0) return [{ rule: null, errors: ['no YAML documents found'], warnings: [] }];
  return real.map(sigmaToPortable);
}
