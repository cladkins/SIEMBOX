/**
 * Sigma -> portable detection conversion (DB-free, unit-tested).
 *
 * Sigma (https://sigmahq.io) is the community standard for shareable detections.
 * This turns a Sigma YAML rule into SIEMBox's PortableRule shape so the huge body
 * of public Sigma content can be imported. A SIEMBox rule is an AND-list of
 * conditions plus optional `exclude` groups, so:
 *   - OR in the condition (`or`, `1 of sel*`, a list of conditions, a selection
 *     that is a list of mappings) becomes one rule per alternative, at most
 *     MAX_SIGMA_SPLIT;
 *   - NOT becomes `exclude` groups (a log matching every condition of a group is
 *     skipped; a log missing the group's field is not, as in Sigma);
 *   - OR-lists of values become one `in` or regex-alternation condition.
 * What still doesn't fit is reported, never guessed: NOT inside NOT, `| count`
 * aggregations, and some modifiers (base64, cidr, wide, gte/lte...).
 */
import * as yaml from '../../utils/yaml';
import { PortableRule, RuleCondition, RULE_SEVERITIES } from './rulePortable';
import { dropInvalidAttackTags } from '../attack/attackTags';

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

/**
 * A Sigma value split at its unescaped `*` wildcards. Each block is a regex
 * source for the text between two stars (`?` -> one character, `\*` `\?` `\\`
 * literal, everything else escaped); `leading`/`trailing` say whether the
 * value starts/ends with a star. Consecutive stars collapse.
 */
function splitGlob(input: string, caseFold: boolean): { leading: boolean; trailing: boolean; blocks: string[] } {
  const blocks: string[] = [];
  let current = '';
  let leading = false;
  let trailing = false;
  let sawStar = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    let piece: string;
    if (ch === '\\') {
      const next = input[i + 1];
      if (next === '*' || next === '?' || next === '\\') {
        piece = escapeRegex(next); // escaped -> literal
        i++;
      } else {
        piece = '\\\\'; // lone backslash -> literal backslash
      }
    } else if (ch === '*') {
      if (current === '') {
        if (blocks.length === 0) leading = true;
      } else {
        blocks.push(current);
        current = '';
      }
      sawStar = true;
      trailing = true;
      continue;
    } else if (ch === '?') {
      piece = '[\\s\\S]';
    } else if (caseFold && /[a-zA-Z]/.test(ch)) {
      piece = `[${ch.toUpperCase()}${ch.toLowerCase()}]`;
    } else {
      piece = escapeRegex(ch);
    }
    current += piece;
    trailing = false;
  }
  if (current !== '') blocks.push(current);
  return { leading, trailing: trailing && sawStar, blocks };
}

/**
 * The blocks of a glob matched left to right, each at its FIRST occurrence
 * after the previous one: `(?:(?!B)[\s\S])*B` cannot step past an occurrence
 * of B, so there is exactly one way to match and the work is linear in the
 * input. Leftmost-first is also exactly glob semantics. (The obvious
 * `.*B1.*B2` is polynomial ReDoS, which the regex safety gate refuses.)
 */
function firstOccurrenceChain(blocks: string[]): string {
  return blocks.map((b) => `(?:(?!${b})[\\s\\S])*${b}`).join('');
}

/**
 * Convert a Sigma glob (with * and ?) to a regex for a whole field value
 * (anchored semantics), in a form the ReDoS gate accepts: `*x*` is plain
 * "contains x", `x*` / `*x` are a prefix / suffix test, and longer globs
 * match their blocks at first occurrence (see firstOccurrenceChain).
 */
function globToRegex(s: string): string {
  const { leading, trailing, blocks } = splitGlob(s, false);
  if (blocks.length === 0) return '^'; // "*": anything
  if (!leading && !trailing && blocks.length === 1) return `^${blocks[0]}$`; // only ? wildcards
  if (leading && trailing && blocks.length === 1) return blocks[0];
  if (!leading && trailing && blocks.length === 1) return `^${blocks[0]}`;
  if (leading && !trailing && blocks.length === 1) return `${blocks[0]}$`;
  const head = leading ? '' : blocks[0];
  const middle = blocks.slice(leading ? 0 : 1, trailing ? undefined : -1);
  const tail = trailing ? '' : `[\\s\\S]*${blocks[blocks.length - 1]}$`;
  return `^${head}${firstOccurrenceChain(middle)}${tail}`;
}

/**
 * Convert one Sigma keyword/value to an UN-anchored "contains" regex fragment,
 * honoring Sigma escaping: `\*` `\?` `\\` are literals; bare `*`/`?` are
 * wildcards. Used for keyword (string-list) selections, which match anywhere
 * in the event: leading/trailing stars add nothing to "contains", and inner
 * ones become a first-occurrence chain (linear, unlike `a.*b`).
 */
function sigmaToRegexFragment(input: string): string {
  // Sigma string matching is case-INSENSITIVE by default, but the engine compiles
  // `regex` with a flagless `new RegExp` (and we must not flip the global operator
  // to /i — that would change every existing rule). So encode case-insensitivity
  // inline as per-letter classes ([Dd]) rather than relying on the `i` flag.
  const { blocks } = splitGlob(input, true);
  if (blocks.length <= 1) return blocks[0] ?? '';
  return `^${firstOccurrenceChain(blocks)}`;
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
    // Equality list WITH wildcards -> regex alternation of globs (still OR,
    // representable). Each alternative carries its own anchors.
    if (!valueMod) {
      const alt = values.map((v) => globToRegex(String(v))).join('|');
      return { conditions: [{ field, operator: 'regex', value: `(?:${alt})` }] };
    }
    // OR of contains/startswith/endswith/re across a list: one regex
    // alternation. contains keeps Sigma's case-insensitivity (as the
    // keyword fragments do); startswith/endswith match as the single-value
    // forms above do.
    if (valueMod === 'contains') {
      return { conditions: [{ field, operator: 'regex', value: `(?:${values.map((v) => sigmaToRegexFragment(String(v))).join('|')})` }] };
    }
    if (valueMod === 'startswith') {
      return { conditions: [{ field, operator: 'regex', value: `^(?:${values.map((v) => escapeRegex(String(v))).join('|')})` }] };
    }
    if (valueMod === 'endswith') {
      return { conditions: [{ field, operator: 'regex', value: `(?:${values.map((v) => escapeRegex(String(v))).join('|')})$` }] };
    }
    if (valueMod === 're') {
      return { conditions: [{ field, operator: 'regex', value: values.map((v) => `(?:${String(v)})`).join('|') }] };
    }
    return { unsupported: `field "${rawField}" is an OR-list with "${valueMod}", which a single condition can't express` };
  }

  const one = buildOne(values[0]);
  if ('unsupported' in one) return one;
  return { conditions: [one] };
}

/** The most SIEMBox rules one Sigma rule becomes when its condition is an OR. */
export const MAX_SIGMA_SPLIT = 10;
/** The most exclusion groups one converted rule carries. */
const MAX_EXCLUDE_GROUPS = 32;

/**
 * One AND-term of a Sigma condition in disjunctive normal form: selections
 * that must all match (`pos`), and negated sub-expressions (`neg`, each itself
 * an OR of terms with no NOT inside) none of which may match.
 */
interface Term {
  pos: string[];
  neg: Term[][];
}

class ConditionError extends Error {}

function andTerms(a: Term[], b: Term[]): Term[] {
  const out: Term[] = [];
  for (const x of a) {
    for (const y of b) out.push({ pos: [...new Set([...x.pos, ...y.pos])], neg: [...x.neg, ...y.neg] });
  }
  if (out.length > 1000) throw new ConditionError('the condition expands to too many alternatives');
  return out;
}

/**
 * Parse a Sigma condition (`and`, `or`, `not`, parentheses, `1 of`/`all of`
 * with `them` or a `prefix*`) into disjunctive normal form. Tokenized by
 * splitting on whitespace (no regex over the condition), then recursive descent:
 * `or` binds loosest, then `and`, then `not`.
 */
function parseCondition(cond: string, selectionNames: string[]): Term[] {
  if (cond.includes('|')) {
    throw new ConditionError(
      `condition "${cond}" uses an aggregation ("| count" and the like); SIEMBox expresses counting with the rule's aggregation block, so add one after import`
    );
  }
  const tokens = cond.split('(').join(' ( ').split(')').join(' ) ').trim().split(/\s+/).filter(Boolean);
  let pos = 0;
  const lower = (i: number) => (tokens[i] ?? '').toLowerCase();
  const fail = (msg: string): never => {
    throw new ConditionError(`condition "${cond}": ${msg}`);
  };
  const namesFor = (pattern: string): string[] => {
    if (pattern.toLowerCase() === 'them') return selectionNames;
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1).toLowerCase();
      const matched = selectionNames.filter((n) => n.toLowerCase().startsWith(prefix));
      if (matched.length === 0) fail(`"${pattern}" matches no selection`);
      return matched;
    }
    if (!selectionNames.includes(pattern)) fail(`unknown selection "${pattern}"`);
    return [pattern];
  };

  const factor = (): Term[] => {
    const t = tokens[pos];
    if (t === undefined) return fail('it ends unexpectedly');
    const lt = t.toLowerCase();
    if (lt === 'not') {
      pos++;
      const inner = factor();
      if (inner.some((term) => term.neg.length > 0)) fail('NOT inside NOT is not supported');
      return [{ pos: [], neg: [inner] }];
    }
    if (t === '(') {
      pos++;
      const e = expr();
      if (tokens[pos] !== ')') fail('unbalanced parentheses');
      pos++;
      return e;
    }
    if ((lt === '1' || lt === 'any' || lt === 'all') && lower(pos + 1) === 'of') {
      const pattern = tokens[pos + 2];
      if (pattern === undefined || pattern === '(' || pattern === ')') return fail(`"${t} of" needs a selection name`);
      pos += 3;
      const names = namesFor(pattern);
      return lt === 'all' ? [{ pos: names, neg: [] }] : names.map((n) => ({ pos: [n], neg: [] }));
    }
    if (lt === 'and' || lt === 'or' || t === ')') return fail(`unexpected "${t}"`);
    pos++;
    if (!selectionNames.includes(t)) fail(`unknown selection "${t}"`);
    return [{ pos: [t], neg: [] }];
  };
  const term = (): Term[] => {
    let d = factor();
    while (lower(pos) === 'and') {
      pos++;
      d = andTerms(d, factor());
    }
    return d;
  };
  const expr = (): Term[] => {
    let d = term();
    while (lower(pos) === 'or') {
      pos++;
      d = [...d, ...term()];
    }
    return d;
  };

  const result = expr();
  if (pos !== tokens.length) fail(`unexpected "${tokens[pos]}"`);
  return result;
}

/** One way a selection can match: an AND-list of conditions. */
interface Variant {
  conditions: RuleCondition[];
  keywords: boolean;
}

/**
 * The ways a selection can match. A mapping is one AND-list; a list of strings
 * is one keyword regex on `message`; a list of mappings is an OR, one variant
 * per mapping. Entries the converter can't express are skipped with a warning.
 */
function selectionVariants(name: string, sel: any, warnings: string[]): Variant[] {
  const fromMap = (map: Record<string, any>): Variant => {
    const conditions: RuleCondition[] = [];
    for (const [rawField, value] of Object.entries(map)) {
      const conv = convertEntry(rawField, value);
      if ('unsupported' in conv) {
        const w = `Skipped ${conv.unsupported}`;
        if (!warnings.includes(w)) warnings.push(w);
        continue;
      }
      conditions.push(...conv.conditions);
    }
    return { conditions, keywords: false };
  };
  if (Array.isArray(sel)) {
    if (sel.length > 0 && sel.every((v) => v === null || typeof v !== 'object')) {
      return [{ conditions: [keywordsToCondition(sel)], keywords: true }];
    }
    if (sel.length > 0 && sel.every((v) => v && typeof v === 'object' && !Array.isArray(v))) {
      return sel.map(fromMap);
    }
    throw new ConditionError(`selection "${name}" must be a mapping, a list of strings, or a list of mappings`);
  }
  if (!sel || typeof sel !== 'object') {
    throw new ConditionError(`selection "${name}" must be a mapping of field: value`);
  }
  return [fromMap(sel)];
}

/** Every way a set of selections can all match: the product of their variants. */
function combine(names: string[], variants: Map<string, Variant[]>): Variant[] {
  let out: Variant[] = [{ conditions: [], keywords: false }];
  for (const n of names) {
    const next: Variant[] = [];
    for (const a of out) {
      for (const b of variants.get(n)!) {
        next.push({ conditions: [...a.conditions, ...b.conditions], keywords: a.keywords || b.keywords });
      }
    }
    out = next;
    if (out.length > 1000) throw new ConditionError('the condition expands to too many alternatives');
  }
  return out;
}

/**
 * Convert a single parsed Sigma document. Returns one result per SIEMBox rule:
 * a condition with OR in it becomes one rule per alternative (at most
 * MAX_SIGMA_SPLIT), each an AND-list; NOT becomes the rule's `exclude` groups.
 */
export function sigmaToPortableAll(doc: any): SigmaConvertResult[] {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return [{ rule: null, errors: ['not a Sigma rule mapping'], warnings }];
  }

  const title = typeof doc.title === 'string' ? doc.title : undefined;
  if (!title) errors.push('Sigma rule needs a title');

  const detection = doc.detection;
  if (!detection || typeof detection !== 'object') {
    errors.push('Sigma rule needs a detection block');
    return [{ rule: null, errors, warnings, title }];
  }
  const conditionList: unknown[] = Array.isArray(detection.condition) ? detection.condition : [detection.condition];
  if (conditionList.length === 0 || conditionList.some((c) => typeof c !== 'string' || c.trim() === '')) {
    errors.push('detection.condition must be a condition string (or a list of them)');
    return [{ rule: null, errors, warnings, title }];
  }
  if (errors.length) return [{ rule: null, errors, warnings, title }];

  const selectionNames = Object.keys(detection).filter((k) => k !== 'condition');
  // Each converted rule: the AND-list it matches, and its exclusion groups.
  const parts: Array<{ conditions: RuleCondition[]; exclude: RuleCondition[][]; keywords: boolean }> = [];
  try {
    // A list of conditions is an OR of them.
    const dnf = conditionList.flatMap((c) => parseCondition(String(c).trim(), selectionNames));
    const used = new Set<string>();
    for (const t of dnf) {
      t.pos.forEach((n) => used.add(n));
      t.neg.forEach((inner) => inner.forEach((it) => it.pos.forEach((n) => used.add(n))));
    }
    const variants = new Map<string, Variant[]>();
    for (const n of used) variants.set(n, selectionVariants(n, detection[n], warnings));

    for (const t of dnf) {
      if (t.pos.length === 0) {
        throw new ConditionError('every alternative needs at least one selection that must match (a rule that is only "not ..." would match nearly every log)');
      }
      const exclude: RuleCondition[][] = [];
      for (const inner of t.neg) {
        for (const it of inner) {
          for (const v of combine(it.pos, variants)) {
            if (v.conditions.length === 0) {
              const w = 'Dropped an exclusion with no convertible fields (it would have excluded every log)';
              if (!warnings.includes(w)) warnings.push(w);
              continue;
            }
            exclude.push(v.conditions);
          }
        }
      }
      if (exclude.length > MAX_EXCLUDE_GROUPS) {
        throw new ConditionError(`the NOT part expands to ${exclude.length} exclusion groups (at most ${MAX_EXCLUDE_GROUPS})`);
      }
      for (const v of combine(t.pos, variants)) parts.push({ conditions: v.conditions, exclude, keywords: v.keywords });
    }
  } catch (e) {
    if (!(e instanceof ConditionError)) throw e;
    errors.push(e.message);
    return [{ rule: null, errors, warnings, title }];
  }

  if (parts.length > MAX_SIGMA_SPLIT) {
    errors.push(
      `the condition is an OR of ${parts.length} alternatives; SIEMBox imports at most ${MAX_SIGMA_SPLIT} rules from one Sigma rule`
    );
    return [{ rule: null, errors, warnings, title }];
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
  // An unknown, revoked or deprecated ATT&CK technique (or an unknown tactic)
  // would fail validateRule; drop it with a warning so a stale community rule
  // still imports.
  const attack = dropInvalidAttackTags(tags);
  warnings.push(...attack.warnings);

  const split = parts.length > 1;
  return parts.map((part, i) => {
    const name = split ? `${title} (part ${i + 1} of ${parts.length})` : title!;
    const partWarnings = [...warnings];
    if (split) {
      partWarnings.unshift(
        `The Sigma condition is an OR, so it imports as ${parts.length} rules, one per alternative. ` +
          `A log matching more than one raises an alert from each.`
      );
    }
    if (part.conditions.length === 0) {
      return {
        rule: null,
        errors: ['no representable conditions were produced for this alternative'],
        warnings: partWarnings,
        title: name,
      };
    }
    const fields = new Set<string>();
    for (const c of part.conditions) fields.add(c.field);
    for (const g of part.exclude) for (const c of g) fields.add(c.field);
    partWarnings.push(
      `Verify these field names exist in your parsed logs: ${[...fields].join(', ')}. ` +
        `Sigma field names often differ from your parser output.`
    );
    if (part.keywords) {
      partWarnings.push(
        `Keyword search matches against the raw "message" field (the whole log line). ` +
          `Make sure your parser keeps the full message.`
      );
    }
    const rule: PortableRule = {
      name,
      description,
      severity: sigmaLevelToSeverity(doc.level),
      enabled: false, // imported rules start disabled so the user reviews them first
      tags: attack.tags,
      conditions: part.conditions,
      ...(part.exclude.length ? { exclude: part.exclude } : {}),
      alert: {
        title: title!,
        description: description || `Sigma detection "${title}" matched`,
      },
    };
    return { rule, errors: [], warnings: partWarnings, title: name, fieldsUsed: [...fields] };
  });
}

/** Convert a single parsed Sigma document; the first rule when it splits (see sigmaToPortableAll). */
export function sigmaToPortable(doc: any): SigmaConvertResult {
  return sigmaToPortableAll(doc)[0];
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
  return real.flatMap(sigmaToPortableAll);
}
