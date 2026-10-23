/**
 * The Content Pack format (siembox.pack/v1) and its validator. DB-free and
 * network-free: the catalog's CI runs it through `npm run validate-packs`, the
 * app runs it on every pack it reads from the catalog, and the bundled
 * fallback packs pass it too (contentPacks.test.ts).
 *
 * A pack lives in the catalog as `packs/<id>.pack.yaml`:
 *
 *   schema: siembox.pack/v1
 *   id: reverse-proxy              # kebab-case, the file name
 *   name: Reverse Proxy & Web
 *   description: ...
 *   icon: Connection               # one of PACK_ICONS
 *   version: 2                     # integer; bump whenever the item lists change
 *   parsers: [traefik-access, ...] # catalog parser names
 *   detections:                    # catalog detections, by any of:
 *     categories: [reverse-proxy]  #   detections/<category>/ directory
 *     tags: []                     #   a tag on the rule
 *     names: []                    #   the rule's exact name
 *   sigma:                         # SigmaHQ rules, by Sigma id (installed
 *     - id: 65354b83-...           # through the SigmaHQ library)
 *       title: Cross Site Scripting Strings
 *   setup:                         # the setup guide, shown before install
 *     - title: Ship the access log
 *       text: |                    # markdown, no raw HTML, http(s) links only
 *         ...
 *       code: |                    # optional, shown verbatim
 *         ...
 *       code_language: yaml
 *
 * Markdown safety: the page renders guide text through the frontend's
 * sanitized markdown path (raw HTML escaped, then DOMPurify), but the catalog
 * should not carry markup in the first place, so this validator refuses raw
 * HTML, images and any link that is not http(s), mailto or relative.
 */

export const PACK_SCHEMA = 'siembox.pack/v1';
/** Catalog file name: packs/<id>.pack.yaml. */
export const PACK_FILE_SUFFIX = '.pack.yaml';

/** Icons the Content Packs page maps (frontend/src/views/ContentPacks.vue). */
export const PACK_ICONS = [
  'Box',
  'Connection',
  'DataLine',
  'Files',
  'House',
  'Key',
  'Lock',
  'Monitor',
  'Share',
  'VideoPlay',
  'Cpu',
  'Cloudy',
  'Message',
] as const;

export const CODE_LANGUAGES = [
  'bash',
  'shell',
  'yaml',
  'json',
  'ini',
  'toml',
  'nginx',
  'apache',
  'conf',
  'dockerfile',
  'text',
] as const;

/** Size caps (characters / entries). */
export const PACK_LIMITS = {
  id: 64,
  name: 80,
  description: 500,
  items: 200,
  sigmaTitle: 255,
  steps: 20,
  stepTitle: 120,
  stepText: 4000,
  stepCode: 4000,
  setupTotal: 20000,
  version: 1_000_000,
} as const;

export interface PackSetupStep {
  title: string;
  /** Markdown (no raw HTML). */
  text: string;
  /** Shown verbatim in a code block (a config snippet, a command). */
  code?: string;
  code_language?: string;
}

export interface PackSigmaRef {
  /** The SigmaHQ rule id (UUID, lower case). */
  id: string;
  /** The rule's title, shown while the SigmaHQ library is not loaded. */
  title: string;
}

export interface PackDetectionSelector {
  categories: string[];
  tags: string[];
  names: string[];
}

export interface ContentPack {
  id: string;
  name: string;
  description: string;
  /** Element Plus icon name the frontend maps to a component (PACK_ICONS). */
  icon: string;
  /** Bumped whenever the pack's item lists change. */
  version: number;
  /** Exact catalog parser names. */
  parsers: string[];
  detections: PackDetectionSelector;
  sigma: PackSigmaRef[];
  setup: PackSetupStep[];
}

export interface PackValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
  /** The normalized pack (only when ok). */
  pack?: ContentPack;
}

/** What a pack's references are checked against (validate-packs with catalog dirs). */
export interface PackCatalogIndex {
  parsers?: Set<string>;
  detections?: Array<{ name: string; path: string; tags: string[] }>;
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]*$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOP_KEYS = ['schema', 'id', 'name', 'description', 'icon', 'version', 'parsers', 'detections', 'sigma', 'setup'];
const STEP_KEYS = ['title', 'text', 'code', 'code_language'];
const SELECTOR_KEYS = ['categories', 'tags', 'names'];

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Remove fenced code blocks and inline code spans (their text is shown literally). */
export function stripCode(md: string): string {
  // Fenced blocks, line by line. Only a closed fence is removed: an unclosed
  // one is checked as text (conservative).
  const lines = md.split('\n');
  const kept: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /^ {0,3}(`{3,}|~{3,})/.exec(lines[i]);
    if (open) {
      const fence = open[1];
      let j = i + 1;
      while (j < lines.length && !lines[j].trimStart().startsWith(fence)) j++;
      if (j < lines.length) {
        i = j;
        continue;
      }
    }
    kept.push(lines[i]);
  }
  // Inline code spans: a run of N backticks up to the next run of exactly N.
  const text = kept.join('\n');
  let out = '';
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '`') {
      out += text[i++];
      continue;
    }
    let n = 0;
    while (text[i + n] === '`') n++;
    const ticks = '`'.repeat(n);
    let close = -1;
    for (let k = text.indexOf(ticks, i + n); k >= 0; k = text.indexOf(ticks, k + 1)) {
      if (text[k + n] !== '`' && text[k - 1] !== '`') {
        close = k;
        break;
      }
    }
    if (close < 0) {
      out += ticks;
      i += n;
      continue;
    }
    i = close + n;
  }
  return out;
}

const SAFE_LINK_RE = /^(?:https?:\/\/|mailto:|\/(?!\/)|#|\.{0,2}\/)/i;

/**
 * Markup problems in guide markdown: raw HTML, images, and link targets that
 * are not http(s), mailto or relative (javascript:, data:, vbscript:, ...).
 * Code (fenced blocks, inline spans) is left out: it renders as literal text.
 */
export function markdownProblems(md: string): string[] {
  const out: string[] = [];
  const text = stripCode(md);
  // Raw HTML: a tag, a comment, a closing tag or a processing instruction. A
  // lone "<" (a comparison, "<your-host>" outside code) is reported too: write
  // placeholders in `code`.
  const tag = text.match(/<\/?[A-Za-z!?][^>\n]*>?/);
  if (tag) out.push(`raw HTML is not allowed (found "${tag[0].slice(0, 40)}"); put placeholders like <host> in \`code\``);
  if (/!\[[^\]]*\]\s*[([]/.test(text)) out.push('images are not allowed in setup guides');
  // HTML entities can spell a scheme the link check would miss (&#106;avascript:).
  if (/&#?[a-z0-9]+;/i.test(text)) out.push('HTML entities are not allowed (write the character itself)');
  const targets: string[] = [];
  for (const m of text.matchAll(/\]\(\s*<?([^)\s>]*)/g)) targets.push(m[1]);
  for (const m of text.matchAll(/^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/gm)) targets.push(m[1]);
  for (const t of targets) {
    if (!SAFE_LINK_RE.test(t)) {
      out.push(`link target "${t.slice(0, 60)}" is not allowed (use http(s), mailto or a relative link)`);
    }
  }
  return out;
}

function stringList(
  v: unknown,
  where: string,
  errors: string[],
  opts: { slug?: boolean; max?: number } = {}
): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) {
    errors.push(`${where} must be a list`);
    return [];
  }
  const out: string[] = [];
  for (const [i, x] of v.entries()) {
    if (typeof x !== 'string' || !x.trim()) {
      errors.push(`${where}[${i}] must be a non-empty string`);
      continue;
    }
    const s = x.trim();
    if (s.length > 255) errors.push(`${where}[${i}] is longer than 255 characters`);
    if (opts.slug && !SLUG_RE.test(s)) errors.push(`${where}[${i}] "${s}" must be a kebab-case name`);
    if (out.includes(s)) errors.push(`${where} lists "${s}" twice`);
    else out.push(s);
  }
  if (out.length > (opts.max ?? PACK_LIMITS.items)) errors.push(`${where} has more than ${opts.max ?? PACK_LIMITS.items} entries`);
  return out;
}

function capped(v: unknown, where: string, max: number, errors: string[], required = true): string {
  if (v === undefined || v === null || v === '') {
    if (required) errors.push(`${where} is required`);
    return '';
  }
  if (typeof v !== 'string') {
    errors.push(`${where} must be a string`);
    return '';
  }
  if (v.length > max) errors.push(`${where} is ${v.length} characters (at most ${max})`);
  return v;
}

/**
 * Validate one pack. `strict` (catalog CI) makes unknown keys errors; the app
 * reads catalog packs non-strict (unknown keys are warnings, so a newer
 * catalog field does not hide a pack from an older SIEMBox). `index` checks
 * that the referenced parsers and detection selectors resolve.
 */
export function validatePack(
  obj: unknown,
  opts: { strict?: boolean; index?: PackCatalogIndex; expectId?: string } = {}
): PackValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!isObj(obj)) return { ok: false, errors: ['a pack must be a YAML mapping'], warnings };

  const unknown = (keys: string[], allowed: string[], where: string) => {
    for (const k of keys) {
      if (allowed.includes(k)) continue;
      (opts.strict ? errors : warnings).push(`unknown key "${k}"${where}`);
    }
  };
  unknown(Object.keys(obj), TOP_KEYS, '');

  if (obj.schema !== PACK_SCHEMA) errors.push(`schema must be "${PACK_SCHEMA}"`);

  const id = capped(obj.id, 'id', PACK_LIMITS.id, errors);
  if (id && !SLUG_RE.test(id)) errors.push('id must be kebab-case (a-z, 0-9, -)');
  if (opts.expectId && id && id !== opts.expectId) errors.push(`id "${id}" does not match the file name "${opts.expectId}"`);
  const name = capped(obj.name, 'name', PACK_LIMITS.name, errors);
  const description = capped(obj.description, 'description', PACK_LIMITS.description, errors);
  for (const p of markdownProblems(description)) errors.push(`description: ${p}`);
  const icon = capped(obj.icon, 'icon', 40, errors);
  if (icon && !(PACK_ICONS as readonly string[]).includes(icon)) errors.push(`icon "${icon}" is not one of ${PACK_ICONS.join(', ')}`);

  const version = obj.version;
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1 || version > PACK_LIMITS.version) {
    errors.push('version must be a positive integer (bump it whenever the pack\'s items change)');
  }

  const parsers = stringList(obj.parsers, 'parsers', errors, { slug: true });

  let detections: PackDetectionSelector = { categories: [], tags: [], names: [] };
  if (obj.detections !== undefined && obj.detections !== null) {
    if (!isObj(obj.detections)) errors.push('detections must be a mapping of categories / tags / names');
    else {
      unknown(Object.keys(obj.detections), SELECTOR_KEYS, ' in detections');
      detections = {
        categories: stringList(obj.detections.categories, 'detections.categories', errors, { slug: true }),
        tags: stringList(obj.detections.tags, 'detections.tags', errors),
        names: stringList(obj.detections.names, 'detections.names', errors),
      };
    }
  }

  const sigma: PackSigmaRef[] = [];
  if (obj.sigma !== undefined && obj.sigma !== null) {
    if (!Array.isArray(obj.sigma)) errors.push('sigma must be a list of { id, title }');
    else {
      if (obj.sigma.length > PACK_LIMITS.items) errors.push(`sigma has more than ${PACK_LIMITS.items} entries`);
      for (const [i, s] of obj.sigma.entries()) {
        if (!isObj(s)) {
          errors.push(`sigma[${i}] must be a mapping { id, title }`);
          continue;
        }
        unknown(Object.keys(s), ['id', 'title'], ` in sigma[${i}]`);
        const sid = typeof s.id === 'string' ? s.id.trim() : '';
        if (!UUID_RE.test(sid)) {
          errors.push(`sigma[${i}].id "${String(s.id ?? '')}" must be a SigmaHQ rule id (a lower-case UUID)`);
          continue;
        }
        const title = capped(s.title, `sigma[${i}].title`, PACK_LIMITS.sigmaTitle, errors);
        if (sigma.some((x) => x.id === sid)) errors.push(`sigma lists ${sid} twice`);
        else sigma.push({ id: sid, title });
      }
    }
  }

  const setup: PackSetupStep[] = [];
  if (!Array.isArray(obj.setup) || obj.setup.length === 0) {
    errors.push('setup must be a list of at least one step { title, text, code? }');
  } else {
    if (obj.setup.length > PACK_LIMITS.steps) errors.push(`setup has more than ${PACK_LIMITS.steps} steps`);
    let total = 0;
    for (const [i, s] of obj.setup.entries()) {
      const where = `setup[${i}]`;
      if (!isObj(s)) {
        errors.push(`${where} must be a mapping { title, text, code? }`);
        continue;
      }
      unknown(Object.keys(s), STEP_KEYS, ` in ${where}`);
      const title = capped(s.title, `${where}.title`, PACK_LIMITS.stepTitle, errors);
      const text = capped(s.text, `${where}.text`, PACK_LIMITS.stepText, errors);
      for (const p of markdownProblems(title)) errors.push(`${where}.title: ${p}`);
      for (const p of markdownProblems(text)) errors.push(`${where}.text: ${p}`);
      const code = capped(s.code, `${where}.code`, PACK_LIMITS.stepCode, errors, false);
      const lang = capped(s.code_language, `${where}.code_language`, 20, errors, false);
      if (lang && !(CODE_LANGUAGES as readonly string[]).includes(lang)) {
        errors.push(`${where}.code_language "${lang}" is not one of ${CODE_LANGUAGES.join(', ')}`);
      }
      if (lang && !code) warnings.push(`${where}.code_language is set but there is no code`);
      total += title.length + text.length + code.length;
      setup.push({ title, text, ...(code ? { code } : {}), ...(lang ? { code_language: lang } : {}) });
    }
    if (total > PACK_LIMITS.setupTotal) errors.push(`setup is ${total} characters in all (at most ${PACK_LIMITS.setupTotal})`);
  }

  if (parsers.length + detections.categories.length + detections.tags.length + detections.names.length + sigma.length === 0) {
    errors.push('a pack must reference at least one parser, detection selector or Sigma rule');
  }

  // References resolve against the catalog the pack ships in.
  if (opts.index?.parsers) {
    for (const p of parsers) if (!opts.index.parsers.has(p)) errors.push(`parser "${p}" is not in the catalog`);
  }
  if (opts.index?.detections) {
    const dets = opts.index.detections;
    const cats = new Set(dets.flatMap((d) => d.path.split('/').slice(0, -1)));
    for (const c of detections.categories) if (!cats.has(c)) errors.push(`detection category "${c}" has no detections in the catalog`);
    for (const t of detections.tags) if (!dets.some((d) => d.tags.includes(t))) errors.push(`detection tag "${t}" matches no catalog detection`);
    for (const n of detections.names) if (!dets.some((d) => d.name === n)) errors.push(`detection "${n}" is not in the catalog`);
  }

  const ok = errors.length === 0;
  return {
    ok,
    errors,
    warnings,
    ...(ok
      ? { pack: { id, name, description, icon, version: version as number, parsers, detections, sigma, setup } }
      : {}),
  };
}

/** True if a catalog detection (by name, path and tags) belongs to a pack. */
export function detectionMatchesPack(
  entry: { name?: string; path?: string; tags?: string[] },
  pack: Pick<ContentPack, 'detections'>
): boolean {
  const { categories, tags, names } = pack.detections;
  if (categories.length) {
    // The category must be a directory segment of the path (detections/<cat>/X.yaml).
    const dirSegs = String(entry.path || '').split('/').slice(0, -1);
    if (categories.some((c) => dirSegs.includes(c))) return true;
  }
  if (tags.length && Array.isArray(entry.tags) && entry.tags.some((t) => tags.includes(t))) return true;
  if (names.length && entry.name && names.includes(entry.name)) return true;
  return false;
}
