/**
 * The application signature format (siembox.app/v1) and its validator. DB-free
 * and network-free: the catalog's CI runs it through `npm run
 * validate-applications`, the app runs it on every signature it reads from the
 * catalog, and the bundled starter set passes it too (bundledApplications.test).
 *
 * A signature lives in the catalog as `applications/<id>.app.yaml`:
 *
 *   schema: siembox.app/v1
 *   id: plex                          # kebab-case, the file name
 *   name: Plex Media Server
 *   vendor: Plex
 *   category: media-server            # one of APP_CATEGORIES
 *   description: ...                  # optional
 *   website: https://www.plex.tv      # optional, http(s)
 *   cpe: { vendor: plex, product: media_server }   # optional (vulnerability linking)
 *   supersedes: [chrome]              # optional: when both match one piece of
 *                                     # evidence, the listed apps are dropped
 *   match:                            # at least one matcher
 *     syslog_program: [plex]          # raw_logs.app_name, exact (case-insensitive);
 *                                     # "postfix/*" also matches postfix/smtpd
 *     parser: [plex]                  # catalog parser names
 *     service:                        # asset_services (nmap)
 *       names: [plexmediaserver]      #   service_name, exact
 *       banner: ['^Plex Media Server (\d[\w.-]*)']  # regexes on banner / version; group 1 = version
 *     container_image: [plexinc/pms-docker, '*\/linuxserver/plex']  # image globs; the tag is the version
 *     package: [plexmediaserver]      # package names (EDR findings); installed version
 *     user_agent: ['PlexMediaServer/(\d[\d.]*)']  # regexes on the user agent; group 1 = version
 *     dns: [plex.tv, '*.plex.direct'] # queried-domain suffixes ("x.y" covers x.y and its subdomains)
 *     os: { family: linux, pretty_name: '^Ubuntu (\d+\.\d+)' }  # EDR agent OS
 *   tests:                            # required: one or more per matcher kind
 *     - source: user_agent
 *       input: 'PlexMediaServer/1.40.0.7998-c29d4c0c8'
 *       version: 1.40.0.7998          # expected version (omit: not checked; null: none)
 *     - source: dns
 *       input: abc.plex.direct
 *     - source: user_agent
 *       input: 'curl/8.0'
 *       match: false                  # must NOT be identified as this app
 *
 * Regexes (service.banner, user_agent, os.pretty_name) run on text a remote
 * sender controls (a user agent), so they are plain JavaScript regexes with no
 * flags, at most one capture group (the version), no named groups, no
 * backreferences, and every one of them goes through the same ReDoS check the
 * parser and detection validators use (recheck; validate-applications) and,
 * in the app, the write-time gate (services/regex/regexSafety) before it runs.
 */

export const APP_SCHEMA = 'siembox.app/v1';
/** Catalog file name: applications/<id>.app.yaml. */
export const APP_FILE_SUFFIX = '.app.yaml';

export const APP_CATEGORIES = [
  'auth',
  'automation',
  'backup',
  'browser',
  'container-runtime',
  'database',
  'dev-tools',
  'dns',
  'file-sharing',
  'game',
  'home-automation',
  'http-client',
  'mail',
  'media-server',
  'messaging',
  'monitoring',
  'network',
  'operating-system',
  'os-component',
  'password-manager',
  'productivity',
  'remote-access',
  'reverse-proxy',
  'saas',
  'security',
  'virtualization',
  'vpn',
  'web-server',
] as const;
export type AppCategory = (typeof APP_CATEGORIES)[number];

/** The evidence sources a signature can match, as stored in the inventory. */
export const MATCH_KINDS = ['syslog_program', 'parser', 'service', 'container_image', 'package', 'user_agent', 'dns', 'os'] as const;
export type MatchKind = (typeof MATCH_KINDS)[number];

/** EDR agent OS families (runtime.GOOS as the endpoint agent reports it). */
export const OS_FAMILIES = ['linux', 'windows', 'darwin', 'freebsd'] as const;

export const APP_LIMITS = {
  id: 64,
  name: 80,
  vendor: 80,
  description: 500,
  website: 200,
  entries: 40,
  entry: 128,
  regex: 200,
  tests: 40,
  testInput: 1024,
} as const;

export interface AppServiceMatcher {
  names: string[];
  banner: string[];
}

export interface AppOsMatcher {
  family: string;
  pretty_name: string | null;
}

export interface AppMatchers {
  syslog_program: string[];
  parser: string[];
  service: AppServiceMatcher;
  container_image: string[];
  package: string[];
  user_agent: string[];
  dns: string[];
  os: AppOsMatcher | null;
}

export interface AppTest {
  source: MatchKind;
  /** A string, or for service {name, banner?, version?}, for os {family, pretty_name?}. */
  input: string | Record<string, string>;
  /** undefined: not checked; null: no version expected. */
  version?: string | null;
  /** false: the input must not be identified as this app. */
  match: boolean;
}

export interface AppSignature {
  id: string;
  name: string;
  vendor: string;
  category: AppCategory;
  description: string;
  website: string | null;
  cpe: { vendor: string; product: string } | null;
  supersedes: string[];
  match: AppMatchers;
  tests: AppTest[];
}

export interface AppValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
  /** The normalized signature (only when ok). */
  app?: AppSignature;
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]*$/;
const CPE_PART_RE = /^[a-z0-9][a-z0-9_.-]{0,99}$/;
const PROGRAM_RE = /^[a-z0-9][a-z0-9 _.@+-]{0,62}(?:\/\*)?$/;
const PARSER_NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,127}$/;
const SERVICE_NAME_RE = /^[a-z0-9][a-z0-9_.+-]{0,63}$/;
const PACKAGE_RE = /^[a-z0-9@][a-z0-9_.+:/@-]{0,127}$/;
const IMAGE_GLOB_RE = /^[a-z0-9*][a-z0-9._/*-]{0,199}$/;
const DOMAIN_LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const URL_RE = /^https?:\/\/[^\s<>"']{3,}$/i;
const TOP_KEYS = ['schema', 'id', 'name', 'vendor', 'category', 'description', 'website', 'cpe', 'supersedes', 'match', 'tests'];
const MATCH_KEYS: string[] = [...MATCH_KINDS];
const SERVICE_KEYS = ['names', 'banner'];
const OS_KEYS = ['family', 'pretty_name'];
const TEST_KEYS = ['source', 'input', 'version', 'match', 'description'];

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * A domain matcher: "zoom.us" (zoom.us and every subdomain) or "*.plex.direct"
 * (subdomains only). Lower case, at least two labels, no trailing dot.
 */
export function domainMatcherProblem(entry: string): string | null {
  const host = entry.startsWith('*.') ? entry.slice(2) : entry;
  if (host.length === 0 || host.length > 253) return 'must be a domain name of 1 to 253 characters';
  if (host !== host.toLowerCase()) return 'must be lower case';
  const labels = host.split('.');
  if (labels.length < 2) return 'needs at least two labels (example.com, not com)';
  for (const label of labels) {
    if (!DOMAIN_LABEL_RE.test(label)) return `has an invalid label "${label}"`;
  }
  return null;
}

/**
 * Problems with a signature regex beyond compiling: no flags (the matcher
 * compiles it without any), at most one capture group (the version), no named
 * groups or backreferences, and it must not match the empty string (it would
 * match every value).
 */
export function signatureRegexProblem(source: string): string | null {
  if (source.length === 0 || source.length > APP_LIMITS.regex) return `must be 1 to ${APP_LIMITS.regex} characters`;
  let re: RegExp;
  try {
    re = new RegExp(source);
  } catch (e) {
    return `does not compile: ${(e as Error).message}`;
  }
  if (/\(\?<(?![=!])/.test(source)) return 'uses a named group; use one plain group for the version';
  if (/\\[1-9]|\\k</.test(source)) return 'uses a backreference';
  // Count capture groups by matching against a string that cannot match, via
  // the source's own group structure: new RegExp(source + '|').exec('') has one
  // entry per group.
  const groups = new RegExp(`${source}|`).exec('')!.length - 1;
  if (groups > 1) return `has ${groups} capture groups; at most one (the version) is allowed — use (?:...) for the rest`;
  if (re.test('')) return 'matches the empty string (it would match every value)';
  return null;
}

/** Normalized Docker image glob: lower case, docker.io/library/ folded, no tag or digest. */
export function imageGlobProblem(entry: string): string | null {
  if (!IMAGE_GLOB_RE.test(entry)) return 'must be an image name glob (lower case letters, digits, . _ - / and *), with no tag';
  if (entry.includes('**')) return 'uses ** (one * already matches any characters, slashes included)';
  const literal = entry.replace(/[*/]/g, '');
  if (literal.length < 3) return 'needs at least three literal characters';
  return null;
}

/** Fold the image name forms Docker treats as one: docker.io/, index.docker.io/, library/. */
export function normalizeImageName(name: string): string {
  let n = name.trim().toLowerCase();
  n = n.replace(/^(?:docker\.io|index\.docker\.io|registry-1\.docker\.io)\//, '');
  if (n.startsWith('library/')) n = n.slice('library/'.length);
  return n;
}

function strList(
  v: unknown,
  where: string,
  errors: string[],
  check: (s: string) => string | null,
  opts: { lower?: boolean } = {}
): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) {
    errors.push(`${where} must be a list`);
    return [];
  }
  if (v.length > APP_LIMITS.entries) errors.push(`${where} has more than ${APP_LIMITS.entries} entries`);
  const out: string[] = [];
  v.forEach((item, i) => {
    if (typeof item !== 'string' || item.trim().length === 0) {
      errors.push(`${where}[${i}] must be a non-empty string`);
      return;
    }
    const value = opts.lower ? item.trim().toLowerCase() : item;
    const problem = check(value);
    if (problem) errors.push(`${where}[${i}] "${item}" ${problem}`);
    else if (out.includes(value)) errors.push(`${where}[${i}] "${item}" is listed twice`);
    else out.push(value);
  });
  return out;
}

const pattern = (re: RegExp, what: string) => (s: string) => (re.test(s) ? null : `is not a valid ${what}`);

function text(v: unknown, where: string, max: number, errors: string[], required: boolean): string {
  if (v === undefined || v === null || v === '') {
    if (required) errors.push(`${where} is required`);
    return '';
  }
  if (typeof v !== 'string') {
    errors.push(`${where} must be a string`);
    return '';
  }
  const t = v.trim();
  if (t.length > max) errors.push(`${where} is longer than ${max} characters`);
  if (/[\u0000-\u001f\u007f]/.test(t.replace(/\n/g, ''))) errors.push(`${where} contains control characters`);
  return t;
}

/** Which matcher kinds a signature uses. */
export function matcherKinds(m: AppMatchers): MatchKind[] {
  const kinds: MatchKind[] = [];
  if (m.syslog_program.length) kinds.push('syslog_program');
  if (m.parser.length) kinds.push('parser');
  if (m.service.names.length || m.service.banner.length) kinds.push('service');
  if (m.container_image.length) kinds.push('container_image');
  if (m.package.length) kinds.push('package');
  if (m.user_agent.length) kinds.push('user_agent');
  if (m.dns.length) kinds.push('dns');
  if (m.os) kinds.push('os');
  return kinds;
}

/** Every regex a signature runs (for the ReDoS check). */
export function collectAppRegexes(app: Pick<AppSignature, 'match'>): Array<{ location: string; source: string; flags: string }> {
  const out: Array<{ location: string; source: string; flags: string }> = [];
  app.match.service.banner.forEach((source, i) => out.push({ location: `match.service.banner[${i}]`, source, flags: '' }));
  app.match.user_agent.forEach((source, i) => out.push({ location: `match.user_agent[${i}]`, source, flags: '' }));
  if (app.match.os?.pretty_name) out.push({ location: 'match.os.pretty_name', source: app.match.os.pretty_name, flags: '' });
  return out;
}

function parseTests(v: unknown, errors: string[]): AppTest[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) {
    errors.push('tests must be a list');
    return [];
  }
  if (v.length > APP_LIMITS.tests) errors.push(`tests has more than ${APP_LIMITS.tests} entries`);
  const out: AppTest[] = [];
  v.forEach((t, i) => {
    const where = `tests[${i}]`;
    if (!isObj(t)) {
      errors.push(`${where} must be a mapping`);
      return;
    }
    for (const k of Object.keys(t)) if (!TEST_KEYS.includes(k)) errors.push(`${where}: unknown key "${k}"`);
    const source = t.source as MatchKind;
    if (!MATCH_KINDS.includes(source)) {
      errors.push(`${where}.source must be one of ${MATCH_KINDS.join(', ')}`);
      return;
    }
    let input: AppTest['input'];
    if (source === 'service' || source === 'os') {
      if (!isObj(t.input)) {
        errors.push(`${where}.input must be a mapping (${source === 'service' ? 'name, banner, version' : 'family, pretty_name'})`);
        return;
      }
      const allowed = source === 'service' ? ['name', 'banner', 'version'] : ['family', 'pretty_name'];
      const obj: Record<string, string> = {};
      for (const [k, val] of Object.entries(t.input)) {
        if (!allowed.includes(k)) errors.push(`${where}.input: unknown key "${k}"`);
        else if (typeof val !== 'string' || val.length > APP_LIMITS.testInput) errors.push(`${where}.input.${k} must be a string up to ${APP_LIMITS.testInput} characters`);
        else obj[k] = val;
      }
      input = obj;
    } else {
      if (typeof t.input !== 'string' || t.input.length === 0 || t.input.length > APP_LIMITS.testInput) {
        errors.push(`${where}.input must be a string of 1 to ${APP_LIMITS.testInput} characters`);
        return;
      }
      input = t.input;
    }
    let version: string | null | undefined;
    if (t.version === null) version = null;
    else if (t.version !== undefined) {
      if (typeof t.version !== 'string' && typeof t.version !== 'number') {
        errors.push(`${where}.version must be a string (quote it) or null`);
        return;
      }
      version = String(t.version);
    }
    if (t.match !== undefined && typeof t.match !== 'boolean') errors.push(`${where}.match must be true or false`);
    out.push({ source, input, version, match: t.match !== false });
  });
  return out;
}

/**
 * Validate one signature document. `strict` (the CLI) also refuses unknown
 * keys and requires tests for every matcher kind; non-strict (the app reading
 * a newer catalog) only warns about unknown keys.
 */
export function validateApplication(doc: unknown, opts: { strict?: boolean; expectId?: string } = {}): AppValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const unknownKey = (msg: string) => (opts.strict ? errors : warnings).push(msg);
  if (!isObj(doc)) return { ok: false, errors: ['a signature must be a YAML mapping'], warnings };

  for (const k of Object.keys(doc)) if (!TOP_KEYS.includes(k)) unknownKey(`unknown key "${k}"`);
  if (doc.schema !== APP_SCHEMA) errors.push(`schema must be "${APP_SCHEMA}"`);

  const id = typeof doc.id === 'string' ? doc.id : '';
  if (!id) errors.push('id is required');
  else if (!SLUG_RE.test(id) || id.length > APP_LIMITS.id) errors.push(`id "${id}" must be kebab-case (a-z, 0-9, -), at most ${APP_LIMITS.id} characters`);
  if (opts.expectId !== undefined && id && id !== opts.expectId) errors.push(`id "${id}" must match the file name (${opts.expectId}${APP_FILE_SUFFIX})`);

  const name = text(doc.name, 'name', APP_LIMITS.name, errors, true);
  const vendor = text(doc.vendor, 'vendor', APP_LIMITS.vendor, errors, true);
  const description = text(doc.description, 'description', APP_LIMITS.description, errors, false);
  const category = doc.category as AppCategory;
  if (!APP_CATEGORIES.includes(category)) errors.push(`category must be one of ${APP_CATEGORIES.join(', ')}`);

  let website: string | null = null;
  if (doc.website !== undefined && doc.website !== null) {
    if (typeof doc.website !== 'string' || !URL_RE.test(doc.website) || doc.website.length > APP_LIMITS.website) errors.push('website must be an http(s) URL');
    else website = doc.website;
  }

  let cpe: AppSignature['cpe'] = null;
  if (doc.cpe !== undefined && doc.cpe !== null) {
    if (!isObj(doc.cpe)) errors.push('cpe must be a mapping with vendor and product');
    else {
      for (const k of Object.keys(doc.cpe)) if (k !== 'vendor' && k !== 'product') unknownKey(`cpe: unknown key "${k}"`);
      const v = doc.cpe.vendor;
      const p = doc.cpe.product;
      if (typeof v !== 'string' || !CPE_PART_RE.test(v)) errors.push('cpe.vendor must be a CPE vendor (lower case, a-z 0-9 _ . -)');
      if (typeof p !== 'string' || !CPE_PART_RE.test(p)) errors.push('cpe.product must be a CPE product (lower case, a-z 0-9 _ . -)');
      if (typeof v === 'string' && typeof p === 'string') cpe = { vendor: v, product: p };
    }
  }

  const supersedes = strList(doc.supersedes, 'supersedes', errors, pattern(SLUG_RE, 'application id'));
  if (id && supersedes.includes(id)) errors.push('supersedes lists the application itself');

  const match: AppMatchers = {
    syslog_program: [],
    parser: [],
    service: { names: [], banner: [] },
    container_image: [],
    package: [],
    user_agent: [],
    dns: [],
    os: null,
  };
  if (!isObj(doc.match)) {
    errors.push('match is required (a mapping of matchers)');
  } else {
    const m = doc.match;
    for (const k of Object.keys(m)) if (!MATCH_KEYS.includes(k)) unknownKey(`match: unknown key "${k}"`);
    match.syslog_program = strList(m.syslog_program, 'match.syslog_program', errors, pattern(PROGRAM_RE, 'program name'), { lower: true });
    match.parser = strList(m.parser, 'match.parser', errors, pattern(PARSER_NAME_RE, 'parser name'));
    if (m.service !== undefined && m.service !== null) {
      if (!isObj(m.service)) errors.push('match.service must be a mapping (names, banner)');
      else {
        for (const k of Object.keys(m.service)) if (!SERVICE_KEYS.includes(k)) unknownKey(`match.service: unknown key "${k}"`);
        match.service.names = strList(m.service.names, 'match.service.names', errors, pattern(SERVICE_NAME_RE, 'nmap service name'), { lower: true });
        match.service.banner = strList(m.service.banner, 'match.service.banner', errors, signatureRegexProblem);
      }
    }
    match.container_image = strList(m.container_image, 'match.container_image', errors, imageGlobProblem).map(normalizeImageName);
    match.package = strList(m.package, 'match.package', errors, pattern(PACKAGE_RE, 'package name'), { lower: true });
    match.user_agent = strList(m.user_agent, 'match.user_agent', errors, signatureRegexProblem);
    match.dns = strList(m.dns, 'match.dns', errors, domainMatcherProblem);
    if (m.os !== undefined && m.os !== null) {
      if (!isObj(m.os)) errors.push('match.os must be a mapping (family, pretty_name)');
      else {
        for (const k of Object.keys(m.os)) if (!OS_KEYS.includes(k)) unknownKey(`match.os: unknown key "${k}"`);
        const family = m.os.family;
        if (typeof family !== 'string' || !(OS_FAMILIES as readonly string[]).includes(family)) errors.push(`match.os.family must be one of ${OS_FAMILIES.join(', ')}`);
        let pretty: string | null = null;
        if (m.os.pretty_name !== undefined && m.os.pretty_name !== null) {
          if (typeof m.os.pretty_name !== 'string') errors.push('match.os.pretty_name must be a regex string');
          else {
            const problem = signatureRegexProblem(m.os.pretty_name);
            if (problem) errors.push(`match.os.pretty_name ${problem}`);
            else pretty = m.os.pretty_name;
          }
        }
        if (typeof family === 'string') match.os = { family, pretty_name: pretty };
      }
    }
    if (matcherKinds(match).length === 0 && errors.length === 0) errors.push('match has no matchers');
  }

  const tests = parseTests(doc.tests, errors);
  if (opts.strict && errors.length === 0) {
    for (const kind of matcherKinds(match)) {
      if (!tests.some((t) => t.source === kind && t.match)) errors.push(`tests: add at least one matching test for match.${kind}`);
    }
    for (const t of tests) {
      if (!matcherKinds(match).includes(t.source)) errors.push(`tests: a ${t.source} test, but the signature has no match.${t.source}`);
    }
  }

  if (errors.length > 0) return { ok: false, errors, warnings };
  return {
    ok: true,
    errors,
    warnings,
    app: { id, name, vendor, category, description, website, cpe, supersedes, match, tests },
  };
}

/**
 * Problems across a set of signatures: duplicate ids, supersedes that name no
 * signature in the set, and one matcher value claimed by two applications
 * (the inventory could not say which one it is). Pure.
 */
export function crossCheckApplications(apps: AppSignature[], opts: { checkSupersedes?: boolean } = {}): Array<{ id: string; error: string }> {
  const problems: Array<{ id: string; error: string }> = [];
  const ids = new Set<string>();
  for (const a of apps) {
    if (ids.has(a.id)) problems.push({ id: a.id, error: `application id "${a.id}" is used twice` });
    ids.add(a.id);
  }
  if (opts.checkSupersedes !== false) {
    for (const a of apps) for (const s of a.supersedes) if (!ids.has(s)) problems.push({ id: a.id, error: `supersedes "${s}", which is not a signature in this catalog` });
  }
  const claims = new Map<string, string>();
  const claim = (a: AppSignature, kind: string, value: string) => {
    const key = `${kind}\u0000${value}`;
    const other = claims.get(key);
    if (other && other !== a.id) problems.push({ id: a.id, error: `match.${kind} "${value}" is also claimed by ${other}` });
    else claims.set(key, a.id);
  };
  for (const a of apps) {
    a.match.syslog_program.forEach((v) => claim(a, 'syslog_program', v));
    a.match.parser.forEach((v) => claim(a, 'parser', v));
    a.match.service.names.forEach((v) => claim(a, 'service.names', v));
    a.match.service.banner.forEach((v) => claim(a, 'service.banner', v));
    a.match.container_image.forEach((v) => claim(a, 'container_image', v));
    a.match.package.forEach((v) => claim(a, 'package', v));
    a.match.user_agent.forEach((v) => claim(a, 'user_agent', v));
    a.match.dns.forEach((v) => claim(a, 'dns', v));
    if (a.match.os) claim(a, 'os', `${a.match.os.family}|${a.match.os.pretty_name ?? ''}`);
  }
  return problems;
}
