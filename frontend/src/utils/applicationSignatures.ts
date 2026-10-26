/**
 * The application signature editor's pure parts (components/applications/
 * SignatureEditor.vue): the form model and its conversion to and from the
 * catalog document (siembox.app/v1) and its YAML, the labels of the Not
 * identified kinds and the catalog statuses. No Vue, no network: unit-tested
 * in applicationSignatures.test.ts. The backend validates; nothing here
 * decides whether a signature is valid.
 */
import yaml from 'js-yaml';

export const SIGNATURE_SCHEMA = 'siembox.app/v1';

/** Same list as the backend's APP_CATEGORIES (appFormat.ts). */
export const APP_CATEGORIES = [
  'auth', 'automation', 'backup', 'browser', 'container-runtime', 'database', 'dev-tools', 'dns', 'file-sharing', 'game', 'home-automation',
  'http-client', 'mail', 'media-server', 'messaging', 'monitoring', 'network', 'operating-system', 'os-component', 'password-manager',
  'productivity', 'remote-access', 'reverse-proxy', 'saas', 'security', 'virtualization', 'vpn', 'web-server',
];

export const MATCH_KINDS = ['syslog_program', 'parser', 'service', 'container_image', 'package', 'user_agent', 'dns', 'os'] as const;
export type MatchKind = (typeof MATCH_KINDS)[number];

export const MATCH_KIND_LABELS: Record<MatchKind, { label: string; hint: string }> = {
  syslog_program: { label: 'Log program', hint: 'The program name in syslog lines, exact (case-insensitive). "postfix/*" also covers postfix/smtpd.' },
  parser: { label: 'Parser', hint: 'The name of the parser that matched the logs.' },
  service: { label: 'nmap service', hint: 'Service names (exact), and/or regexes on the product/version or banner (group 1 = version).' },
  container_image: { label: 'Container image', hint: 'Image names without the tag; * matches anything ("*/linuxserver/plex"). The tag is the version.' },
  package: { label: 'Package', hint: 'Installed package names (endpoint agents) and EDR findings, exact.' },
  user_agent: { label: 'User agent', hint: 'Regexes on the user agent; group 1 = version.' },
  dns: { label: 'DNS domain', hint: '"example.com" covers it and its subdomains, "*.example.com" only the subdomains.' },
  os: { label: 'Endpoint OS', hint: "The endpoint agent's OS family, and a regex on its PRETTY_NAME (group 1 = version)." },
};

/** The Not identified list's kinds (application_unmatched.source). */
export const UNMATCHED_KINDS = ['syslog_program', 'parser', 'container', 'package', 'service', 'user_agent', 'dns'] as const;
export const UNMATCHED_KIND_LABELS: Record<string, string> = {
  syslog_program: 'Log program',
  parser: 'Parser',
  container: 'Container image',
  package: 'Installed package',
  service: 'Network service',
  user_agent: 'User-agent product',
  dns: 'DNS domain',
};

export type CatalogStatus = 'not_in_catalog' | 'same' | 'differs';
export const CATALOG_STATUS: Record<CatalogStatus, { label: string; type: 'info' | 'success' | 'warning'; hint: string }> = {
  not_in_catalog: { label: 'Not in the catalog', type: 'info', hint: 'Only here. Use Contribute to validate it and propose it to the community catalog.' },
  same: { label: 'Same as catalog', type: 'success', hint: 'The catalog has this signature with the same content: the local copy can be deleted.' },
  differs: { label: 'Differs from catalog', type: 'warning', hint: "The catalog has this id with other content: your local copy overrides it here. Contribute it if the catalog's is wrong." },
};

export interface TestRow {
  source: MatchKind;
  /** A string input; for service and os the fields below. */
  input: string;
  name: string;
  banner: string;
  serviceVersion: string;
  family: string;
  prettyName: string;
  /** '' = not checked; 'none' = no version expected; otherwise the version. */
  version: string;
  shouldMatch: boolean;
}

export interface SignatureForm {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  website: string;
  cpeVendor: string;
  cpeProduct: string;
  supersedes: string[];
  syslog_program: string[];
  parser: string[];
  serviceNames: string[];
  serviceBanner: string[];
  container_image: string[];
  package: string[];
  user_agent: string[];
  dns: string[];
  osFamily: string;
  osPrettyName: string;
  tests: TestRow[];
}

export function emptyTest(source: MatchKind = 'syslog_program'): TestRow {
  return { source, input: '', name: '', banner: '', serviceVersion: '', family: 'linux', prettyName: '', version: '', shouldMatch: true };
}

export function emptyForm(): SignatureForm {
  return {
    id: '', name: '', vendor: '', category: '', description: '', website: '', cpeVendor: '', cpeProduct: '', supersedes: [],
    syslog_program: [], parser: [], serviceNames: [], serviceBanner: [], container_image: [], package: [], user_agent: [], dns: [],
    osFamily: '', osPrettyName: '', tests: [],
  };
}

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' || typeof x === 'number').map(String) : []);
const str = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);

/** A catalog document (as YAML loads it) as the form. Unknown keys are dropped (the YAML view keeps them). */
export function docToForm(doc: unknown): SignatureForm {
  const f = emptyForm();
  if (!isObj(doc)) return f;
  f.id = str(doc.id);
  f.name = str(doc.name);
  f.vendor = str(doc.vendor);
  f.category = str(doc.category);
  f.description = str(doc.description);
  f.website = str(doc.website);
  if (isObj(doc.cpe)) {
    f.cpeVendor = str(doc.cpe.vendor);
    f.cpeProduct = str(doc.cpe.product);
  }
  f.supersedes = strs(doc.supersedes);
  const m = isObj(doc.match) ? doc.match : {};
  f.syslog_program = strs(m.syslog_program);
  f.parser = strs(m.parser);
  if (isObj(m.service)) {
    f.serviceNames = strs(m.service.names);
    f.serviceBanner = strs(m.service.banner);
  }
  f.container_image = strs(m.container_image);
  f.package = strs(m.package);
  f.user_agent = strs(m.user_agent);
  f.dns = strs(m.dns);
  if (isObj(m.os)) {
    f.osFamily = str(m.os.family);
    f.osPrettyName = str(m.os.pretty_name);
  }
  f.tests = (Array.isArray(doc.tests) ? doc.tests : []).filter(isObj).map((t) => {
    const row = emptyTest((MATCH_KINDS as readonly string[]).includes(t.source) ? (t.source as MatchKind) : 'syslog_program');
    if (isObj(t.input)) {
      row.name = str(t.input.name);
      row.banner = str(t.input.banner);
      row.serviceVersion = str(t.input.version);
      row.family = str(t.input.family) || 'linux';
      row.prettyName = str(t.input.pretty_name);
    } else row.input = str(t.input);
    row.version = t.version === null ? 'none' : t.version === undefined ? '' : str(t.version);
    row.shouldMatch = t.match !== false;
    return row;
  });
  return f;
}

const clean = (list: string[]) => list.map((s) => s.trim()).filter(Boolean);

/** The form as a catalog document: keys in the catalog's order, empty fields and matchers left out. */
export function formToDoc(f: SignatureForm): Record<string, unknown> {
  const doc: Record<string, unknown> = { schema: SIGNATURE_SCHEMA, id: f.id.trim(), name: f.name.trim(), vendor: f.vendor.trim(), category: f.category };
  if (f.description.trim()) doc.description = f.description.trim();
  if (f.website.trim()) doc.website = f.website.trim();
  if (f.cpeVendor.trim() || f.cpeProduct.trim()) doc.cpe = { vendor: f.cpeVendor.trim(), product: f.cpeProduct.trim() };
  if (clean(f.supersedes).length) doc.supersedes = clean(f.supersedes);
  const match: Record<string, unknown> = {};
  if (clean(f.syslog_program).length) match.syslog_program = clean(f.syslog_program);
  if (clean(f.parser).length) match.parser = clean(f.parser);
  const names = clean(f.serviceNames);
  const banner = f.serviceBanner.filter((s) => s.length > 0);
  if (names.length || banner.length) {
    const service: Record<string, unknown> = {};
    if (names.length) service.names = names;
    if (banner.length) service.banner = banner;
    match.service = service;
  }
  if (clean(f.container_image).length) match.container_image = clean(f.container_image);
  if (clean(f.package).length) match.package = clean(f.package);
  const ua = f.user_agent.filter((s) => s.length > 0);
  if (ua.length) match.user_agent = ua;
  if (clean(f.dns).length) match.dns = clean(f.dns);
  if (f.osFamily) match.os = f.osPrettyName ? { family: f.osFamily, pretty_name: f.osPrettyName } : { family: f.osFamily };
  doc.match = match;
  doc.tests = f.tests.map((t) => {
    let input: unknown = t.input;
    if (t.source === 'service') {
      const o: Record<string, string> = { name: t.name.trim() };
      if (t.serviceVersion) o.version = t.serviceVersion;
      if (t.banner) o.banner = t.banner;
      input = o;
    } else if (t.source === 'os') {
      const o: Record<string, string> = { family: t.family };
      if (t.prettyName) o.pretty_name = t.prettyName;
      input = o;
    }
    const out: Record<string, unknown> = { source: t.source, input };
    if (t.version === 'none') out.version = null;
    else if (t.version.trim()) out.version = t.version.trim();
    if (!t.shouldMatch) out.match = false;
    return out;
  });
  return doc;
}

/** The document as YAML (block style, single quotes where quoting is needed). */
export function docToYaml(doc: unknown): string {
  return yaml.dump(doc, { lineWidth: -1, noRefs: true, quotingType: "'" });
}

/** YAML text as a document, or why it cannot be read. */
export function yamlToDoc(text: string): { doc: unknown; error: string | null } {
  try {
    return { doc: yaml.load(text), error: null };
  } catch (e) {
    return { doc: null, error: e instanceof Error ? e.message.split('\n')[0] : String(e) };
  }
}

/** A kebab-case id from a name ("Acme Server" -> "acme-server"). */
export function idFromName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

/** One list entry per line, for the matcher text areas. */
export function linesToList(text: string): string[] {
  return text.split('\n').map((s) => s.replace(/\r$/, ''));
}
export function listToLines(list: string[]): string {
  return list.join('\n');
}

/** A test's input in words, for the editor's list. */
export function testInputLabel(t: TestRow): string {
  if (t.source === 'service') return [t.name, t.serviceVersion, t.banner].filter(Boolean).join(' · ');
  if (t.source === 'os') return [t.family, t.prettyName].filter(Boolean).join(' · ');
  return t.input;
}

/** Which matcher kinds the form uses (each needs a test to be contributed). */
export function usedKinds(f: SignatureForm): MatchKind[] {
  const kinds: MatchKind[] = [];
  if (clean(f.syslog_program).length) kinds.push('syslog_program');
  if (clean(f.parser).length) kinds.push('parser');
  if (clean(f.serviceNames).length || f.serviceBanner.some(Boolean)) kinds.push('service');
  if (clean(f.container_image).length) kinds.push('container_image');
  if (clean(f.package).length) kinds.push('package');
  if (f.user_agent.some(Boolean)) kinds.push('user_agent');
  if (clean(f.dns).length) kinds.push('dns');
  if (f.osFamily) kinds.push('os');
  return kinds;
}

/** Kinds used with no matching test yet (the catalog needs one each). */
export function kindsWithoutTests(f: SignatureForm): MatchKind[] {
  return usedKinds(f).filter((k) => !f.tests.some((t) => t.source === k && t.shouldMatch));
}

/** The Not identified kind in words. */
export function unmatchedKindLabel(kind: string): string {
  return UNMATCHED_KIND_LABELS[kind] ?? kind;
}

/**
 * Several Not identified values believed to be one application: the first
 * one's draft, with the other drafts' matcher values and tests added.
 */
export function mergeDrafts(drafts: Array<Record<string, any>>): Record<string, any> {
  if (drafts.length === 0) return formToDoc(emptyForm());
  const first = JSON.parse(JSON.stringify(drafts[0]));
  first.match = isObj(first.match) ? first.match : {};
  first.tests = Array.isArray(first.tests) ? first.tests : [];
  const add = (key: string, values: unknown) => {
    const list: string[] = Array.isArray(first.match[key]) ? first.match[key] : [];
    for (const v of strs(values)) if (!list.includes(v)) list.push(v);
    if (list.length) first.match[key] = list;
  };
  for (const d of drafts.slice(1)) {
    const m = isObj(d.match) ? d.match : {};
    for (const key of ['syslog_program', 'parser', 'container_image', 'package', 'user_agent', 'dns']) add(key, m[key]);
    if (isObj(m.service)) {
      const svc = isObj(first.match.service) ? first.match.service : {};
      for (const key of ['names', 'banner']) {
        const list: string[] = Array.isArray(svc[key]) ? svc[key] : [];
        for (const v of strs(m.service[key])) if (!list.includes(v)) list.push(v);
        if (list.length) svc[key] = list;
      }
      first.match.service = svc;
    }
    for (const t of Array.isArray(d.tests) ? d.tests : []) first.tests.push(t);
  }
  return first;
}
