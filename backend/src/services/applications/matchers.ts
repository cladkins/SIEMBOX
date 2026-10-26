/**
 * Matching evidence to application signatures. Pure and DB-free: the rollup
 * (rollup.ts) feeds it the values it aggregated, the validator runs each
 * signature's tests through it, and the tests feed it real data shapes.
 *
 * What each source looks like (and so what the matchers expect):
 *
 *   syslog_program  raw_logs.app_name: the RFC 3164 TAG with the pid and shipper
 *                   suffixes stripped (syslogParser.extractTag): "sshd",
 *                   "postfix/smtpd", "dockerd", a log shipper's tag or container
 *                   name ("plex", "vaultwarden"). Compared lower-cased.
 *   parser          parsers.name of the parser that matched the log, i.e. the
 *                   catalog parser name ("plex", "traefik-access").
 *   service         asset_services from an nmap scan: service_name ("ssh",
 *                   "postgresql", "ms-wbt-server"); service_version and banner
 *                   are filled only by scanners that report a product (nmap's
 *                   node-nmap mapping puts the TLS tunnel in banner, "ssl").
 *   container_image shipper_containers.image, the image reference docker ps
 *                   shows: "lscr.io/linuxserver/plex:1.40.0", "nginx:1.25-alpine",
 *                   "postgres:16", "ghcr.io/home-assistant/home-assistant:stable",
 *                   "image@sha256:...". The tag is the version when it starts
 *                   with a number.
 *   package         an EDR (grype) finding: package=<name> installed=<version>
 *                   in asset_vulnerabilities.evidence (edrService.edrVulnRow).
 *   user_agent      parsed_data.user_agent of web/proxy logs (nginx, Traefik,
 *                   Caddy, NPM, Authentik): "Mozilla/5.0 (...) Firefox/121.0",
 *                   "python-requests/2.31.0", "curl/8.0".
 *   dns             the queried name of a DNS log (Pi-hole: parsed_data.domain,
 *                   or .host for the JSON adblock export), lower case, no dot.
 *   os              edr_agents.os (runtime.GOOS: linux, windows, darwin) and
 *                   os_version (Linux: /etc/os-release PRETTY_NAME, e.g.
 *                   "Ubuntu 22.04.4 LTS"; otherwise the GOOS again).
 */
import { normalizeImageName, type AppSignature, type MatchKind } from './appFormat';

export interface AppMatch {
  appId: string;
  version: string | null;
}

/** Longest value the matchers look at (a user agent is truncated to this before it reaches them). */
export const MAX_MATCH_INPUT = 512;

/**
 * A version string as the inventory stores it: trimmed, at most 64
 * characters, starts with a digit (a leading v is dropped), only characters a
 * version uses. Anything else is no version.
 */
export function cleanVersion(v: string | null | undefined): string | null {
  if (v === null || v === undefined) return null;
  let s = String(v).trim();
  if (/^v\d/i.test(s)) s = s.slice(1);
  if (s.length === 0 || s.length > 64) return null;
  if (!/^\d[0-9A-Za-z.+~:_-]*$/.test(s)) return null;
  return s;
}

/** An image reference split into its normalized name and tag (no digest). */
export function parseImageRef(ref: string): { name: string; tag: string | null } | null {
  let r = ref.trim();
  if (r.length === 0 || r.length > 1024) return null;
  const at = r.indexOf('@');
  if (at >= 0) r = r.slice(0, at);
  if (/^(?:sha256:)?[0-9a-f]{12,64}$/i.test(r)) return null; // a bare image id: no name
  const slash = r.lastIndexOf('/');
  const colon = r.lastIndexOf(':');
  let tag: string | null = null;
  if (colon > slash) {
    tag = r.slice(colon + 1) || null;
    r = r.slice(0, colon);
  }
  const name = normalizeImageName(r);
  if (!name) return null;
  return { name, tag };
}

/**
 * The version an image tag names: "1.25.3-alpine" -> 1.25.3, "16" -> 16,
 * "v2.10.4" -> 2.10.4, "version-1.40.0.7998-c29d4c0c8" (LinuxServer) ->
 * 1.40.0.7998, "17.0.1-ls200" -> 17.0.1; "latest", "stable", "main" -> none.
 */
export function versionFromTag(tag: string | null): string | null {
  if (!tag) return null;
  const m = /^(?:v|version-|release-)?(\d+(?:\.\d+){0,5})/i.exec(tag);
  return m ? cleanVersion(m[1]) : null;
}

/** Glob match where * is any run of characters (slashes included). Linear-ish two-pointer walk, no regex. */
export function globMatch(pattern: string, value: string): boolean {
  let p = 0;
  let v = 0;
  let star = -1;
  let mark = 0;
  while (v < value.length) {
    if (p < pattern.length && pattern[p] !== '*' && pattern[p] === value[v]) {
      p++;
      v++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      mark = v;
    } else if (star >= 0) {
      p = star + 1;
      v = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

/** The domain a DNS log names, as matched: lower case, no trailing dot, plausible. */
export function cleanDomain(d: string | null | undefined): string | null {
  if (!d) return null;
  const s = String(d).trim().toLowerCase().replace(/\.+$/, '');
  if (s.length === 0 || s.length > 253 || !s.includes('.') || s.startsWith('.')) return null;
  if (!/^[a-z0-9_.-]+$/.test(s)) return null;
  return s;
}

/**
 * The product a user agent names, for the unmatched list: the first
 * product/version token, or the last one when the first is the browser
 * boilerplate "Mozilla" ("Mozilla/5.0 (...) Foo/1.2" -> Foo). Comments in
 * parentheses are skipped. Null when the agent has no product token.
 */
export function userAgentProduct(ua: string): string | null {
  const s = ua.slice(0, MAX_MATCH_INPUT);
  let depth = 0;
  let flat = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) flat += ch;
  }
  const tokens = flat
    .split(/\s+/)
    .map((t) => /^([A-Za-z][A-Za-z0-9._+-]{0,47})\/[^\s/]/.exec(t)?.[1])
    .filter((t): t is string => !!t);
  if (tokens.length === 0) {
    const bare = /^([A-Za-z][A-Za-z0-9._+-]{1,47})$/.exec(flat.trim());
    return bare ? bare[1] : null;
  }
  const generic = new Set(['mozilla', 'applewebkit', 'khtml', 'gecko', 'safari', 'version', 'mobile']);
  if (tokens[0].toLowerCase() === 'mozilla') {
    for (let i = tokens.length - 1; i >= 0; i--) if (!generic.has(tokens[i].toLowerCase())) return tokens[i];
    return tokens[tokens.length - 1];
  }
  return tokens[0];
}

interface CompiledRegex {
  appId: string;
  re: RegExp;
}

/** The compiled lookup structures for one signature set. */
export class AppIndex {
  readonly apps: Map<string, AppSignature>;
  private programs = new Map<string, string[]>();
  private programPrefixes: Array<{ prefix: string; appId: string }> = [];
  private parsers = new Map<string, string[]>();
  private serviceNames = new Map<string, string[]>();
  private banners: CompiledRegex[] = [];
  private images: Array<{ glob: string; appId: string }> = [];
  private packages = new Map<string, string[]>();
  private userAgents: CompiledRegex[] = [];
  private domainsExact = new Map<string, string[]>(); // "zoom.us": zoom.us and subdomains
  private domainsSub = new Map<string, string[]>(); // "*.plex.direct": subdomains only
  private os: Array<{ appId: string; family: string; re: RegExp | null }> = [];
  private supersedes = new Map<string, Set<string>>();
  private uaCache = new Map<string, AppMatch[]>();
  static readonly UA_CACHE_MAX = 20_000;

  /**
   * `skipRegex`: regex sources the safety gate refused (they are left out, the
   * rest of the signature still matches).
   */
  constructor(signatures: AppSignature[], opts: { skipRegex?: Set<string> } = {}) {
    const skip = opts.skipRegex ?? new Set<string>();
    this.apps = new Map(signatures.map((s) => [s.id, s]));
    const add = (map: Map<string, string[]>, key: string, appId: string) => {
      const list = map.get(key);
      if (!list) map.set(key, [appId]);
      else if (!list.includes(appId)) list.push(appId);
    };
    for (const s of signatures) {
      for (const p of s.match.syslog_program) {
        if (p.endsWith('/*')) this.programPrefixes.push({ prefix: p.slice(0, -1), appId: s.id });
        else add(this.programs, p, s.id);
      }
      for (const p of s.match.parser) add(this.parsers, p, s.id);
      for (const n of s.match.service.names) add(this.serviceNames, n, s.id);
      for (const b of s.match.service.banner) if (!skip.has(b)) this.banners.push({ appId: s.id, re: new RegExp(b) });
      for (const g of s.match.container_image) this.images.push({ glob: g, appId: s.id });
      for (const p of s.match.package) add(this.packages, p, s.id);
      for (const u of s.match.user_agent) if (!skip.has(u)) this.userAgents.push({ appId: s.id, re: new RegExp(u) });
      for (const d of s.match.dns) {
        if (d.startsWith('*.')) add(this.domainsSub, d.slice(2), s.id);
        else add(this.domainsExact, d, s.id);
      }
      if (s.match.os) {
        const pretty = s.match.os.pretty_name;
        if (!pretty || !skip.has(pretty)) this.os.push({ appId: s.id, family: s.match.os.family, re: pretty ? new RegExp(pretty) : null });
      }
      if (s.supersedes.length) this.supersedes.set(s.id, new Set(s.supersedes));
    }
  }

  get size(): number {
    return this.apps.size;
  }

  /** Drop matches another match in the same list supersedes; one entry per app (the first with a version wins). */
  private resolve(matches: AppMatch[]): AppMatch[] {
    if (matches.length === 0) return matches;
    const byApp = new Map<string, AppMatch>();
    for (const m of matches) {
      const prev = byApp.get(m.appId);
      if (!prev || (!prev.version && m.version)) byApp.set(m.appId, m);
    }
    const ids = [...byApp.keys()];
    const dropped = new Set<string>();
    for (const id of ids) for (const s of this.supersedes.get(id) ?? []) if (byApp.has(s)) dropped.add(s);
    return [...byApp.values()].filter((m) => !dropped.has(m.appId));
  }

  private plain(ids: string[] | undefined, version: string | null = null): AppMatch[] {
    return (ids ?? []).map((appId) => ({ appId, version }));
  }

  matchProgram(appName: string): AppMatch[] {
    const p = appName.trim().toLowerCase();
    if (!p) return [];
    const out = this.plain(this.programs.get(p));
    for (const { prefix, appId } of this.programPrefixes) if (p.startsWith(prefix) && p.length > prefix.length) out.push({ appId, version: null });
    return this.resolve(out);
  }

  matchParser(parserName: string): AppMatch[] {
    return this.resolve(this.plain(this.parsers.get(parserName)));
  }

  /** nmap service: by name (version = service_version), or by a banner regex (version = its group). */
  matchService(service: { name?: string | null; version?: string | null; banner?: string | null }): AppMatch[] {
    const out = this.plain(this.serviceNames.get((service.name ?? '').trim().toLowerCase()), cleanVersion(service.version));
    const texts = [service.banner, service.version].filter((t): t is string => typeof t === 'string' && t.length > 0).map((t) => t.slice(0, MAX_MATCH_INPUT));
    for (const { appId, re } of this.banners) {
      for (const t of texts) {
        const m = re.exec(t);
        if (m) {
          out.push({ appId, version: cleanVersion(m[1]) ?? cleanVersion(service.version) });
          break;
        }
      }
    }
    return this.resolve(out);
  }

  /** A container image reference; the version is the tag's. */
  matchImage(ref: string): AppMatch[] {
    const parsed = parseImageRef(ref);
    if (!parsed) return [];
    const version = versionFromTag(parsed.tag);
    const out: AppMatch[] = [];
    for (const { glob, appId } of this.images) if (globMatch(glob, parsed.name)) out.push({ appId, version });
    return this.resolve(out);
  }

  matchPackage(name: string, installedVersion?: string | null): AppMatch[] {
    return this.resolve(this.plain(this.packages.get(name.trim().toLowerCase()), cleanVersion(installedVersion)));
  }

  /** A user agent (truncated to MAX_MATCH_INPUT); results cached per distinct string. */
  matchUserAgent(ua: string): AppMatch[] {
    const s = ua.slice(0, MAX_MATCH_INPUT);
    const hit = this.uaCache.get(s);
    if (hit) return hit;
    const out: AppMatch[] = [];
    for (const { appId, re } of this.userAgents) {
      const m = re.exec(s);
      if (m) out.push({ appId, version: cleanVersion(m[1]) });
    }
    const result = this.resolve(out);
    if (this.uaCache.size >= AppIndex.UA_CACHE_MAX) this.uaCache.clear();
    this.uaCache.set(s, result);
    return result;
  }

  /** A queried domain: every suffix of it is looked up (a few map lookups). */
  matchDomain(domain: string): AppMatch[] {
    const d = cleanDomain(domain);
    if (!d) return [];
    const out: AppMatch[] = [];
    const labels = d.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const suffix = labels.slice(i).join('.');
      out.push(...this.plain(this.domainsExact.get(suffix)));
      if (i > 0) out.push(...this.plain(this.domainsSub.get(suffix)));
    }
    return this.resolve(out);
  }

  /** An EDR agent's OS: family (GOOS) and PRETTY_NAME. */
  matchOs(family: string | null | undefined, prettyName: string | null | undefined): AppMatch[] {
    const f = (family ?? '').trim().toLowerCase();
    const pretty = (prettyName ?? '').slice(0, MAX_MATCH_INPUT);
    const out: AppMatch[] = [];
    for (const o of this.os) {
      if (o.family !== f) continue;
      if (!o.re) {
        out.push({ appId: o.appId, version: null });
        continue;
      }
      const m = o.re.exec(pretty);
      if (m) out.push({ appId: o.appId, version: cleanVersion(m[1]) });
    }
    // A specific distribution beats the bare family.
    const specific = out.filter((m) => this.os.find((o) => o.appId === m.appId)?.re);
    return this.resolve(specific.length ? specific : out);
  }

  /** Run one signature test input through the matcher for its source. */
  matchTestInput(source: MatchKind, input: string | Record<string, string>): AppMatch[] {
    const str = typeof input === 'string' ? input : '';
    const obj = typeof input === 'string' ? {} : input;
    switch (source) {
      case 'syslog_program':
        return this.matchProgram(str);
      case 'parser':
        return this.matchParser(str);
      case 'service':
        return this.matchService({ name: obj.name, banner: obj.banner, version: obj.version });
      case 'container_image':
        return this.matchImage(str);
      case 'package':
        return this.matchPackage(str);
      case 'user_agent':
        return this.matchUserAgent(str);
      case 'dns':
        return this.matchDomain(str);
      case 'os':
        return this.matchOs(obj.family, obj.pretty_name);
    }
  }
}

/** The outcome of one signature's tests against a whole index. Pure. */
export function runAppTests(app: AppSignature, index: AppIndex): string[] {
  const failures: string[] = [];
  app.tests.forEach((t, i) => {
    const matches = index.matchTestInput(t.source, t.input);
    const mine = matches.find((m) => m.appId === app.id);
    const shown = typeof t.input === 'string' ? JSON.stringify(t.input) : JSON.stringify(t.input);
    if (!t.match) {
      if (mine) failures.push(`tests[${i}] (${t.source} ${shown}) must not match, but it does`);
      return;
    }
    if (!mine) {
      const others = matches.map((m) => m.appId).join(', ');
      failures.push(`tests[${i}] (${t.source} ${shown}) does not match${others ? ` (matches ${others} instead)` : ''}`);
      return;
    }
    if (t.version !== undefined && (mine.version ?? null) !== (t.version === null ? null : cleanVersion(t.version))) {
      failures.push(`tests[${i}] (${t.source} ${shown}) gives version ${mine.version ?? 'none'}, expected ${t.version ?? 'none'}`);
    }
  });
  return failures;
}
