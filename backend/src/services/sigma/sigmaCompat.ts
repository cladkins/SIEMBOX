/**
 * Which SigmaHQ rules can engage on this install's logs (DB-free, unit-tested).
 *
 * A converted Sigma rule is "compatible" when, for one of its parts, some
 * parser's recent parsed logs carry every field the part's conditions need:
 * the rule can engage on logs this install actually produces. Otherwise it is
 * "no matching logs yet", naming the first field no parser emits.
 *
 * Fields alone decide, not a match: most Sigma rules detect attacks, and an
 * attack in the last day's sample is the exception, so "a sample satisfied
 * the rule" would hide nearly every useful rule. The dry run still runs, with
 * the same evaluator as the detection recommendations
 * (detectionRecommendations.conditionsMatchSample, exclude groups included),
 * to report how many sampled logs the rule would have fired on: a rule that
 * matches routine traffic is a noisy one.
 *
 * A SIEMBox rule has no log source filter: a converted Sigma rule runs on
 * every parsed log. So a part also has to fit the rule's Sigma logsource: it
 * counts only for parsers whose name, or the `service` their logs carry, fits
 * it (LOGSOURCE_HINTS). Otherwise a GitHub audit rule keyed on `action` would
 * be "compatible" with a firewall parser that also has an `action` field, and
 * a keyword rule (Sigma `keywords`, a regex on the raw `message`) for SQL
 * servers would fire on every firewall log that says "DROP".
 *
 * Bounded: planSigmaCompat precomputes the fields each parser's samples carry
 * and keeps only the part/parser pairs with every field, before any regex
 * runs (most of SigmaHQ keys on Windows fields no parser emits);
 * countSigmaMatches runs only those pairs, in the regex test pool.
 */
import { conditionsMatchSample } from '../rules/detectionRecommendations';

type Cond = { field: string; operator: string; value?: any };

export interface CompatPart {
  conditions: Cond[];
  exclude?: Cond[][];
}

export interface CompatCandidate {
  sigma_id: string;
  product?: string | null;
  category?: string | null;
  service?: string | null;
  parts: CompatPart[];
}

export interface CompatSource {
  parser_name: string;
  samples: Array<Record<string, any>>;
}

export interface CompatParser {
  parser_name: string;
  /** Parts (0-based) whose fields this parser's logs carry. */
  parts: number[];
  /** Sampled logs a part would have fired on (absent when the dry run did not run). */
  matched?: number;
  sampled: number;
}

export interface CompatResult {
  compatible: boolean;
  parsers: CompatParser[];
  /** Not compatible: the first field of the rule that no sampled parser emits. */
  missing_field?: string;
  /** Not compatible: parsers have the fields, but none fits the rule's logsource ("product github"). */
  logsource_mismatch?: string;
  /** Some part searches the raw message for keywords. */
  keyword: boolean;
}

/** Work for the bounded dry run: per compatible rule, the part/parser pairs to evaluate. */
export interface CompatPairs {
  sigma_id: string;
  pairs: Array<{ part: CompatPart; index: number; source: number }>;
}

/**
 * Parser-name (or `service` value) fragments that fit a Sigma logsource. Keys
 * are `service:`, `category:` or `product:` values, most specific first; a
 * logsource with no entry falls back to its own name (product "okta" fits a
 * parser named okta-audit).
 */
export const LOGSOURCE_HINTS: Record<string, string[]> = {
  'category:webserver': ['nginx', 'apache', 'httpd', 'caddy', 'traefik', 'haproxy', 'proxy-manager', 'access'],
  'category:proxy': ['squid', 'proxy', 'traefik', 'haproxy', 'nginx', 'caddy', 'access'],
  'category:firewall': ['firewall', 'netfilter', 'iptables', 'nftables', 'pfsense', 'opnsense', 'ufw'],
  'category:dns': ['dns', 'pihole', 'pi-hole', 'bind', 'unbound', 'adguard', 'dnsmasq'],
  'category:database': ['postgres', 'mysql', 'mariadb', 'mssql', 'database'],
  'category:antivirus': ['clamav', 'antivirus', 'defender'],
  'service:apache': ['apache', 'httpd'],
  'service:nginx': ['nginx'],
  'service:sshd': ['ssh'],
  'service:sudo': ['sudo'],
  'service:auth': ['ssh', 'sudo', 'pam', 'login'],
  'service:syslog': ['syslog', 'linux', 'kernel', 'journal'],
  'service:cron': ['cron'],
  'service:vsftpd': ['vsftpd', 'ftp'],
  'service:auditd': ['auditd', 'audit'],
  'product:linux': ['linux', 'syslog', 'kernel', 'journal', 'ssh', 'sudo', 'pam', 'cron', 'audit'],
  'product:zeek': ['zeek', 'bro'],
};

/** Fields that have a value in at least one sample. */
export function fieldPresence(samples: Array<Record<string, any>>): Set<string> {
  const out = new Set<string>();
  for (const s of samples) {
    if (!s || typeof s !== 'object') continue;
    for (const [k, v] of Object.entries(s)) if (v !== undefined && v !== null) out.add(k);
  }
  return out;
}

/** The fields a part needs present (`exists: false` is the only condition that does not). */
export function requiredFields(part: CompatPart): string[] {
  const out: string[] = [];
  for (const c of part.conditions) {
    if (c.operator === 'exists' && c.value === false) continue;
    if (!out.includes(c.field)) out.push(c.field);
  }
  return out;
}

/** A keyword part: a regex on the raw message (how sigmaConvert renders Sigma `keywords`). */
export function isKeywordPart(part: CompatPart): boolean {
  return part.conditions.some((c) => c.field === 'message' && c.operator === 'regex');
}

/** The rule's logsource as a label and the fragments that fit it (none: no logsource, every parser fits). */
export function sigmaLogsource(c: Pick<CompatCandidate, 'product' | 'category' | 'service'>): { label: string; hints: string[] } {
  for (const [kind, value] of [
    ['service', c.service],
    ['category', c.category],
    ['product', c.product],
  ] as const) {
    if (!value) continue;
    return { label: `${kind} ${value}`, hints: LOGSOURCE_HINTS[`${kind}:${value}`] ?? [value] };
  }
  return { label: 'no logsource', hints: [] };
}

export function planSigmaCompat(
  candidates: CompatCandidate[],
  sources: CompatSource[]
): { results: Map<string, CompatResult>; pairs: CompatPairs[]; sources: CompatSource[] } {
  const live = sources.filter((s) => s.samples.length > 0);
  const presence = live.map((s) => fieldPresence(s.samples));
  // What each parser is, for the logsource check: its name and the services its logs name.
  const identity = live.map((s) => {
    const names = new Set([s.parser_name.toLowerCase()]);
    for (const d of s.samples) if (typeof d?.service === 'string') names.add(d.service.toLowerCase());
    return [...names];
  });
  const results = new Map<string, CompatResult>();
  const pairs: CompatPairs[] = [];

  for (const c of candidates) {
    const keyword = c.parts.some(isKeywordPart);
    const logsource = sigmaLogsource(c);
    const fitsLogsource = (i: number) =>
      logsource.hints.length === 0 || logsource.hints.some((h) => identity[i].some((n) => n.includes(h)));
    const byParser = new Map<number, CompatParser>();
    const work: CompatPairs['pairs'] = [];
    let missing: string | undefined;
    let logsourceMiss = false;

    c.parts.forEach((part, index) => {
      const need = requiredFields(part);
      // The parser closest to having every field names the first one missing.
      let closest = -1;
      let most = -1;
      presence.forEach((p, i) => {
        const n = need.filter((f) => p.has(f)).length;
        if (n > most) [closest, most] = [i, n];
      });
      const fits = presence.map((p, i) => (need.every((f) => p.has(f)) ? i : -1)).filter((i) => i >= 0);
      if (fits.length === 0) {
        missing ??= closest >= 0 ? need.find((f) => !presence[closest].has(f)) : need[0];
        return;
      }
      const usable = fits.filter(fitsLogsource);
      if (usable.length === 0) {
        logsourceMiss = true;
        return;
      }
      for (const i of usable) {
        const m = byParser.get(i) ?? { parser_name: live[i].parser_name, parts: [], sampled: live[i].samples.length };
        m.parts.push(index);
        byParser.set(i, m);
        work.push({ part, index, source: i });
      }
    });

    if (byParser.size > 0) {
      results.set(c.sigma_id, { compatible: true, parsers: [...byParser.values()], keyword });
      pairs.push({ sigma_id: c.sigma_id, pairs: work });
    } else if (logsourceMiss && !missing) {
      results.set(c.sigma_id, { compatible: false, parsers: [], keyword, logsource_mismatch: logsource.label });
    } else {
      results.set(c.sigma_id, {
        compatible: false,
        parsers: [],
        keyword,
        missing_field: missing ?? c.parts[0]?.conditions[0]?.field,

      });
    }
  }
  return { results, pairs, sources: live };
}

/**
 * The dry run: per compatible rule and parser, how many sampled logs some
 * part would have fired on. Pure; the route runs it in the regex test pool.
 */
export function countSigmaMatches(sources: CompatSource[], work: CompatPairs[]): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const item of work) {
    const perParser: Record<string, number> = {};
    const hits = new Map<number, Set<number>>();
    for (const { part, source } of item.pairs) {
      const seen = hits.get(source) ?? new Set<number>();
      hits.set(source, seen);
      sources[source].samples.forEach((data, si) => {
        if (seen.has(si)) return;
        try {
          if (conditionsMatchSample(part.conditions, data, part.exclude)) seen.add(si);
        } catch {
          /* a malformed condition never matches */
        }
      });
    }
    for (const [source, seen] of hits) perParser[sources[source].parser_name] = seen.size;
    out[item.sigma_id] = perParser;
  }
  return out;
}
