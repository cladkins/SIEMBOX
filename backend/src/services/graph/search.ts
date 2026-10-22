/**
 * GET /api/graph/search: what a typed string could mean, as at most 10
 * candidates. Small tables only; never parsed_logs or raw_logs.
 *
 *   1. A literal `type:key`: that entity (nothing else, even when invalid).
 *   2. An IP: ip:<it>, and the asset with that ip_address.
 *   3. `ALR-123`, `#123` or `alert 123`: that alert, if it exists.
 *   4. CVE-... or NUCLEI-...: the vulnerability with that id.
 *   5. Contains @: user:<q> (exact), and a monitored email identity for it.
 *   6. Host- or domain-like: assets by host name prefix (5), shippers by name
 *      or host name prefix (3), watched domains (3), host:<q>, domain:<q> (with
 *      a dot), user:<q> (without), and rules by name (3).
 *   7. Anything else: user:<q>, and rules by name (3).
 *
 * Hints come from cheap probes: alert counts in the last 30 days (counted
 * over at most 1,001 rows) for IP, user, host and domain candidates, and facts
 * of the records. Every LIKE pattern is escaped.
 */
import { MAX_ALERT_ID, parseAlertRef } from '../alerts/alertRef';
import { runBudgeted } from './budget';
import { badParam } from './errors';
import { canonicalDomain, canonicalHost, canonicalIp, canonicalUser, entityRef, isNodeType, tryParseEntity, type EntityRef } from './entityKey';
import { hydrate } from './hydrate';
import { hasUnsafeChars } from './labels';
import { withSlot, type Caller, type GraphDeps } from './neighborhood';
import { loadCenter, VALUE_TYPES } from './relations';
import { containsPattern, prefixPattern } from './resolvers/common';
import { countAlertsNaming } from './resolvers/alerts';
import { canExpandType, canSeeType, visibilityClass } from './visibility';
import { resolveWindow } from './window';
import type { GraphNode, SearchCandidate, SearchResponse } from './types';

export const MAX_QUERY = 200;
export const MAX_CANDIDATES = 10;

const ALERT_ID = /^(?:#|alert\s{0,3}#?)\s{0,3}([1-9][0-9]{0,9})$/i;
const VULN_ID = /^(?:cve|nuclei)-[\w.-]{1,100}$/i;
const HOST_LIKE = /^[a-z0-9_][a-z0-9_.-]{0,252}$/i;

/** The query, trimmed, or a 400. */
export function validateQuery(q: unknown): string {
  if (typeof q !== 'string') throw badParam('q is required (1-200 characters)');
  const trimmed = q.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_QUERY) throw badParam('q must be 1-200 characters');
  if (hasUnsafeChars(trimmed)) throw badParam('q may not contain control or bidi characters');
  return trimmed;
}

function hintFor(node: GraphNode, alerts: { total: number; capped: boolean } | null): string {
  const f = node.facts;
  const alertHint = alerts
    ? alerts.total === 0
      ? 'no alerts in 30 d'
      : `${alerts.capped ? '1,000+' : alerts.total} alert${alerts.total === 1 ? '' : 's'} in 30 d`
    : '';
  switch (node.type) {
    case 'alert':
      return [f.severity, f.status].filter(Boolean).join(' · ');
    case 'asset':
      return ['asset', f.ip, f.criticality].filter(Boolean).join(' · ');
    case 'vuln':
      return [f.severity, f.cvss !== null && f.cvss !== undefined ? `CVSS ${f.cvss}` : null].filter(Boolean).join(' · ');
    case 'rule':
      return ['rule', f.severity, f.enabled === false ? 'disabled' : null].filter(Boolean).join(' · ');
    case 'shipper':
      return ['shipper', f.status].filter(Boolean).join(' · ');
    case 'identity':
      return f.kind === 'email_domain' ? 'monitored email domain' : 'monitored identity';
    case 'domain':
      return [f.watched ? `watched (${f.watched})` : null, alertHint].filter(Boolean).join(' · ');
    default:
      return alertHint;
  }
}

/** The candidates for `q`, cached for 20 s per visibility class. */
export async function search(deps: GraphDeps, caller: Caller, rawQuery: unknown): Promise<SearchResponse> {
  const q = validateQuery(rawQuery);
  const minute = Math.floor(deps.now() / 60_000);
  const key = JSON.stringify(['search', visibilityClass(caller.role), q, minute]);
  const { value, cached } = await deps.cache.get(
    key,
    () => withSlot(deps, caller, () => computeSearch(deps, caller, q)),
    (result) => !result.incomplete
  );
  return { ...value.value, cached };
}

async function computeSearch(deps: GraphDeps, caller: Caller, q: string) {
  const started = deps.now();
  const role = caller.role;
  const window = resolveWindow({ window: '30d' }, deps.now());
  return runBudgeted(
    deps.acquire,
    async (budget) => {
      const refs: EntityRef[] = [];
      const add = (ref: EntityRef | null) => {
        if (ref && canSeeType(role, ref.type) && !refs.some((r) => r.id === ref.id)) refs.push(ref);
      };
      let incomplete = false;
      const lookup = async (label: string, sql: string, params: unknown[], type: 'asset' | 'alert' | 'vuln' | 'shipper' | 'identity' | 'rule') => {
        if (!canSeeType(role, type)) return;
        const result = await budget.step(`search:${label}`, (query) => query<{ id: string | number }>(sql, params));
        if (result.status !== 'ok') {
          incomplete = true;
          return;
        }
        for (const row of result.value) add(entityRef(type, String(row.id)));
      };

      const colon = q.indexOf(':');
      const literalType = colon > 0 ? q.slice(0, colon).trim().toLowerCase() : '';
      const ip = canonicalIp(q);
      if (!ip && isNodeType(literalType)) {
        // 1. A literal type:key: exactly that, if it is valid (and exists, for
        // records). Only a type the role may expand: a non-admin sees accounts
        // only as a sign-in alert names them, so it can't probe which exist.
        const ref = tryParseEntity(q);
        if (ref && canExpandType(role, ref.type)) {
          if (VALUE_TYPES.has(ref.type)) add(ref);
          else {
            const found = await budget.step('search:literal', (query) => loadCenter(query, ref));
            if (found.status === 'ok' && found.value.exists) add(ref);
            if (found.status !== 'ok') incomplete = true;
          }
        }
      } else if (ip) {
        // 2. An IP, and the asset that has it.
        add(entityRef('ip', ip));
        await lookup('asset-ip', `SELECT a.id FROM assets a WHERE a.ip_address = $1::inet LIMIT 1`, [ip], 'asset');
      } else if (ALERT_ID.test(q) || /^alr-/i.test(q)) {
        // 3. ALR-123 / #123 / alert 123.
        const id = ALERT_ID.test(q) ? Number(ALERT_ID.exec(q)![1]) : (parseAlertRef(q) ?? 0);
        if (id >= 1 && id <= MAX_ALERT_ID) await lookup('alert', `SELECT a.id FROM alerts a WHERE a.id = $1`, [id], 'alert');
      } else if (VULN_ID.test(q)) {
        // 4. CVE-... / NUCLEI-...
        await lookup('vuln', `SELECT v.id FROM vulnerabilities v WHERE v.cve_id = $1 OR v.cve_id = upper($1) ORDER BY v.id LIMIT 5`, [q], 'vuln');
      } else if (q.includes('@')) {
        // 5. An address: the user, and its monitored identity.
        add(canonicalUser(q) ? entityRef('user', canonicalUser(q)!) : null);
        await lookup(
          'identity',
          `SELECT i.id FROM monitored_identities i WHERE i.kind = 'email' AND i.value = lower($1) ORDER BY i.id LIMIT 3`,
          [q],
          'identity'
        );
      } else if (HOST_LIKE.test(q)) {
        // 6. Host- or domain-like.
        const prefix = prefixPattern(q.toLowerCase());
        await lookup(
          'assets',
          `SELECT a.id FROM assets a WHERE lower(a.hostname) LIKE $1 ESCAPE '\\' ORDER BY a.hostname, a.id LIMIT 5`,
          [prefix],
          'asset'
        );
        await lookup(
          'shippers',
          `SELECT s.id FROM log_shippers s WHERE lower(s.name) LIKE $1 ESCAPE '\\' OR lower(s.hostname) LIKE $1 ESCAPE '\\' ORDER BY s.name, s.id LIMIT 3`,
          [prefix],
          'shipper'
        );
        if (canSeeType(role, 'domain')) {
          const watched = await budget.step('search:watched', (query) =>
            query<{ domain: string }>(`SELECT wd.domain FROM watched_domains wd WHERE wd.domain LIKE $1 ESCAPE '\\' ORDER BY wd.domain LIMIT 3`, [prefix])
          );
          if (watched.status === 'ok') for (const row of watched.value) add(entityRef('domain', row.domain));
          else incomplete = true;
        }
        const host = canonicalHost(q);
        add(host ? entityRef('host', host) : null);
        const domain = q.includes('.') ? canonicalDomain(q) : null;
        add(domain ? entityRef('domain', domain) : null);
        if (!q.includes('.')) {
          const user = canonicalUser(q);
          add(user ? entityRef('user', user) : null);
        }
        await lookup('rules', `SELECT r.id FROM detection_rules r WHERE r.name ILIKE $1 ESCAPE '\\' ORDER BY r.name LIMIT 3`, [containsPattern(q)], 'rule');
      } else {
        // 7. Anything else: a user name, or a rule.
        const user = canonicalUser(q);
        add(user ? entityRef('user', user) : null);
        await lookup('rules', `SELECT r.id FROM detection_rules r WHERE r.name ILIKE $1 ESCAPE '\\' ORDER BY r.name LIMIT 3`, [containsPattern(q)], 'rule');
      }

      const chosen = refs.slice(0, MAX_CANDIDATES);
      const facts = await hydrate(budget, role, chosen, new Map());
      if (facts.partial) incomplete = true;
      const candidates: SearchCandidate[] = [];
      for (const ref of chosen) {
        if (facts.missing.has(ref.id)) continue;
        const node = facts.nodes.get(ref.id);
        if (!node) continue;
        let alerts: { total: number; capped: boolean } | null = null;
        if (VALUE_TYPES.has(ref.type)) {
          const centerInfo = { exists: true, row: null };
          const probe = await budget.step(`search:hint:${ref.type}`, (query) =>
            countAlertsNaming(query, { role, window, vulnStatus: 'open', center: ref, centerInfo })
          );
          if (probe.status === 'ok') alerts = probe.value;
          else incomplete = true;
        }
        candidates.push({ entity: ref.id, type: ref.type, label: node.label, hint: hintFor(node, alerts) });
      }
      return { value: { candidates, elapsed_ms: deps.now() - started }, incomplete };
    },
    deps.budget
  );
}
