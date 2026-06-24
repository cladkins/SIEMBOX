/**
 * DB-free parse → derive → normalize pipeline.
 *
 * This is the single source of truth for "what fields does a parser produce for
 * a log line". The production engine (parserEngine) uses it on every log, and
 * the portable-parser validator / CI test runner uses it to self-test a parser
 * against its `test_samples` — WITHOUT a database — so a parser that passes CI
 * behaves identically once imported.
 *
 * It deliberately imports only pure modules (cef, derive, fieldNormalizer); it
 * must never pull in the DB layer or the rules engine.
 */
import { parseCefExtension } from './cef';
import { applyDerivations } from './derive';
import { normalizeParsedData } from '../normalize/fieldNormalizer';

/** Structural shape of a parser (a DB `Parser` row satisfies this). */
export interface ParserDef {
  name: string;
  parser_type: 'regex' | 'grok' | 'json';
  pattern: string;
  field_mappings: Record<string, string>;
  derivations?: any[] | null;
  event_type?: string | null;
}

export interface RunContext {
  /** The syslog packet sender (forwarder/observer) — fallback actor IP. */
  packetSourceIp?: string;
}

export interface RunResult {
  /** Canonical, normalized fields (what detection rules see). */
  fields: Record<string, any>;
  /** Resolved event type (parser column wins, else auto-derived). */
  event_type: string | null;
}

/**
 * Best-effort service name derived from the matched parser, used to populate the
 * canonical `service` field when the parser itself does not emit one (e.g. the
 * SSH parser implies service "sshd").
 */
export function deriveService(parserName: string): string | undefined {
  const n = (parserName || '').toLowerCase();
  if (n.includes('ssh')) return 'sshd';
  if (n.includes('sudo')) return 'sudo';
  if (n.includes('nginx')) return 'nginx';
  if (n.includes('traefik')) return 'traefik';
  if (n.includes('caddy')) return 'caddy';
  if (n.includes('vaultwarden')) return 'vaultwarden';
  if (n.includes('authelia')) return 'authelia';
  if (n.includes('authentik')) return 'authentik';
  if (n.includes('keycloak')) return 'keycloak';
  if (n.includes('home-assistant') || n.includes('homeassistant')) return 'home-assistant';
  if (n.includes('nextcloud')) return 'nextcloud';
  if (n.includes('pihole') || n.includes('pi-hole')) return 'pihole';
  if (n.includes('unifi')) return 'unifi';
  if (n.includes('jellyfin')) return 'jellyfin';
  if (n.includes('plex')) return 'plex';
  return undefined;
}

function determineEventType(parserName: string, fields: Record<string, any>): string {
  if (parserName.toLowerCase().includes('ssh')) {
    if (fields.event?.includes('Failed')) return 'ssh_failed_login';
    if (fields.event?.includes('Accepted')) return 'ssh_successful_login';
    return 'ssh_auth';
  } else if (parserName.toLowerCase().includes('vaultwarden')) {
    if (fields.event === 'login_failure') return 'vaultwarden_failed_login';
    if (fields.event === 'login_success') return 'vaultwarden_successful_login';
    if (fields.action === 'vault_export') return 'vaultwarden_vault_export';
    if (fields.event === 'device_registered') return 'vaultwarden_device_registered';
    return 'vaultwarden_event';
  } else if (parserName.toLowerCase().includes('apache') || parserName.toLowerCase().includes('nginx')) {
    return 'http_request';
  } else if (parserName.toLowerCase().includes('sudo')) {
    return 'sudo_command';
  } else if (parserName.toLowerCase().includes('firewall')) {
    return 'firewall_event';
  }
  return 'generic';
}

/**
 * Per-parser, declarative post-processing applied to the freshly-mapped fields:
 * CEF extension split, the parser's own data-driven `derivations`, and the shared
 * canonical `auth_outcome` marker. Contains NO per-parser branches by design.
 */
function postProcessFields(parser: ParserDef, fields: Record<string, any>): Record<string, any> {
  // CEF extension parsing: break the raw "key=value key=value ..." extension into
  // individual fields so src/dst/act/UNIFIipsSignature/etc. become queryable.
  if (typeof fields.extension === 'string' && fields.extension.length > 0) {
    for (const [key, value] of Object.entries(parseCefExtension(fields.extension))) {
      if (fields[key] === undefined) fields[key] = value;
    }
  }

  // Declarative, data-driven derivations carried by the parser — the portable
  // replacement for what used to be hardcoded per-parser blocks. ALL
  // parser-specific field logic lives as data and is applied generically here.
  applyDerivations(fields, parser.derivations);

  // Canonical authentication outcome shared across all auth parsers, so
  // cross-service rules (e.g. GEO-001) can key on one field regardless of each
  // parser's wording.
  if (fields.auth_outcome === undefined && fields.event !== undefined) {
    const e = String(fields.event).toLowerCase();
    if (e === 'failed password' || e === 'authentication failed' || e === 'login_failure') {
      fields.auth_outcome = 'failure';
    } else if (
      e === 'accepted password' ||
      e === 'accepted publickey' ||
      e === 'authentication success' ||
      e === 'login_success'
    ) {
      fields.auth_outcome = 'success';
    }
  }

  return fields;
}

function applyRegexParser(parser: ParserDef, message: string): { fields: Record<string, any>; event_type: string } | null {
  const regex = new RegExp(parser.pattern);
  const match = message.match(regex);
  if (!match) return null;

  const fields: Record<string, any> = {};
  if (match.groups) {
    // field_mappings is documented as {group: field}, but several seeded parsers
    // wrote it reversed as {field: group}. Accept BOTH directions so the value is
    // never silently dropped: prefer {group: field}, then fall back to {field: group}.
    for (const [a, b] of Object.entries(parser.field_mappings)) {
      if (match.groups[a] !== undefined) {
        fields[b] = match.groups[a];
      } else if (match.groups[b] !== undefined) {
        fields[a] = match.groups[b];
      }
    }
  } else {
    for (const [groupNum, fieldName] of Object.entries(parser.field_mappings)) {
      const index = parseInt(groupNum, 10);
      if (match[index] !== undefined) fields[fieldName] = match[index];
    }
  }

  // DEFAULT `message` to the raw line, but let an explicit field_mappings -> message
  // win so a parser can surface a cleaned-up message instead of the whole line.
  // (The JSON path already lets mappings own `message`; this keeps the two parser
  // types consistent. The full original line is always retained on the raw_logs
  // row, so there's no need to duplicate it into every parsed record here.)
  if (fields.message === undefined) fields.message = message;
  const processedFields = postProcessFields(parser, fields);
  return { fields: processedFields, event_type: determineEventType(parser.name, processedFields) };
}

/**
 * Resolve a dotted/indexed path within a parsed JSON object, e.g.
 * "request.client_ip" or "request.headers.User-Agent[0]". Returns undefined for
 * flat keys (the caller already tried those as a top-level lookup).
 */
function getJsonPath(obj: any, path: string): any {
  const parts = path.replace(/\[(\d+)\]/g, '.$1').split('.');
  if (parts.length < 2) return undefined;
  return parts.reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function applyJsonParser(parser: ParserDef, message: string): { fields: Record<string, any>; event_type: string } | null {
  try {
    let jsonString = message.trim();
    // Some applications prefix their JSON logs with labels like "Authentik Server: {...}".
    const jsonStart = jsonString.search(/[{[]/);
    if (jsonStart > 0) jsonString = jsonString.substring(jsonStart);

    const parsed = JSON.parse(jsonString);
    if (typeof parsed !== 'object' || parsed === null) return null;

    const fields: Record<string, any> = {};
    if (Object.keys(parser.field_mappings).length > 0) {
      for (const [sourceField, targetField] of Object.entries(parser.field_mappings)) {
        // Prefer an exact top-level key; fall back to a dotted path (e.g. Caddy's
        // "request.client_ip") so nested JSON logs can map nested values. Flat keys
        // always win, so existing flat-mapped parsers are unaffected.
        const value =
          parsed[sourceField] !== undefined ? parsed[sourceField] : getJsonPath(parsed, sourceField);
        if (value !== undefined) fields[targetField] = value;
      }
    } else {
      Object.assign(fields, parsed);
    }

    const processedFields = postProcessFields(parser, fields);
    return { fields: processedFields, event_type: determineEventType(parser.name, processedFields) };
  } catch {
    return null; // Not valid JSON
  }
}

/** Apply a parser to a raw message, returning post-processed (un-normalized) fields. */
function applyParser(parser: ParserDef, message: string): { fields: Record<string, any>; event_type: string } | null {
  switch (parser.parser_type) {
    case 'regex':
      return applyRegexParser(parser, message);
    case 'grok':
      // Grok is not fully implemented; fall back to regex (simplified conversion).
      return applyRegexParser(parser, message);
    case 'json':
      return applyJsonParser(parser, message);
    default:
      return null;
  }
}

/**
 * Run the full DB-free pipeline: match + map + derive + normalize. Returns the
 * canonical fields a detection rule would see, or null if the parser did not
 * match. Geo enrichment is intentionally NOT done here (environment-dependent);
 * the production engine adds it separately.
 */
export function runParser(parser: ParserDef, message: string, ctx: RunContext = {}): RunResult | null {
  const result = applyParser(parser, message);
  if (!result) return null;

  const event_type = parser.event_type || result.event_type || null;
  const fields = normalizeParsedData(result.fields, {
    packetSourceIp: ctx.packetSourceIp,
    eventType: event_type,
    service: deriveService(parser.name),
  });
  return { fields, event_type };
}
