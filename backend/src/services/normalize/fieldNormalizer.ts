/**
 * Canonical field schema + alias normalization for detection.
 *
 * Historically each parser emitted its own field names (`src_ip` vs `client_ip`
 * vs `source_ip`, `username` vs `user`, `request_uri` vs `path`, ...), while a
 * detection rule references exactly one name. The result was that a rule only
 * matched logs from parsers that happened to use the same spelling, so a large
 * share of rules silently never fired.
 *
 * This module fills a canonical set of fields, NON-DESTRUCTIVELY (originals are
 * kept), so every rule sees consistent field names regardless of which parser
 * produced the log. Normalization runs once, at parse time, so both rule
 * condition evaluation and the SQL-based aggregation see the canonical fields.
 *
 * Canonical fields (the names rules should use going forward):
 *   source_ip, source_port, dest_ip, dest_port, user, target_user, host,
 *   service, method, path, status_code, event_type, observer_ip
 */

/** canonical field -> synonyms that should populate it when it is absent. */
export const FIELD_ALIASES: Record<string, string[]> = {
  source_ip: ['src_ip', 'client_ip', 'remote_addr', 'remote_ip', 'ip_address', 'source_address', 'caller_ip'],
  source_port: ['src_port'],
  dest_ip: ['dst_ip', 'destination_ip', 'dest_address'],
  dest_port: ['dst_port'],
  user: ['username', 'user_name', 'remote_user', 'account', 'src_user', 'login_email', 'user_email'],
  target_user: ['dst_user', 'effective_user'],
  host: ['hostname', 'syslog_host', 'host_name'],
  service: ['program', 'process', 'process_name', 'application', 'app', 'logger'],
  method: ['http_method', 'http_verb'],
  path: ['request_uri', 'request_url', 'url', 'uri'],
  status_code: ['status', 'http_status', 'response_code'],
};

export interface NormalizeContext {
  /** The syslog packet sender (the forwarder/observer), e.g. the log shipper. */
  packetSourceIp?: string;
  /** Categorized event type (stored as a top-level column on the parsed log). */
  eventType?: string | null;
  /** Service derived from the matched parser (e.g. the SSH parser -> "sshd"). */
  service?: string;
}

function isEmpty(v: any): boolean {
  return v === undefined || v === null || v === '';
}

/**
 * Return a normalized copy of `fields` with canonical fields filled in.
 * Original keys are always preserved.
 */
export function normalizeParsedData(
  fields: Record<string, any>,
  context: NormalizeContext = {}
): Record<string, any> {
  const out: Record<string, any> = { ...fields };

  // 1) Fill each canonical field from the first present synonym.
  for (const [canonical, synonyms] of Object.entries(FIELD_ALIASES)) {
    if (isEmpty(out[canonical])) {
      for (const syn of synonyms) {
        if (!isEmpty(out[syn])) {
          out[canonical] = out[syn];
          break;
        }
      }
    }
  }

  // 2) service fallback from the matched parser (e.g. SSH parser -> "sshd").
  if (isEmpty(out.service) && !isEmpty(context.service)) {
    out.service = context.service;
  }

  // 3) source_ip: prefer an in-message IP; fall back to the packet sender so
  //    that logs without an embedded address still attribute to a source.
  if (isEmpty(out.source_ip) && !isEmpty(context.packetSourceIp)) {
    out.source_ip = context.packetSourceIp;
  }

  // 4) Mirror source_ip <-> client_ip so rules using either name still match.
  if (!isEmpty(out.source_ip) && isEmpty(out.client_ip)) out.client_ip = out.source_ip;
  if (!isEmpty(out.client_ip) && isEmpty(out.source_ip)) out.source_ip = out.client_ip;

  // 5) Always expose the forwarder/sender separately from the actor IP.
  if (!isEmpty(context.packetSourceIp) && isEmpty(out.observer_ip)) {
    out.observer_ip = context.packetSourceIp;
  }

  // 6) Surface the categorized event_type so rules can key on it.
  if (!isEmpty(context.eventType) && isEmpty(out.event_type)) {
    out.event_type = context.eventType as string;
  }

  return out;
}
