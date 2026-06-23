import { ParserModel, Parser } from '../../models/Parser';
import { RawLog } from '../../models/RawLog';
import { ParsedLogModel } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { RulesEngine } from '../rules/rulesEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { normalizeParsedData } from '../normalize/fieldNormalizer';
import { geoipService } from '../geoip/geoipService';
import { parseCefExtension } from './cef';

export class ParserEngine {
  private parsers: Parser[] = [];
  private rulesEngine: RulesEngine;

  constructor() {
    this.rulesEngine = RulesEngine.getInstance();
  }

  async initialize(): Promise<void> {
    try {
      // Load all enabled parsers from database, ordered by priority
      this.parsers = await ParserModel.findEnabled();
      logger.info(`Loaded ${this.parsers.length} parsers`);

      // Initialize rules engine
      await this.rulesEngine.initialize();
    } catch (error) {
      logger.error('Failed to initialize parser engine:', error);
      ErrorLogService.logBackgroundError('parser-engine', error, { dedupeKey: 'initialize' });
      throw error;
    }
  }

  async processLog(rawLog: RawLog): Promise<void> {
    try {
      let parsed = false;

      // Try each parser in priority order
      for (const parser of this.parsers) {
        const result = this.applyParser(parser, rawLog.raw_message);

        if (result) {
          // Parser matched, store parsed log
          // Use parser.event_type if set, otherwise use auto-determined event type
          const eventType = parser.event_type || result.event_type || null;

          // Normalize fields to the canonical schema so detection rules match
          // regardless of which parser (and field spelling) produced the log.
          const normalizedData = normalizeParsedData(result.fields, {
            packetSourceIp: rawLog.source_ip,
            eventType,
            service: this.deriveService(parser.name),
          });

          // GeoIP enrichment: derive country/country_code/geo_foreign from the
          // normalized actor IP. No-op (geo fields stay absent) when the MMDB is
          // missing or the IP is private/invalid. Never overwrite existing values.
          const geoIp = normalizedData.source_ip;
          if (geoIp && normalizedData.country === undefined && normalizedData.country_code === undefined) {
            const geo = geoipService.lookup(geoIp);
            if (geo) {
              normalizedData.country = geo.country_name;
              normalizedData.country_code = geo.country_code;
              if (normalizedData.geo_foreign === undefined) {
                normalizedData.geo_foreign = geoipService.isForeign(geo.country_code);
              }
            }
          }

          const parsedLog = await ParsedLogModel.create({
            raw_log_id: rawLog.id,
            parser_id: parser.id,
            parsed_data: normalizedData,
            timestamp: rawLog.timestamp,
            source_ip: rawLog.source_ip,
            event_type: eventType,
          });

          logger.debug('Log parsed successfully', {
            parser: parser.name,
            rawLogId: rawLog.id,
            parsedLogId: parsedLog.id,
          });

          // Run detection rules against parsed log
          await this.rulesEngine.evaluateLog(parsedLog);

          parsed = true;
          break; // Stop after first successful parse
        }
      }

      if (!parsed) {
        logger.debug('No parser matched for log', {
          rawLogId: rawLog.id,
          message: rawLog.raw_message.substring(0, 100),
        });
      }
    } catch (error) {
      logger.error('Error processing log:', { error, rawLogId: rawLog.id });
    }
  }

  /**
   * Best-effort service name derived from the matched parser, used to populate
   * the canonical `service` field when the parser itself does not emit one
   * (e.g. the SSH parser implies service "sshd").
   */
  private deriveService(parserName: string): string | undefined {
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

  private applyParser(
    parser: Parser,
    message: string
  ): { fields: Record<string, any>; event_type?: string } | null {
    try {
      switch (parser.parser_type) {
        case 'regex':
          return this.applyRegexParser(parser, message);
        case 'grok':
          return this.applyGrokParser(parser, message);
        case 'json':
          return this.applyJsonParser(parser, message);
        default:
          logger.warn(`Unknown parser type: ${parser.parser_type}`);
          return null;
      }
    } catch (error) {
      logger.error(`Error applying parser ${parser.name}:`, error);
      return null;
    }
  }

  private applyRegexParser(
    parser: Parser,
    message: string
  ): { fields: Record<string, any>; event_type?: string } | null {
    try {
      const regex = new RegExp(parser.pattern);
      const match = message.match(regex);

      if (!match) {
        return null;
      }

      const fields: Record<string, any> = {};

      // Map regex groups to field names using field_mappings.
      if (match.groups) {
        // field_mappings is documented as {groupName: fieldName}, but several
        // seeded parsers wrote it reversed as {fieldName: groupName} (e.g. SSH
        // "source_ip":"src_ip" where the regex group is actually `src_ip`).
        // Accept BOTH directions so the value is never silently dropped: prefer
        // {group: field}, then fall back to {field: group}.
        for (const [a, b] of Object.entries(parser.field_mappings)) {
          if (match.groups[a] !== undefined) {
            fields[b] = match.groups[a];
          } else if (match.groups[b] !== undefined) {
            fields[a] = match.groups[b];
          }
        }
      } else {
        // Numbered groups (match[1], match[2], etc.)
        for (const [groupNum, fieldName] of Object.entries(parser.field_mappings)) {
          const index = parseInt(groupNum, 10);
          if (match[index] !== undefined) {
            fields[fieldName] = match[index];
          }
        }
      }

      // Include the full message
      fields.message = message;

      // Post-process fields for specific parsers
      const processedFields = this.postProcessFields(parser.name, fields);

      // Determine event type from parser name or extracted fields
      const event_type = this.determineEventType(parser.name, processedFields);

      return { fields: processedFields, event_type };
    } catch (error) {
      logger.error(`Regex parser ${parser.name} error:`, error);
      return null;
    }
  }

  private applyGrokParser(
    parser: Parser,
    message: string
  ): { fields: Record<string, any>; event_type?: string } | null {
    // Grok parsing would require a grok library
    // For now, we'll use simplified grok-to-regex conversion
    // In production, use a library like 'node-grok' or 'grok-js'

    logger.warn('Grok parser not fully implemented, falling back to regex');
    return this.applyRegexParser(parser, message);
  }

  private applyJsonParser(
    parser: Parser,
    message: string
  ): { fields: Record<string, any>; event_type?: string } | null {
    try {
      // Strip common prefixes before parsing JSON
      // Some applications prefix their JSON logs with labels like "Authentik Server: {...}"
      let jsonString = message.trim();

      // Try to find JSON object/array in the message
      const jsonStart = jsonString.search(/[{\[]/);
      if (jsonStart > 0) {
        // There's text before the JSON, strip it
        jsonString = jsonString.substring(jsonStart);
        logger.debug('Stripped prefix from JSON message', {
          original: message.substring(0, 50),
          stripped: jsonString.substring(0, 50)
        });
      }

      // Try to parse message as JSON
      const parsed = JSON.parse(jsonString);

      if (typeof parsed !== 'object' || parsed === null) {
        return null;
      }

      // If field_mappings is provided, remap fields
      const fields: Record<string, any> = {};

      if (Object.keys(parser.field_mappings).length > 0) {
        for (const [sourceField, targetField] of Object.entries(parser.field_mappings)) {
          if (parsed[sourceField] !== undefined) {
            fields[targetField] = parsed[sourceField];
          }
        }
      } else {
        // No mapping, use all fields as-is
        Object.assign(fields, parsed);
      }

      // Run the same post-processing as the regex path so JSON parsers (e.g.
      // authentik) get their derivations and the shared auth_outcome marker.
      const processedFields = this.postProcessFields(parser.name, fields);

      const event_type = this.determineEventType(parser.name, processedFields);

      return { fields: processedFields, event_type };
    } catch (error) {
      // Not valid JSON
      return null;
    }
  }

  private postProcessFields(parserName: string, fields: Record<string, any>): Record<string, any> {
    // CEF extension parsing: break the raw "key=value key=value ..." extension
    // into individual fields so src/dst/act/UNIFIipsSignature/etc. become
    // queryable by rules instead of being trapped in one string. Applies to any
    // CEF parser (they capture a group named `extension`).
    if (typeof fields.extension === 'string' && fields.extension.length > 0) {
      for (const [key, value] of Object.entries(parseCefExtension(fields.extension))) {
        if (fields[key] === undefined) fields[key] = value;
      }
    }

    // Post-processing for Vaultwarden parser to derive action, event, and path fields
    if (parserName === 'vaultwarden-access' && fields.message) {
      const message = fields.message.toLowerCase();

      // Derive action field for vault operations
      if (message.includes('vault export')) {
        fields.action = 'vault_export';
      } else if (message.includes('vault import')) {
        fields.action = 'vault_import';
      } else if (message.includes('vault sync')) {
        fields.action = 'vault_sync';
      } else if (message.includes('vault accessed')) {
        fields.action = 'vault_access';
      }

      // Derive event field for authentication and device events
      // Real Vaultwarden wording (1.30+): "Username or password is incorrect",
      // "Invalid TOTP code!", "Invalid admin token", "logged in successfully".
      if (
        message.includes('username or password is incorrect') ||
        message.includes('invalid totp code') ||
        message.includes('invalid admin token') ||
        message.includes('this user has been disabled') ||
        message.includes('failed login') ||
        message.includes('invalid password')
      ) {
        fields.event = 'login_failure';
      } else if (
        message.includes('logged in successfully') ||
        message.includes('successful login')
      ) {
        fields.event = 'login_success';
      } else if (message.includes('did not complete a 2fa login')) {
        fields.event = 'login_2fa_incomplete';
      }

      // Derive path from module (approximation for API monitoring)
      if (fields.module) {
        const module = fields.module.toLowerCase();
        if (module.includes('::api::core')) {
          fields.path = '/api/core';
        } else if (module.includes('::api::identity')) {
          fields.path = '/api/identity';
        } else if (module.includes('::api::admin')) {
          fields.path = '/admin';
        } else if (module.includes('::api::')) {
          fields.path = '/api';
        }
      }

      // Ensure service field is always set
      fields.service = 'vaultwarden';
    }

    // SSO / auth portals (Authelia, authentik, Keycloak): derive a uniform
    // `event` failure/success marker so one cross-IdP rule (AUTH-007) matches
    // regardless of each vendor's wording. Authelia emits no event at all;
    // Keycloak's is a type like LOGIN_ERROR; authentik's is an action plus a
    // success flag.
    if (parserName === 'authelia-access' && fields.message) {
      const m = String(fields.message).toLowerCase();
      if (/unsuccessful|authentication failed|invalid|denied|\bfailed\b/.test(m)) {
        fields.event = 'authentication failed';
      } else if (/successful|authenticated/.test(m)) {
        fields.event = 'authentication success';
      }
    } else if (parserName === 'authentik-audit') {
      const evt = String(fields.event ?? '').toLowerCase();
      const success = String(fields.success ?? '').toLowerCase();
      if (success === 'false' || /fail|denied|invalid/.test(evt)) {
        fields.event = 'authentication failed';
      }
    } else if (parserName === 'keycloak-event') {
      if (/error/i.test(String(fields.event ?? ''))) {
        fields.event = 'authentication failed';
      }
    }

    // Home Assistant core log (home-assistant.log). The actionable lines come
    // from logger homeassistant.components.http.ban. Pull the client IP out of
    // the message (three shapes) and derive a uniform `event` marker. service
    // must be set explicitly because the normalizer otherwise treats `logger`
    // as the service.
    if (parserName === 'home-assistant' && fields.message) {
      const msg = String(fields.message);
      const ipMatch =
        msg.match(/Banned IP\s+(\d{1,3}(?:\.\d{1,3}){3})/) ||
        msg.match(/\bfrom\s+\S+\s+\((\d{1,3}(?:\.\d{1,3}){3})\)/) ||
        msg.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b/);
      if (ipMatch) {
        fields.client_ip = ipMatch[1];
        fields.source_ip = ipMatch[1];
      }
      const m = msg.toLowerCase();
      if (m.includes('banned ip') && m.includes('too many login attempts')) {
        fields.event = 'ip_banned';
      } else if (m.includes('invalid authentication')) {
        fields.event = 'login_failure';
      }
      fields.service = 'home-assistant';
    }

    // Jellyfin server log. Two actionable message shapes on the generic line:
    //   auth fail: Authentication request for "<user>" has been denied (IP: "<ip>")
    //   playback:  ...SessionManager: Playback start reported by app "<app>" "<ver>" playing "<title>"
    // The auth line carries user+IP; the playback line carries neither (IP comes
    // from the packet sender via the normalizer). service is set explicitly
    // because the normalizer treats the captured `category` as a service synonym.
    if (parserName === 'jellyfin' && fields.message) {
      const msg = String(fields.message);
      const denied = msg.match(
        /Authentication request for\s+"?(?<user>[^"]+?)"?\s+has been denied\s+\(IP:\s*"?(?<ip>\d{1,3}(?:\.\d{1,3}){3})"?\)/
      );
      if (denied && denied.groups) {
        fields.user = denied.groups.user;
        fields.client_ip = denied.groups.ip;
        fields.source_ip = denied.groups.ip;
        fields.event = 'login_failure';
      }
      const play = msg.match(
        /Playback start reported by app\s+"(?<app>[^"]*)"\s+"(?<appver>[^"]*)"\s+playing\s+"(?<item>[^"]*)"/
      );
      if (play && play.groups) {
        fields.event = 'playback_start';
        fields.client_app = play.groups.app;
        fields.media_item = play.groups.item;
      }
      fields.service = 'jellyfin';
    }

    // Plex Media Server log. The reliable per-event line is:
    //   Completed: [<ip:port>] <status> GET <uri> ...   -> client_ip + status_code
    // Playback start is a 200 on /:/timeline with state=playing; an auth failure
    // is a 401/403 (Plex delegates real auth to MyPlex). The username is on a
    // separate "[Now] User is <name>" line.
    if (parserName === 'plex' && fields.message) {
      const msg = String(fields.message);
      const completed = msg.match(
        /Completed:\s*\[(?<ip>[0-9a-fA-F:.]+?):\d+\]\s+(?<status>\d{3})\s+(?<method>GET|POST|PUT|DELETE|HEAD)\s+(?<uri>\S+)/
      );
      if (completed && completed.groups) {
        fields.client_ip = completed.groups.ip;
        fields.source_ip = completed.groups.ip;
        fields.status_code = completed.groups.status;
        fields.method = completed.groups.method;
        fields.request_uri = completed.groups.uri;
        if (/\/:\/timeline\b/.test(completed.groups.uri) && /[?&]state=playing\b/.test(completed.groups.uri)) {
          fields.event = 'playback_start';
        }
        if (completed.groups.status === '401' || completed.groups.status === '403') {
          fields.event = 'login_failure';
        }
      }
      const now = msg.match(/\[Now\]\s+User is\s+(?<user>.+?)\s+\(ID:\s*(?<uid>\d+)\)/);
      if (now && now.groups) {
        fields.user = now.groups.user;
        fields.user_id = now.groups.uid;
      }
      fields.service = 'plex';
    }

    // Canonical authentication outcome shared across all auth parsers, so
    // cross-service rules (e.g. GEO-001) can key on one field regardless of each
    // parser's wording: SSH "Failed password", SSO "authentication failed",
    // vaultwarden/HA/media "login_failure", etc.
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

  private determineEventType(parserName: string, fields: Record<string, any>): string {
    // Determine event type from parser name or field values
    if (parserName.toLowerCase().includes('ssh')) {
      if (fields.event?.includes('Failed')) {
        return 'ssh_failed_login';
      } else if (fields.event?.includes('Accepted')) {
        return 'ssh_successful_login';
      }
      return 'ssh_auth';
    } else if (parserName.toLowerCase().includes('vaultwarden')) {
      if (fields.event === 'login_failure') {
        return 'vaultwarden_failed_login';
      } else if (fields.event === 'login_success') {
        return 'vaultwarden_successful_login';
      } else if (fields.action === 'vault_export') {
        return 'vaultwarden_vault_export';
      } else if (fields.event === 'device_registered') {
        return 'vaultwarden_device_registered';
      }
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

  async testParser(parser: Parser, sample: string): Promise<any> {
    const result = this.applyParser(parser, sample);
    return result ? result.fields : null;
  }
}
