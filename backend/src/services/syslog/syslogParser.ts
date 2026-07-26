import { logger } from '../../utils/logger';

export interface ParsedSyslog {
  timestamp: Date;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  appName: string | null;
  processId: string | null;
  shipperId: string | null;
  message: string;
}

/**
 * Strip ANSI / VT100 escape sequences (color codes, cursor moves) that many apps
 * emit on colorized stdout. They carry no analytical value and, left in, both
 * break ^-anchored parsers (the line starts with an ESC byte) and clutter the
 * UI/search. The two char classes in the CSI body are disjoint, so this is linear
 * (no ReDoS).
 */
export function stripAnsi(input: string): string {
  return input
    // CSI sequences incl. SGR colors: ESC '[' params intermediates final-byte.
    .replace(/\x1b\[[0-9;:?]*[ -/]*[@-~]/g, '')
    // Any remaining stray ESC bytes (OSC starts, lone escapes, etc.).
    .replace(/\x1b/g, '');
}

/**
 * UniFi devices (APs, gateways) use a device prefix — "<12-hex MAC>,<model>-<fw>" —
 * as their syslog TAG, with the real program name following inside the message
 * ("…18870: hostapd: wifi0ap5: STA …"). Detecting it lets us surface the actual
 * subsystem (hostapd/kernel/stahtd/…) as app_name instead of one junk app per device.
 */
const UNIFI_DEVICE_TAG = /^[0-9a-f]{12},\S+$/i;

/** What a re-extracted program name must look like (hostapd, kernel, ubnt-fanctrl, …). */
const PROGRAM_LIKE = /^[A-Za-z_][\w./-]*$/;

/**
 * Sanity check a TAG candidate. RFC 3164 tags are short program identifiers; when
 * a device logs an untagged line whose first ':' sits inside a value (UniFi
 * gateway iptables lines split at "MAC=28:70:…"), the naive first-colon split
 * produces "tags" full of key=value junk. Reject those and treat the line as
 * untagged instead, so the full message reaches the parsers intact.
 */
function isPlausibleTag(candidate: string): boolean {
  if (candidate.length > 64) return false;
  if (candidate.includes('=') || candidate.includes('"')) return false;
  // "CEF" before the first colon is the ArcSight CEF envelope ("CEF:0|vendor|…"),
  // not a syslog TAG — splitting it off would leave "0|vendor|…" in the message
  // and no CEF parser could ever match. Keep the whole line intact instead.
  if (/^CEF$/i.test(candidate)) return false;
  return true;
}

interface TagParts {
  appName: string;
  processId: string | null;
  shipperId: string | null;
  message: string;
}

/**
 * Extract TAG (app name and optionally process ID and/or shipper ID) from the
 * post-hostname remainder of an RFC 3164 line. Supports single- and multi-word
 * TAGs:
 *   "sshd[1234]: message"
 *   "Authentik Server: message"
 *   "nginx[a1b2c3d4]: message"           (with shipper ID)
 *   "sshd[1234][a1b2c3d4]: message"      (with both process ID and shipper ID)
 *
 * The TAG is everything before the FIRST colon (a tag never legitimately
 * contains one); the pid/shipper suffixes are then parsed off it end-anchored.
 * All patterns here are linear — this runs on every raw network packet, so
 * lazy-scan constructs like "(.+?)\[(\d+)\]:" (quadratic on hostile input, and
 * able to cross earlier colons and produce colon-filled junk app names) are
 * deliberately avoided.
 */
function extractTag(rest: string): TagParts | null {
  const firstColon = rest.match(/^([^:]+):(.*)$/);
  if (!firstColon) return null;
  const rawTag = firstColon[1];
  const message = firstColon[2].replace(/^\s+/, '');

  const both = rawTag.match(/^(.*)\[(\d+)\]\[([0-9a-f]{8})\]$/);
  if (both) {
    return { appName: both[1].trim(), processId: both[2], shipperId: both[3], message };
  }
  const shipper = rawTag.match(/^(.*)\[([0-9a-f]{8})\]$/);
  if (shipper) {
    return { appName: shipper[1].trim(), processId: null, shipperId: shipper[2], message };
  }
  const procId = rawTag.match(/^(.*)\[(\d+)\]$/);
  if (procId) {
    return { appName: procId[1].trim(), processId: procId[2], shipperId: null, message };
  }
  return { appName: rawTag.trim(), processId: null, shipperId: null, message };
}

/**
 * Parse a syslog message following RFC 3164 or RFC 5424
 * RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
 * RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MESSAGE
 */
export function parseSyslogMessage(rawMessage: string): ParsedSyslog {
  const originalMessage = rawMessage;
  // Strip ANSI/color escapes up front so they can't break ^-anchored parsers
  // downstream and never get stored or displayed (~1 in 6 shipped lines carries
  // them — colorized container stdout).
  rawMessage = stripAnsi(rawMessage);
  const result: ParsedSyslog = {
    timestamp: new Date(),
    facility: null,
    severity: null,
    hostname: null,
    appName: null,
    processId: null,
    shipperId: null,
    message: rawMessage,
  };

  try {
    // Extract PRI (priority) value: <number>
    const priMatch = rawMessage.match(/^<(\d+)>/);
    if (priMatch) {
      const priority = parseInt(priMatch[1], 10);
      result.facility = Math.floor(priority / 8);
      result.severity = priority % 8;

      // Remove PRI from message
      rawMessage = rawMessage.substring(priMatch[0].length);

      // Strip trailing newline/carriage return characters that break regex
      // matching. (Loop instead of /[\r\n]+$/ — quadratic on hostile input.)
      let end = rawMessage.length;
      while (end > 0 && (rawMessage[end - 1] === '\n' || rawMessage[end - 1] === '\r')) end--;
      if (end < rawMessage.length) rawMessage = rawMessage.slice(0, end);
    }

    // Try RFC 5424 format first (has VERSION after PRI). The message group
    // starts non-space so the \s+ separator owns the run (keeps it linear —
    // this runs on every raw network packet).
    const rfc5424Match = rawMessage.match(
      /^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.*)?$/
    );

    if (rfc5424Match) {
      // RFC 5424 format
      const [, _version, timestamp, hostname, appName, procId, _msgId, _structuredData, message] =
        rfc5424Match;

      result.timestamp = parseTimestamp(timestamp) || new Date();
      result.hostname = hostname !== '-' ? hostname : null;
      result.appName = appName !== '-' ? appName : null;
      result.processId = procId !== '-' ? procId : null;
      result.message = message ?? '';
    } else {
      // Try RFC 3164 format: TIMESTAMP HOSTNAME TAG: MESSAGE. As above, the
      // rest group starts non-space to keep the match linear.
      const rfc3164Pattern = /^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S.*)$/;
      const rfc3164Match = rawMessage.match(rfc3164Pattern);

      if (rfc3164Match) {
        const [, timestamp, hostname, rest] = rfc3164Match;

        result.timestamp = parseTimestamp(timestamp) || new Date();
        result.hostname = hostname;

        // UniFi AP tags — "<mac>,<model>-<fw>" with the real program following in
        // the message — are peeled BEFORE the generic cascade, whose pid/shipper
        // patterns would otherwise mis-split on brackets deeper in the line
        // ("…18870: syswrapper[16283]: …" must not become app "…18870: syswrapper").
        let tagSource = rest;
        let unifiDeviceTag: string | null = null;
        // [^\s:] keeps this linear on hostile input (\S here was quadratic).
        const unifiMatch = rest.match(/^([0-9a-f]{12},[^\s:]+):(.*)$/i);
        if (unifiMatch && UNIFI_DEVICE_TAG.test(unifiMatch[1])) {
          unifiDeviceTag = unifiMatch[1];
          // Trim the separator, then a possible empty middle field
          // ("…18870: : wevent: msg").
          tagSource = unifiMatch[2].replace(/^\s+/, '').replace(/^:\s*/, '');
        }

        const tag = extractTag(tagSource);
        if (unifiDeviceTag) {
          if (tag && isPlausibleTag(tag.appName) && PROGRAM_LIKE.test(tag.appName)) {
            result.appName = tag.appName;
            result.processId = tag.processId;
            result.shipperId = tag.shipperId;
            // Some daemons repeat their name ("stahtd: stahtd: msg") — drop the echo.
            result.message = tag.message.startsWith(`${tag.appName}: `)
              ? tag.message.slice(tag.appName.length + 2)
              : tag.message;
          } else {
            // No program-like tag in the remainder — keep the device tag as the app.
            result.appName = unifiDeviceTag;
            result.message = tagSource;
          }
          if (!result.hostname) result.hostname = unifiDeviceTag;
        } else if (tag && isPlausibleTag(tag.appName)) {
          result.appName = tag.appName;
          result.processId = tag.processId;
          result.shipperId = tag.shipperId;
          result.message = tag.message;
        } else if (tag) {
          // Tag candidate is key=value junk — an untagged line whose first ':' sits
          // inside a value (UniFi gateway iptables: "[PREROUTING-DNAT-4] DESCR=…
          // MAC=28:70:…"). Keep the whole line as the message so parsers see it intact.
          result.message = rest;
        } else {
          result.message = rest;
          logger.warn('Could not extract TAG from syslog', {
            original: originalMessage.substring(0, 80),
            rest: rest.substring(0, 80)
          });
        }

        // Older UniFi AP firmware puts the device tag in the HOSTNAME slot with its
        // trailing colon ("…18870: hostapd: msg" and no separate hostname) — clean it.
        if (result.hostname && /^[0-9a-f]{12},\S+:$/i.test(result.hostname)) {
          result.hostname = result.hostname.slice(0, -1);
        }

        // Log successful parsing
        if (result.appName) {
          logger.debug('Syslog parsed successfully', {
            original: originalMessage.substring(0, 80),
            extracted: result.message.substring(0, 80),
            appName: result.appName,
            hostname: result.hostname
          });
        }
      } else {
        logger.warn('RFC 3164 match failed', {
          original: originalMessage.substring(0, 80),
          afterPRI: rawMessage.substring(0, 80),
          messageLength: rawMessage.length,
          startsWithDigit: /^\d/.test(rawMessage),
          containsColon: rawMessage.includes(':'),
          firstSpace: rawMessage.indexOf(' ')
        });
      }
    }
  } catch (error) {
    logger.error('Error parsing syslog message:', { error, rawMessage: originalMessage.substring(0, 100) });
  }

  return result;
}

/**
 * Parse various timestamp formats commonly found in syslog
 */
function parseTimestamp(timestampStr: string): Date | null {
  try {
    // ISO 8601 format (RFC 5424): 2024-01-15T12:34:56.789Z
    if (timestampStr.includes('T')) {
      return new Date(timestampStr);
    }

    // BSD syslog format (RFC 3164): Jan 15 12:34:56
    const currentYear = new Date().getFullYear();
    const bsdMatch = timestampStr.match(/^(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)$/);

    if (bsdMatch) {
      const [, month, day, hour, minute, second] = bsdMatch;
      const monthMap: Record<string, number> = {
        Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
        Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
      };

      const monthNum = monthMap[month];
      if (monthNum !== undefined) {
        return new Date(
          currentYear,
          monthNum,
          parseInt(day),
          parseInt(hour),
          parseInt(minute),
          parseInt(second)
        );
      }
    }

    // Fallback: try to parse as-is
    const parsed = new Date(timestampStr);
    return isNaN(parsed.getTime()) ? null : parsed;
  } catch (error) {
    logger.error('Error parsing timestamp:', { error, timestampStr });
    return null;
  }
}

/**
 * Get facility name from facility code
 */
export function getFacilityName(facility: number): string {
  const facilities: Record<number, string> = {
    0: 'kern',
    1: 'user',
    2: 'mail',
    3: 'daemon',
    4: 'auth',
    5: 'syslog',
    6: 'lpr',
    7: 'news',
    8: 'uucp',
    9: 'cron',
    10: 'authpriv',
    11: 'ftp',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7',
  };

  return facilities[facility] || `unknown(${facility})`;
}

/**
 * Get severity name from severity code
 */
export function getSeverityName(severity: number): string {
  const severities: Record<number, string> = {
    0: 'emerg',
    1: 'alert',
    2: 'crit',
    3: 'err',
    4: 'warning',
    5: 'notice',
    6: 'info',
    7: 'debug',
  };

  return severities[severity] || `unknown(${severity})`;
}
