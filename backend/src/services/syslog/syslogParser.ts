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

      // Strip trailing newline/carriage return characters that break regex matching
      rawMessage = rawMessage.replace(/[\r\n]+$/, '');
    }

    // Try RFC 5424 format first (has VERSION after PRI)
    const rfc5424Match = rawMessage.match(
      /^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/
    );

    if (rfc5424Match) {
      // RFC 5424 format
      const [, _version, timestamp, hostname, appName, procId, _msgId, _structuredData, message] =
        rfc5424Match;

      result.timestamp = parseTimestamp(timestamp) || new Date();
      result.hostname = hostname !== '-' ? hostname : null;
      result.appName = appName !== '-' ? appName : null;
      result.processId = procId !== '-' ? procId : null;
      result.message = message;
    } else {
      // Try RFC 3164 format: TIMESTAMP HOSTNAME TAG: MESSAGE
      const rfc3164Pattern = /^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$/;
      const rfc3164Match = rawMessage.match(rfc3164Pattern);

      if (rfc3164Match) {
        const [, timestamp, hostname, rest] = rfc3164Match;

        result.timestamp = parseTimestamp(timestamp) || new Date();
        result.hostname = hostname;

        // Extract TAG (app name and optionally process ID and/or shipper ID)
        // Support both single-word and multi-word TAGs
        // Examples:
        //   "sshd[1234]: message"
        //   "Authentik Server: message"
        //   "nginx[a1b2c3d4]: message" (with shipper ID)
        //   "sshd[1234][a1b2c3d4]: message" (with both process ID and shipper ID)

        // Try to match with process ID and/or shipper ID
        // Pattern: appname[digits][8hexchars] or appname[digits] or appname[8hexchars] or appname
        const tagWithBothMatch = rest.match(/^(.+?)\[(\d+)\]\[([0-9a-f]{8})\]:\s*(.*)$/);
        const tagWithProcIdMatch = rest.match(/^(.+?)\[(\d+)\]:\s*(.*)$/);
        const tagWithShipperMatch = rest.match(/^(.+?)\[([0-9a-f]{8})\]:\s*(.*)$/);
        const tagPlainMatch = rest.match(/^(.+?):\s*(.*)$/);

        if (tagWithBothMatch) {
          const [, appName, procId, shipperId, message] = tagWithBothMatch;
          result.appName = appName.trim();
          result.processId = procId;
          result.shipperId = shipperId;
          result.message = message;
        } else if (tagWithShipperMatch) {
          const [, appName, shipperId, message] = tagWithShipperMatch;
          result.appName = appName.trim();
          result.processId = null;
          result.shipperId = shipperId;
          result.message = message;
        } else if (tagWithProcIdMatch) {
          const [, appName, procId, message] = tagWithProcIdMatch;
          result.appName = appName.trim();
          result.processId = procId;
          result.shipperId = null;
          result.message = message;
        } else if (tagPlainMatch) {
          const [, appName, message] = tagPlainMatch;
          result.appName = appName.trim();
          result.processId = null;
          result.shipperId = null;
          result.message = message;
        } else {
          result.message = rest;
          logger.warn('Could not extract TAG from syslog', {
            original: originalMessage.substring(0, 80),
            rest: rest.substring(0, 80)
          });
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
