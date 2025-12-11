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
 * Parse a syslog message following RFC 3164 or RFC 5424
 * RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
 * RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MESSAGE
 */
export function parseSyslogMessage(rawMessage: string): ParsedSyslog {
  const originalMessage = rawMessage;
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

      // Debug: Log the message after PRI removal with character codes
      logger.info('DEBUG: After PRI removal', {
        message: rawMessage.substring(0, 100),
        length: rawMessage.length,
        firstChars: Array.from(rawMessage.substring(0, 20))
          .map(c => `${c}(${c.charCodeAt(0)})`)
          .join(' '),
      });
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

      logger.info('DEBUG: RFC 5424 matched successfully');
    } else {
      // Try RFC 3164 format: TIMESTAMP HOSTNAME TAG: MESSAGE
      logger.info('DEBUG: Attempting RFC 3164 match', {
        message: rawMessage.substring(0, 100),
        testPattern: '/^(\\S+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(\\S+)\\s+(.+)$/',
        firstChars: Array.from(rawMessage.substring(0, 30))
          .map(c => `${c}(${c.charCodeAt(0)})`)
          .join(' '),
      });

      // Test the regex match and log详细 details
      const rfc3164Pattern = /^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$/;
      const rfc3164Match = rawMessage.match(rfc3164Pattern);

      logger.info('DEBUG: Regex match result', {
        matched: !!rfc3164Match,
        messageType: typeof rawMessage,
        hasNewline: rawMessage.includes('\n'),
        hasCarriageReturn: rawMessage.includes('\r'),
        endsWithDollar: /\$$/. test(rawMessage),
        firstTenChars: rawMessage.substring(0, 10),
        lastTenChars: rawMessage.substring(rawMessage.length - 10),
      });

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
        const tagMatch = rest.match(/^(.+?)(?:\[(\d+)\])?(?:\[([0-9a-f]{8})\])?:\s*(.*)$/);
        if (tagMatch) {
          const [, appName, procId, shipperId, message] = tagMatch;
          result.appName = appName.trim();
          result.processId = procId || null;
          result.shipperId = shipperId || null;
          result.message = message;

          logger.debug('Syslog parsed successfully', {
            original: originalMessage.substring(0, 80),
            extracted: message.substring(0, 80),
            appName,
            hostname: result.hostname
          });
        } else {
          result.message = rest;
          logger.warn('Could not extract TAG from syslog', {
            original: originalMessage.substring(0, 80),
            rest: rest.substring(0, 80)
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
