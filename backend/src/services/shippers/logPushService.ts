/**
 * HTTP log-push ingestion (POST /api/shippers/logs). Mirrors the
 * create-then-process sequence in services/syslog/syslogServer.ts, so a
 * pushed entry gets identical parse/normalize/geoip/detection treatment as a
 * syslog-ingested one.
 */
import { logger } from '../../utils/logger';
import { LogShipper } from '../../models/LogShipper';
import { RawLogModel } from '../../models/RawLog';
import { ParserEngine } from '../parser/parserEngine';

export const MAX_LOG_PUSH_BATCH_SIZE = 1000;
const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_ERRORS_RETURNED = 20;

export interface LogPushEntry {
  message: string;
  hostname: string | null;
  app_name: string | null;
  timestamp: string | null;
  facility: number | null;
  severity: number | null;
  event_id: string | null;
}

export interface LogPushResult {
  accepted: number;
  duplicate: number;
  rejected: number;
  errors: Array<{ index: number; error: string }>;
}

/**
 * `message` is strict (reject the entry if missing/empty/oversized); every
 * other field is lenient (invalid -> null, entry still accepted) because per
 * CLAUDE.md only raw_message is load-bearing for parsing.
 */
export function validateLogPushEntry(
  raw: unknown
): { ok: true; entry: LogPushEntry } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object') {
    return { ok: false, error: 'entry must be an object' };
  }
  const r = raw as Record<string, unknown>;

  const message = r.message;
  if (typeof message !== 'string' || message.trim().length === 0) {
    return { ok: false, error: 'message is required and must be a non-empty string' };
  }
  if (Buffer.byteLength(message, 'utf8') > MAX_MESSAGE_BYTES) {
    return { ok: false, error: `message exceeds ${MAX_MESSAGE_BYTES} bytes` };
  }

  const facility =
    Number.isInteger(r.facility) && (r.facility as number) >= 0 && (r.facility as number) <= 23
      ? (r.facility as number)
      : null;
  const severity =
    Number.isInteger(r.severity) && (r.severity as number) >= 0 && (r.severity as number) <= 7
      ? (r.severity as number)
      : null;

  return {
    ok: true,
    entry: {
      message,
      hostname: typeof r.hostname === 'string' ? r.hostname.slice(0, 255) : null,
      app_name: typeof r.app_name === 'string' ? r.app_name.slice(0, 255) : null,
      timestamp: typeof r.timestamp === 'string' ? r.timestamp : null,
      facility,
      severity,
      event_id: typeof r.event_id === 'string' ? r.event_id.slice(0, 255) : null,
    },
  };
}

/** Parses a client-supplied timestamp, falling back to "now" if absent/invalid. */
function resolveTimestamp(value: string | null): Date {
  if (!value) return new Date();
  const parsed = new Date(value);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}

export async function ingestPushedLogs(
  shipper: LogShipper,
  rawEntries: unknown[],
  sourceIp: string
): Promise<LogPushResult> {
  // Reuses the same short-id space unknown-sources/parsers key off of: the
  // first 8 hex chars of a hash, mirroring how syslog derives shipper_id from
  // the tag's [8-hex] suffix. See shippers.ts's unknown-sources CTE.
  const shipperShortId = shipper.http_push_key_hash!.slice(0, 8);
  const parserEngine = ParserEngine.getInstance();
  const result: LogPushResult = { accepted: 0, duplicate: 0, rejected: 0, errors: [] };

  for (let i = 0; i < rawEntries.length; i++) {
    const validated = validateLogPushEntry(rawEntries[i]);
    if (!validated.ok) {
      result.rejected++;
      if (result.errors.length < MAX_ERRORS_RETURNED) {
        result.errors.push({ index: i, error: validated.error });
      }
      continue;
    }

    try {
      const rawLog = await RawLogModel.create({
        timestamp: resolveTimestamp(validated.entry.timestamp),
        raw_message: validated.entry.message,
        source_ip: sourceIp,
        facility: validated.entry.facility,
        severity: validated.entry.severity,
        hostname: validated.entry.hostname,
        app_name: validated.entry.app_name,
        shipper_id: shipperShortId,
        ingest_event_id: validated.entry.event_id,
      });
      if (!rawLog) {
        result.duplicate++;
        continue;
      }
      await parserEngine.processLog(rawLog);
      result.accepted++;
    } catch (error) {
      logger.error('HTTP log push: failed to ingest entry', { error, shipperId: shipper.id, index: i });
      result.rejected++;
      if (result.errors.length < MAX_ERRORS_RETURNED) {
        result.errors.push({ index: i, error: 'internal error storing log' });
      }
    }
  }

  return result;
}
