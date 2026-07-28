import { ParserModel, Parser } from '../../models/Parser';
import { RawLog } from '../../models/RawLog';
import { ParsedLogModel } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { RulesEngine } from '../rules/rulesEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { geoipService } from '../geoip/geoipService';
import { runParser } from './runParser';
import { normalizeParsedData } from '../normalize/fieldNormalizer';
import { query } from '../../config/database';

/** Flush accumulated match counts at most this often (or when the map grows). */
const MATCH_COUNT_FLUSH_MS = 5000;
const MATCH_COUNT_FLUSH_KEYS = 64;
/** Prune parser_match_hourly rows older than 8 days, roughly every 6 hours. */
const MATCH_COUNT_PRUNE_MS = 6 * 60 * 60 * 1000;

export class ParserEngine {
  private static instance: ParserEngine | null = null;
  private parsers: Parser[] = [];
  private rulesEngine: RulesEngine;
  /** "<hourISO>|<parserId>" -> count, flushed in batches to parser_match_hourly. */
  private pendingMatchCounts = new Map<string, number>();
  private lastMatchCountFlush = Date.now();
  private lastMatchCountPrune = 0;

  constructor() {
    this.rulesEngine = RulesEngine.getInstance();
  }

  /**
   * Shared engine the running syslog server processes logs through. Parser CRUD /
   * catalog / pack endpoints call getInstance().reload() so enabling or importing
   * a parser takes effect immediately — the in-memory parser list is otherwise
   * only loaded once at startup, so changes wouldn't apply without a restart.
   */
  static getInstance(): ParserEngine {
    if (!ParserEngine.instance) {
      ParserEngine.instance = new ParserEngine();
    }
    return ParserEngine.instance;
  }

  async initialize(): Promise<void> {
    try {
      await this.loadParsers();

      // Initialize rules engine
      await this.rulesEngine.initialize();
    } catch (error) {
      logger.error('Failed to initialize parser engine:', error);
      ErrorLogService.logBackgroundError('parser-engine', error, { dedupeKey: 'initialize' });
      throw error;
    }
  }

  /**
   * Reload the in-memory parser list from the DB after a parser change (enable,
   * import, catalog/pack install, delete). Does NOT re-init the rules engine —
   * detection rules reload on their own changes.
   */
  async reload(): Promise<void> {
    await this.loadParsers();
  }

  private async loadParsers(): Promise<void> {
    // Enabled parsers, ordered by priority (lower number = higher priority).
    this.parsers = await ParserModel.findEnabled();
    logger.info(`Loaded ${this.parsers.length} parsers`);
  }

  async processLog(rawLog: RawLog): Promise<void> {
    try {
      let parsed = false;

      // Try each parser in priority order
      for (const parser of this.parsers) {
        // Match + map + derive + normalize via the shared DB-free pipeline (the
        // same path the portable-parser validator/CI uses, so behavior matches).
        const result = runParser(parser, rawLog.raw_message, { packetSourceIp: rawLog.source_ip });

        if (result) {
          const eventType = result.event_type;
          const normalizedData = result.fields;

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

          this.bumpMatchCount(parser.id);
          parsed = true;
          break; // Stop after first successful parse
        }
      }

      if (!parsed) {
        // Embedded generic fallback — the ONE parser SIEMBox ships itself; every
        // specific parser lives in the catalog. Most logs reach here: catalog
        // parsers anchored on the syslog header can't match the header-stripped
        // message, and many apps have no parser at all. Rather than drop these to
        // raw-only, synthesize a minimal structured record (the message plus the
        // service from the syslog tag, host, and source) so every log stays
        // queryable in the Parsed Logs view. Detection rules are intentionally NOT
        // evaluated here — these carry no extracted fields and the volume is high.
        const fallbackFields = normalizeParsedData(
          {
            message: rawLog.raw_message,
            service: rawLog.app_name || undefined,
            host: rawLog.hostname || undefined,
          },
          { packetSourceIp: rawLog.source_ip, eventType: 'unparsed' }
        );

        await ParsedLogModel.create({
          raw_log_id: rawLog.id,
          parser_id: null,
          parsed_data: fallbackFields,
          timestamp: rawLog.timestamp,
          source_ip: rawLog.source_ip,
          event_type: 'unparsed',
        });

        this.bumpMatchCount(null);
      }
    } catch (error) {
      logger.error('Error processing log:', { error, rawLogId: rawLog.id });
      // Deduped by message (60s) so a systemic failure — every log erroring —
      // surfaces on the dashboard once a minute instead of not at all, without
      // one bad pattern flooding application_errors at ingest rate.
      ErrorLogService.logBackgroundError('parser-engine', error, {
        dedupeKey: `process:${error instanceof Error ? error.message : String(error)}`,
        rawLogId: rawLog.id,
      });
    }
  }

  async testParser(parser: Parser, sample: string): Promise<any> {
    // Run the same DB-free pipeline used in production so the test reflects the
    // canonical fields a detection rule would actually see.
    const result = runParser(parser, sample);
    return result ? result.fields : null;
  }

  /**
   * Count a match (parserId) or fallback (null) into the in-memory hourly
   * accumulator, flushing in batches so stats reads never have to aggregate
   * parsed_logs. Buckets use server ingest time — sender clock skew cannot
   * distort the counters. Flushing is inline (no timers): a quiet stream just
   * delays the last few counts until the next log arrives, which is fine for
   * 24h-scale statistics.
   */
  private bumpMatchCount(parserId: number | null): void {
    const hour = new Date();
    hour.setMinutes(0, 0, 0);
    const key = `${hour.toISOString()}|${parserId ?? 0}`;
    this.pendingMatchCounts.set(key, (this.pendingMatchCounts.get(key) || 0) + 1);

    if (
      Date.now() - this.lastMatchCountFlush >= MATCH_COUNT_FLUSH_MS ||
      this.pendingMatchCounts.size >= MATCH_COUNT_FLUSH_KEYS
    ) {
      void this.flushMatchCounts();
    }
  }

  private async flushMatchCounts(): Promise<void> {
    if (this.pendingMatchCounts.size === 0) return;
    const batch = this.pendingMatchCounts;
    this.pendingMatchCounts = new Map();
    this.lastMatchCountFlush = Date.now();

    const values: string[] = [];
    const params: any[] = [];
    let i = 1;
    for (const [key, count] of batch) {
      const [hourIso, parserId] = key.split('|');
      values.push(`($${i}, $${i + 1}, $${i + 2})`);
      params.push(new Date(hourIso), parseInt(parserId, 10), count);
      i += 3;
    }

    try {
      await query(
        `INSERT INTO parser_match_hourly (hour, parser_id, matches)
         VALUES ${values.join(', ')}
         ON CONFLICT (hour, parser_id)
         DO UPDATE SET matches = parser_match_hourly.matches + EXCLUDED.matches`,
        params
      );
    } catch (error) {
      // Dropped counts skew stats slightly; merging back on failure could grow
      // unbounded during a DB outage, so log and move on.
      logger.error('Failed to flush parser match counts:', { error });
    }

    if (Date.now() - this.lastMatchCountPrune >= MATCH_COUNT_PRUNE_MS) {
      this.lastMatchCountPrune = Date.now();
      try {
        await query(`DELETE FROM parser_match_hourly WHERE hour < NOW() - INTERVAL '8 days'`);
      } catch (error) {
        logger.error('Failed to prune parser match counts:', { error });
      }
    }
  }
}
