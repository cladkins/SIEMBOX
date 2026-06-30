import { ParserModel, Parser } from '../../models/Parser';
import { RawLog } from '../../models/RawLog';
import { ParsedLogModel } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { RulesEngine } from '../rules/rulesEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { geoipService } from '../geoip/geoipService';
import { runParser } from './runParser';
import { normalizeParsedData } from '../normalize/fieldNormalizer';

export class ParserEngine {
  private static instance: ParserEngine | null = null;
  private parsers: Parser[] = [];
  private rulesEngine: RulesEngine;

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
      }
    } catch (error) {
      logger.error('Error processing log:', { error, rawLogId: rawLog.id });
    }
  }

  async testParser(parser: Parser, sample: string): Promise<any> {
    // Run the same DB-free pipeline used in production so the test reflects the
    // canonical fields a detection rule would actually see.
    const result = runParser(parser, sample);
    return result ? result.fields : null;
  }
}
