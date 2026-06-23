import { ParserModel, Parser } from '../../models/Parser';
import { RawLog } from '../../models/RawLog';
import { ParsedLogModel } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { RulesEngine } from '../rules/rulesEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { geoipService } from '../geoip/geoipService';
import { runParser } from './runParser';

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
        logger.debug('No parser matched for log', {
          rawLogId: rawLog.id,
          message: rawLog.raw_message.substring(0, 100),
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
