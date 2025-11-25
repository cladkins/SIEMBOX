import { ParserModel, Parser } from '../../models/Parser';
import { RawLog } from '../../models/RawLog';
import { ParsedLogModel } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { RulesEngine } from '../rules/rulesEngine';

export class ParserEngine {
  private parsers: Parser[] = [];
  private rulesEngine: RulesEngine;

  constructor() {
    this.rulesEngine = new RulesEngine();
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
          const parsedLog = await ParsedLogModel.create({
            raw_log_id: rawLog.id,
            parser_id: parser.id,
            parsed_data: result.fields,
            timestamp: rawLog.timestamp,
            source_ip: rawLog.source_ip,
            event_type: result.event_type || null,
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

      // Map regex groups to field names using field_mappings
      if (match.groups) {
        // Named groups
        for (const [groupName, fieldName] of Object.entries(parser.field_mappings)) {
          if (match.groups[groupName] !== undefined) {
            fields[fieldName] = match.groups[groupName];
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

      // Determine event type from parser name or extracted fields
      const event_type = this.determineEventType(parser.name, fields);

      return { fields, event_type };
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
      // Try to parse message as JSON
      const parsed = JSON.parse(message);

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

      const event_type = this.determineEventType(parser.name, fields);

      return { fields, event_type };
    } catch (error) {
      // Not valid JSON
      return null;
    }
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
