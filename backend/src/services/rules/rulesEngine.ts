import { DetectionRuleModel, DetectionRule } from '../../models/DetectionRule';
import { AlertModel } from '../../models/Alert';
import { ParsedLog } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { query } from '../../config/database';

interface RuleCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'not_contains' | 'not_in_whitelist' | 'exists';
  value: string | number | boolean;
}

interface RuleAggregation {
  field: string;
  timeframe: string; // e.g., '5m', '1h'
  threshold: number;
  distinct_count?: string; // e.g., 'source_ip >= 3' for distributed attack detection
}

interface RuleLogic {
  conditions: RuleCondition[];
  aggregation?: RuleAggregation;
}

export class RulesEngine {
  private rules: DetectionRule[] = [];

  async initialize(): Promise<void> {
    try {
      // Load all enabled rules from database
      this.rules = await DetectionRuleModel.findEnabled();
      logger.info(`Loaded ${this.rules.length} detection rules`);
    } catch (error) {
      logger.error('Failed to initialize rules engine:', error);
      throw error;
    }
  }

  async evaluateLog(parsedLog: ParsedLog): Promise<void> {
    for (const rule of this.rules) {
      try {
        const matched = await this.evaluateRule(rule, parsedLog);
        if (matched) {
          logger.info(`Rule matched: ${rule.name}`, { parsedLogId: parsedLog.id });
        }
      } catch (error) {
        logger.error(`Error evaluating rule ${rule.name}:`, error);
      }
    }
  }

  private async evaluateRule(rule: DetectionRule, parsedLog: ParsedLog): Promise<boolean> {
    const ruleLogic: RuleLogic = rule.rule_logic;

    // Evaluate conditions (now async)
    const conditionsMatch = await this.evaluateConditions(ruleLogic.conditions, parsedLog.parsed_data);

    if (!conditionsMatch) {
      return false;
    }

    // If rule has aggregation, check if threshold is met
    if (ruleLogic.aggregation) {
      const thresholdMet = await this.evaluateAggregation(
        rule,
        ruleLogic.aggregation,
        parsedLog
      );

      if (thresholdMet) {
        await this.createAlert(rule, parsedLog, ruleLogic.aggregation);
        return true;
      }

      return false;
    } else {
      // No aggregation, create alert immediately
      await this.createAlert(rule, parsedLog);
      return true;
    }
  }

  private async evaluateConditions(
    conditions: RuleCondition[],
    data: Record<string, any>
  ): Promise<boolean> {
    for (const condition of conditions) {
      const fieldValue = data[condition.field];

      // Skip null/undefined check for 'exists' operator (it handles these cases)
      if (condition.operator !== 'exists' && (fieldValue === undefined || fieldValue === null)) {
        return false;
      }

      const matched = await this.evaluateCondition(condition, fieldValue);
      if (!matched) {
        return false;
      }
    }

    return true; // All conditions matched
  }

  private async evaluateCondition(condition: RuleCondition, fieldValue: any): Promise<boolean> {
    const { operator, value } = condition;
    const fieldStr = String(fieldValue);
    const valueStr = String(value);

    switch (operator) {
      case 'equals':
        return fieldStr === valueStr;

      case 'contains':
        return fieldStr.toLowerCase().includes(valueStr.toLowerCase());

      case 'not_contains':
        return !fieldStr.toLowerCase().includes(valueStr.toLowerCase());

      case 'regex':
        try {
          const regex = new RegExp(valueStr);
          return regex.test(fieldStr);
        } catch (error) {
          logger.error('Invalid regex pattern:', { pattern: valueStr, error });
          return false;
        }

      case 'greater_than':
        return Number(fieldValue) > Number(value);

      case 'less_than':
        return Number(fieldValue) < Number(value);

      case 'exists':
        // Check if field exists and is not null/undefined
        return value === true ? fieldValue !== undefined && fieldValue !== null : fieldValue === undefined || fieldValue === null;

      case 'not_in_whitelist':
        // Check if IP address is NOT in whitelist
        if (value !== true) {
          logger.warn('not_in_whitelist operator requires value: true');
          return false;
        }
        return await this.checkIpNotInWhitelist(fieldValue);

      default:
        logger.warn(`Unknown operator: ${operator}`);
        return false;
    }
  }

  private async checkIpNotInWhitelist(ipAddress: string): Promise<boolean> {
    try {
      // Query whitelist table to check if IP is whitelisted
      const result = await query(
        `SELECT 1 FROM ip_whitelist WHERE ip_address >> $1::inet LIMIT 1`,
        [ipAddress]
      );

      // Return true if IP is NOT in whitelist (no rows found)
      const isWhitelisted = (result.rowCount || 0) > 0;
      return !isWhitelisted;
    } catch (error) {
      logger.error('Error checking IP whitelist:', { ipAddress, error });
      // On error, assume not whitelisted (fail-safe)
      return true;
    }
  }

  private async evaluateAggregation(
    rule: DetectionRule,
    aggregation: RuleAggregation,
    parsedLog: ParsedLog
  ): Promise<boolean> {
    const timeframeMinutes = this.parseTimeframe(aggregation.timeframe);
    const fieldValue = parsedLog.parsed_data[aggregation.field];

    if (fieldValue === undefined) {
      return false;
    }

    // Query database for matching logs within timeframe
    const startTime = new Date(Date.now() - timeframeMinutes * 60 * 1000);

    // Check if distinct_count is specified
    if (aggregation.distinct_count) {
      return await this.evaluateDistinctCountAggregation(
        rule,
        aggregation,
        parsedLog,
        fieldValue,
        startTime
      );
    }

    // Standard count aggregation
    const result = await query(
      `SELECT COUNT(*) FROM parsed_logs
       WHERE parsed_data->>$1 = $2
       AND timestamp >= $3`,
      [aggregation.field, String(fieldValue), startTime]
    );

    const count = parseInt(result.rows[0].count, 10);

    logger.debug('Aggregation check', {
      rule: rule.name,
      field: aggregation.field,
      value: fieldValue,
      count,
      threshold: aggregation.threshold,
    });

    return count >= aggregation.threshold;
  }

  private async evaluateDistinctCountAggregation(
    rule: DetectionRule,
    aggregation: RuleAggregation,
    parsedLog: ParsedLog,
    fieldValue: any,
    startTime: Date
  ): Promise<boolean> {
    // Parse distinct_count: "source_ip >= 3" => field="source_ip", operator=">=", threshold=3
    const distinctMatch = aggregation.distinct_count!.match(/^(\w+)\s*(>=|>|<=|<|=)\s*(\d+)$/);

    if (!distinctMatch) {
      logger.error('Invalid distinct_count format', {
        rule: rule.name,
        distinct_count: aggregation.distinct_count,
      });
      return false;
    }

    const [, distinctField, operator, distinctThresholdStr] = distinctMatch;
    const distinctThreshold = parseInt(distinctThresholdStr, 10);

    // Query for both total count and distinct count
    const result = await query(
      `SELECT
         COUNT(*) as total_count,
         COUNT(DISTINCT parsed_data->>$1) as distinct_count
       FROM parsed_logs
       WHERE parsed_data->>$2 = $3
       AND timestamp >= $4`,
      [distinctField, aggregation.field, String(fieldValue), startTime]
    );

    const totalCount = parseInt(result.rows[0].total_count, 10);
    const distinctCount = parseInt(result.rows[0].distinct_count, 10);

    // Check if total count meets threshold
    if (totalCount < aggregation.threshold) {
      logger.debug('Distinct count aggregation: total count below threshold', {
        rule: rule.name,
        totalCount,
        threshold: aggregation.threshold,
      });
      return false;
    }

    // Check if distinct count meets threshold
    let distinctThresholdMet = false;
    switch (operator) {
      case '>=':
        distinctThresholdMet = distinctCount >= distinctThreshold;
        break;
      case '>':
        distinctThresholdMet = distinctCount > distinctThreshold;
        break;
      case '<=':
        distinctThresholdMet = distinctCount <= distinctThreshold;
        break;
      case '<':
        distinctThresholdMet = distinctCount < distinctThreshold;
        break;
      case '=':
        distinctThresholdMet = distinctCount === distinctThreshold;
        break;
      default:
        logger.error('Unknown distinct count operator', { operator });
        return false;
    }

    logger.debug('Distinct count aggregation check', {
      rule: rule.name,
      aggregationField: aggregation.field,
      aggregationValue: fieldValue,
      distinctField,
      totalCount,
      distinctCount,
      distinctThreshold,
      operator,
      thresholdMet: distinctThresholdMet,
    });

    return distinctThresholdMet;
  }

  private parseTimeframe(timeframe: string): number {
    const match = timeframe.match(/^(\d+)([smhd])$/);
    if (!match) {
      logger.warn(`Invalid timeframe format: ${timeframe}, defaulting to 5 minutes`);
      return 5;
    }

    const [, amount, unit] = match;
    const value = parseInt(amount, 10);

    switch (unit) {
      case 's':
        return value / 60; // Convert seconds to minutes
      case 'm':
        return value;
      case 'h':
        return value * 60;
      case 'd':
        return value * 60 * 24;
      default:
        return 5;
    }
  }

  private async createAlert(
    rule: DetectionRule,
    parsedLog: ParsedLog,
    aggregation?: RuleAggregation
  ): Promise<void> {
    try {
      // Extract variables for alert title/description
      const variables: Record<string, any> = {
        ...parsedLog.parsed_data,
        source_ip: parsedLog.source_ip,
        timestamp: parsedLog.timestamp,
      };

      if (aggregation) {
        // Get count for aggregation
        const timeframeMinutes = this.parseTimeframe(aggregation.timeframe);
        const startTime = new Date(Date.now() - timeframeMinutes * 60 * 1000);
        const fieldValue = parsedLog.parsed_data[aggregation.field];

        if (aggregation.distinct_count) {
          // Get both total count and distinct count
          const distinctMatch = aggregation.distinct_count.match(/^(\w+)\s*(>=|>|<=|<|=)\s*(\d+)$/);
          if (distinctMatch) {
            const [, distinctField] = distinctMatch;

            const result = await query(
              `SELECT
                 COUNT(*) as total_count,
                 COUNT(DISTINCT parsed_data->>$1) as distinct_count
               FROM parsed_logs
               WHERE parsed_data->>$2 = $3
               AND timestamp >= $4`,
              [distinctField, aggregation.field, String(fieldValue), startTime]
            );

            variables.count = parseInt(result.rows[0].total_count, 10);
            variables.distinct_count = parseInt(result.rows[0].distinct_count, 10);
          }
        } else {
          // Standard count aggregation
          const result = await query(
            `SELECT COUNT(*) FROM parsed_logs
             WHERE parsed_data->>$1 = $2
             AND timestamp >= $3`,
            [aggregation.field, String(fieldValue), startTime]
          );

          variables.count = parseInt(result.rows[0].count, 10);
        }
      }

      // Parse alert template from rule_logic
      const alertTemplate = rule.rule_logic.alert || {
        title: rule.name,
        description: rule.description || '',
      };

      const title = this.replaceVariables(alertTemplate.title, variables);
      const description = this.replaceVariables(alertTemplate.description || '', variables);

      await AlertModel.create({
        rule_id: rule.id,
        parsed_log_id: parsedLog.id,
        severity: rule.severity,
        title,
        description,
        matched_data: variables,
      });

      logger.info('Alert created', { rule: rule.name, title });
    } catch (error) {
      logger.error('Failed to create alert:', { error, rule: rule.name });
    }
  }

  private replaceVariables(template: string, variables: Record<string, any>): string {
    return template.replace(/\{(\w+)\}/g, (match, key) => {
      return variables[key] !== undefined ? String(variables[key]) : match;
    });
  }

  async reloadRules(): Promise<void> {
    logger.info('Reloading detection rules...');
    await this.initialize();
  }
}
