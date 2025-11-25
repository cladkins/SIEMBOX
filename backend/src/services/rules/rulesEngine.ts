import { DetectionRuleModel, DetectionRule } from '../../models/DetectionRule';
import { AlertModel } from '../../models/Alert';
import { ParsedLog } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { query } from '../../config/database';

interface RuleCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'not_contains';
  value: string | number;
}

interface RuleAggregation {
  field: string;
  timeframe: string; // e.g., '5m', '1h'
  threshold: number;
}

interface RuleLogic {
  conditions: RuleCondition[];
  aggregation?: RuleAggregation;
}

export class RulesEngine {
  private rules: DetectionRule[] = [];
  private _aggregationCache: Map<string, any[]> = new Map();

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

    // Evaluate conditions
    const conditionsMatch = this.evaluateConditions(ruleLogic.conditions, parsedLog.parsed_data);

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

  private evaluateConditions(
    conditions: RuleCondition[],
    data: Record<string, any>
  ): boolean {
    for (const condition of conditions) {
      const fieldValue = data[condition.field];

      if (fieldValue === undefined || fieldValue === null) {
        return false;
      }

      const matched = this.evaluateCondition(condition, fieldValue);
      if (!matched) {
        return false;
      }
    }

    return true; // All conditions matched
  }

  private evaluateCondition(condition: RuleCondition, fieldValue: any): boolean {
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

      default:
        logger.warn(`Unknown operator: ${operator}`);
        return false;
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

        const result = await query(
          `SELECT COUNT(*) FROM parsed_logs
           WHERE parsed_data->>$1 = $2
           AND timestamp >= $3`,
          [aggregation.field, String(fieldValue), startTime]
        );

        variables.count = parseInt(result.rows[0].count, 10);
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
