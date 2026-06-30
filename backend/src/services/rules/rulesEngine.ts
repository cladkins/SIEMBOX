import { DetectionRuleModel, DetectionRule } from '../../models/DetectionRule';
import { AlertModel } from '../../models/Alert';
import { ParsedLog } from '../../models/ParsedLog';
import { logger } from '../../utils/logger';
import { query } from '../../config/database';
import { ErrorLogService } from '../errors/errorLogService';
import { NotificationService } from '../notifications/notificationService';
import { FeedService } from '../threatintel/feedService';

interface RuleCondition {
  field: string;
  operator:
    | 'equals'
    | 'not_equals'
    | 'contains'
    | 'not_contains'
    | 'regex'
    | 'greater_than'
    | 'less_than'
    | 'in'
    | 'not_in'
    | 'not_in_whitelist'
    | 'on_threat_feed'
    | 'not_on_threat_feed'
    | 'exists';
  value: string | number | boolean | Array<string | number>;
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
  private static instance: RulesEngine | null = null;
  private rules: DetectionRule[] = [];

  static getInstance(): RulesEngine {
    if (!RulesEngine.instance) {
      RulesEngine.instance = new RulesEngine();
    }
    return RulesEngine.instance;
  }

  async initialize(): Promise<void> {
    try {
      // Load all enabled rules from database
      this.rules = await DetectionRuleModel.findEnabled();
      logger.info(`Loaded ${this.rules.length} detection rules`);
    } catch (error) {
      logger.error('Failed to initialize rules engine:', error);
      ErrorLogService.logBackgroundError('rules-engine', error, { dedupeKey: 'initialize' });
      throw error;
    }
  }

  async reload(): Promise<void> {
    try {
      // Reload all enabled rules from database
      this.rules = await DetectionRuleModel.findEnabled();
      logger.info(`Reloaded ${this.rules.length} detection rules`);
    } catch (error) {
      logger.error('Failed to reload rules:', error);
      ErrorLogService.logBackgroundError('rules-engine', error, { dedupeKey: 'reload' });
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

      case 'not_equals':
        return fieldStr !== valueStr;

      case 'in': {
        const list = Array.isArray(value)
          ? value.map((v) => String(v))
          : valueStr.split(',').map((s) => s.trim());
        return list.includes(fieldStr);
      }

      case 'not_in': {
        const list = Array.isArray(value)
          ? value.map((v) => String(v))
          : valueStr.split(',').map((s) => s.trim());
        return !list.includes(fieldStr);
      }

      case 'on_threat_feed':
        if (value !== true && value !== 'true') {
          logger.warn('on_threat_feed operator requires value: true');
          return false;
        }
        return await this.checkIpOnThreatFeed(fieldValue);

      case 'not_on_threat_feed':
        if (value !== true && value !== 'true') {
          logger.warn('not_on_threat_feed operator requires value: true');
          return false;
        }
        return !(await this.checkIpOnThreatFeed(fieldValue));

      default:
        logger.warn(`Unknown operator: ${operator}`);
        return false;
    }
  }

  private async checkIpNotInWhitelist(ipAddress: string): Promise<boolean> {
    try {
      // Query whitelist table to check if IP is whitelisted
      const result = await query(
        // `>>=` is "contains or equals", so both a subnet (192.168.1.0/24) and a
        // single host (192.168.1.76/32) match the given IP. `>>` alone would
        // miss exact /32 entries.
        `SELECT 1 FROM ip_whitelist WHERE ip_address >>= $1::inet LIMIT 1`,
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

  /**
   * True when the IP is present in any enabled threat-intel feed (exact-IP match
   * against threat_indicators, reusing the lookup the Threat Intel page uses).
   * Fail-closed: on error, returns false so we don't raise false alerts.
   */
  private async checkIpOnThreatFeed(ip: any): Promise<boolean> {
    try {
      const matches = await FeedService.lookupIp(String(ip).trim());
      return matches.length > 0;
    } catch (error) {
      logger.error('Error checking IP against threat feeds:', { ip, error });
      return false;
    }
  }

  private async evaluateAggregation(
    rule: DetectionRule,
    aggregation: RuleAggregation,
    parsedLog: ParsedLog
  ): Promise<boolean> {
    const fieldValue = parsedLog.parsed_data[aggregation.field];
    if (fieldValue === undefined || fieldValue === null) {
      return false;
    }

    const timeframeMinutes = this.parseTimeframe(aggregation.timeframe);
    const startTime = new Date(Date.now() - timeframeMinutes * 60 * 1000);

    // Count logs that share the aggregation value AND match the rule's own
    // conditions (not merely any log sharing the value).
    const { total, distinct } = await this.countMatchingLogs(
      rule,
      aggregation,
      fieldValue,
      startTime
    );

    if (total < aggregation.threshold) {
      return false;
    }

    // Plain count aggregation: total over the threshold is enough.
    if (!aggregation.distinct_count) {
      logger.debug('Aggregation check', {
        rule: rule.name,
        field: aggregation.field,
        value: fieldValue,
        count: total,
        threshold: aggregation.threshold,
      });
      return true;
    }

    // Distinct-count aggregation: "<field> <op> <n>".
    const distinctMatch = aggregation.distinct_count.match(/^(\w+)\s*(>=|>|<=|<|=)\s*(\d+)$/);
    if (!distinctMatch) {
      logger.error('Invalid distinct_count format', {
        rule: rule.name,
        distinct_count: aggregation.distinct_count,
      });
      return false;
    }

    const [, distinctField, operator, distinctThresholdStr] = distinctMatch;
    const distinctThreshold = parseInt(distinctThresholdStr, 10);

    let met = false;
    switch (operator) {
      case '>=': met = distinct >= distinctThreshold; break;
      case '>': met = distinct > distinctThreshold; break;
      case '<=': met = distinct <= distinctThreshold; break;
      case '<': met = distinct < distinctThreshold; break;
      case '=': met = distinct === distinctThreshold; break;
      default:
        logger.error('Unknown distinct count operator', { operator });
        return false;
    }

    logger.debug('Distinct count aggregation check', {
      rule: rule.name,
      aggregationField: aggregation.field,
      aggregationValue: fieldValue,
      distinctField,
      totalCount: total,
      distinctCount: distinct,
      distinctThreshold,
      operator,
      thresholdMet: met,
    });

    return met;
  }

  /**
   * Count logs in the window that share the aggregation field value AND match
   * the rule's own conditions. The earlier implementation counted every log
   * sharing the value (so "5 failed logins from an IP" was really "5 logs from
   * an IP"); re-applying the conditions makes the count reflect the rule. Also
   * returns how many distinct values of the distinct_count field appear among
   * the matching logs.
   */
  private async countMatchingLogs(
    rule: DetectionRule,
    aggregation: RuleAggregation,
    fieldValue: any,
    startTime: Date
  ): Promise<{ total: number; distinct: number }> {
    const conditions = (rule.rule_logic as RuleLogic).conditions || [];

    let distinctField: string | null = null;
    if (aggregation.distinct_count) {
      const m = aggregation.distinct_count.match(/^(\w+)\s*(>=|>|<=|<|=)\s*(\d+)$/);
      if (m) distinctField = m[1];
    }

    const result = await query(
      `SELECT parsed_data FROM parsed_logs
       WHERE parsed_data->>$1 = $2
       AND timestamp >= $3
       ORDER BY timestamp DESC
       LIMIT 50000`,
      [aggregation.field, String(fieldValue), startTime]
    );

    let total = 0;
    const distinctValues = new Set<string>();

    for (const row of result.rows) {
      const data: Record<string, any> = row.parsed_data || {};
      if (await this.evaluateConditions(conditions, data)) {
        total++;
        if (distinctField && data[distinctField] !== undefined && data[distinctField] !== null) {
          distinctValues.add(String(data[distinctField]));
        }
      }
    }

    return { total, distinct: distinctValues.size };
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
        source_ip: parsedLog.source_ip, // fallback; normalized parsed_data.source_ip below wins
        ...parsedLog.parsed_data,
        timestamp: parsedLog.timestamp,
      };

      if (aggregation) {
        const timeframeMinutes = this.parseTimeframe(aggregation.timeframe);
        const startTime = new Date(Date.now() - timeframeMinutes * 60 * 1000);
        const fieldValue = parsedLog.parsed_data[aggregation.field];

        const { total, distinct } = await this.countMatchingLogs(
          rule,
          aggregation,
          fieldValue,
          startTime
        );
        variables.count = total;
        if (aggregation.distinct_count) {
          variables.distinct_count = distinct;
        }
      }

      // The IP this alert concerns (used for the allow-list, dedup, and threat-intel context).
      const alertIp = String(
        parsedLog.parsed_data['client_ip'] ??
        parsedLog.parsed_data['source_ip'] ??
        parsedLog.source_ip ??
        ''
      ).trim();

      // Threat-intel context: if the IP is on any enabled feed, record which feeds
      // flagged it so the alert (via {threat_feeds}) and matched_data can name them.
      // Best-effort — never blocks alert creation.
      try {
        if (alertIp) {
          const feeds = await FeedService.lookupIp(alertIp);
          if (feeds.length > 0) variables.threat_feeds = feeds.map((f) => f.name).join(', ');
        }
      } catch {
        /* best-effort enrichment */
      }

      // Parse alert template from rule_logic
      const alertTemplate = rule.rule_logic.alert || {
        title: rule.name,
        description: rule.description || '',
      };

      const title = this.replaceVariables(alertTemplate.title, variables);
      const description = this.replaceVariables(alertTemplate.description || '', variables);

      // Global allow-list: never alert on trusted/whitelisted IPs, so an
      // operator can silence their own internal hosts with one whitelist entry
      // instead of editing every rule. (checkIpNotInWhitelist returns true when
      // the IP is NOT whitelisted.)
      if (alertIp && !(await this.checkIpNotInWhitelist(alertIp))) {
        logger.debug('Alert suppressed: whitelisted IP', { rule: rule.name, ip: alertIp });
        return;
      }

      // Cooldown: collapse alert storms to a single alert per (rule, title)
      // within a window, so a sustained condition doesn't emit one alert per log.
      const cooldownMin = Math.max(aggregation ? this.parseTimeframe(aggregation.timeframe) : 0, 10);
      const cooldownSince = new Date(Date.now() - cooldownMin * 60 * 1000);
      const recent = await query(
        `SELECT 1 FROM alerts WHERE rule_id = $1 AND title = $2 AND created_at >= $3 LIMIT 1`,
        [rule.id, title, cooldownSince]
      );
      if ((recent.rowCount || 0) > 0) {
        logger.debug('Alert suppressed: duplicate within cooldown', { rule: rule.name, title });
        return;
      }

      await AlertModel.create({
        rule_id: rule.id,
        parsed_log_id: parsedLog.id,
        severity: rule.severity,
        title,
        description,
        matched_data: variables,
      });

      void NotificationService.notifyAlert({
        severity: rule.severity,
        ruleName: rule.name,
        title,
        description,
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
