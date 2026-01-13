/**
 * DetectionRule Factory for Testing
 * Creates test detection rule data using Fishery
 */

import { Factory } from 'fishery';
import { DetectionRule } from '../../../src/models/DetectionRule';

export const detectionRuleFactory = Factory.define<DetectionRule>(({ sequence }) => ({
  id: sequence,
  name: `Detection Rule ${sequence}`,
  description: `Test detection rule description ${sequence}`,
  enabled: true,
  severity: 'medium',
  rule_yaml: `name: "Detection Rule ${sequence}"
description: "Test detection rule"
severity: medium
conditions:
  - field: message
    operator: contains
    value: "error"
threshold: 5
time_window: 300`,
  rule_logic: {
    conditions: [
      {
        field: 'message',
        operator: 'contains',
        value: 'error',
      },
    ],
    threshold: 5,
    time_window: 300,
  },
  tags: ['test', 'generic'],
  created_at: new Date(),
  updated_at: new Date(),
}));

export const criticalRuleFactory = detectionRuleFactory.params({
  severity: 'critical',
  name: 'Critical Security Event',
  rule_logic: {
    conditions: [
      {
        field: 'message',
        operator: 'contains',
        value: 'unauthorized access',
      },
    ],
    threshold: 1,
    time_window: 60,
  },
  tags: ['security', 'critical'],
});

export const failedLoginRuleFactory = detectionRuleFactory.params({
  name: 'Failed Login Attempts',
  severity: 'high',
  rule_logic: {
    conditions: [
      {
        field: 'message',
        operator: 'contains',
        value: 'Failed password',
      },
      {
        field: 'app_name',
        operator: 'equals',
        value: 'sshd',
      },
    ],
    threshold: 5,
    time_window: 300,
  },
  tags: ['authentication', 'ssh'],
});

export const bruteForceRuleFactory = detectionRuleFactory.params({
  name: 'Brute Force Attack',
  severity: 'critical',
  rule_logic: {
    conditions: [
      {
        field: 'http_status',
        operator: 'equals',
        value: '401',
      },
    ],
    threshold: 10,
    time_window: 60,
  },
  tags: ['web', 'brute-force', 'authentication'],
});
