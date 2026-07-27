/**
 * Tests for the detection-rule recommendation core: candidate rules' conditions
 * are dry-run against sampled parsed logs with the real condition evaluator,
 * ranked by matching daily volume × rule severity. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  recommendRules,
  conditionsMatchSample,
  RuleSourceSample,
  CandidateRule,
  SEVERITY_WEIGHTS,
} from './detectionRecommendations';

const sshFailures: RuleSourceSample = {
  parser_name: 'ssh-authentication',
  samples: [
    { event: 'Failed password', service: 'sshd', source_ip: '203.0.113.5', auth_outcome: 'failure' },
    { event: 'Failed password', service: 'sshd', source_ip: '203.0.113.6', auth_outcome: 'failure' },
    { event: 'Accepted password', service: 'sshd', source_ip: '198.51.100.9', auth_outcome: 'success' },
  ],
  daily_volume: 3000,
};

const httpTraffic: RuleSourceSample = {
  parser_name: 'nginx-proxy-manager',
  samples: [{ method: 'GET', status_code: '200', client_ip: '203.0.113.9', path: '/' }],
  daily_volume: 60000,
};

const bruteForceRule: CandidateRule = {
  name: 'SSH Brute Force Detection',
  severity: 'high',
  conditions: [
    { field: 'event', operator: 'contains', value: 'Failed password' },
    { field: 'service', operator: 'equals', value: 'sshd' },
  ],
  aggregation: { field: 'source_ip', timeframe: '5m', threshold: 5 },
};

const dnsRule: CandidateRule = {
  name: 'DNS Anomaly',
  severity: 'low',
  conditions: [{ field: 'query_type', operator: 'exists', value: true }],
};

test('recommends rules whose conditions your parsed data satisfies', () => {
  const { recommendations } = recommendRules([sshFailures, httpTraffic], [bruteForceRule, dnsRule]);
  assert.equal(recommendations.length, 1);
  const rec = recommendations[0];
  assert.equal(rec.name, 'SSH Brute Force Detection');
  assert.equal(rec.sources.length, 1);
  assert.equal(rec.sources[0].parser_name, 'ssh-authentication');
  assert.equal(rec.sources[0].matched, 2); // failures only, not the success
  // 2/3 of 3000/day, weighted by severity
  assert.equal(rec.est_daily_matches, 2000);
  assert.equal(rec.score, 2000 * SEVERITY_WEIGHTS.high);
  assert.deepEqual(rec.aggregation, bruteForceRule.aggregation);
});

test('severity outweighs raw volume in ranking', () => {
  const criticalNarrow: CandidateRule = {
    name: 'critical-auth',
    severity: 'critical',
    conditions: [{ field: 'auth_outcome', operator: 'equals', value: 'failure' }],
  };
  const lowBroad: CandidateRule = {
    name: 'low-http',
    severity: 'low',
    conditions: [{ field: 'method', operator: 'exists', value: true }],
  };
  const { recommendations } = recommendRules([sshFailures, httpTraffic], [lowBroad, criticalNarrow]);
  // critical: 2/3×3000×10 = 20000 > low: 1/1×60000×1 = 60000... volume wins here;
  // shrink the low-severity stream to make the point cleanly
  const smallHttp = { ...httpTraffic, daily_volume: 15000 };
  const r2 = recommendRules([sshFailures, smallHttp], [lowBroad, criticalNarrow]).recommendations;
  assert.deepEqual(r2.map((r) => r.name), ['critical-auth', 'low-http']);
  assert.equal(recommendations.length, 2);
});

test('DB-backed operators count as satisfied when the field is present', () => {
  assert.equal(
    conditionsMatchSample(
      [{ field: 'source_ip', operator: 'not_in_whitelist', value: true }],
      { source_ip: '203.0.113.5' }
    ),
    true
  );
  assert.equal(
    conditionsMatchSample([{ field: 'source_ip', operator: 'not_in_whitelist', value: true }], {}),
    false
  );
});

test('invalid regex conditions never match instead of throwing', () => {
  assert.equal(
    conditionsMatchSample([{ field: 'path', operator: 'regex', value: '(unclosed[' }], { path: '/x' }),
    false
  );
});

test('rules with no conditions are never recommended', () => {
  const { recommendations } = recommendRules([httpTraffic], [{ name: 'blind', severity: 'high' }]);
  assert.equal(recommendations.length, 0);
});
