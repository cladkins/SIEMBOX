/**
 * Tests for the parser recommendation core: candidates are dry-run against
 * sampled unparsed messages with the real runParser pipeline, ranked by
 * severity-weighted coverage gained, and unmatched sources surface as
 * parser-authoring targets. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  recommendParsers,
  distinctSamples,
  SourceSample,
  HIGH_SEVERITY_WEIGHT,
} from './parserRecommendations';
import { PortableParser } from './parserPortable';

const sshCandidate: PortableParser = {
  schema: 'siembox.parser/v1',
  name: 'ssh-fixture',
  parser_type: 'regex',
  pattern: '^(?<event>Failed password) for (?<user>\\S+) from (?<src_ip>[\\d.]+)',
  field_mappings: { event: 'event', user: 'user', src_ip: 'src_ip' },
};

const nginxCandidate: PortableParser = {
  schema: 'siembox.parser/v1',
  name: 'nginx-fixture',
  parser_type: 'regex',
  pattern: '^(?<client_ip>[\\d.]+) - - \\[',
  field_mappings: { client_ip: 'client_ip' },
};

const brokenCandidate: PortableParser = {
  schema: 'siembox.parser/v1',
  name: 'broken-fixture',
  parser_type: 'regex',
  pattern: '(unclosed[',
  field_mappings: {},
};

const samples: SourceSample[] = [
  {
    app_name: 'sshd',
    messages: [
      'Failed password for root from 203.0.113.5 port 22 ssh2',
      'Failed password for admin from 203.0.113.6 port 22 ssh2',
      'Server listening on 0.0.0.0 port 22',
    ],
    unparsed_daily: 3000,
    unparsed_high_sev_daily: 1500,
  },
  {
    app_name: 'homebox',
    messages: ['level=INFO msg="request completed" status=200'],
    unparsed_daily: 80000,
    unparsed_high_sev_daily: 0,
  },
];

test('recommends the matching parser with per-source rates and volume estimates', () => {
  const { recommendations } = recommendParsers(samples, [sshCandidate, nginxCandidate]);
  assert.equal(recommendations.length, 1);
  const rec = recommendations[0];
  assert.equal(rec.name, 'ssh-fixture');
  assert.equal(rec.sources.length, 1);
  assert.equal(rec.sources[0].app_name, 'sshd');
  assert.equal(rec.sources[0].matched, 2);
  assert.equal(rec.sources[0].sampled, 3);
  // 2/3 of 3000 daily, 2/3 of 1500 high-severity
  assert.equal(rec.est_daily_matches, 2000);
  assert.equal(rec.est_daily_high_severity, 1000);
  assert.equal(rec.score, 2000 + (HIGH_SEVERITY_WEIGHT - 1) * 1000);
});

test('high-severity volume outranks raw volume', () => {
  const noisy: SourceSample = {
    app_name: 'chatty',
    messages: ['0.0.0.0 - - [26/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1"'],
    unparsed_daily: 9000,
    unparsed_high_sev_daily: 0,
  };
  const critical: SourceSample = {
    app_name: 'sshd',
    messages: ['Failed password for root from 203.0.113.5 port 22 ssh2'],
    unparsed_daily: 1200,
    unparsed_high_sev_daily: 1200,
  };
  const { recommendations } = recommendParsers([noisy, critical], [sshCandidate, nginxCandidate]);
  assert.deepEqual(
    recommendations.map((r) => r.name),
    ['ssh-fixture', 'nginx-fixture']
  );
});

test('sources nothing matches surface as uncovered, high-severity first', () => {
  const { uncovered } = recommendParsers(samples, [sshCandidate]);
  assert.equal(uncovered.length, 1);
  assert.equal(uncovered[0].app_name, 'homebox');
  assert.match(uncovered[0].example, /request completed/);
  // Uncovered sources carry full sample lines to seed the AI builder.
  assert.ok(Array.isArray(uncovered[0].samples) && uncovered[0].samples.length >= 1);
});

test('distinctSamples dedupes by digit-normalized template and caps count', () => {
  const lines = [
    '2026-07-27 12:00:00 INFO request id=1 done',
    '2026-07-27 12:00:01 INFO request id=2 done', // same shape as above -> collapsed
    '2026-07-27 12:00:02 ERROR db connection refused', // distinct shape
    '',
  ];
  const out = distinctSamples(lines, 8);
  assert.equal(out.length, 2);
  assert.match(out[0], /request id=1/); // original line kept, not the template
  assert.match(out[1], /connection refused/);
});

test('distinctSamples respects the limit and caps line length', () => {
  // Distinct shapes must differ by more than digits (digit-runs are normalized).
  const words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf'];
  const many = words.map((w) => `${w} event message`);
  assert.equal(distinctSamples(many, 5).length, 5);
  const long = ['x'.repeat(5000)];
  assert.equal(distinctSamples(long)[0].length, 2000);
});

test('a candidate with an invalid pattern is skipped, not fatal', () => {
  const { recommendations } = recommendParsers(samples, [brokenCandidate, sshCandidate]);
  assert.deepEqual(
    recommendations.map((r) => r.name),
    ['ssh-fixture']
  );
});
