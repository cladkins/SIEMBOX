/**
 * Tests for the self-test runner's two-stage transport check: a test sample
 * written as a FULL syslog line validates an input production never stores
 * (syslogParser strips the header before parsers run), so a parser that only
 * matches the full line must fail its self-tests — unless the sample opts out
 * with `embedded_syslog: true` (shipper file transport, header survives).
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSelfTests, PortableParser } from './parserPortable';

/** A parser whose pattern REQUIRES the syslog header — the CI-green/prod-dead class. */
const headerAnchored: PortableParser = {
  schema: 'siembox.parser/v1',
  name: 'header-anchored-fixture',
  parser_type: 'regex',
  pattern:
    '^(?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[\\d+\\]:\\s+(?<event>Failed password) for (?<user>\\S+)',
  field_mappings: { timestamp: 'timestamp', hostname: 'hostname', event: 'event', user: 'user' },
  test_samples: [
    {
      input: 'Jan 15 12:00:00 web sshd[123]: Failed password for root from 203.0.113.5 port 1 ssh2',
      expect: { event: 'Failed password', user: 'root' },
    },
  ],
};

test('full-syslog-line sample fails when the parser cannot match the stripped message', () => {
  const res = runSelfTests(headerAnchored);
  assert.equal(res.ok, false);
  assert.equal(res.failures.length, 1);
  assert.match(res.failures[0].note || '', /header-stripped message/);
});

test('embedded_syslog: true opts a full-line sample out of the transport check', () => {
  const optedOut: PortableParser = {
    ...headerAnchored,
    test_samples: headerAnchored.test_samples!.map((s) => ({ ...s, embedded_syslog: true })),
  };
  assert.equal(runSelfTests(optedOut).ok, true);
});

test('optional-header parser passes: matches both the full line and the stripped form', () => {
  const optionalHeader: PortableParser = {
    ...headerAnchored,
    name: 'optional-header-fixture',
    pattern:
      '^(?:(?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[\\d+\\]:\\s+)?(?<event>Failed password) for (?<user>\\S+)',
  };
  assert.equal(runSelfTests(optionalHeader).ok, true);
});

test('message-form samples are untouched by the transport check', () => {
  const messageForm: PortableParser = {
    schema: 'siembox.parser/v1',
    name: 'message-form-fixture',
    parser_type: 'regex',
    pattern: '^query\\[(?<query_type>[^\\]]+)\\]\\s+(?<domain>\\S+)',
    field_mappings: { query_type: 'query_type', domain: 'domain' },
    test_samples: [{ input: 'query[A] example.com from 203.0.113.5', expect: { query_type: 'A' } }],
  };
  assert.equal(runSelfTests(messageForm).ok, true);
});
