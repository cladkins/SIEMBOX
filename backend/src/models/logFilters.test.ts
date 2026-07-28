/**
 * Tests for the raw/parsed log filter builders. These build SQL fragments plus
 * positional bind params, where an off-by-one in the bind index silently
 * returns the wrong rows instead of erroring — so they're worth pinning without
 * needing a database. `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildParsedLogFilters } from './ParsedLog';
import { buildRawLogFilters } from './RawLog';

test('no filters produces no WHERE clause and no params', () => {
  assert.deepEqual(buildParsedLogFilters(), { whereClause: '', params: [] });
  assert.deepEqual(buildRawLogFilters(), { whereClause: '', params: [] });
});

test('parseStatus=unparsed selects the fallback records with no bind param', () => {
  const { whereClause, params } = buildParsedLogFilters({ parseStatus: 'unparsed' });

  // NULL needs IS NULL, not `= $n` — the latter matches nothing at all.
  assert.equal(whereClause, 'WHERE pl.parser_id IS NULL');
  assert.deepEqual(params, []);
});

test('parseStatus=parsed excludes the fallback records', () => {
  const { whereClause, params } = buildParsedLogFilters({ parseStatus: 'parsed' });

  assert.equal(whereClause, 'WHERE pl.parser_id IS NOT NULL');
  assert.deepEqual(params, []);
});

test('omitting parseStatus keeps the historical "both populations" behaviour', () => {
  const { whereClause } = buildParsedLogFilters({ sourceIp: '10.0.0.1' });

  assert.ok(!whereClause.includes('parser_id'));
});

test('parseStatus does not consume a bind slot, so later filters keep their index', () => {
  // Regression guard: parseStatus adds a condition but no param. If it ever
  // took an index, `search` below would bind to the wrong placeholder.
  const { whereClause, params } = buildParsedLogFilters({
    sourceIp: '10.0.0.1',
    parseStatus: 'unparsed',
    search: 'sshd',
  });

  assert.equal(
    whereClause,
    'WHERE pl.source_ip = $1 AND pl.parser_id IS NULL AND pl.parsed_data::text ILIKE $2'
  );
  assert.deepEqual(params, ['10.0.0.1', '%sshd%']);
});

test('parsed appName filters the joined raw_logs column, not parsed_logs', () => {
  // "Source" in the Parsed Logs view IS raw_logs.app_name, reached via the join.
  const { whereClause, params } = buildParsedLogFilters({ appName: 'sshd' });

  assert.equal(whereClause, 'WHERE rl.app_name = $1');
  assert.deepEqual(params, ['sshd']);
});

test('raw appName filters the same underlying column as the parsed view', () => {
  const { whereClause, params } = buildRawLogFilters({ appName: 'sshd' });

  assert.equal(whereClause, 'WHERE app_name = $1');
  assert.deepEqual(params, ['sshd']);
});

test('raw filters bind in order with sequential indexes', () => {
  const start = new Date('2026-01-01T00:00:00Z');
  const { whereClause, params } = buildRawLogFilters({
    sourceIp: '10.0.0.1',
    appName: 'nginx',
    hostname: 'web01',
    search: 'error',
    severity: 3,
    startTime: start,
  });

  assert.equal(
    whereClause,
    'WHERE source_ip = $1 AND app_name = $2 AND hostname = $3 AND raw_message ILIKE $4 ' +
      'AND severity = $5 AND timestamp >= $6'
  );
  assert.deepEqual(params, ['10.0.0.1', 'nginx', 'web01', '%error%', 3, start]);
});

test('severity 0 (emergency) is still filtered — it is a valid value, not "unset"', () => {
  const { whereClause, params } = buildRawLogFilters({ severity: 0 });

  assert.equal(whereClause, 'WHERE severity = $1');
  assert.deepEqual(params, [0]);
});

test('parserId 0 is honoured rather than treated as absent', () => {
  const { whereClause, params } = buildParsedLogFilters({ parserId: 0 });

  assert.equal(whereClause, 'WHERE pl.parser_id = $1');
  assert.deepEqual(params, [0]);
});

test('NaN parserId (a non-numeric query string) is ignored', () => {
  const { whereClause, params } = buildParsedLogFilters({ parserId: NaN });

  assert.equal(whereClause, '');
  assert.deepEqual(params, []);
});
