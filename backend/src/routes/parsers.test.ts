/**
 * validateCreateParserBody is the one DB-free piece of POST /api/parsers (the
 * "Create Parser" button's endpoint). It mirrors the rule
 * services/parser/parserPortable.ts already enforces on every other
 * parser-ingestion path (validate/import/catalog install): JSON parsers don't
 * take a pattern, but pattern must still be present as a string -- the column
 * is NOT NULL. Before this, the route's own unconditional `!pattern` check
 * made creating a JSON-type parser impossible from this endpoint.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateCreateParserBody } from './parsers';

const base = { name: 'my-parser', field_mappings: { message: 'message' } };

test('accepts a json parser with an empty-string pattern', () => {
  assert.equal(validateCreateParserBody({ ...base, parser_type: 'json', pattern: '' }), null);
});

test('accepts a regex parser with a non-empty pattern', () => {
  assert.equal(validateCreateParserBody({ ...base, parser_type: 'regex', pattern: '^(?<message>.+)$' }), null);
});

test('rejects a regex/grok parser with an empty pattern', () => {
  for (const parser_type of ['regex', 'grok']) {
    const error = validateCreateParserBody({ ...base, parser_type, pattern: '' });
    assert.match(error ?? '', /pattern is required for regex\/grok parsers/);
  }
});

test('rejects a missing pattern (not a string at all), even for json', () => {
  for (const parser_type of ['json', 'regex']) {
    const error = validateCreateParserBody({ ...base, parser_type, pattern: undefined });
    assert.match(error ?? '', /Missing required fields/);
  }
});

test('rejects a non-string pattern', () => {
  const error = validateCreateParserBody({ ...base, parser_type: 'json', pattern: 123 as unknown as string });
  assert.match(error ?? '', /Missing required fields/);
});

test('rejects a missing name, parser_type, or field_mappings', () => {
  assert.match(validateCreateParserBody({ ...base, parser_type: 'json', pattern: '', name: '' }) ?? '', /Missing required fields/);
  assert.match(validateCreateParserBody({ name: 'x', field_mappings: {}, parser_type: '', pattern: '' }) ?? '', /Missing required fields/);
  assert.match(
    validateCreateParserBody({ name: 'x', parser_type: 'json', pattern: '', field_mappings: undefined }) ?? '',
    /Missing required fields/
  );
});
