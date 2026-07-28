/**
 * Detection-rule coverage tests.
 *
 * Rules are data, so a pattern can quietly stop matching what it was written
 * for without anything failing. These pin two blind spots found by firing
 * synthetic attacks through the live pipeline:
 *
 *  1. PROXY-001 missed percent-encoded SQL injection. The rules engine compiles
 *     patterns with `new RegExp(value)` — no flags — so matching is
 *     case-sensitive, and `\b` does not help after an encoded separator because
 *     in "%20UNION" the character before U is '0', a word character. Real
 *     tooling emits encoded, often lowercase payloads, so the rule caught
 *     roughly half of what it should.
 *  2. PROXY-005 keys on user_agent, which only some HTTP parsers capture.
 *
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

const RULES = path.join(__dirname, '../../../../rules');

function ruleRegex(file: string, field: string): RegExp {
  const doc = yaml.load(fs.readFileSync(path.join(RULES, file), 'utf8')) as any;
  const cond = doc.conditions.find((c: any) => c.field === field && c.operator === 'regex');
  assert.ok(cond, `${file} has no regex condition on ${field}`);
  // Compiled exactly as rulesEngine does — no flags.
  return new RegExp(String(cond.value));
}

const SQLI = ruleRegex('reverse-proxy/PROXY-001-sql-injection.yaml', 'path');

const ENCODED_ATTACKS: Array<[string, string]> = [
  ['percent-encoded quote (sqlmap default)', "/product?id=1%27"],
  ['percent-encoded double quote', '/product?id=1%22'],
  ['encoded UNION SELECT', '/product?id=-1%20UNION%20SELECT%201,2,3'],
  ['encoded lowercase union select', '/product?id=-1%20union%20select%201,2,3'],
  ['mixed-case keyword', '/product?id=1+UnIoN+SeLeCt+null'],
  ['encoded comment marker', '/product?id=1%2D%2D+'],
  ['encoded semicolon then DROP', '/product?id=1%3B+DROP+TABLE+users'],
  ['lowercase drop table', '/product?id=1;drop table users'],
  ['uppercase hex literal', '/product?id=0X4142'],
];

const LITERAL_ATTACKS: Array<[string, string]> = [
  ['literal quote', "/product?id=1'"],
  ['plus-separated UNION', '/search?q=1+UNION+SELECT+*+FROM+users--'],
  ['boolean OR injection', "/login?u=admin'+OR+'1'='1"],
];

// URLs that must NOT alert. A SQL-injection rule that fires on ordinary traffic
// is worse than one that misses, because the noise trains operators to ignore it.
const BENIGN = [
  '/index.html',
  '/api/v1/health',
  '/articles/communion-service', // contains "union"
  '/docs/selection-guide', // contains "select"
  '/search?q=cats+or+dogs', // natural-language lowercase "or"
  '/blog/my-first-post',
  '/static/js/app.min.js',
  '/report?year=2026&month=07',
  '/search?q=hello%20world',
  '/u/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0',
  '/products/dropdown-menu', // contains "drop"
  '/account/updates', // contains "update"
];

for (const [label, url] of [...ENCODED_ATTACKS, ...LITERAL_ATTACKS]) {
  test(`PROXY-001 detects SQL injection: ${label}`, () => {
    assert.ok(SQLI.test(url), `pattern did not match ${url}`);
  });
}

test('PROXY-001 does not fire on ordinary traffic', () => {
  const firing = BENIGN.filter((u) => SQLI.test(u));
  assert.deepEqual(firing, [], `false positives on: ${firing.join(', ')}`);
});

test('PROXY-005 keys on user_agent, so its source parser must capture one', () => {
  // The rule is only reachable from parsers that actually extract user_agent.
  // apache-nginx-access-log does not, which is why it must not sort ahead of
  // standard-nginx-access (see parserPriority.test.ts).
  const doc = yaml.load(
    fs.readFileSync(path.join(RULES, 'reverse-proxy/PROXY-005-malicious-user-agent.yaml'), 'utf8')
  ) as any;
  assert.ok(doc.conditions.some((c: any) => c.field === 'user_agent'));

  const catalog = path.join(__dirname, '../../../../catalog/parsers');
  const capturing = fs
    .readdirSync(catalog)
    .filter((f) => f.endsWith('.parser.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(catalog, f), 'utf8')))
    .filter((p) => JSON.stringify(p.field_mappings).includes('user_agent'));

  assert.ok(capturing.length > 0, 'no catalog parser captures user_agent at all');
});
