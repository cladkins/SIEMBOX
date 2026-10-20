/**
 * Unit tests for Sigma -> portable conversion. Run with `npm test` (tsx --test).
 * Each successful conversion is also re-validated through validateRule so an
 * imported rule can never be one the engine would reject.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sigmaToPortable, sigmaToPortableAll, convertSigmaYaml, MAX_SIGMA_SPLIT } from './sigmaConvert';
import { conditionsMatchSample } from './detectionRecommendations';
import { validateRule, collectRuleRegexes, ruleRegexTypeErrors } from './rulePortable';
import { scanRegexRefs } from '../parser/redos';

/** Assert a converted rule is non-null and passes strict portable validation. */
function assertValid(result: ReturnType<typeof sigmaToPortable>) {
  assert.ok(result.rule, `expected a rule, got errors: ${result.errors.join('; ')}`);
  const v = validateRule(result.rule, { strict: true });
  assert.ok(v.ok, `converted rule failed validation: ${v.errors.join('; ')}`);
}

test('converts a basic single-selection web rule', () => {
  const r = sigmaToPortable({
    title: 'Suspicious Admin Path',
    description: 'Access to /admin',
    level: 'high',
    tags: ['attack.t1190'],
    detection: {
      selection: { 'c-uri': '/admin', 'sc-status': 200 },
      condition: 'selection',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.severity, 'high');
  assert.equal(r.rule!.enabled, false); // imported disabled for review
  assert.ok(r.rule!.tags!.includes('sigma'));
  assert.ok(r.rule!.tags!.includes('attack.t1190'));
  // c-uri -> path, sc-status -> status_code
  const fields = r.rule!.conditions.map((c) => c.field).sort();
  assert.deepEqual(fields, ['path', 'status_code']);
  const pathCond = r.rule!.conditions.find((c) => c.field === 'path');
  assert.equal(pathCond!.operator, 'equals');
  assert.equal(pathCond!.value, '/admin');
});

test('list value becomes an `in` (OR membership) condition', () => {
  const r = sigmaToPortable({
    title: 'Bad methods',
    level: 'medium',
    detection: {
      selection: { 'cs-method': ['PUT', 'DELETE', 'TRACE'] },
      condition: 'selection',
    },
  });
  assertValid(r);
  const c = r.rule!.conditions[0];
  assert.equal(c.field, 'method');
  assert.equal(c.operator, 'in');
  assert.deepEqual(c.value, ['PUT', 'DELETE', 'TRACE']);
});

test('contains / startswith / endswith / re modifiers map correctly', () => {
  const r = sigmaToPortable({
    title: 'Modifiers',
    level: 'low',
    detection: {
      selection: {
        'c-uri|contains': '../',
        'c-useragent|startswith': 'sqlmap',
        'cs-uri-stem|endswith': '.php',
        'c-uri|re': '/api/v[0-9]+/admin',
      },
      condition: 'selection',
    },
  });
  assertValid(r);
  const byVal = Object.fromEntries(r.rule!.conditions.map((c) => [String(c.value), c]));
  assert.equal(byVal['../'].operator, 'contains');
  assert.equal(byVal['^sqlmap'].operator, 'regex'); // startswith -> anchored regex
  assert.equal(byVal['\\.php$'].operator, 'regex'); // endswith -> escaped + anchored
  assert.equal(byVal['/api/v[0-9]+/admin'].operator, 'regex'); // re -> regex passthrough
});

test('wildcard values convert to anchored regex', () => {
  const r = sigmaToPortable({
    title: 'Wildcards',
    level: 'medium',
    detection: { selection: { 'c-uri': '*/wp-admin/*' }, condition: 'selection' },
  });
  assertValid(r);
  const c = r.rule!.conditions[0];
  assert.equal(c.operator, 'regex');
  // `*x*` on a whole value is "contains x": a plain literal, not ^.*x.*$, which
  // is polynomial ReDoS (the regex safety gate refuses it).
  assert.equal(c.value, '/wp-admin/');
  const re = new RegExp(String(c.value));
  assert.equal(re.test('/blog/wp-admin/index.php'), true);
  assert.equal(re.test('/wp-login.php'), false);
});

test('`|all` modifier produces an AND list of conditions', () => {
  const r = sigmaToPortable({
    title: 'All of these',
    level: 'high',
    detection: {
      selection: { 'c-uri|contains|all': ['etc', 'passwd'] },
      condition: 'selection',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.conditions.length, 2);
  assert.ok(r.rule!.conditions.every((c) => c.operator === 'contains'));
  assert.deepEqual(r.rule!.conditions.map((c) => c.value).sort(), ['etc', 'passwd']);
});

test('multiple selections AND-ed via `a and b` and `all of them`', () => {
  const and = sigmaToPortable({
    title: 'Two sels',
    level: 'medium',
    detection: {
      selection1: { 'cs-method': 'POST' },
      selection2: { 'sc-status': 403 },
      condition: 'selection1 and selection2',
    },
  });
  assertValid(and);
  assert.equal(and.rule!.conditions.length, 2);

  const allOf = sigmaToPortable({
    title: 'All of them',
    level: 'medium',
    detection: {
      sel_a: { 'cs-method': 'POST' },
      sel_b: { 'sc-status': 403 },
      condition: 'all of them',
    },
  });
  assertValid(allOf);
  assert.equal(allOf.rule!.conditions.length, 2);
});

test('null value means "field exists"', () => {
  const r = sigmaToPortable({
    title: 'Has user agent',
    level: 'low',
    detection: { selection: { 'c-useragent': null }, condition: 'selection' },
  });
  assertValid(r);
  assert.equal(r.rule!.conditions[0].operator, 'exists');
  assert.equal(r.rule!.conditions[0].value, true);
});

test('OR splits into one rule per alternative; NOT inside NOT, bare NOT and | count are refused', () => {
  const refused: Array<[string, RegExp]> = [
    ['not (selection and not filter)', /NOT inside NOT/],
    ['not filter', /at least one selection that must match/],
    ['selection | count() > 5', /aggregation/],
    ['selection and (filter', /unbalanced parentheses/],
    ['selection and other', /unknown selection "other"/],
  ];
  for (const [condition, why] of refused) {
    const r = sigmaToPortable({
      title: 'Complex',
      level: 'high',
      detection: { selection: { a: 'x' }, filter: { b: 'y' }, condition },
    });
    assert.equal(r.rule, null, `condition "${condition}" should be unsupported`);
    assert.match(r.errors.join(' '), why);
  }
});

test('a keywords selection (list of strings) converts to a regex on message', () => {
  const r = sigmaToPortable({
    title: 'Suspicious SQL Query',
    level: 'medium',
    detection: {
      keywords: ['drop', 'truncate', 'dump', 'select \\*'],
      condition: 'keywords',
    },
    falsepositives: ['Inventory and monitoring activity'],
  });
  assertValid(r);
  assert.equal(r.rule!.conditions.length, 1);
  const c = r.rule!.conditions[0];
  assert.equal(c.field, 'message');
  assert.equal(c.operator, 'regex');
  // Un-anchored alternation against `message`; each keyword is encoded
  // case-INsensitively (Sigma default) as per-letter classes, and the escaped
  // `\*` is a LITERAL asterisk, not a wildcard.
  assert.equal(
    c.value,
    '(?:[Dd][Rr][Oo][Pp]|[Tt][Rr][Uu][Nn][Cc][Aa][Tt][Ee]|[Dd][Uu][Mm][Pp]|[Ss][Ee][Ll][Ee][Cc][Tt] \\*)'
  );
});

test('keywords with a bare wildcard become a regex wildcard', () => {
  const r = sigmaToPortable({
    title: 'Wildcard keyword',
    level: 'low',
    detection: { keywords: ['/etc/*/passwd'], condition: 'keywords' },
  });
  assertValid(r);
  // An inner `*` is a first-occurrence chain (linear), not `.*` (polynomial
  // ReDoS once the line is unanchored); letters become case-insensitive classes.
  const value = String(r.rule!.conditions[0].value);
  assert.equal(
    value,
    '(?:^(?:(?!/[Ee][Tt][Cc]/)[\\s\\S])*/[Ee][Tt][Cc]/(?:(?!/[Pp][Aa][Ss][Ss][Ww][Dd])[\\s\\S])*/[Pp][Aa][Ss][Ss][Ww][Dd])'
  );
  const re = new RegExp(value);
  assert.equal(re.test('GET /ETC/x/y/passwd HTTP/1.1'), true);
  assert.equal(re.test('cat /etc/passwd'), false, 'the wildcard needs a segment between');
  assert.equal(re.test('/passwd then /etc/'), false, 'order matters');
});

/** Classic glob matcher (`*` any run, `?` one character): the reference semantics. */
function globMatches(glob: string, s: string): boolean {
  const dp = Array.from({ length: glob.length + 1 }, () => new Array<boolean>(s.length + 1).fill(false));
  dp[0][0] = true;
  for (let i = 1; i <= glob.length; i++) if (glob[i - 1] === '*') dp[i][0] = dp[i - 1][0];
  for (let i = 1; i <= glob.length; i++) {
    for (let j = 1; j <= s.length; j++) {
      const g = glob[i - 1];
      if (g === '*') dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
      else if (g === '?' || g === s[j - 1]) dp[i][j] = dp[i - 1][j - 1];
    }
  }
  return dp[glob.length][s.length];
}

/** Deterministic PRNG so a failure reproduces. */
function prng(seed: number): () => number {
  return () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
}

test('wildcard values and keywords match exactly what the Sigma glob means', () => {
  // Overlapping blocks ("aa" then "ab", "ab" then "ba") are where a shortcut
  // linearization goes wrong, so the alphabet is built to produce them.
  const rand = prng(42);
  const tokens = ['a', 'b', 'ab', 'ba', 'aa', '*', '*', '?'];
  for (let n = 0; n < 1500; n++) {
    const glob = Array.from({ length: 1 + Math.floor(rand() * 5) }, () => tokens[Math.floor(rand() * tokens.length)]).join('');
    const field = sigmaToPortable({ title: 't', detection: { sel: { f: glob }, condition: 'sel' } }).rule!.conditions[0];
    const keyword = sigmaToPortable({ title: 't', detection: { keywords: [glob], condition: 'keywords' } }).rule!.conditions[0];
    const fieldRe = field.operator === 'regex' ? new RegExp(String(field.value)) : null;
    const keywordRe = new RegExp(String(keyword.value));
    for (let m = 0; m < 20; m++) {
      const subject = Array.from({ length: Math.floor(rand() * 7) }, () => 'ab'[Math.floor(rand() * 2)]).join('');
      const expected = /[*?]/.test(glob) ? globMatches(glob, subject) : subject === glob;
      const actual = fieldRe ? fieldRe.test(subject) : subject === String(field.value);
      assert.equal(actual, expected, `field glob ${JSON.stringify(glob)} on ${JSON.stringify(subject)}`);
      assert.equal(keywordRe.test(subject), globMatches(`*${glob}*`, subject), `keyword ${JSON.stringify(glob)} on ${JSON.stringify(subject)}`);
    }
  }
});

test('wildcard conversions are linear: recheck proves them safe and a crafted line stays fast', () => {
  const r = sigmaToPortable({
    title: 'Globs',
    level: 'medium',
    detection: {
      sel: { 'c-uri': '*/wp-*/admin*', 'cs-user-agent': ['*sqlmap*', 'nikto*', '*masscan'] },
      kw: ['*union*select*', 'drop * table'],
      condition: 'sel and kw',
    },
  });
  assertValid(r);
  const refs = collectRuleRegexes(r.rule);
  assert.ok(refs.length >= 3, 'the globs became regex conditions');
  const vulnerable = scanRegexRefs(refs).filter((f) => f.status === 'vulnerable');
  assert.deepEqual(vulnerable, [], 'no converted glob is ReDoS-vulnerable');
  // The shape recheck flagged before this change: many starts, no end token.
  const hostile = '/wp-'.repeat(16_000);
  for (const ref of refs) {
    const started = process.hrtime.bigint();
    new RegExp(ref.source, ref.flags).test(hostile);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms < 250, `${ref.location} took ${ms.toFixed(0)} ms on a 64 KB crafted line`);
  }
});

test('a selection that is a list of maps (OR) splits into one rule per map', () => {
  const rs = sigmaToPortableAll({
    title: 'List selection',
    level: 'high',
    detection: { selection: [{ a: 'x' }, { b: 'y' }], condition: 'selection' },
  });
  assert.deepEqual(rs.map((r) => r.rule?.conditions), [
    [{ field: 'a', operator: 'equals', value: 'x' }],
    [{ field: 'b', operator: 'equals', value: 'y' }],
  ]);
  rs.forEach(assertValid);
});

test('gte/lte and unsupported modifiers are skipped with a warning', () => {
  // Only the gte field is present -> nothing representable -> rule fails with reason.
  const r = sigmaToPortable({
    title: 'Gte only',
    level: 'low',
    detection: { selection: { 'bytes|gte': 1000 }, condition: 'selection' },
  });
  assert.equal(r.rule, null);
  assert.ok(r.warnings.join(' ').includes('gte') || r.errors.join(' ').includes('representable'));
});

test('convertSigmaYaml handles multiple --- separated documents', () => {
  const text = `
title: Rule A
level: high
detection:
  selection:
    c-uri: /a
  condition: selection
---
title: Rule B
level: low
detection:
  selection:
    c-uri: /b
  condition: selection
`;
  const results = convertSigmaYaml(text);
  assert.equal(results.length, 2);
  assert.equal(results[0].rule!.name, 'Rule A');
  assert.equal(results[1].rule!.name, 'Rule B');
});

test('invalid YAML returns a single error result', () => {
  const results = convertSigmaYaml(':\n  - [unclosed');
  assert.equal(results.length, 1);
  assert.equal(results[0].rule, null);
  assert.ok(results[0].errors[0].toLowerCase().includes('yaml'));
});

test('a pasted rule with wrapped quoted text and a wrapped tag list converts', () => {
  // Continuation lines no deeper than their key, as an editor or a chat paste
  // wraps them: js-yaml 4 folds them, and the YAML loader must keep doing so.
  const results = convertSigmaYaml(
    'title: Admin Area Access\n' +
      'description: "Detects requests to the admin area\nof the proxy"\n' +
      'tags: [attack.t1190,\nattack.initial_access]\n' +
      'level: medium\n' +
      'detection:\n  selection:\n    c-uri|startswith: /admin\n  condition: selection\n'
  );
  assert.equal(results.length, 1);
  assertValid(results[0]);
  assert.equal(results[0].rule!.description, 'Detects requests to the admin area of the proxy');
  assert.ok(results[0].rule!.tags!.includes('attack.t1190'));
  assert.ok(results[0].rule!.tags!.includes('attack.initial_access'));
});

// ---- OR and NOT (rule splitting and exclude groups) -------------------------

/** What the engine does with a converted rule on one log (conditions, then exclude). */
function fires(rule: any, data: Record<string, any>): boolean {
  return conditionsMatchSample(rule.conditions, data, rule.exclude);
}

test('"1 of selection_*" imports as one rule per selection, named by part', () => {
  const rs = convertSigmaYaml(`
title: Web shell access
level: high
detection:
  selection_php:
    uri|endswith: '.php'
    status: 200
  selection_jsp:
    uri|endswith: '.jsp'
  condition: 1 of selection_*
`);
  assert.equal(rs.length, 2);
  assert.deepEqual(rs.map((r) => r.rule!.name), ['Web shell access (part 1 of 2)', 'Web shell access (part 2 of 2)']);
  for (const r of rs) {
    assertValid(r);
    assert.equal(r.rule!.alert.title, 'Web shell access'); // alerts keep the Sigma title
    assert.match(r.warnings[0], /imports as 2 rules, one per alternative/);
  }
  // Sigma's uri/status map to SIEMBox's path/status_code.
  assert.equal(fires(rs[0].rule, { path: '/x/shell.php', status_code: '200' }), true);
  assert.equal(fires(rs[0].rule, { path: '/x/shell.php', status_code: '404' }), false);
  assert.equal(fires(rs[1].rule, { path: '/a.jsp' }), true);
});

test('or, parentheses and a list of conditions expand to the same alternatives', () => {
  const detection = { a: { f: '1' }, b: { g: '2' }, c: { h: '3' } };
  const viaParens = sigmaToPortableAll({ title: 'T', detection: { ...detection, condition: 'a and (b or c)' } });
  const viaList = sigmaToPortableAll({ title: 'T', detection: { ...detection, condition: ['a and b', 'a and c'] } });
  const shape = (rs: any[]) => rs.map((r) => r.rule.conditions.map((c: any) => c.field).join('+'));
  assert.deepEqual(shape(viaParens), ['f+g', 'f+h']);
  assert.deepEqual(shape(viaList), ['f+g', 'f+h']);
  const oneOfThem = sigmaToPortableAll({ title: 'T', detection: { ...detection, condition: '1 of them' } });
  assert.deepEqual(shape(oneOfThem), ['f', 'g', 'h']);
});

test(`more than ${MAX_SIGMA_SPLIT} alternatives is refused, not imported as a pile of rules`, () => {
  const detection: Record<string, any> = { condition: '1 of sel*' };
  for (let i = 0; i <= MAX_SIGMA_SPLIT; i++) detection[`sel${i}`] = { f: String(i) };
  const rs = sigmaToPortableAll({ title: 'Many', detection });
  assert.equal(rs.length, 1);
  assert.equal(rs[0].rule, null);
  assert.match(rs[0].errors.join(' '), new RegExp(`OR of ${MAX_SIGMA_SPLIT + 1} alternatives`));
});

test('"selection and not filter" becomes an exclude group with Sigma semantics', () => {
  const r = sigmaToPortable({
    title: 'Sudo to root outside admins',
    level: 'medium',
    detection: {
      selection: { program: 'sudo', target_user: 'root' },
      filter_admin: { user: ['alice', 'bob'] },
      condition: 'selection and not filter_admin',
    },
  });
  assertValid(r);
  assert.deepEqual(r.rule!.exclude, [[{ field: 'user', operator: 'in', value: ['alice', 'bob'] }]]);
  const base = { program: 'sudo', target_user: 'root' };
  assert.equal(fires(r.rule, { ...base, user: 'mallory' }), true); // filter doesn't match
  assert.equal(fires(r.rule, { ...base, user: 'alice' }), false); // filtered out
  // A log without the filter's field is NOT filtered out (as in Sigma).
  assert.equal(fires(r.rule, base), true);
  assert.equal(fires(r.rule, { program: 'sudo', target_user: 'bob' }), false); // selection fails
});

test('NOT of an OR (1 of filter_*, a list of maps) excludes each alternative', () => {
  const r = sigmaToPortable({
    title: 'T',
    detection: {
      selection: { event: 'login' },
      filter_a: { src: '10.0.0.1' },
      filter_b: [{ user: 'svc' }, { user: 'backup', host: 'nas' }],
      condition: 'selection and not 1 of filter_*',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.exclude!.length, 3);
  assert.equal(fires(r.rule, { event: 'login', src: '10.0.0.1' }), false);
  assert.equal(fires(r.rule, { event: 'login', user: 'svc' }), false);
  assert.equal(fires(r.rule, { event: 'login', user: 'backup', host: 'nas' }), false);
  assert.equal(fires(r.rule, { event: 'login', user: 'backup', host: 'pc' }), true); // group needs both
  assert.equal(fires(r.rule, { event: 'login', src: '10.0.0.2', user: 'eve' }), true);
});

test('OR-lists of contains/startswith/endswith/re become one regex condition', () => {
  const r = sigmaToPortable({
    title: 'T',
    detection: {
      selection: {
        'cmd|contains': ['wget ', 'CURL '],
        'path|startswith': ['/tmp/', '/dev/shm/'],
        'file|endswith': ['.sh', '.py'],
        'ua|re': ['^sqlmap', 'nikto'],
      },
      condition: 'selection',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.conditions.length, 4);
  assert.ok(r.rule!.conditions.every((c) => c.operator === 'regex'));
  const hit = { cmd: 'curl http://x | sh', path: '/dev/shm/a', file: 'run.py', ua: 'Nikto/2.5' };
  assert.equal(fires(r.rule, { ...hit, ua: 'nikto/2.5' }), true); // contains is case-insensitive
  assert.equal(fires(r.rule, { ...hit, path: '/var/tmp/a', ua: 'nikto' }), false); // startswith anchors
  assert.equal(fires(r.rule, { ...hit, file: 'run.pyc', ua: 'nikto' }), false); // endswith anchors
  // The regex gate reads them (no rule can smuggle an unchecked pattern).
  assert.equal(collectRuleRegexes(r.rule).length, 4);
});

test('exclude-group regexes reach the regex safety gate, and bad exclude shapes are refused', () => {
  const rule = {
    name: 'x',
    severity: 'low',
    conditions: [{ field: 'a', operator: 'equals', value: '1' }],
    exclude: [[{ field: 'b', operator: 'regex', value: '^ok' }]],
    alert: { title: 't', description: 'd' },
  };
  assert.deepEqual(
    collectRuleRegexes(rule).map((r) => r.location),
    ['exclude[0][0].value']
  );
  assert.ok(validateRule(rule, { strict: true }).ok);
  for (const [exclude, msg] of [
    [{}, /exclude must be a list/],
    [[[]], /exclude\[0\] must be a non-empty list/],
    [[[{ field: 'b', operator: 'nope', value: 1 }]], /exclude\[0\]\[0\]\.operator "nope"/],
  ] as const) {
    assert.match(validateRule({ ...rule, exclude }).errors.join(' '), msg);
  }
  // The rule routes' shape check (they store YAML as-is) refuses the same shapes.
  assert.deepEqual(ruleRegexTypeErrors(rule), []);
  for (const exclude of [{}, [[]], [['x']], [{ field: 'b' }]]) {
    assert.deepEqual(ruleRegexTypeErrors({ ...rule, exclude }), ['exclude must be a list of non-empty condition lists']);
  }
});
