/**
 * The write-time regex gate (regexSafety.ts): what it refuses, what it accepts
 * with a warning, and the verdict cache. DB-free: the persistent store is
 * replaced by an in-memory fake. Run with `npm test` (tsx --test).
 */
import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  assessParserRegexes,
  assessRegexes,
  assessRuleRegexes,
  checkerId,
  clearRegexVerdictCache,
  closeRegexScanPool,
  collectRuleRegexes,
  isRefused,
  mergeReports,
  peekRegexSafety,
  refusalBody,
  refusalCode,
  setTransientVerdictTtl,
  setVerdictStore,
  type RegexVerdict,
  type VerdictStore,
} from './regexSafety';
import { isUndecidedUnbounded, redosErrorMessage, redosUndecidedMessage, scanParserRedos } from '../parser/redos';

setVerdictStore(null);
beforeEach(() => clearRegexVerdictCache());
after(async () => {
  await closeRegexScanPool();
});

test('an exponential regex is refused with the contribute check wording', async () => {
  const report = await assessParserRegexes({ parser_type: 'regex', pattern: '^(a+)+$' });
  assert.equal(report.vulnerable.length, 1);
  const [f] = report.vulnerable;
  assert.equal(f.location, 'pattern');
  assert.equal(f.source, '^(a+)+$');
  assert.equal(f.complexity, 'exponential');
  assert.ok(f.attack, 'recheck says which input is slow');
  assert.deepEqual(report.errors, ['ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before saving']);
  // The same sentence the contribute check uses, with its own verb.
  assert.equal(redosErrorMessage(f, 'contributing'), 'ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before contributing');

  const body = refusalBody('Parser "x"', report);
  assert.equal(body.code, 'REGEX_UNSAFE');
  assert.match(body.message, /^Parser "x" was not saved: ReDoS: regex at pattern is vulnerable \(exponential\)/);
});

test('a polynomial regex in a derivation is refused too, named by its location', async () => {
  const report = await assessParserRegexes({
    parser_type: 'regex',
    pattern: '^(?<message>.+)$',
    derivations: [{ when: { message: { matches: 'curl.*\\|' } }, set: { suspicious: true } }],
  });
  assert.deepEqual(report.vulnerable.map((f) => [f.location, f.flags, f.complexity]), [
    ['derivations[0].when.message.matches', 'i', 'polynomial, degree 2'],
  ]);
});

test('a linear regex passes with nothing to report', async () => {
  const report = await assessParserRegexes({
    parser_type: 'regex',
    pattern: '^(?<client_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) - (?<user>\\S+) \\[(?<ts>[^\\]]+)\\]',
  });
  assert.deepEqual(report, { vulnerable: [], undecided: [], unknown: [], errors: [], warnings: [] });
});

test('an indeterminate regex is accepted with a warning', async (t) => {
  // A safe but large pattern recheck cannot settle within a tiny budget.
  const previous = process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
  process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = '100';
  t.after(() => {
    if (previous === undefined) delete process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
    else process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = previous;
  });
  const pattern =
    '^(?<client_ip>[\\d.]+) - (?<remote_user>\\S+) \\[(?<timestamp>[^\\]]+)\\] "(?<method>\\w+) (?<request_uri>\\S+) ' +
    '(?<protocol>[^"]+)" (?<status_code>\\d{3}) (?<bytes>\\d+|-)(?: "(?<referer>[^"]*)" "(?<user_agent>[^"]*)")?' +
    '(?: (?<request_time>[\\d.]+))?(?: (?<upstream>\\S+))?$';
  const report = await assessParserRegexes({ parser_type: 'regex', pattern });
  assert.equal(report.vulnerable.length, 0, 'never refused');
  assert.equal(report.unknown.length, 1);
  assert.match(report.warnings[0], /^ReDoS: regex at pattern could not be proven safe \(unknown: the analysis hit its time budget\)$/);
});

test('a regex the analyzer cannot read is refused when the linear-time fallback cannot bound it either', async (t) => {
  // Annex B reads \u{17} (no u flag) as "u" seventeen times. recheck cannot
  // parse it, so the verdict is "unknown"; V8's linear engine refuses a repeat
  // of 17, so the fallback would not cut it: 'a'.repeat(27) + 'u'.repeat(16) + '!'
  // backtracks for about 8 s on the event loop. It used to be saved with a warning.
  const report = await assessParserRegexes({ parser_type: 'regex', pattern: '^(?<x>(a+)+)\\u{17}$' });
  assert.equal(report.vulnerable.length, 0, 'not proven vulnerable');
  assert.deepEqual(report.unknown, []);
  assert.deepEqual(report.undecided.map((f) => [f.location, f.status, f.unbounded]), [
    ['pattern', 'unknown', "V8's linear-time fallback cannot run it (a counted repeat over 16)"],
  ]);
  assert.match(report.undecided[0].detail ?? '', /could not parse it/);
  assert.equal(isRefused(report), true);
  assert.equal(report.errors.length, 1);
  assert.match(
    report.errors[0],
    /^ReDoS: regex at pattern could not be proven safe \(unknown: the analyzer could not parse it \(.+\)\) and V8's linear-time fallback cannot run it \(a counted repeat over 16\), so nothing would bound it on a log line — rewrite it before saving$/
  );
  const body = refusalBody('Parser "x"', report);
  assert.equal(body.code, 'REGEX_UNDECIDED');
  assert.deepEqual(body.regex_safety.undecided, report.undecided);

  // The same unreadable regex inside the linear engine (\u{1}): the fallback
  // bounds it on a log line, so it is accepted with a warning, as before.
  const bounded = await assessParserRegexes({ parser_type: 'regex', pattern: '^(?<x>(a+)+)\\u{1}$' });
  assert.equal(isRefused(bounded), false);
  assert.equal(bounded.warnings.length, 1);
  assert.match(bounded.warnings[0], /^ReDoS: regex at pattern could not be proven safe \(unknown: the analyzer could not parse it \(.+\)\)$/);

  // ...but not as a rule condition with the i flag (the linear engine has no
  // i), nor as a derivation `matches` (always case-insensitive).
  const rule = await assessRuleRegexes({
    conditions: [{ field: 'message', operator: 'regex', value: '^(a+)+\\u{1}$', flags: 'i' }],
  });
  assert.equal(refusalCode(rule), 'REGEX_UNDECIDED');
  assert.match(rule.errors[0], /^ReDoS: regex at conditions\[0\]\.value could not be proven safe .*the i flag/);
  const derived = await assessParserRegexes({
    parser_type: 'regex',
    pattern: '^(?<message>.+)$',
    derivations: [{ when: { message: { matches: '^(a+)+\\u{1}$' } }, set: { t: '1' } }],
  });
  assert.deepEqual(derived.undecided.map((f) => f.location), ['derivations[0].when.message.matches']);

  // A proven-vulnerable regex next to it keeps the REGEX_UNSAFE code; both are listed.
  const both = await assessRegexes([
    { location: 'pattern', source: '^(a+)+$', flags: '' },
    { location: 'derivations[0].extract.x', source: '^(a+)+\\u{17}$', flags: '' },
  ]);
  assert.equal(refusalCode(both), 'REGEX_UNSAFE');
  assert.equal(both.errors.length, 2);
  const merged = mergeReports([{ prefix: 'rules[1].', report: both }]);
  assert.deepEqual(merged.undecided.map((f) => f.location), ['rules[1].derivations[0].extract.x']);
  assert.equal(merged.errors.length, 2);

  // With the fallback off, nothing bounds any regex: the bounded one is refused too.
  const previous = process.env.REGEX_LINEAR_FALLBACK;
  process.env.REGEX_LINEAR_FALLBACK = 'false';
  t.after(() => {
    if (previous === undefined) delete process.env.REGEX_LINEAR_FALLBACK;
    else process.env.REGEX_LINEAR_FALLBACK = previous;
  });
  const off = await assessParserRegexes({ parser_type: 'regex', pattern: '^(?<x>(a+)+)\\u{1}$' });
  assert.match(off.errors[0] ?? '', /V8's linear-time fallback is off \(REGEX_LINEAR_FALLBACK=false\)/);

  // The CLI validators (the catalog CI) fail on the same regexes, so content that passes there installs.
  const cli = scanParserRedos({ parser_type: 'regex', pattern: '^(?<x>(a+)+)\\u{17}$' }, { required: true });
  assert.deepEqual(cli.map(isUndecidedUnbounded), [true]);
  assert.match(redosUndecidedMessage(cli[0], 'contributing'), /nothing would bound it on a log line — rewrite it before contributing$/);
});

test('an analysis that only ran out of time is accepted even outside the linear engine, and the warning says nothing bounds it', async (t) => {
  // Refusing these would refuse shipped content: on the pure-JS analyzer the
  // Docker image runs, rules such as PROXY-001 (lookahead) outlast the default budget.
  const previous = process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
  process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = '100';
  t.after(() => {
    if (previous === undefined) delete process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
    else process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = previous;
  });
  // The large pattern the "indeterminate" test uses, as a case-insensitive rule condition.
  const value =
    '^(?<client_ip>[\\d.]+) - (?<remote_user>\\S+) \\[(?<timestamp>[^\\]]+)\\] "(?<method>\\w+) (?<request_uri>\\S+) ' +
    '(?<protocol>[^"]+)" (?<status_code>\\d{3}) (?<bytes>\\d+|-)(?: "(?<referer>[^"]*)" "(?<user_agent>[^"]*)")?' +
    '(?: (?<request_time>[\\d.]+))?(?: (?<upstream>\\S+))?$';
  const report = await assessRuleRegexes({ conditions: [{ field: 'message', operator: 'regex', value, flags: 'i' }] });
  assert.equal(isRefused(report), false);
  const why = "V8's linear-time fallback cannot run it (the i flag, which every derivation `matches` has)";
  assert.deepEqual(report.unknown.map((f) => [f.outOfTime, f.unbounded]), [[true, why]]);
  assert.deepEqual(report.warnings, [
    'ReDoS: regex at conditions[0].value could not be proven safe (unknown: the analysis hit its time budget); ' +
      `${why}, so until an analysis decides it nothing bounds it on a log line`,
  ]);
});

test("a rule's regex conditions are analyzed as the engine compiles them", async () => {
  const rule = {
    conditions: [
      { field: 'message', operator: 'contains', value: 'x' },
      { field: 'message', operator: 'regex', value: '(?i)^(a|a)+$' },
      { field: 'path', operator: 'regex', value: '^/admin', flags: 'i' },
    ],
  };
  assert.deepEqual(collectRuleRegexes(rule), [
    { location: 'conditions[1].value', source: '^(a|a)+$', flags: 'i' },
    { location: 'conditions[2].value', source: '^/admin', flags: 'i' },
  ]);
  // rule_logic rows (as stored) are read the same way.
  assert.equal(collectRuleRegexes({ rule_logic: rule }).length, 2);
  const report = await assessRuleRegexes(rule);
  assert.deepEqual(report.vulnerable.map((f) => f.location), ['conditions[1].value']);
});

test('verdicts are cached in memory and in the store, so a regex is analyzed once', async () => {
  const saved = new Map<string, RegexVerdict>();
  let loads = 0;
  const store: VerdictStore = {
    async load(keys) {
      loads++;
      return new Map(keys.filter((k) => saved.has(k)).map((k) => [k, saved.get(k)!]));
    },
    async loadAll() {
      return new Map(saved);
    },
    async save(entries) {
      for (const { key, verdict } of entries) saved.set(key, verdict);
    },
  };
  setVerdictStore(store);
  try {
    const refs = [{ location: 'pattern', source: '^(b+)+c$', flags: '' }];
    const first = await assessRegexes(refs);
    assert.equal(first.vulnerable.length, 1);
    assert.equal(saved.size, 1, 'the verdict was persisted');

    // Same process: memory answers, the store is not asked.
    const loadsBefore = loads;
    await assessRegexes(refs);
    assert.equal(loads, loadsBefore);

    // "After a restart": memory is empty, the store answers, nothing is re-analyzed.
    clearRegexVerdictCache();
    const tampered = [...saved.keys()][0];
    saved.set(tampered, { status: 'vulnerable', complexity: 'from the store' });
    const again = await assessRegexes(refs);
    assert.equal(again.vulnerable[0].complexity, 'from the store');
  } finally {
    setVerdictStore(null);
  }
});

test('peek never waits: an unseen regex is pending, then reports its verdict', async () => {
  const refs = [{ location: 'pattern', source: '^(c+)+d$', flags: '' }];
  assert.equal(peekRegexSafety(refs).status, 'pending');
  await assessRegexes(refs); // joins the background analysis peek started
  const after = peekRegexSafety(refs);
  assert.equal(after.status, 'vulnerable');
  assert.equal(after.vulnerable[0].location, 'pattern');
  assert.equal(peekRegexSafety([]).status, 'none');
});

test('a bounded repeat over overlapping alternatives is refused (recheck\'s defaults call it safe)', async () => {
  // With recheck's defaults this is "safe" (the {1,12} is expanded and counted
  // as constant), yet 'a'.repeat(10) + '!' stalls a V8 match for tens of seconds.
  const pattern = '^(?<x>(?:a|a|a|a|a|a|a|a){1,12})$';
  const report = await assessParserRegexes({ parser_type: 'regex', pattern });
  assert.deepEqual(report.vulnerable.map((f) => [f.location, f.complexity]), [['pattern', 'exponential']]);
  // Realistic-looking forms of the same mistake.
  for (const source of ['^(?:[a-z0-9]|[a-z0-9-]){1,30}$', '^(?:\\w|\\d){1,29}$']) {
    const r = await assessRegexes([{ location: 'pattern', source, flags: '' }]);
    assert.equal(r.vulnerable.length, 1, `${source} is refused`);
  }
  // The CLI validators (the catalog CI) use the same parameters and agree.
  const cli = scanParserRedos({ parser_type: 'regex', pattern }, { required: true });
  assert.deepEqual(cli.map((f) => f.status), ['vulnerable']);
});

test('overlapping fixed-width alternations with no quantifier are refused (recheck\'s automaton calls them safe)', async () => {
  // Ten groups of eight identical alternatives: 8^10 backtracking steps on the
  // 11 bytes 'a'.repeat(10) + '!' (about 14 s in V8). recheck's 'auto' picks its
  // automaton backend for these, which only asks whether the cost GROWS with
  // the input, and rates them safe; the fuzz pass measures the steps.
  const groups = '(?:a|a|a|a|a|a|a|a)'.repeat(10);
  const pattern = `^(?<x>${groups})$`;
  const report = await assessParserRegexes({ parser_type: 'regex', pattern });
  assert.deepEqual(report.vulnerable.map((f) => f.location), ['pattern']);
  assert.match(report.errors[0], /^ReDoS: regex at pattern is vulnerable \(exponential\)/);

  // The same mistake as a rule condition (with and without `i`), a derivation, and in realistic shapes.
  const rule = await assessRuleRegexes({
    conditions: [
      { field: 'message', operator: 'regex', value: `^(?:${groups})$` },
      { field: 'message', operator: 'regex', value: `(?i)^(?:${groups})$` },
    ],
  });
  assert.deepEqual(rule.vulnerable.map((f) => f.location), ['conditions[0].value', 'conditions[1].value']);
  const derived = await assessParserRegexes({
    parser_type: 'regex',
    pattern: '^(?<message>.+)$',
    derivations: [{ extract: { user: { from: 'message', pattern: `^(?<u>${groups})$` } } }],
  });
  assert.deepEqual(derived.vulnerable.map((f) => f.location), ['derivations[0].extract.user']);
  for (const source of [`^${'(?:\\w|\\d)'.repeat(24)}$`, `^${'(?:[a-z0-9]|[a-z0-9-])'.repeat(24)}$`]) {
    const r = await assessRegexes([{ location: 'pattern', source, flags: '' }]);
    assert.equal(r.vulnerable.length, 1, `${source} is refused`);
  }

  // The CLI validators (the catalog CI) run the same two passes and agree.
  const cli = scanParserRedos({ parser_type: 'regex', pattern }, { required: true });
  assert.deepEqual(cli.map((f) => f.status), ['vulnerable']);
});

test('the checker id names the analysis and its parameters, so verdicts made any other way are redone', () => {
  assert.match(
    checkerId(),
    /^recheck@[^;]+;analysis=auto\+fuzz;attackLimit=10000000;maxRepeatCount=5;maxSimpleRepeatCount=5;timeout=10000$/
  );
});

test('a verdict that only ran out of time is never stored, and memory forgets it', async (t) => {
  const previous = process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
  process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = '100';
  const saved = new Map<string, RegexVerdict>();
  let loads = 0;
  setVerdictStore({
    async load(keys) {
      loads++;
      return new Map(keys.filter((k) => saved.has(k)).map((k) => [k, saved.get(k)!]));
    },
    async loadAll() {
      return new Map(saved);
    },
    async save(entries) {
      for (const { key, verdict } of entries) saved.set(key, verdict);
    },
  });
  t.after(() => {
    setVerdictStore(null);
    setTransientVerdictTtl(10 * 60_000);
    if (previous === undefined) delete process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
    else process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = previous;
  });
  // The same large, safe pattern the "indeterminate" test uses: undecidable in 100 ms.
  const refs = [
    {
      location: 'pattern',
      source:
        '^(?<client_ip>[\\d.]+) - (?<remote_user>\\S+) \\[(?<timestamp>[^\\]]+)\\] "(?<method>\\w+) (?<request_uri>\\S+) ' +
        '(?<protocol>[^"]+)" (?<status_code>\\d{3}) (?<bytes>\\d+|-)(?: "(?<referer>[^"]*)" "(?<user_agent>[^"]*)")?' +
        '(?: (?<request_time>[\\d.]+))?(?: (?<upstream>\\S+))?$',
      flags: '',
    },
  ];
  const first = await assessRegexes(refs);
  assert.match(first.warnings[0] ?? '', /hit its time budget/);
  assert.equal(saved.size, 0, 'a time-budget "unknown" is not persisted');
  assert.equal(loads, 1);

  // Within the retry window, memory answers (a save is not slowed down again).
  await assessRegexes(refs);
  assert.equal(loads, 1);

  // Once it expires, the regex is looked up and analyzed again.
  setTransientVerdictTtl(0);
  const again = await assessRegexes(refs);
  assert.equal(loads, 2);
  assert.match(again.warnings[0] ?? '', /hit its time budget/);
  assert.equal(saved.size, 0);
});

test('one call with more new regexes than the queue holds is analyzed a few at a time, not refused as busy', async () => {
  // The scan pool refuses a 65th waiting task (that is how saturation from
  // concurrent callers is detected); one save with 80 new regexes is not that.
  const refs = Array.from({ length: 80 }, (_, i) => ({
    location: `derivations[0].extract.f${i}`,
    source: `^busy${i}x(\\d+)$`,
    flags: '',
  }));
  const report = await assessRegexes(refs);
  assert.deepEqual(report, { vulnerable: [], undecided: [], unknown: [], errors: [], warnings: [] });
});
