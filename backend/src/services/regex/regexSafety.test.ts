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
  clearRegexVerdictCache,
  closeRegexScanPool,
  collectRuleRegexes,
  peekRegexSafety,
  refusalBody,
  setVerdictStore,
  type RegexVerdict,
  type VerdictStore,
} from './regexSafety';
import { redosErrorMessage } from '../parser/redos';

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
  assert.deepEqual(report, { vulnerable: [], unknown: [], errors: [], warnings: [] });
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
