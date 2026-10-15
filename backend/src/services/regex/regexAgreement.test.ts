/**
 * The ReDoS gate and the engines must read a regex the same way. The gate
 * analyzes strings; the engines used to let `new RegExp` stringify anything
 * (`["^(a+)+$"]` becomes "^(a+)+$", `flags: [i]` becomes "i"), so a value
 * wrapped in a list was stored as "safe" and then ran as the vulnerable
 * pattern it hid. Now the engines compile only strings and the validators
 * refuse anything else. DB-free; `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyDerivations, validateDerivations } from '../parser/derive';
import { collectParserRegexes } from '../parser/redos';
import { runParser } from '../parser/runParser';
import { validatePortableParser } from '../parser/parserPortable';
import { collectRuleRegexes, ruleRegexTypeErrors, validateRule } from '../rules/rulePortable';
import { normalizeUserRegex, testUserRegex, UserRegexError } from '../rules/userRegex';
import { validateUpdateParserBody } from '../../routes/parsers';

function within(ms: number, run: () => void): number {
  const started = Date.now();
  run();
  const took = Date.now() - started;
  assert.ok(took < ms, `took ${took} ms`);
  return took;
}

// The array-wrapped regexes below are harmless ones that WOULD match their
// input if compiled (`new RegExp(["^a+!$"])` is /^a+!$/), so "no match" proves
// nothing was compiled. (The stall a hidden ^(a+)+$ caused is covered end to
// end in routes/regexSafety.db.test.ts.)

test('a derivation matcher that is not a string never compiles, and is not collected', () => {
  const derivations = [{ when: { payload: { matches: ['^a+!$'] } }, set: { hit: 'yes' } }];
  // The gate's view: nothing to analyze.
  assert.deepEqual(collectParserRegexes({ parser_type: 'json', pattern: '', derivations }), []);
  // The engine's view: nothing runs either (the matcher fails).
  const fields: Record<string, any> = { payload: 'aaa!' };
  applyDerivations(fields, derivations);
  assert.equal(fields.hit, undefined);
  // A string matcher still works.
  const ok: Record<string, any> = { payload: 'ADMIN' };
  applyDerivations(ok, [{ when: { payload: { matches: '^admin$' } }, set: { hit: 'yes' } }]);
  assert.equal(ok.hit, 'yes');
});

test('an extract pattern that is not a string never compiles, and is not collected', () => {
  const derivations = [{ extract: { q: { from: 'payload', pattern: ['^(a+)!$'] } } }];
  assert.deepEqual(collectParserRegexes({ parser_type: 'json', pattern: '', derivations }), []);
  const fields: Record<string, any> = { payload: 'aaa!' };
  applyDerivations(fields, derivations);
  assert.equal(fields.q, undefined);
  const ok: Record<string, any> = { payload: 'aaa!' };
  applyDerivations(ok, [{ extract: { q: { from: 'payload', pattern: '^(a+)!$' } } }]);
  assert.equal(ok.q, 'aaa');
});

test('a parser pattern that is not a string never compiles', () => {
  const parser = {
    name: 'x',
    parser_type: 'regex' as const,
    pattern: ['^(?<p>a+)!$'] as unknown as string,
    field_mappings: { p: 'p' },
  };
  assert.deepEqual(collectParserRegexes(parser), []);
  assert.equal(runParser(parser, 'aaa!'), null);
  assert.ok(runParser({ ...parser, pattern: '^(?<p>a+)!$' }, 'aaa!'), 'the string form matches');
});

test('validateDerivations refuses a non-string `matches` (it used to String() it)', () => {
  assert.deepEqual(validateDerivations([{ when: { message: { matches: ['^(a|a)+$'] } }, set: { x: 'y' } }]), [
    'derivations[0].when.message.matches must be a string (a regex)',
  ]);
  assert.deepEqual(validateDerivations([{ when: { message: { matches: 42 } }, set: { x: 'y' } }]), [
    'derivations[0].when.message.matches must be a string (a regex)',
  ]);
  assert.deepEqual(validateDerivations([{ when: { message: { matches: '^ok$' } }, set: { x: 'y' } }]), []);
  // So the import, catalog install, content packs and `validate-parsers` refuse it too.
  const portable = {
    schema: 'siembox.parser/v1',
    name: 'array-matches',
    parser_type: 'regex',
    pattern: '^(?<payload>\\S+)$',
    field_mappings: { payload: 'payload' },
    derivations: [{ when: { payload: { matches: ['^(a|a)+$'] } }, set: { x: 'y' } }],
  };
  const v = validatePortableParser(portable);
  assert.equal(v.ok, false);
  assert.ok(v.errors.includes('derivations[0].when.payload.matches must be a string (a regex)'), v.errors.join('; '));
});

test('PUT /api/parsers/:id body checks: pattern and derivation regexes must be strings', () => {
  assert.equal(validateUpdateParserBody({ pattern: ['|^(c+)+$|'] }), 'pattern must be a string');
  assert.equal(validateUpdateParserBody({ pattern: 7 }), 'pattern must be a string');
  assert.match(
    validateUpdateParserBody({ derivations: [{ extract: { q: { from: 'p', pattern: ['^(a+)+$'] } } }] }) ?? '',
    /^Invalid derivations: derivations\[0\]\.extract\.q\.pattern must be a non-empty string$/
  );
  assert.match(
    validateUpdateParserBody({ derivations: [{ when: { p: { matches: ['^(a+)+$'] } }, set: { t: '1' } }] }) ?? '',
    /matches must be a string/
  );
  assert.equal(validateUpdateParserBody({ pattern: '^ok$', derivations: null }), null);
  assert.equal(validateUpdateParserBody({ enabled: false } as any), null);
});

test('rule flags that are not a string are refused by the compiler, so the gate and the engine agree', () => {
  // ^(?:q|Q)+$ is linear case-sensitively and exponential with "i".
  assert.throws(() => normalizeUserRegex('^(?:q|Q)+$', ['i']), UserRegexError);
  assert.deepEqual(normalizeUserRegex('^(?:q|Q)+$', 'i'), { source: '^(?:q|Q)+$', flags: 'i' });
  assert.deepEqual(normalizeUserRegex('^x$', null), { source: '^x$', flags: '' });

  const rule = { conditions: [{ field: 'payload', operator: 'regex', value: '^(?:q|Q)+$', flags: ['i'] }] };
  // The gate collects nothing for it (it used to collect it with NO flags: "safe")...
  assert.deepEqual(collectRuleRegexes(rule), []);
  // ...and the engine's call does not run it (it used to apply "i": exponential).
  within(200, () => {
    const r = testUserRegex('^(?:q|Q)+$', 'q'.repeat(27) + '!', ['i'] as unknown as string);
    assert.equal(r.matched, false);
    assert.match(r.error ?? '', /flags must be a string/);
  });
  // A string flag is collected with the flags the engine applies.
  assert.deepEqual(collectRuleRegexes({ conditions: [{ ...rule.conditions[0], flags: 'i' }] }), [
    { location: 'conditions[0].value', source: '^(?:q|Q)+$', flags: 'i' },
  ]);
});

test('POST/PUT /api/rules type checks: regex flags must be a string, value a scalar', () => {
  assert.deepEqual(
    ruleRegexTypeErrors({
      conditions: [
        { field: 'payload', operator: 'regex', value: '^x$', flags: ['i'] },
        { field: 'payload', operator: 'regex', value: ['^(a+)+$'] },
        { field: 'payload', operator: 'regex', value: '^ok$', flags: 'i' },
        { field: 'payload', operator: 'regex', value: 404 },
        { field: 'payload', operator: 'in', value: ['a', 'b'] },
      ],
    }),
    ['conditions[0].flags must be a string (e.g. "i")', 'conditions[1].value for "regex" must be a string']
  );
  assert.deepEqual(ruleRegexTypeErrors(undefined), []);
  assert.deepEqual(ruleRegexTypeErrors({ conditions: 'nope' }), []);
  // validateRule (catalog, packs, CI) already refused non-string flags; still does.
  const v = validateRule({
    name: 'x',
    severity: 'low',
    conditions: [{ field: 'payload', operator: 'regex', value: '^x$', flags: ['i'] }],
    alert: { title: 't', description: 'd' },
  });
  assert.ok(v.errors.includes('conditions[0].flags must be a string (e.g. "i")'), v.errors.join('; '));
});
