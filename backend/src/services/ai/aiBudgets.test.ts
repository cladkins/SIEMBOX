/**
 * AI budgets (aiBudgets.ts): defaults, stored values, bounds and the save plan.
 * Pure, DB-free. `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AI_BUDGET_FIELDS,
  AI_BUDGET_SETTING_KEYS,
  AiBudgetValidationError,
  ANSWER_CALL_TIMEOUT_MS,
  MAX_ANALYST_WALL_SECONDS,
  aiBudgetBounds,
  defaultAiBudgets,
  parseAiBudgets,
  planAiBudgetSave,
  tokenLimitNote,
} from './aiBudgets';
import { isSecretSettingKey, isReadableSetting } from '../settings/settingsRedaction';

test('defaults: raised so answers are not cut short out of the box', () => {
  assert.deepEqual(defaultAiBudgets(), {
    analyst: { answerMaxTokens: 4000, stepMaxTokens: 1500, maxToolCalls: 10, wallBudgetSeconds: 180 },
    triage: { answerMaxTokens: 3000, stepMaxTokens: 1500, maxToolCalls: 6, wallBudgetSeconds: 110 },
    builder: { maxTokens: 8000 },
    explain: { maxTokens: 3000 },
  });
});

test('an install that never changed a budget (no rows) gets the defaults', () => {
  assert.deepEqual(parseAiBudgets({}), defaultAiBudgets());
  assert.deepEqual(
    parseAiBudgets({ ai_chat_answer_max_output: '', ai_builder_max_output: 'abc', ai_chat_max_tool_calls: null }),
    defaultAiBudgets()
  );
});

test('stored values win over the defaults; triage keeps the rows the AI Triage form saved', () => {
  const b = parseAiBudgets({
    ai_chat_answer_max_output: '12000',
    ai_chat_step_max_output: '600',
    ai_chat_max_tool_calls: '4',
    ai_chat_wall_budget_seconds: '90',
    // Saved by PUT /api/settings/ai-triage before this change: kept as they are.
    ai_triage_max_tool_calls: '9',
    ai_triage_wall_budget_seconds: '200',
    ai_builder_max_output: '16000',
  });
  assert.deepEqual(b.analyst, { answerMaxTokens: 12000, stepMaxTokens: 600, maxToolCalls: 4, wallBudgetSeconds: 90 });
  assert.equal(b.triage.maxToolCalls, 9);
  assert.equal(b.triage.wallBudgetSeconds, 200);
  assert.equal(b.triage.answerMaxTokens, 3000, 'unset fields keep their defaults');
  assert.equal(b.builder.maxTokens, 16000);
});

test('a hand-edited row outside the bounds is clamped into them', () => {
  const b = parseAiBudgets({
    ai_chat_answer_max_output: '999999',
    ai_chat_step_max_output: '10',
    ai_chat_max_tool_calls: '100',
    ai_chat_wall_budget_seconds: '5000',
  });
  assert.equal(b.analyst.answerMaxTokens, 32000);
  assert.equal(b.analyst.stepMaxTokens, 256);
  assert.equal(b.analyst.maxToolCalls, 25);
  assert.equal(b.analyst.wallBudgetSeconds, MAX_ANALYST_WALL_SECONDS);
});

test('bounds: tokens 256-32000, lookups 1-25, analyst time 30-240 s, triage time 20-280 s', () => {
  const bounds = aiBudgetBounds();
  for (const [section, fields] of Object.entries(bounds)) {
    for (const [field, spec] of Object.entries(fields)) {
      if (/Tokens$/.test(field)) assert.deepEqual([spec.min, spec.max], [256, 32000], `${section}.${field}`);
      assert.ok(spec.default >= spec.min && spec.default <= spec.max, `${section}.${field} default is in bounds`);
    }
  }
  assert.deepEqual([bounds.analyst.maxToolCalls.min, bounds.analyst.maxToolCalls.max], [1, 25]);
  assert.deepEqual([bounds.triage.maxToolCalls.min, bounds.triage.maxToolCalls.max], [1, 25]);
  assert.deepEqual([bounds.analyst.wallBudgetSeconds.min, bounds.analyst.wallBudgetSeconds.max], [30, 240]);
  assert.deepEqual([bounds.triage.wallBudgetSeconds.min, bounds.triage.wallBudgetSeconds.max], [20, 280]);
});

test('the longest analyst run stays under the request path timeouts (nginx 420 s, browser 415 s)', () => {
  // Gathering may run the whole time budget; the answer call after it has its own allowance.
  const worstMs = MAX_ANALYST_WALL_SECONDS * 1000 + ANSWER_CALL_TIMEOUT_MS;
  assert.ok(worstMs <= 360_000, `worst case ${worstMs} ms leaves room for tool time under 415 s`);
});

test('save plan: valid values become rows; a value equal to its default removes the row', () => {
  const writes = planAiBudgetSave({
    analyst: { answerMaxTokens: 6000, maxToolCalls: 10 },
    triage: { wallBudgetSeconds: 200 },
    builder: { maxTokens: 8000 },
  });
  assert.deepEqual(writes, {
    ai_chat_answer_max_output: '6000',
    ai_chat_max_tool_calls: null, // = default: follow the default
    ai_triage_wall_budget_seconds: '200',
    ai_builder_max_output: null,
  });
  assert.deepEqual(planAiBudgetSave({}), {});
});

test('save plan: out-of-bounds, fractional, non-numeric and unknown input is refused', () => {
  const bad: unknown[] = [
    null,
    [],
    'x',
    { analyst: { answerMaxTokens: 255 } },
    { analyst: { answerMaxTokens: 32001 } },
    { analyst: { stepMaxTokens: 1000.5 } },
    { analyst: { maxToolCalls: 0 } },
    { analyst: { maxToolCalls: 26 } },
    { analyst: { wallBudgetSeconds: 29 } },
    { analyst: { wallBudgetSeconds: 241 } },
    { triage: { wallBudgetSeconds: 281 } },
    { triage: { maxToolCalls: '6' } },
    { builder: { maxTokens: Number.NaN } },
    { builder: { maxTokens: Infinity } },
    { explain: { maxTokens: 100 } },
    { analyst: 5 },
    { analyst: { temperature: 1 } },
    { cheapo: { maxTokens: 1000 } },
  ];
  for (const body of bad) {
    assert.throws(() => planAiBudgetSave(body), AiBudgetValidationError, JSON.stringify(body));
  }
  assert.throws(
    () => planAiBudgetSave({ analyst: { maxToolCalls: 30 } }),
    /analyst\.maxToolCalls \(AI Analyst max data lookups\) must be a whole number between 1 and 25/
  );
});

test('setting rows: one per budget, readable by GET /api/settings, never named like a credential', () => {
  assert.equal(new Set(AI_BUDGET_SETTING_KEYS).size, AI_BUDGET_SETTING_KEYS.length);
  for (const key of AI_BUDGET_SETTING_KEYS) {
    assert.equal(isSecretSettingKey(key), false, `${key} is not redacted as a secret`);
    assert.equal(isReadableSetting(key, '4000'), true, `${key} is on the reviewed readable list`);
  }
  assert.equal(AI_BUDGET_FIELDS.triage.maxToolCalls.key, 'ai_triage_max_tool_calls');
  assert.equal(AI_BUDGET_FIELDS.triage.wallBudgetSeconds.key, 'ai_triage_wall_budget_seconds');
});

test('the token-limit note names the limit and where to raise it', () => {
  assert.equal(
    tokenLimitNote(4000, 'This answer', 'Answer length'),
    'This answer hit the 4000-token output limit, so it may be cut off. An admin can raise "Answer length" in Settings → AI → AI budgets.'
  );
});
